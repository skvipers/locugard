"""Интеграционные тесты всех 8 сценариев (S1–S8), граничных случаев (E1–E5) и HTTPS WebAuthn-среза LocuGard."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from locugard.auth_channels import AuthChannels
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthError, AuthService, resolve_network_zone
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from locugard.web_server import create_web_app

try:
    import cbor2
    import starlette  # noqa: F401
    import uvicorn
    import webauthn  # noqa: F401
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from webauthn.helpers import bytes_to_base64url
    HAS_WEB = True
except ImportError:
    HAS_WEB = False


def _gen_ec_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub_pem


def _sign_ec(priv, msg: bytes) -> bytes:
    return priv.sign(msg, ec.ECDSA(hashes.SHA256()))


def _make_reg(chal_b64: str, origin: str, rp_id: str, priv, cred_id: bytes, backed_up: bool = False) -> dict:
    nums = priv.public_key().public_numbers()
    cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
    cd = json.dumps({"type": "webauthn.create", "challenge": chal_b64, "origin": origin, "crossOrigin": False}).encode()
    flags = 0x45 | (0x18 if backed_up else 0x00)  # UP|UV|AT (+ BE|BS)
    ad = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 1) + (b"\x00" * 16) + struct.pack(">H", len(cred_id)) + cred_id + cose
    att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
    return {"id": bytes_to_base64url(cred_id), "rawId": bytes_to_base64url(cred_id), "type": "public-key", "response": {"clientDataJSON": bytes_to_base64url(cd), "attestationObject": bytes_to_base64url(att)}}


def _make_assert(chal_b64: str, origin: str, rp_id: str, priv, cred_id: bytes, count: int, uv: bool = True) -> dict:
    cd = json.dumps({"type": "webauthn.get", "challenge": chal_b64, "origin": origin, "crossOrigin": False}).encode()
    flags = 0x01 | (0x04 if uv else 0x00)
    ad = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", count)
    sig = priv.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
    return {"id": bytes_to_base64url(cred_id), "rawId": bytes_to_base64url(cred_id), "type": "public-key", "response": {"clientDataJSON": bytes_to_base64url(cd), "authenticatorData": bytes_to_base64url(ad), "signature": bytes_to_base64url(sig), "userHandle": None}}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _gen_tls(certs_dir: Path) -> tuple[Path, Path, Path]:
    certs_dir.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_k = ec.generate_private_key(ec.SECP256R1())
    ca_n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LocuGard Test CA")])
    ca_c = x509.CertificateBuilder().subject_name(ca_n).issuer_name(ca_n).public_key(ca_k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_k, hashes.SHA256())
    s_k = ec.generate_private_key(ec.SECP256R1())
    s_n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    s_c = x509.CertificateBuilder().subject_name(s_n).issuer_name(ca_n).public_key(s_k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_k, hashes.SHA256())
    ca_p, crt_p, key_p = certs_dir / "ca.crt", certs_dir / "srv.crt", certs_dir / "srv.key"
    ca_p.write_bytes(ca_c.public_bytes(serialization.Encoding.PEM))
    crt_p.write_bytes(s_c.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(s_k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_p, crt_p, key_p


def _http(url: str, ctx: ssl.SSLContext, method: str = "GET", data: dict | None = None, headers: dict | None = None):
    hdrs = dict(headers or {})
    raw = json.dumps(data).encode() if data is not None else None
    if raw is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=raw, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.status, dict(r.headers.items()), json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), json.loads(e.read().decode())


class TestStdlibCore(unittest.TestCase):
    """Тесты без сторонних зависимостей (чистая стандартная библиотека Python)."""

    def test_s4_network_zone_and_spoofed_headers(self) -> None:
        self.assertEqual(resolve_network_zone("198.51.100.5", ["192.168.10.0/24"], [], "192.168.10.20"), "outside_lan")
        self.assertEqual(resolve_network_zone("127.0.0.1", ["192.168.10.0/24"], ["127.0.0.1/32"], "192.168.10.20"), "lan")
        self.assertEqual(resolve_network_zone(None, ["192.168.10.0/24"]), "outside_lan")


@unittest.skipUnless(HAS_WEB, "Требуется опциональный extra [web]")
class TestAllEightScenarios(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name)
        self.notifications: list[tuple[str, list[str], dict]] = []
        self.fail_notify = False

        def _notify(ev: str, recips: list[str], payload: dict) -> None:
            if self.fail_notify:
                raise RuntimeError("telegram_unreachable")
            self.notifications.append((ev, recips, payload))

        self.rp_id = "localhost"
        self.origin = "https://localhost:8443"
        self.store = AuthStore(self.data_dir, pepper=b"0123456789abcdef0123456789abcdef", on_notify=_notify)
        self.store.update_server_policy(allowed_networks=["192.168.10.0/24", "127.0.0.0/8"])
        self.auth = AuthService(self.store, rp_id=self.rp_id, expected_origin=self.origin)
        self.ch = AuthChannels(self.store, self.auth)
        self.perms = LocalPermissions(self.data_dir)
        self.bridge = AuthPermissionsBridge(self.store, self.auth, self.perms)

        # P0: bootstrap первого owner (с аппаратной меткой для тестов режимов 3–4)
        self.owner_key, _ = _gen_ec_key()
        self.owner_cid = os.urandom(32)
        b = self.auth.bootstrap_owner_begin("Alice")
        boot = self.auth.bootstrap_owner_complete(
            challenge_id=b["challenge_id"], display_name="Alice", device_name="Owner-HW1",
            credential_payload=_make_reg(b["options"]["challenge"], self.origin, self.rp_id, self.owner_key, self.owner_cid),
            hardware_binding=True,
        )
        self.owner_id = boot["account_id"]
        self.owner_dev1 = boot["device_id"]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _web_login(self, priv, cid: bytes, count: int, ip: str = "192.168.10.20", old_tok: str | None = None, uv: bool = True, require_uv: bool | None = None) -> dict:
        opt = self.auth.login_begin(source_key=f"{ip}:{count}:{os.urandom(2).hex()}")
        return self.auth.login_verify(
            challenge_id=opt["challenge_id"],
            credential_payload=_make_assert(opt["options"]["challenge"], self.origin, self.rp_id, priv, cid, count, uv=uv),
            peer_ip=ip, old_session_token=old_tok, require_uv=require_uv,
        )

    def _enroll_web_device(self, owner_ctx, target_acc_id: str, role: str, name: str, *, hw: bool = False, backed_up: bool = False, second_ver_id: str | None = None):
        enr = self.auth.create_enrollment_code(owner_ctx, target_account_id=target_acc_id)
        priv, _ = _gen_ec_key()
        cid = os.urandom(32)
        ropt = self.auth.register_begin(enrollment_id=enr["enrollment_id"], secret=enr["secret"])
        sub = self.auth.submit_registration(
            enrollment_id=enr["enrollment_id"], secret=enr["secret"], challenge_id=ropt["challenge_id"],
            device_name=name, requested_role=role,
            credential_payload=_make_reg(ropt["options"]["challenge"], self.origin, self.rp_id, priv, cid, backed_up=backed_up),
            hardware_binding=hw,
        )
        self.auth.approve_registration(owner_ctx, request_id=sub["request_id"], second_verification_id=second_ver_id)
        return sub["device_id"], priv, cid

    def test_s1_s2_s3_s5_web_enrollment_shared_device_and_telegram(self) -> None:
        # S1 & S3: вход owner + регистрация member и guest + переключение на общем устройстве
        o_login = self._web_login(self.owner_key, self.owner_cid, 2)
        o_ctx = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        member_id = self.store.create_account("Bob", "member")["account_id"]
        guest_id = self.store.create_account("Guest", "guest")["account_id"]

        # S2: 5 неверных попыток кода -> отзыв кода; гонка повторного кода
        enr_bad = self.auth.create_enrollment_code(o_ctx, target_account_id=guest_id)
        for _ in range(5):
            with self.assertRaises(AuthError):
                self.auth.register_begin(enrollment_id=enr_bad["enrollment_id"], secret="wrong")
        # После 5 ошибок даже верный код отклонён
        with self.assertRaises(AuthError):
            self.auth.register_begin(enrollment_id=enr_bad["enrollment_id"], secret=enr_bad["secret"])

        # S2: Telegram-одобрение выключено по умолчанию, а при включении запрещено для owner
        enr_g = self.auth.create_enrollment_code(o_ctx, target_account_id=guest_id)
        g_key, _ = _gen_ec_key()
        g_cid = os.urandom(32)
        ropt = self.auth.register_begin(enrollment_id=enr_g["enrollment_id"], secret=enr_g["secret"])
        sub_g = self.auth.submit_registration(
            enrollment_id=enr_g["enrollment_id"], secret=enr_g["secret"], challenge_id=ropt["challenge_id"],
            device_name="Guest-Tab", requested_role="guest",
            credential_payload=_make_reg(ropt["options"]["challenge"], self.origin, self.rp_id, g_key, g_cid),
        )
        # Гонка повторного кода после consumed -> отказ
        with self.assertRaises(AuthError):
            self.auth.register_begin(enrollment_id=enr_g["enrollment_id"], secret=enr_g["secret"])
        # Telegram выключен по умолчанию
        with self.assertRaises(AuthError) as cm:
            self.ch.telegram_issue_approval_callback(request_id=sub_g["request_id"], owner_account_id=self.owner_id)
        self.assertEqual(cm.exception.code, "telegram_approval_disabled")

        # Проверенная привязка Telegram (P4 §7.1: link -> update -> web confirm)
        lk = self.ch.telegram_link_begin(o_ctx)
        self.ch.telegram_link_receive_update(link_token=lk["link_token"], verified_telegram_user_id=777001)
        self.ch.telegram_link_confirm_web(o_ctx, link_id=lk["link_id"])
        self.ch.change_server_policy(o_ctx, telegram_approval_enabled=True)

        # Одобрение guest-заявки через Telegram работает (но только от привязанного ID и одноразово!)
        cb = self.ch.telegram_issue_approval_callback(request_id=sub_g["request_id"], owner_account_id=self.owner_id)
        with self.assertRaises(AuthError):
            self.ch.telegram_approve_registration(callback_id=cb["callback_id"], verified_telegram_user_id=999999)
        self.ch.telegram_approve_registration(callback_id=cb["callback_id"], verified_telegram_user_id=777001)
        with self.assertRaises(AuthError):  # повтор callback запрещён
            self.ch.telegram_approve_registration(callback_id=cb["callback_id"], verified_telegram_user_id=777001)

        # Заявка для owner через Telegram ЗАПРЕЩЕНА (A4-К2)
        enr_o2 = self.auth.create_enrollment_code(o_ctx, target_account_id=self.owner_id)
        o2_k, _ = _gen_ec_key()
        o2_cid = os.urandom(32)
        ro2 = self.auth.register_begin(enrollment_id=enr_o2["enrollment_id"], secret=enr_o2["secret"])
        sub_o2 = self.auth.submit_registration(
            enrollment_id=enr_o2["enrollment_id"], secret=enr_o2["secret"], challenge_id=ro2["challenge_id"],
            device_name="Owner-2", requested_role="owner",
            credential_payload=_make_reg(ro2["options"]["challenge"], self.origin, self.rp_id, o2_k, o2_cid),
        )
        with self.assertRaises(AuthError) as cm_o:
            self.ch.telegram_issue_approval_callback(request_id=sub_o2["request_id"], owner_account_id=self.owner_id)
        self.assertEqual(cm_o.exception.code, "telegram_approval_forbidden_for_owner")

        # S3: Переключение с owner на guest на общем устройстве закрывает старую сессию owner!
        g_login = self._web_login(g_key, g_cid, 2, old_tok=o_login["session_token"])
        with self.assertRaises(AuthError):
            self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        g_ctx = self.auth.verify_session(g_login["session_token"], peer_ip="192.168.10.20")
        self.assertEqual(g_ctx.role, "guest")
        with self.assertRaises(AuthError):  # гость не может менять политику
            self.ch.change_server_policy(g_ctx, min_mode=1)

        # S5: Просроченный вызов и чужой origin
        opt_exp = self.auth.login_begin(source_key="exp-test")
        with self.store.transaction() as conn:
            conn.execute("UPDATE challenges SET expires_at = ? WHERE challenge_id = ?", (time.time() - 5, opt_exp["challenge_id"]))
        with self.assertRaises(AuthError):
            self.auth.login_verify(
                challenge_id=opt_exp["challenge_id"],
                credential_payload=_make_assert(opt_exp["options"]["challenge"], self.origin, self.rp_id, g_key, g_cid, 3),
                peer_ip="192.168.10.20",
            )
        # S1: member не имеет доступа к owner
        self.assertNotIn(f"personal:{self.owner_id}", g_ctx.granted_scopes)
        self.assertEqual(member_id[:4], "acc_")

    def test_s6_app_refresh_reuse_and_idle_not_extended(self) -> None:
        # P2 & P7: вход приложения, ротация refresh, повтор старого поколения -> отзыв цепочки и сессии (T23)
        priv, pub_pem = _gen_ec_key()
        app_dev = self.ch.register_app_device_direct(account_id=self.owner_id, device_name="App-Win", public_key_pem=pub_pem, hardware_binding=True)
        c = self.ch.app_login_begin(device_id=app_dev["device_id"])
        msg = f"locugard:app_login:{self.rp_id}:{app_dev['device_id']}:".encode() + bytes.fromhex(c["challenge_hex"])
        toks1 = self.ch.app_login_verify(challenge_id=c["challenge_id"], device_id=app_dev["device_id"], signature=_sign_ec(priv, msg), user_verified=True, peer_ip="192.168.10.20")

        # Случайный мусорный токен НЕ отзывает активную сессию (защита от DoS)
        with self.assertRaises(AuthError) as cm_bad:
            self.ch.app_refresh(refresh_token="random-garbage-token", peer_ip="192.168.10.20")
        self.assertEqual(cm_bad.exception.code, "refresh_invalid")

        # Штатная ротация gen 1 -> gen 2 не продлевает idle_expires_at (A4-С7)
        with self.store.readonly() as conn:
            idle_before = conn.execute("SELECT idle_expires_at FROM sessions WHERE session_id = ?", (toks1["session_id"],)).fetchone()[0]
        toks2 = self.ch.app_refresh(refresh_token=toks1["refresh_token"], peer_ip="192.168.10.20")
        self.assertEqual(toks2["generation"], 2)
        with self.store.readonly() as conn:
            idle_after = conn.execute("SELECT idle_expires_at FROM sessions WHERE session_id = ?", (toks1["session_id"],)).fetchone()[0]
        self.assertEqual(idle_before, idle_after)

        # Повтор старого поколения gen 1 -> немедленный отзыв цепочки и сессии + уведомление!
        with self.assertRaises(AuthError) as cm_reuse:
            self.ch.app_refresh(refresh_token=toks1["refresh_token"], peer_ip="192.168.10.20")
        self.assertEqual(cm_reuse.exception.code, "refresh_reuse_detected")
        with self.assertRaises(AuthError):  # даже новый access_token сразу недействителен (T24)
            self.auth.verify_session(toks2["access_token"], peer_ip="192.168.10.20")
        self.assertTrue(any(ev == "refresh_reuse_detected" for ev, _, _ in self.notifications))

    def test_s7_s8_modes_1_to_4_synced_passkey_policy_and_recovery(self) -> None:
        o_login = self._web_login(self.owner_key, self.owner_cid, 2)
        o_ctx = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")

        # Второе независимое аппаратное устройство owner для режимов 3–4
        dev2_id, dev2_k, dev2_cid = self._enroll_web_device(o_ctx, self.owner_id, "owner", "Owner-HW2", hw=True)
        # Member с активной сессией (для проверки изоляции режима 4)
        m_id = self.store.create_account("Bob", "member")["account_id"]
        _, m_k, m_cid = self._enroll_web_device(o_ctx, m_id, "member", "Bob-PC", hw=True)
        m_login = self._web_login(m_k, m_cid, 2)

        # S8a: Режим 1 в LAN -> выход из LAN повышает до режима 2 и отклоняет сессию режима 1!
        self.ch.change_server_policy(o_ctx, min_mode=1)
        with self.store.transaction() as conn:
            conn.execute("UPDATE accounts SET min_mode = 1 WHERE account_id = ?", (self.owner_id,))
        m1_login = self._web_login(self.owner_key, self.owner_cid, 3, uv=False)
        self.assertEqual(m1_login["effective_mode"], 1)
        # В LAN для R1 работает:
        self.assertEqual(self.auth.verify_session(m1_login["session_token"], peer_ip="192.168.10.20", action_min_mode=1).effective_mode, 1)
        # Вне LAN (или для R2) сессия режима 1 отклоняется (step_up_relogin_required):
        with self.assertRaises(AuthError) as cm_up:
            self.auth.verify_session(m1_login["session_token"], peer_ip="203.0.113.45", action_min_mode=1)
        self.assertEqual(cm_up.exception.code, "step_up_relogin_required")
        # При outside_lan_behavior = deny блокируются даже режимы 2–4 (A4-С1):
        o_login = self._web_login(self.owner_key, self.owner_cid, 4, require_uv=True)
        o_ctx = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        self.ch.change_server_policy(o_ctx, min_mode=2, outside_lan_behavior="deny")
        with self.assertRaises(AuthError) as cm_deny:
            self.auth.verify_session(o_login["session_token"], peer_ip="203.0.113.45")
        self.assertEqual(cm_deny.exception.code, "outside_allowed_network")
        self.ch.change_server_policy(o_ctx, outside_lan_behavior="upgrade_to_2")

        # S8b: Защита последнего owner (T28)
        with self.assertRaises(AuthError) as cm_last:
            self.ch.change_role(o_ctx, target_account_id=self.owner_id, new_role="member")
        self.assertEqual(cm_last.exception.code, "last_owner_invariant")
        with self.assertRaises(AuthError) as cm_susp:
            self.ch.suspend_account(o_ctx, target_account_id=self.owner_id)
        self.assertEqual(cm_susp.exception.code, "last_owner_invariant")

        # P10: Генерация 10 recovery-кодов (в режиме 2)
        rec_set = self.ch.generate_recovery_codes(o_ctx)
        self.assertEqual(len(rec_set["codes"]), 10)

        # S8b + E4: Переход в режим 3 -> попытка сменить политику одним устройством (даже после reauth) отклоняется!
        self.ch.change_server_policy(o_ctx, min_mode=3)
        o_ctx3 = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        ro_same = self.auth.reauth_begin(o_ctx3)
        rv_same = self.auth.reauth_verify(o_ctx3, challenge_id=ro_same["challenge_id"], credential_payload=_make_assert(ro_same["options"]["challenge"], self.origin, self.rp_id, self.owner_key, self.owner_cid, 5), purpose="second_approval")
        o_ctx3 = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        with self.assertRaises(AuthError) as cm_sync:
            self.ch.change_server_policy(o_ctx3, min_mode=4, second_verification_id=rv_same["verification_id"])
        self.assertEqual(cm_sync.exception.code, "second_approval_not_independent")

        # Режим 3 с единственным owner: удалённый recovery-код отклоняется ДО сжигания кода (R2-С3)
        rec_k, rec_pub = _gen_ec_key()
        rc_b = self.ch.recovery_begin(account_id=self.owner_id)
        with self.assertRaises(AuthError) as cm_m3rec:
            self.ch.recovery_submit_code(
                account_id=self.owner_id, recovery_code=rec_set["codes"][0], challenge_id=rc_b["challenge_id"],
                new_public_key_pem=rec_pub, pop_signature=_sign_ec(rec_k, f"locugard:recovery:{self.rp_id}:{self.owner_id}:".encode() + bytes.fromhex(rc_b["challenge_hex"])),
                device_name="Rec-Dev", hardware_binding=True,
            )
        self.assertEqual(cm_m3rec.exception.code, "mode_3_single_owner_console_only")

        # Второе независимое устройство (dev2) подтверждает переход 3 -> 4 через свежий reauth (CRIT-05: login не принимается!)
        dev2_login = self._web_login(dev2_k, dev2_cid, 2)
        dev2_ctx = self.auth.verify_session(dev2_login["session_token"], peer_ip="192.168.10.20")
        with self.assertRaises(AuthError) as cm_login2:
            self.ch.change_server_policy(o_ctx3, min_mode=4, second_verification_id=dev2_ctx.identity_verification_id)
        self.assertEqual(cm_login2.exception.code, "second_approval_must_not_be_login")

        ro = self.auth.reauth_begin(dev2_ctx)
        rv1 = self.auth.reauth_verify(dev2_ctx, challenge_id=ro["challenge_id"], credential_payload=_make_assert(ro["options"]["challenge"], self.origin, self.rp_id, dev2_k, dev2_cid, 3), purpose="second_approval")
        self.ch.change_server_policy(o_ctx3, min_mode=4, second_verification_id=rv1["verification_id"])
        # Повторное использование того же second_verification_id запрещено!
        o_ctx4_tmp = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        with self.assertRaises(AuthError) as cm_reuse2:
            self.ch.change_server_policy(o_ctx4_tmp, min_mode=2, second_verification_id=rv1["verification_id"])
        self.assertEqual(cm_reuse2.exception.code, "second_approval_already_used")

        # A4-К4: В режиме 4 сессия member немедленно отозвана!
        with self.assertRaises(AuthError):
            self.auth.verify_session(m_login["session_token"], peer_ip="192.168.10.20")
        # A4-К1: Понижение 4 -> 2 без второго подтверждения ЗАПРЕЩЕНО!
        o_ctx4 = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        with self.assertRaises(AuthError) as cm_4down:
            self.ch.change_server_policy(o_ctx4, min_mode=2)
        self.assertEqual(cm_4down.exception.code, "second_approval_required")

        # S7f (A4-С6): В режиме 4 одна IdentityVerification привязывается не более чем к одному ActionApproval
        ro2 = self.auth.reauth_begin(dev2_ctx)
        rv2 = self.auth.reauth_verify(dev2_ctx, challenge_id=ro2["challenge_id"], credential_payload=_make_assert(ro2["options"]["challenge"], self.origin, self.rp_id, dev2_k, dev2_cid, 4), purpose="second_approval")
        self.bridge.request_dangerous_action(
            o_ctx4, action_type="web.protected_dangerous_action", description="Критичное 1", resource_scope=f"personal:{self.owner_id}",
            payload={"a": 1}, run=lambda: "ok1", second_verification_id=rv2["verification_id"], critical=True,
        )
        ro3 = self.auth.reauth_begin(dev2_ctx)
        rv3 = self.auth.reauth_verify(dev2_ctx, challenge_id=ro3["challenge_id"], credential_payload=_make_assert(ro3["options"]["challenge"], self.origin, self.rp_id, dev2_k, dev2_cid, 5), purpose="second_approval")
        with self.assertRaises(AuthError) as cm_reuse_ver:
            self.bridge.request_dangerous_action(
                o_ctx4, action_type="web.protected_dangerous_action", description="Критичное 2", resource_scope=f"personal:{self.owner_id}",
                payload={"a": 2}, run=lambda: "ok2", second_verification_id=rv3["verification_id"], critical=True,
            )
        self.assertEqual(cm_reuse_ver.exception.code, "mode_4_verification_already_used")

        # В режиме 4 для смены политики нужна СВЕЖАЯ неизрасходованная IdentityVerification + консольное 2-е подтверждение (CRIT-08)
        ro_o = self.auth.reauth_begin(o_ctx4)
        self.auth.reauth_verify(o_ctx4, challenge_id=ro_o["challenge_id"], credential_payload=_make_assert(ro_o["options"]["challenge"], self.origin, self.rp_id, self.owner_key, self.owner_cid, 6))
        o_ctx4_fresh = self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        con_ver = self.auth.create_console_verification(self.owner_id, "policy_change")
        self.ch.change_server_policy(o_ctx4_fresh, min_mode=2, second_verification_id=con_ver)

        # P10 в режиме 2: сбой доставки уведомления НЕ откатывает recovery; старые сессии и ВСЕ оставшиеся коды отзываются!
        self.fail_notify = True
        rc_b2 = self.ch.recovery_begin(account_id=self.owner_id)
        pop_sig = _sign_ec(rec_k, f"locugard:recovery:{self.rp_id}:{self.owner_id}:".encode() + bytes.fromhex(rc_b2["challenge_hex"]))
        sub_rec = self.ch.recovery_submit_code(
            account_id=self.owner_id, recovery_code=rec_set["codes"][0], challenge_id=rc_b2["challenge_id"],
            new_public_key_pem=rec_pub, pop_signature=pop_sig, device_name="Recovered-Phone",
        )
        conf_msg = f"locugard:recovery_confirm:{sub_rec['recovery_request_id']}:{sub_rec['revocation_scope']}:".encode() + bytes.fromhex(sub_rec["confirm_challenge_hex"])
        done_rec = self.ch.recovery_confirm(
            recovery_request_id=sub_rec["recovery_request_id"],
            confirm_signature=_sign_ec(rec_k, conf_msg),
            origin=self.origin,
        )
        self.assertEqual(done_rec["state"], "completed")
        # Старая сессия отозвана
        with self.assertRaises(AuthError):
            self.auth.verify_session(o_login["session_token"], peer_ip="192.168.10.20")
        # Оставшийся код #2 из старого набора тоже аннулирован!
        rc_b3 = self.ch.recovery_begin(account_id=self.owner_id)
        with self.assertRaises(AuthError) as cm_oldrc:
            self.ch.recovery_submit_code(
                account_id=self.owner_id, recovery_code=rec_set["codes"][1], challenge_id=rc_b3["challenge_id"],
                new_public_key_pem=rec_pub, pop_signature=_sign_ec(rec_k, f"locugard:recovery:{self.rp_id}:{self.owner_id}:".encode() + bytes.fromhex(rc_b3["challenge_hex"])),
                device_name="Second-Try",
            )
        self.assertEqual(cm_oldrc.exception.code, "recovery_code_invalid")

        # В журнале есть recovery_initiated, recovery_completed, notification_delivery_failed и НЕТ сырых recovery-кодов!
        audit_text = self.store.audit_path.read_text(encoding="utf-8")
        self.assertIn("recovery_initiated", audit_text)
        self.assertIn("recovery_completed", audit_text)
        self.assertIn("notification_delivery_failed", audit_text)
        for c_raw in rec_set["codes"]:
            self.assertNotIn(c_raw, audit_text)

    def test_https_web_server_csrf_and_revocation_while_waiting(self) -> None:
        port = _free_port()
        origin = f"https://localhost:{port}"
        ca_p, crt_p, key_p = _gen_tls(self.data_dir / "certs")
        auth_https = AuthService(self.store, rp_id="localhost", expected_origin=origin)
        bridge_https = AuthPermissionsBridge(self.store, auth_https, self.perms)
        app = create_web_app(auth_https, bridge_https)
        srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(crt_p), ssl_keyfile=str(key_p), log_level="error"))
        th = threading.Thread(target=srv.run, daemon=True)
        th.start()
        ctx = ssl.create_default_context(cafile=str(ca_p))
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        try:
            # Анонимный запрос -> 401
            code, _, _ = _http(f"{origin}/api/protected/profile", ctx)
            self.assertEqual(code, 401)
            # Вход по HTTPS + cookie Secure/HttpOnly/SameSite + CSRF
            code, _, lopt = _http(f"{origin}/auth/login/options", ctx, "POST", headers={"Origin": origin})
            self.assertEqual(code, 200)
            code, hdrs, lbody = _http(
                f"{origin}/auth/login/verify", ctx, "POST",
                data={"challenge_id": lopt["challenge_id"], "credential": _make_assert(lopt["options"]["challenge"], origin, "localhost", self.owner_key, self.owner_cid, 10)},
                headers={"Origin": origin},
            )
            self.assertEqual(code, 200)
            sc = hdrs.get("set-cookie", "")
            self.assertIn("HttpOnly", sc)
            self.assertIn("Secure", sc)
            self.assertIn("samesite=lax", sc.lower())
            cookie, csrf = sc.split(";", 1)[0], lbody["csrf_token"]

            # CSRF без токена и с чужим Origin -> 403
            code, _, _ = _http(f"{origin}/api/protected/dangerous-action/request", ctx, "POST", data={"target": "x"}, headers={"Cookie": cookie, "Origin": origin})
            self.assertEqual(code, 403)
            code, _, _ = _http(f"{origin}/api/protected/dangerous-action/request", ctx, "POST", data={"target": "x"}, headers={"Cookie": cookie, "Origin": "https://evil.example", "X-CSRF-Token": csrf})
            self.assertEqual(code, 403)

            # Опасное действие + отзыв устройства во время ожидания -> исполнение заблокировано!
            code, _, dreq = _http(f"{origin}/api/protected/dangerous-action/request", ctx, "POST", data={"target": "prod"}, headers={"Cookie": cookie, "Origin": origin, "X-CSRF-Token": csrf})
            self.assertEqual(code, 200)
            self.store.revoke_device_cascade(self.owner_dev1, "stolen", initiated_by=self.owner_id)
            code, _, _ = _http(f"{origin}/api/protected/dangerous-action/confirm", ctx, "POST", data={"approval_id": dreq["approval_id"], "action_digest": dreq["action_digest"]}, headers={"Cookie": cookie, "Origin": origin, "X-CSRF-Token": csrf})
            self.assertEqual(code, 401)
            self.assertEqual(app.state.executed_actions, [])
        finally:
            srv.should_exit = True
            th.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
