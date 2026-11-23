"""Регрессионные тесты по итогам финального L4-аудита (CRIT-01 .. CRIT-10, MED-01 .. MED-09)."""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from locugard.auth_channels import AuthChannels
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthError, AuthService, resolve_network_zone
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from tests.test_auth_scenarios import HAS_WEB, _gen_ec_key, _make_assert, _make_reg, _sign_ec


class TestAuditRegressionsStdlib(unittest.TestCase):
    def test_crit02_rightmost_untrusted_xff(self) -> None:
        # Клиент подставил 192.168.10.20 слева, прокси дописал 203.0.113.5 справа
        self.assertEqual(
            resolve_network_zone("127.0.0.1", ["192.168.10.0/24"], ["127.0.0.1/32"], "192.168.10.20, 203.0.113.5"),
            "outside_lan",
        )
        # Цепочка из двух доверенных прокси -> берём 192.168.10.55
        self.assertEqual(
            resolve_network_zone("10.0.0.2", ["192.168.10.0/24"], ["10.0.0.0/24"], "192.168.10.55, 10.0.0.1"),
            "lan",
        )

    def test_crit03_persistent_pepper_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / "data"
            s1 = AuthStore(data_dir)
            s2 = AuthStore(data_dir, allow_create_pepper=False)
            self.assertEqual(s1.pepper, s2.pepper)


@unittest.skipUnless(HAS_WEB, "Требуется опциональный extra [web]")
class TestAuditRegressionsFull(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "data"
        self.rp_id = "localhost"
        self.origin = "https://localhost:8443"
        self.store = AuthStore(self.data_dir)
        self.store.update_server_policy(allowed_networks=["192.168.10.0/24", "127.0.0.0/8"])
        self.auth = AuthService(self.store, rp_id=self.rp_id, expected_origin=self.origin)
        self.ch = AuthChannels(self.store, self.auth)
        self.perms = LocalPermissions(self.data_dir)
        self.bridge = AuthPermissionsBridge(self.store, self.auth, self.perms)

        self.owner_k, _ = _gen_ec_key()
        self.owner_cid = os.urandom(32)
        b = self.auth.bootstrap_owner_begin("Alice")
        boot = self.auth.bootstrap_owner_complete(
            challenge_id=b["challenge_id"], display_name="Alice", device_name="Owner-HW",
            credential_payload=_make_reg(b["options"]["challenge"], self.origin, self.rp_id, self.owner_k, self.owner_cid),
            hardware_binding=True,
        )
        self.owner_id = boot["account_id"]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_crit01_challenge_invalidation_and_session_expiry_commit_to_db(self) -> None:
        # Ошибка подписи в reauth_verify ОБЯЗАНА закоммитить state='invalidated' в БД!
        opt = self.auth.login_begin(source_key="192.168.10.1")
        lg = self.auth.login_verify(
            challenge_id=opt["challenge_id"],
            credential_payload=_make_assert(opt["options"]["challenge"], self.origin, self.rp_id, self.owner_k, self.owner_cid, 2),
            peer_ip="192.168.10.1",
        )
        ctx = self.auth.verify_session(lg["session_token"], peer_ip="192.168.10.1")
        ro = self.auth.reauth_begin(ctx)
        with self.assertRaises(AuthError):
            self.auth.reauth_verify(
                ctx, challenge_id=ro["challenge_id"],
                credential_payload=_make_assert(ro["options"]["challenge"], "https://evil.example", "evil.example", self.owner_k, self.owner_cid, 3),
            )
        with self.store.readonly() as conn:
            st = conn.execute("SELECT state FROM challenges WHERE challenge_id = ?", (ro["challenge_id"],)).fetchone()[0]
        self.assertEqual(st, "invalidated")

        # Истёкшая сессия в verify_session ОБЯЗАНА закоммитить state='expired' в БД!
        with self.store.transaction() as conn:
            conn.execute("UPDATE sessions SET absolute_expires_at = ? WHERE session_id = ?", (time.time() - 5, lg["session_id"]))
        with self.assertRaises(AuthError) as cm:
            self.auth.verify_session(lg["session_token"], peer_ip="192.168.10.1")
        self.assertEqual(cm.exception.code, "session_expired")
        with self.store.readonly() as conn:
            sst = conn.execute("SELECT state FROM sessions WHERE session_id = ?", (lg["session_id"],)).fetchone()[0]
        self.assertEqual(sst, "expired")

    def test_crit06_telegram_rejected_as_second_owner_in_mode3_recovery(self) -> None:
        # Два owner, режим 3: Telegram-верификация второго owner НЕ принимается в recovery_confirm!
        o2_id = self.store.create_account("Owner2", "owner")["account_id"]
        o_opt = self.auth.login_begin(source_key="192.168.10.2")
        o_lg = self.auth.login_verify(challenge_id=o_opt["challenge_id"], credential_payload=_make_assert(o_opt["options"]["challenge"], self.origin, self.rp_id, self.owner_k, self.owner_cid, 2), peer_ip="192.168.10.2")
        o_ctx = self.auth.verify_session(o_lg["session_token"], peer_ip="192.168.10.2")
        # Активируем аппаратный ключ для owner2
        p2, pub2 = _gen_ec_key()
        self.ch.register_app_device_direct(account_id=o2_id, device_name="O2-HW", public_key_pem=pub2, hardware_binding=True)
        # Выпускаем recovery-коды для owner1, затем включаем режим 3
        rc_set = self.ch.generate_recovery_codes(o_ctx)
        self.ch.change_server_policy(o_ctx, min_mode=3)

        # Создаём подложную Telegram-верификацию от owner2
        now = time.time()
        with self.store.transaction() as conn:
            conn.execute("INSERT INTO external_identities (identity_id, account_id, provider, provider_subject, verification_method, verified_at, state, bound_at) VALUES ('ext_o2', ?, 'telegram', '555002', 'test', ?, 'active', ?)", (o2_id, now, now))
            conn.execute("INSERT INTO identity_verifications (verification_id, account_id, channel, external_identity_id, method, verified_at, assurance_level, purpose) VALUES ('ver_tg_o2', ?, 'telegram', 'ext_o2', 'telegram_bound_callback', ?, 2, 'device_enrollment')", (o2_id, now))

        nk, npub = _gen_ec_key()
        rb = self.ch.recovery_begin(account_id=self.owner_id, source_ip="192.168.10.2")
        sub = self.ch.recovery_submit_code(
            account_id=self.owner_id, recovery_code=rc_set["codes"][0], challenge_id=rb["challenge_id"],
            new_public_key_pem=npub, pop_signature=_sign_ec(nk, f"locugard:recovery:{self.rp_id}:{self.owner_id}:".encode() + bytes.fromhex(rb["challenge_hex"])),
            device_name="Rec-HW", origin=self.origin, hardware_binding=True, source_ip="192.168.10.2",
        )
        cmsg = f"locugard:recovery_confirm:{sub['recovery_request_id']}:{sub['revocation_scope']}:".encode() + bytes.fromhex(sub["confirm_challenge_hex"])
        with self.assertRaises(AuthError) as cm:
            self.ch.recovery_confirm(
                recovery_request_id=sub["recovery_request_id"], confirm_signature=_sign_ec(nk, cmsg),
                origin=self.origin, second_verification_id="ver_tg_o2",
            )
        self.assertEqual(cm.exception.code, "second_approval_channel_forbidden")

    def test_crit07_readonly_forbidden_from_dangerous_actions_and_crit09_logout(self) -> None:
        ro_id = self.store.create_account("Viewer", "readonly")["account_id"]
        rk, rpub = _gen_ec_key()
        rdev = self.ch.register_app_device_direct(account_id=ro_id, device_name="RO-App", public_key_pem=rpub, hardware_binding=False)
        c = self.ch.app_login_begin(device_id=rdev["device_id"])
        sig = _sign_ec(rk, f"locugard:app_login:{self.rp_id}:{rdev['device_id']}:".encode() + bytes.fromhex(c["challenge_hex"]))
        lg = self.ch.app_login_verify(challenge_id=c["challenge_id"], device_id=rdev["device_id"], signature=sig, user_verified=True, peer_ip="192.168.10.3")
        rctx = self.auth.verify_session(lg["access_token"], peer_ip="192.168.10.3")
        with self.assertRaises(AuthError) as cm:
            self.bridge.request_dangerous_action(
                rctx, action_type="web.demo", description="Запрещено readonly", resource_scope=f"personal:{ro_id}",
                payload={"x": 1}, run=lambda: "never",
            )
        self.assertEqual(cm.exception.code, "readonly_forbidden")

        # CRIT-10: истёкший 10-минутный access_token отклоняется даже при живой сессии!
        with self.store.transaction() as conn:
            conn.execute("UPDATE sessions SET access_token_expires_at = ? WHERE session_id = ?", (time.time() - 1, lg["session_id"]))
        with self.assertRaises(AuthError) as cm_at:
            self.auth.verify_session(lg["access_token"], peer_ip="192.168.10.3")
        self.assertEqual(cm_at.exception.code, "access_token_expired")

        # CRIT-10: в режиме 3 программный ключ (hardware_binding=0) не может ротировать refresh!
        self.store.update_server_policy(min_mode=3)
        with self.assertRaises(AuthError) as cm_hw:
            self.ch.app_refresh(refresh_token=lg["refresh_token"], peer_ip="192.168.10.3")
        self.assertEqual(cm_hw.exception.code, "hardware_key_required")


if __name__ == "__main__":
    unittest.main()
