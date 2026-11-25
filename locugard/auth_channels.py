"""Канальные и расширенные протоколы LocuGard: P2/P7, P4, P6, P10 (усилено по итогам L4-аудита)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from typing import Any

from .auth_service import (
    CHALLENGE_TTL_S,
    MAX_PENDING_REG_PER_ACCOUNT,
    MODE_DEFAULTS,
    REG_CHALLENGE_TTL_S,
    REG_REQUEST_TTL_S,
    AuthError,
    AuthService,
    VerifiedContext,
    extract_client_ip,
    resolve_network_zone,
)
from .auth_store import AuthStore, hash_secret, key_fingerprint

ACCESS_TOKEN_TTL_S = 600
TG_LINK_TTL_S = 300
TG_CALLBACK_TTL_S = 300
RECOVERY_REQ_TTL_S = 600
PAIRING_TTL_S = 300
PAIRING_MAX_PENDING = 10
PAIRING_MAX_CODE_FAILS = 5
SSO_CODE_TTL_S = 60
_AUDIENCE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_PKCE_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43,128}$")
_USER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _gen_user_code() -> str:
    raw = "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def _norm_user_code(val: str | None) -> str:
    return re.sub(r"[\s-]+", "", (val or "").strip().upper())


def _pkce_s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _validate_audience(audience: str | None) -> str:
    val = (audience or "locugard").strip()
    if not _AUDIENCE_RE.match(val):
        raise AuthError("invalid_audience", status_code=400)
    return val


def _verify_ecdsa_p256(public_key_pem: bytes, message: bytes, signature: bytes) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pub = serialization.load_pem_public_key(public_key_pem)
    pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))


class AuthChannels:
    """Единый фасад расширенных протоколов поверх AuthStore и AuthService."""

    def __init__(self, store: AuthStore, auth: AuthService):
        self.store = store
        self.auth = auth

    # =========================================================================
    # P2 & P7: Приложение (ключ хранилища ОС + ротация refresh + TTL access 10m)
    # =========================================================================

    def register_app_device_direct(
        self, *, account_id: str, device_name: str, public_key_pem: bytes, hardware_binding: bool = True,
    ) -> dict[str, Any]:
        dev_id, cred_id, now = f"dev_{secrets.token_hex(8)}", f"cred_{secrets.token_hex(8)}", time.time()
        fp = key_fingerprint(public_key_pem)
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at, activated_at) VALUES (?, ?, ?, 'app_install', 'active', ?, ?, ?, ?)",
                (dev_id, account_id, device_name, "direct" if hardware_binding else "none", int(hardware_binding), now, now),
            )
            conn.execute(
                "INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, user_verification, attestation_level, backup_state, state, created_at, activated_at) VALUES (?, ?, ?, ?, ?, 'ES256', 'os_keystore', ?, 1, ?, 'single_device', 'active', ?, ?)",
                (cred_id, dev_id, account_id, f"app_{cred_id}", public_key_pem, fp, "direct" if hardware_binding else "none", now, now),
            )
        return {"device_id": dev_id, "credential_id": cred_id, "key_fingerprint": fp}

    def app_register_begin(self, *, enrollment_id: str, secret: str, source_key: str = "unknown") -> dict[str, Any]:
        """P3 (нативный клиент): проверка одноразового кода регистрации и выдача PoP-вызова."""
        if not self.auth.rl.allow(f"reg_begin:{source_key}", 10, 3600):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            enr, err = self.auth._validate_enrollment_code(conn, enrollment_id, secret, now)
            if err is None:
                chal_bytes = secrets.token_bytes(32)
                chal_id = f"chal_{secrets.token_hex(12)}"
                expires_at = now + REG_CHALLENGE_TTL_S
                conn.execute(
                    "INSERT INTO challenges (challenge_id, purpose, account_id, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'app_register', ?, ?, ?, ?, ?, ?, 'issued')",
                    (chal_id, enr["target_account_id"], chal_bytes, self.auth.expected_origin, self.auth.rp_id, now, expires_at),
                )
                out = {
                    "challenge_id": chal_id,
                    "challenge_hex": chal_bytes.hex(),
                    "rp_id": self.auth.rp_id,
                    "allowed_role": enr["allowed_role"],
                    "target_account_id": enr["target_account_id"],
                    "expires_at": expires_at,
                }
        if err is not None:
            self.store.audit("app_register_begin_denied", "denied", reason_code=err.code, extra={"enrollment_id": enrollment_id})
            raise err
        return out

    def app_register_submit(
        self,
        *,
        enrollment_id: str,
        secret: str,
        challenge_id: str,
        device_name: str,
        requested_role: str,
        public_key_pem: bytes,
        signature: bytes,
        hardware_binding: bool = False,
        source_key: str = "unknown",
    ) -> dict[str, Any]:
        """P3 (нативный клиент): проверка PoP-подписи ECDSA P-256 и создание pending-заявки на одобрение owner."""
        if not self.auth.rl.allow(f"reg_submit:{source_key}", 10, 3600):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        policy = self.store.get_server_policy()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            enr, err = self.auth._validate_enrollment_code(conn, enrollment_id, secret, now)
            if err is None:
                chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
                if not chal or chal["state"] != "issued" or chal["purpose"] != "app_register" or chal["account_id"] != enr["target_account_id"]:
                    if chal and chal["state"] == "issued":
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                    err = AuthError("challenge_invalid", status_code=401)
                elif now > chal["expires_at"]:
                    conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                    err = AuthError("challenge_expired", status_code=401)
                else:
                    target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (enr["target_account_id"],)).fetchone()
                    if not target:
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("target_account_invalid", status_code=404)
                    elif requested_role != enr["allowed_role"] or requested_role != target["role"]:
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("role_mismatch", status_code=403)
                    else:
                        eff = self.auth.compute_effective_mode(policy, actor_min_mode=target["min_mode"], target_min_mode=target["min_mode"], action_min_mode=2, network_zone="lan")
                        mcfg = MODE_DEFAULTS[eff]
                        pending_cnt = conn.execute("SELECT COUNT(*) FROM registration_requests WHERE target_account_id = ? AND state = 'pending'", (target["account_id"],)).fetchone()[0]
                        if not mcfg["new_device_access"]:
                            conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                            err = AuthError("new_devices_forbidden_in_mode_4", status_code=403)
                        elif pending_cnt >= MAX_PENDING_REG_PER_ACCOUNT:
                            conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                            err = AuthError("too_many_pending_registrations", status_code=429)
                        elif mcfg["hardware_key_required"] and not hardware_binding:
                            conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                            err = AuthError("hardware_key_required", status_code=403)
                        else:
                            domain_msg = f"locugard:app_register:{chal['rp_id']}:{enrollment_id}:".encode() + chal["challenge_bytes"]
                            try:
                                _verify_ecdsa_p256(public_key_pem, domain_msg, signature)
                            except Exception:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                err = AuthError("invalid_signature", status_code=401)
                            else:
                                dev_id = f"dev_{secrets.token_hex(8)}"
                                cred_id = f"cred_{secrets.token_hex(8)}"
                                req_id = f"rreq_{secrets.token_hex(8)}"
                                fp = key_fingerprint(public_key_pem)
                                expires_at = now + REG_REQUEST_TTL_S
                                conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                                conn.execute("UPDATE enrollment_codes SET state = 'consumed', consumed_at = ? WHERE enrollment_id = ?", (now, enrollment_id))
                                conn.execute(
                                    "INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at) VALUES (?, ?, ?, 'app_install', 'pending', ?, ?, ?)",
                                    (dev_id, target["account_id"], device_name.strip() or "Native Device", "direct" if hardware_binding else "none", int(hardware_binding), now),
                                )
                                conn.execute(
                                    "INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, user_verification, attestation_level, backup_state, state, created_at) VALUES (?, ?, ?, ?, ?, 'ES256', 'os_keystore', ?, 1, ?, 'single_device', 'pending', ?)",
                                    (cred_id, dev_id, target["account_id"], f"app_{cred_id}", public_key_pem, fp, "direct" if hardware_binding else "none", now),
                                )
                                conn.execute(
                                    "INSERT INTO registration_requests (request_id, enrollment_id, target_account_id, device_id, credential_id, requested_role, key_fingerprint, created_at, expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                                    (req_id, enrollment_id, target["account_id"], dev_id, cred_id, requested_role, fp, now, expires_at),
                                )
                                out = {
                                    "request_id": req_id,
                                    "device_id": dev_id,
                                    "credential_id": cred_id,
                                    "key_fingerprint": fp,
                                    "state": "pending",
                                    "expires_at": expires_at,
                                    "target_account_id": target["account_id"],
                                }
        if err is not None:
            self.store.audit("app_register_denied", "denied", reason_code=err.code, extra={"enrollment_id": enrollment_id})
            raise err
        self.store.audit("registration_request_created", "ok", account_id=out["target_account_id"], device_id=out["device_id"], credential_id=out["credential_id"], extra={"request_id": out["request_id"], "key_fingerprint": out["key_fingerprint"], "channel": "app"})
        return {
            "request_id": out["request_id"],
            "device_id": out["device_id"],
            "credential_id": out["credential_id"],
            "key_fingerprint": out["key_fingerprint"],
            "state": "pending",
            "expires_at": out["expires_at"],
        }

    def app_login_begin(self, *, device_id: str, source_key: str = "unknown") -> dict[str, Any]:
        if not self.auth.rl.allow(f"app_login_chal:{source_key}", 10, 60):
            raise AuthError("rate_limited", status_code=429)
        chal_bytes, chal_id, now = secrets.token_bytes(32), f"chal_{secrets.token_hex(12)}", time.time()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO challenges (challenge_id, purpose, device_id, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'app_login', ?, ?, ?, ?, ?, ?, 'issued')",
                (chal_id, device_id, chal_bytes, self.auth.expected_origin, self.auth.rp_id, now, now + CHALLENGE_TTL_S),
            )
        return {"challenge_id": chal_id, "challenge_hex": chal_bytes.hex(), "rp_id": self.auth.rp_id, "expires_at": now + CHALLENGE_TTL_S}

    def app_login_verify(
        self, *, challenge_id: str, device_id: str, signature: bytes, user_verified: bool,
        peer_ip: str | None, forwarded_for: str | None = None, audience: str = "locugard",
    ) -> dict[str, Any]:
        aud = _validate_audience(audience)
        now = time.time()
        policy = self.store.get_server_policy()
        zone = resolve_network_zone(peer_ip, policy["allowed_networks"], self.auth.trusted_proxies, forwarded_for)
        if zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)

        err: AuthError | None = None
        out: dict[str, Any] = {}
        acc_id_log: str | None = None
        with self.store.transaction() as conn:
            chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
            if not chal or chal["state"] != "issued" or chal["purpose"] != "app_login" or chal["device_id"] != device_id:
                if chal and chal["state"] == "issued":
                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("authentication_failed", status_code=401)
            elif now > chal["expires_at"]:
                conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("challenge_expired", status_code=401)
            else:
                dev = conn.execute("SELECT * FROM devices WHERE device_id = ? AND state = 'active'", (device_id,)).fetchone()
                if not dev:
                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                    err = AuthError("authentication_failed", status_code=401)
                else:
                    acc = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (dev["account_id"],)).fetchone()
                    cred = conn.execute(
                        "SELECT * FROM credentials WHERE device_id = ? AND account_id = ? AND state = 'active' ORDER BY created_at ASC LIMIT 1",
                        (device_id, dev["account_id"]),
                    ).fetchone()
                    if not acc or not cred:
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("authentication_failed", status_code=401)
                    else:
                        acc_id_log = acc["account_id"]
                        # MED-04 & LOW-04: сначала проверяем криптоподпись с chal['rp_id'], потом политику
                        domain_msg = f"locugard:app_login:{chal['rp_id']}:{device_id}:".encode() + chal["challenge_bytes"]
                        try:
                            _verify_ecdsa_p256(cred["public_key"], domain_msg, signature)
                        except Exception:
                            conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                            err = AuthError("authentication_failed", status_code=401)
                        else:
                            eff = self.auth.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=2, network_zone=zone)
                            mcfg = MODE_DEFAULTS[eff]
                            if acc["role"] not in mcfg["allowed_roles"]:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                err = AuthError("role_forbidden_in_mode", status_code=403)
                            elif mcfg["uv_required"] and not user_verified:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                err = AuthError("user_verification_required", status_code=403)
                            elif mcfg["hardware_key_required"] and not dev["hardware_binding"]:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                err = AuthError("hardware_key_required", status_code=403)
            if err is None:
                ver_id, sess_id, chain_id = f"ver_{secrets.token_hex(8)}", f"sess_{secrets.token_hex(8)}", f"chn_{secrets.token_hex(8)}"
                access_token, refresh_token, csrf_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                abs_ttl = min(policy["session_ttl_s"], mcfg["session_ttl_s"])
                idle_ttl = min(policy["idle_ttl_s"], mcfg["idle_ttl_s"])
                abs_exp, idle_exp = now + abs_ttl, min(now + abs_ttl, now + idle_ttl)
                access_exp = min(abs_exp, now + ACCESS_TOKEN_TTL_S)
                conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                conn.execute(
                    "INSERT INTO identity_verifications (verification_id, account_id, channel, device_id, credential_id, session_id, method, challenge_id, verified_at, assurance_level, purpose) VALUES (?, ?, 'app', ?, ?, ?, 'app_keystore_uv', ?, ?, ?, 'login')",
                    (ver_id, acc["account_id"], dev["device_id"], cred["credential_id"], sess_id, challenge_id, now, eff),
                )
                conn.execute(
                    "INSERT INTO sessions (session_id, session_token_hash, csrf_token_hash, account_id, device_id, credential_id, auth_method, authenticated_at, identity_verification_id, created_at, last_activity_at, absolute_expires_at, idle_expires_at, access_token_expires_at, audience, network_zone_at_login, mode_at_login, state) VALUES (?, ?, ?, ?, ?, ?, 'app_keystore_uv', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                    (sess_id, hash_secret(access_token, self.store.pepper), hash_secret(csrf_token, self.store.pepper), acc["account_id"], dev["device_id"], cred["credential_id"], now, ver_id, now, now, abs_exp, idle_exp, access_exp, aud, zone, eff),
                )
                conn.execute(
                    "INSERT INTO refresh_token_chains (chain_id, session_id, generation, current_token_hash, rotated_at, state) VALUES (?, ?, 1, ?, ?, 'active')",
                    (chain_id, sess_id, hash_secret(refresh_token, self.store.pepper), now),
                )
                out = {
                    "session_id": sess_id,
                    "chain_id": chain_id,
                    "account_id": acc["account_id"],
                    "role": acc["role"],
                    "device_id": dev["device_id"],
                    "audience": aud,
                    "access_token": access_token,
                    "access_expires_in": ACCESS_TOKEN_TTL_S,
                    "access_expires_at": access_exp,
                    "session_expires_at": abs_exp,
                    "idle_expires_at": idle_exp,
                    "refresh_token": refresh_token,
                    "generation": 1,
                }
        if err is not None:
            self.store.audit("app_login_denied", "denied", reason_code=err.code, account_id=acc_id_log, device_id=device_id, network_zone=zone)
            raise err
        self.store.audit("app_login_succeeded", "ok", account_id=acc_id_log, device_id=device_id, session_id=out["session_id"], network_zone=zone)
        return out

    def app_refresh(self, *, refresh_token: str, peer_ip: str | None, forwarded_for: str | None = None) -> dict[str, Any]:
        """P7: атомарная ротация refresh-токена; CRIT-01/CRIT-10/MED-05."""
        now = time.time()
        policy = self.store.get_server_policy()
        client_ip = extract_client_ip(peer_ip, self.auth.trusted_proxies, forwarded_for)
        zone = resolve_network_zone(peer_ip, policy["allowed_networks"], self.auth.trusted_proxies, forwarded_for)
        if zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)

        tok_hash = hash_secret(refresh_token, self.store.pepper)
        err: AuthError | None = None
        out: dict[str, Any] | None = None
        notify_reuse: tuple[str, str, str] | None = None

        with self.store.transaction() as conn:
            hist = conn.execute("SELECT * FROM refresh_token_history WHERE token_hash = ?", (tok_hash,)).fetchone()
            if hist:
                chain = conn.execute("SELECT * FROM refresh_token_chains WHERE chain_id = ?", (hist["chain_id"],)).fetchone()
                sess = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (chain["session_id"],)).fetchone()
                was_active = chain["state"] == "active"
                conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = COALESCE(revoked_at, ?), revocation_reason = 'refresh_reuse_detected', reuse_detected_at = COALESCE(reuse_detected_at, ?) WHERE chain_id = ?", (now, now, chain["chain_id"]))
                conn.execute("UPDATE sessions SET state = 'revoked', ended_at = COALESCE(ended_at, ?), end_reason = 'refresh_reuse_detected' WHERE session_id = ?", (now, chain["session_id"]))
                if was_active:
                    self.store.record_revocation_event_conn(
                        conn, "refresh_reuse_detected", reason="refresh_reuse_detected",
                        account_id=sess["account_id"], device_id=sess["device_id"], session_id=sess["session_id"], audience=sess["audience"], occurred_at=now,
                    )
                    notify_reuse = (sess["account_id"], sess["device_id"], sess["session_id"])
                err = AuthError("refresh_reuse_detected", status_code=401)
            else:
                chain = conn.execute("SELECT * FROM refresh_token_chains WHERE current_token_hash = ?", (tok_hash,)).fetchone()
                if not chain:
                    if not self.auth.rl.allow(f"refresh_bad:{client_ip or 'unknown'}", 30, 60):
                        err = AuthError("rate_limited", status_code=429)
                    else:
                        err = AuthError("refresh_invalid", status_code=401)
                elif chain["state"] != "active":
                    err = AuthError("refresh_chain_revoked", status_code=401)
                elif not self.auth.rl.allow(f"refresh_chain:{chain['chain_id']}", 30, 60):
                    err = AuthError("rate_limited", status_code=429)
                else:
                    sess = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (chain["session_id"],)).fetchone()
                    if not sess or sess["state"] != "active":
                        err = AuthError("session_invalid_or_revoked", status_code=401)
                    else:
                        acc = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (sess["account_id"],)).fetchone()
                        dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (sess["device_id"],)).fetchone()
                        cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ?", (sess["credential_id"],)).fetchone()
                        if not acc or not dev or not cred or acc["state"] != "active" or dev["state"] != "active" or cred["state"] != "active":
                            err = AuthError("context_revoked_or_inactive", status_code=401)
                        else:
                            eff = self.auth.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=2, network_zone=zone)
                            mcfg = MODE_DEFAULTS[eff]
                            eff_abs = min(sess["absolute_expires_at"], sess["created_at"] + min(policy["session_ttl_s"], mcfg["session_ttl_s"]))
                            eff_idle = min(sess["idle_expires_at"], sess["last_activity_at"] + min(policy["idle_ttl_s"], mcfg["idle_ttl_s"]))
                            if now > eff_abs or now > eff_idle:
                                conn.execute("UPDATE sessions SET state = 'expired', ended_at = ?, end_reason = 'ttl_expired' WHERE session_id = ?", (now, sess["session_id"]))
                                conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = 'session_expired' WHERE chain_id = ?", (now, chain["chain_id"]))
                                err = AuthError("session_expired", status_code=401)
                            elif acc["role"] not in mcfg["allowed_roles"]:
                                err = AuthError("role_forbidden_in_mode", status_code=403)
                            elif mcfg["hardware_key_required"] and not dev["hardware_binding"]:
                                # CRIT-10: программный ключ не может ротировать refresh в режимах 3–4
                                err = AuthError("hardware_key_required", status_code=403)
                            else:
                                new_refresh, new_access = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                                new_gen = chain["generation"] + 1
                                access_exp = min(eff_abs, now + ACCESS_TOKEN_TTL_S)
                                conn.execute("INSERT INTO refresh_token_history (chain_id, generation, token_hash, rotated_at) VALUES (?, ?, ?, ?)", (chain["chain_id"], chain["generation"], chain["current_token_hash"], now))
                                conn.execute("UPDATE refresh_token_chains SET generation = ?, current_token_hash = ?, rotated_at = ? WHERE chain_id = ?", (new_gen, hash_secret(new_refresh, self.store.pepper), now, chain["chain_id"]))
                                conn.execute("UPDATE sessions SET session_token_hash = ?, access_token_expires_at = ? WHERE session_id = ?", (hash_secret(new_access, self.store.pepper), access_exp, sess["session_id"]))
                                out = {
                                    "session_id": sess["session_id"],
                                    "audience": sess["audience"],
                                    "access_token": new_access,
                                    "refresh_token": new_refresh,
                                    "generation": new_gen,
                                    "access_expires_in": ACCESS_TOKEN_TTL_S,
                                    "access_expires_at": access_exp,
                                    "session_expires_at": eff_abs,
                                    "idle_expires_at": eff_idle,
                                }

        if err is not None:
            if notify_reuse:
                self.store.emit_revocation_signal()
                self.store.audit("refresh_reuse_detected", "denied", reason_code="refresh_reuse_detected", account_id=notify_reuse[0], device_id=notify_reuse[1], session_id=notify_reuse[2], network_zone=zone)
                self.store.notify("refresh_reuse_detected", [notify_reuse[0]], {"account_id": notify_reuse[0], "device_id": notify_reuse[1], "session_id": notify_reuse[2]})
            else:
                self.store.audit("refresh_denied", "denied", reason_code=err.code, network_zone=zone)
            raise err
        assert out is not None
        return out

    def app_logout(self, *, access_token: str | None) -> None:
        """P5 (нативный клиент): выход по Bearer access_token с отзывом refresh-цепочки и событием отзыва."""
        if not access_token:
            raise AuthError("unauthorized", status_code=401)
        now = time.time()
        tok_hash = hash_secret(access_token, self.store.pepper)
        with self.store.transaction() as conn:
            sess = conn.execute("SELECT * FROM sessions WHERE session_token_hash = ? AND state = 'active'", (tok_hash,)).fetchone()
            if not sess:
                raise AuthError("session_invalid_or_revoked", status_code=401)
            conn.execute("UPDATE sessions SET state = 'closed', ended_at = ?, end_reason = 'user_logout' WHERE session_id = ?", (now, sess["session_id"]))
            conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = 'user_logout' WHERE session_id = ? AND state = 'active'", (now, sess["session_id"]))
            self.store.record_revocation_event_conn(
                conn, "session_closed", reason="user_logout",
                account_id=sess["account_id"], device_id=sess["device_id"], session_id=sess["session_id"], audience=sess["audience"], occurred_at=now,
            )
        self.store.emit_revocation_signal()
        self.store.audit("session_closed", "ok", reason_code="user_logout", account_id=sess["account_id"], device_id=sess["device_id"], session_id=sess["session_id"])

    def introspect_token(
        self,
        *,
        access_token: str | None,
        expected_audience: str,
        peer_ip: str | None = None,
        forwarded_for: str | None = None,
        touch_activity: bool = False,
    ) -> dict[str, Any]:
        """Серверная интроспекция Bearer-токена для внешних сервисов (Apogeus, Docalaizer) без доступа к SQLite/pepper."""
        aud = _validate_audience(expected_audience)
        try:
            ctx = self.auth.verify_session(
                access_token,
                peer_ip=peer_ip,
                forwarded_for=forwarded_for,
                action_min_mode=1,
                touch_activity=touch_activity,
                expected_audience=aud,
            )
        except AuthError as e:
            return {"active": False, "reason": e.code}
        acc = self.store.get_account(ctx.account_id)
        return {
            "active": True,
            "account_id": ctx.account_id,
            "display_name": acc["display_name"] if acc else "",
            "role": ctx.role,
            "device_id": ctx.device_id,
            "session_id": ctx.session_id,
            "audience": ctx.audience,
            "effective_mode": ctx.effective_mode,
            "network_zone": ctx.network_zone,
            "access_expires_at": ctx.access_token_expires_at,
            "session_expires_at": ctx.absolute_expires_at,
            "idle_expires_at": ctx.idle_expires_at,
            "policy_version": ctx.policy_version,
        }

    # =========================================================================
    # P4: Проверенная привязка Telegram и опциональное одобрение (режим 2, non-owner)
    # =========================================================================

    def telegram_link_begin(self, ctx: VerifiedContext) -> dict[str, Any]:
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        if not self.auth.rl.allow(f"tg_link:{ctx.account_id}", 5, 3600):
            raise AuthError("rate_limited", status_code=429)
        link_id, token, now = f"tgl_{secrets.token_hex(8)}", secrets.token_urlsafe(32), time.time()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO telegram_link_requests (link_id, account_id, session_id, policy_version, token_hash, issued_at, expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, 'issued')",
                (link_id, ctx.account_id, ctx.session_id, ctx.policy_version, hash_secret(token, self.store.pepper), now, now + TG_LINK_TTL_S),
            )
        return {"link_id": link_id, "link_token": token, "expires_at": now + TG_LINK_TTL_S}

    def telegram_link_receive_update(self, *, link_token: str, verified_telegram_user_id: int) -> dict[str, Any]:
        if not self.auth.rl.allow(f"tg_recv:{int(verified_telegram_user_id)}", 10, 300):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            req = conn.execute("SELECT * FROM telegram_link_requests WHERE token_hash = ?", (hash_secret(link_token, self.store.pepper),)).fetchone()
            if not req or req["state"] != "issued":
                err = AuthError("telegram_link_invalid", status_code=401)
            elif now > req["expires_at"]:
                conn.execute("UPDATE telegram_link_requests SET state = 'expired' WHERE link_id = ?", (req["link_id"],))
                err = AuthError("telegram_link_expired", status_code=410)
            else:
                subj = str(int(verified_telegram_user_id))
                conflict = conn.execute("SELECT account_id FROM external_identities WHERE provider = 'telegram' AND provider_subject = ? AND state = 'active'", (subj,)).fetchone()
                if conflict and conflict["account_id"] != req["account_id"]:
                    err = AuthError("telegram_id_already_bound", status_code=409)
                else:
                    conn.execute("UPDATE telegram_link_requests SET telegram_subject = ?, state = 'received' WHERE link_id = ?", (subj, req["link_id"]))
                    out = {"link_id": req["link_id"], "telegram_subject": subj, "state": "received"}
        if err is not None:
            raise err
        return out

    def telegram_link_confirm_web(self, ctx: VerifiedContext, *, link_id: str, second_verification_id: str | None = None) -> dict[str, Any]:
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        now = time.time()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            req = conn.execute("SELECT * FROM telegram_link_requests WHERE link_id = ?", (link_id,)).fetchone()
            if not req or req["state"] != "received" or req["account_id"] != ctx.account_id or req["session_id"] != ctx.session_id:
                err = AuthError("telegram_link_invalid", status_code=409)
            elif now > req["expires_at"]:
                conn.execute("UPDATE telegram_link_requests SET state = 'expired' WHERE link_id = ?", (link_id,))
                err = AuthError("telegram_link_expired", status_code=410)
            elif req["policy_version"] != ctx.policy_version:
                err = AuthError("policy_changed", status_code=409)
            else:
                if ctx.effective_mode >= 3:
                    self.auth.verify_independent_second_approval_conn(conn, ctx, second_verification_id, consume_op_id=link_id, require_owner=(ctx.role == "owner"))
                self.auth.consume_primary_verification_mode4_conn(conn, ctx, link_id)
                # MED-02: каскадный отзыв прежней привязки и её callback/одобрений
                old_ids = [r["identity_id"] for r in conn.execute("SELECT identity_id FROM external_identities WHERE account_id = ? AND provider = 'telegram' AND state = 'active'", (ctx.account_id,)).fetchall()]
                for oid in old_ids:
                    conn.execute("UPDATE external_identities SET state = 'revoked', revoked_at = ? WHERE identity_id = ?", (now, oid))
                    conn.execute("UPDATE telegram_callbacks SET state = 'revoked' WHERE external_identity_id = ? AND state = 'issued'", (oid,))
                ext_id = f"ext_{secrets.token_hex(8)}"
                try:
                    conn.execute(
                        "INSERT INTO external_identities (identity_id, account_id, provider, provider_subject, verification_method, verified_at, state, bound_at) VALUES (?, ?, 'telegram', ?, 'verified_bot_link_web_confirm', ?, 'active', ?)",
                        (ext_id, ctx.account_id, req["telegram_subject"], now, now),
                    )
                    conn.execute("UPDATE telegram_link_requests SET state = 'confirmed' WHERE link_id = ?", (link_id,))
                    out = {"identity_id": ext_id, "telegram_subject": req["telegram_subject"], "state": "active"}
                except sqlite3.IntegrityError:
                    err = AuthError("telegram_id_already_bound", status_code=409)
        if err is not None:
            raise err
        self.store.audit("telegram_bound", "ok", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, extra={"identity_id": out["identity_id"]})
        return out

    def telegram_issue_approval_callback(self, *, request_id: str, owner_account_id: str) -> dict[str, Any]:
        policy = self.store.get_server_policy()
        if not policy["telegram_approval_enabled"]:
            raise AuthError("telegram_approval_disabled", status_code=403)
        if policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)
        now = time.time()
        with self.store.transaction() as conn:
            req = conn.execute("SELECT * FROM registration_requests WHERE request_id = ? AND state = 'pending'", (request_id,)).fetchone()
            if not req or now > req["expires_at"]:
                raise AuthError("registration_request_not_pending", status_code=409)
            target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (req["target_account_id"],)).fetchone()
            owner = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (owner_account_id,)).fetchone()
            if not target or not owner:
                raise AuthError("forbidden", status_code=403)
            if target["role"] == "owner":
                raise AuthError("telegram_approval_forbidden_for_owner", status_code=403)
            eff = self.auth.compute_effective_mode(policy, actor_min_mode=owner["min_mode"], target_min_mode=target["min_mode"], action_min_mode=2, network_zone="outside_lan")
            if eff != 2:
                raise AuthError("telegram_approval_mode_2_only", status_code=403)
            ext = conn.execute("SELECT * FROM external_identities WHERE account_id = ? AND provider = 'telegram' AND state = 'active'", (owner_account_id,)).fetchone()
            if not ext:
                raise AuthError("telegram_not_bound", status_code=403)
            conn.execute("UPDATE telegram_callbacks SET state = 'revoked' WHERE request_id = ? AND state = 'issued'", (request_id,))
            cb_id = f"tgcb_{secrets.token_hex(12)}"
            exp = min(now + TG_CALLBACK_TTL_S, req["expires_at"])
            conn.execute("INSERT INTO telegram_callbacks (callback_id, request_id, account_id, external_identity_id, expires_at, state) VALUES (?, ?, ?, ?, ?, 'issued')", (cb_id, request_id, owner_account_id, ext["identity_id"], exp))
        return {"callback_id": cb_id, "expires_at": exp}

    def telegram_approve_registration(self, *, callback_id: str, verified_telegram_user_id: int) -> dict[str, Any]:
        policy = self.store.get_server_policy()
        if not policy["telegram_approval_enabled"]:
            raise AuthError("telegram_approval_disabled", status_code=403)
        if policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)
        subj = str(int(verified_telegram_user_id))
        if not self.auth.rl.allow(f"tg_cb:{subj}", 5, 300):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            cb = conn.execute("SELECT * FROM telegram_callbacks WHERE callback_id = ?", (callback_id,)).fetchone()
            if not cb or cb["state"] != "issued":
                err = AuthError("telegram_callback_invalid", status_code=401)
            elif now > cb["expires_at"]:
                conn.execute("UPDATE telegram_callbacks SET state = 'expired' WHERE callback_id = ?", (callback_id,))
                err = AuthError("telegram_callback_expired", status_code=410)
            else:
                ext = conn.execute("SELECT * FROM external_identities WHERE identity_id = ? AND state = 'active'", (cb["external_identity_id"],)).fetchone()
                owner = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (cb["account_id"],)).fetchone()
                req = conn.execute("SELECT * FROM registration_requests WHERE request_id = ? AND state = 'pending'", (cb["request_id"],)).fetchone()
                if not ext or ext["provider_subject"] != subj:
                    err = AuthError("telegram_sender_mismatch", status_code=403)
                elif not owner or not req or now > req["expires_at"]:
                    err = AuthError("registration_request_not_pending", status_code=409)
                else:
                    target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (req["target_account_id"],)).fetchone()
                    code = conn.execute("SELECT * FROM enrollment_codes WHERE enrollment_id = ?", (req["enrollment_id"],)).fetchone()
                    if not target or not code or target["role"] == "owner" or req["requested_role"] != target["role"] or code["allowed_role"] != target["role"]:
                        err = AuthError("telegram_approval_forbidden", status_code=403)
                    else:
                        eff = self.auth.compute_effective_mode(policy, actor_min_mode=owner["min_mode"], target_min_mode=target["min_mode"], action_min_mode=2, network_zone="outside_lan")
                        if eff != 2:
                            err = AuthError("telegram_approval_mode_2_only", status_code=403)
            if err is None:
                ver_id = f"ver_{secrets.token_hex(8)}"
                conn.execute("UPDATE telegram_callbacks SET state = 'consumed', consumed_at = ? WHERE callback_id = ?", (now, callback_id))
                conn.execute("INSERT INTO identity_verifications (verification_id, account_id, channel, external_identity_id, method, verified_at, assurance_level, purpose) VALUES (?, ?, 'telegram', ?, 'telegram_bound_callback', ?, 2, 'device_enrollment')", (ver_id, owner["account_id"], ext["identity_id"], now))
                conn.execute("UPDATE devices SET state = 'active', activated_at = ? WHERE device_id = ? AND state = 'pending'", (now, req["device_id"]))
                conn.execute("UPDATE credentials SET state = 'active', activated_at = ? WHERE credential_id = ? AND state = 'pending'", (now, req["credential_id"]))
                conn.execute("UPDATE registration_requests SET state = 'approved', approved_by_account_id = ?, approval_verification_id = ?, resolved_at = ? WHERE request_id = ?", (owner["account_id"], ver_id, now, req["request_id"]))
                out = {"request_id": req["request_id"], "device_id": req["device_id"], "target_id": target["account_id"], "owner_id": owner["account_id"], "state": "active"}
        if err is not None:
            self.store.audit("telegram_approval_rejected", "denied", reason_code=err.code, extra={"callback_id": callback_id})
            raise err
        self.store.audit("registration_approved_telegram", "ok", account_id=out["target_id"], device_id=out["device_id"], extra={"request_id": out["request_id"], "approved_by": out["owner_id"]})
        return {"request_id": out["request_id"], "device_id": out["device_id"], "state": "active"}

    # =========================================================================
    # P6: Атомарная смена политики, ролей и приостановка аккаунтов (MED-01)
    # =========================================================================

    def change_server_policy(
        self, ctx: VerifiedContext, *, min_mode: int | None = None, outside_lan_behavior: str | None = None,
        telegram_approval_enabled: bool | None = None, session_ttl_s: int | None = None, idle_ttl_s: int | None = None,
        second_verification_id: str | None = None, target_digest: str | None = None,
    ) -> dict[str, Any]:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        if min_mode is not None and min_mode not in MODE_DEFAULTS:
            raise AuthError("invalid_security_mode", status_code=400)
        if outside_lan_behavior is not None and outside_lan_behavior not in ("upgrade_to_2", "deny"):
            raise AuthError("invalid_outside_lan_behavior", status_code=400)
        if (session_ttl_s is not None and session_ttl_s <= 0) or (idle_ttl_s is not None and idle_ttl_s <= 0):
            raise AuthError("invalid_ttl", status_code=400)

        now = time.time()
        op_id = f"pol_{secrets.token_hex(6)}"
        with self.store.transaction() as conn:
            actor = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (ctx.account_id,)).fetchone()
            if not actor:
                raise AuthError("owner_required", status_code=403)
            cur = dict(conn.execute("SELECT * FROM server_policy WHERE id = 1").fetchone())
            cur_policy = {**cur, "allowed_networks": json.loads(cur["allowed_networks_json"]), "telegram_approval_enabled": bool(cur["telegram_approval_enabled"])}
            eff = self.auth.compute_effective_mode(cur_policy, actor_min_mode=actor["min_mode"], action_min_mode=2, network_zone=ctx.network_zone)
            if eff >= 3:
                self.auth.verify_independent_second_approval_conn(conn, ctx, second_verification_id, consume_op_id=op_id, require_owner=True, expected_target_digest=target_digest, effective_mode=eff)
            self.auth.consume_primary_verification_mode4_conn(conn, ctx, op_id, effective_mode=eff)

            new_ver = cur["policy_version"] + 1
            new_mode = min_mode if min_mode is not None else cur["min_mode"]
            new_tg = int(telegram_approval_enabled) if telegram_approval_enabled is not None else cur["telegram_approval_enabled"]
            conn.execute(
                "UPDATE server_policy SET min_mode=?, outside_lan_behavior=?, telegram_approval_enabled=?, session_ttl_s=?, idle_ttl_s=?, policy_version=?, updated_at=?, updated_by_account_id=? WHERE id=1",
                (
                    new_mode,
                    outside_lan_behavior if outside_lan_behavior is not None else cur["outside_lan_behavior"],
                    new_tg,
                    session_ttl_s if session_ttl_s is not None else cur["session_ttl_s"],
                    idle_ttl_s if idle_ttl_s is not None else cur["idle_ttl_s"],
                    new_ver, now, ctx.account_id,
                ),
            )
            conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = 'policy_changed' WHERE state IN ('pending', 'approved') AND policy_version < ?", (new_ver,))
            if not new_tg or new_mode >= 3:
                conn.execute("UPDATE telegram_callbacks SET state = 'revoked' WHERE state = 'issued'")
            if new_mode >= 2:
                conn.execute("UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = 'policy_upgraded' WHERE state = 'active' AND mode_at_login < 2", (now,))
            if new_mode >= 3:
                conn.execute("UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = 'hardware_key_required' WHERE state = 'active' AND device_id IN (SELECT device_id FROM devices WHERE hardware_binding = 0)", (now,))
            if new_mode == 4:
                conn.execute("UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = 'mode_4_isolation' WHERE state = 'active' AND account_id IN (SELECT account_id FROM accounts WHERE role != 'owner')", (now,))
                conn.execute("UPDATE enrollment_codes SET state = 'revoked', revoked_at = ? WHERE state = 'issued'", (now,))
                conn.execute("UPDATE registration_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = 'mode_4_isolation' WHERE state = 'pending'", (now,))
                conn.execute("UPDATE recovery_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = 'mode_4_isolation' WHERE state = 'pending'", (now,))
            conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = 'policy_changed' WHERE state = 'active' AND session_id IN (SELECT session_id FROM sessions WHERE state != 'active')", (now,))
        new_policy = self.store.get_server_policy()
        self.store.audit("policy_updated", "ok", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, policy_version=new_policy["policy_version"], extra={"min_mode": new_policy["min_mode"]})
        return new_policy

    def change_role(self, ctx: VerifiedContext, *, target_account_id: str, new_role: str, second_verification_id: str | None = None, target_digest: str | None = None) -> dict[str, Any]:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if new_role not in ("owner", "member", "guest", "readonly"):
            raise AuthError("invalid_role", status_code=400)
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        now, op_id = time.time(), f"role_{secrets.token_hex(6)}"
        policy = self.store.get_server_policy()
        with self.store.transaction() as conn:
            actor = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (ctx.account_id,)).fetchone()
            cur = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (target_account_id,)).fetchone()
            if not actor or not cur:
                raise AuthError("account_not_found", status_code=404)
            eff = self.auth.compute_effective_mode(policy, actor_min_mode=actor["min_mode"], target_min_mode=cur["min_mode"], action_min_mode=2, network_zone=ctx.network_zone)
            if eff >= 3:
                self.auth.verify_independent_second_approval_conn(conn, ctx, second_verification_id, consume_op_id=op_id, require_owner=True, expected_target_digest=target_digest, effective_mode=eff)
            self.auth.consume_primary_verification_mode4_conn(conn, ctx, op_id, effective_mode=eff)
            if cur["role"] == "owner" and cur["state"] == "active" and new_role != "owner":
                if self.store.count_active_owners(conn, require_active_key=True) <= 1:
                    raise AuthError("last_owner_invariant", status_code=409)
            conn.execute("UPDATE accounts SET role = ?, updated_at = ? WHERE account_id = ?", (new_role, now, target_account_id))
            if cur["role"] == "owner" and new_role != "owner":
                conn.execute("UPDATE telegram_callbacks SET state = 'revoked' WHERE account_id = ? AND state = 'issued'", (target_account_id,))
                conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = 'approver_demoted' WHERE state IN ('pending', 'approved') AND second_verification_id IN (SELECT verification_id FROM identity_verifications WHERE account_id = ?)", (target_account_id,))
                conn.execute("UPDATE registration_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = 'approver_demoted' WHERE state = 'pending' AND (approval_verification_id IN (SELECT verification_id FROM identity_verifications WHERE account_id = ?) OR second_approval_id IN (SELECT verification_id FROM identity_verifications WHERE account_id = ?))", (now, target_account_id, target_account_id))
                conn.execute("UPDATE recovery_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = 'approver_demoted' WHERE state = 'pending' AND second_verification_id IN (SELECT verification_id FROM identity_verifications WHERE account_id = ?)", (now, target_account_id))
            old_role = cur["role"]
        self.store.audit("role_changed", "ok", account_id=ctx.account_id, extra={"target_account_id": target_account_id, "old_role": old_role, "new_role": new_role})
        return self.store.get_account(target_account_id)

    def suspend_account(self, ctx: VerifiedContext, *, target_account_id: str, second_verification_id: str | None = None, target_digest: str | None = None) -> None:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        now, op_id = time.time(), f"susp_{secrets.token_hex(6)}"
        policy = self.store.get_server_policy()
        with self.store.transaction() as conn:
            actor = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (ctx.account_id,)).fetchone()
            cur = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (target_account_id,)).fetchone()
            if not actor or not cur:
                raise AuthError("account_not_found", status_code=404)
            eff = self.auth.compute_effective_mode(policy, actor_min_mode=actor["min_mode"], target_min_mode=cur["min_mode"], action_min_mode=2, network_zone=ctx.network_zone)
            if cur["role"] == "owner" and eff >= 3:
                self.auth.verify_independent_second_approval_conn(conn, ctx, second_verification_id, consume_op_id=op_id, require_owner=True, expected_target_digest=target_digest, effective_mode=eff)
            self.auth.consume_primary_verification_mode4_conn(conn, ctx, op_id, effective_mode=eff)
            if cur["role"] == "owner" and cur["state"] == "active" and self.store.count_active_owners(conn, require_active_key=True) <= 1:
                raise AuthError("last_owner_invariant", status_code=409)
            conn.execute("UPDATE accounts SET state = 'suspended', updated_at = ? WHERE account_id = ?", (now, target_account_id))
            conn.execute("UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = 'account_suspended' WHERE account_id = ? AND state = 'active'", (now, target_account_id))
            conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = 'account_suspended' WHERE state = 'active' AND session_id IN (SELECT session_id FROM sessions WHERE account_id = ?)", (now, target_account_id))
            conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = 'account_suspended' WHERE account_id = ? AND state IN ('pending', 'approved')", (target_account_id,))
            self.store.record_revocation_event_conn(conn, "account_suspended", reason="account_suspended", account_id=target_account_id, occurred_at=now)
        self.store.emit_revocation_signal()
        self.store.audit("account_suspended", "ok", account_id=ctx.account_id, extra={"target_account_id": target_account_id})

    # =========================================================================
    # P10: Recovery-коды и восстановление (CRIT-01, CRIT-06, CRIT-08, MED-03)
    # =========================================================================

    def generate_recovery_codes(self, ctx: VerifiedContext, *, second_verification_id: str | None = None, target_digest: str | None = None) -> dict[str, Any]:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        set_id, now = f"rset_{secrets.token_hex(6)}", time.time()
        raw_codes: list[str] = []
        with self.store.transaction() as conn:
            if ctx.effective_mode >= 3:
                self.auth.verify_independent_second_approval_conn(conn, ctx, second_verification_id, consume_op_id=set_id, require_owner=True, expected_target_digest=target_digest)
            self.auth.consume_primary_verification_mode4_conn(conn, ctx, set_id)
            conn.execute("UPDATE recovery_codes SET state = 'revoked', revoked_at = ? WHERE account_id = ? AND state = 'active'", (now, ctx.account_id))
            for _ in range(10):
                raw = secrets.token_hex(16)
                pretty = "-".join(raw[i:i + 8] for i in range(0, 32, 8))
                raw_codes.append(pretty)
                conn.execute("INSERT INTO recovery_codes (recovery_code_id, account_id, set_id, code_hash, generated_at, state) VALUES (?, ?, ?, ?, ?, 'active')", (f"rc_{secrets.token_hex(8)}", ctx.account_id, set_id, hash_secret(pretty, self.store.pepper), now))
        self.store.audit("recovery_set_generated", "ok", account_id=ctx.account_id, device_id=ctx.device_id, extra={"set_id": set_id, "count": 10})
        self.store.notify("recovery_set_generated", [ctx.account_id], {"set_id": set_id, "account_id": ctx.account_id})
        return {"set_id": set_id, "codes": raw_codes}

    def recovery_begin(self, *, account_id: str, source_ip: str = "unknown") -> dict[str, Any]:
        if not self.auth.rl.allow(f"rec_begin:{source_ip}", 10, 900):
            raise AuthError("rate_limited", status_code=429)
        chal_bytes, chal_id, now = secrets.token_bytes(32), f"chal_{secrets.token_hex(12)}", time.time()
        with self.store.transaction() as conn:
            conn.execute("INSERT INTO challenges (challenge_id, purpose, account_id, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'recovery', ?, ?, ?, ?, ?, ?, 'issued')", (chal_id, account_id, chal_bytes, self.auth.expected_origin, self.auth.rp_id, now, now + REG_CHALLENGE_TTL_S))
        return {"challenge_id": chal_id, "challenge_hex": chal_bytes.hex()}

    def recovery_submit_code(
        self, *, account_id: str, recovery_code: str, challenge_id: str, new_public_key_pem: bytes,
        pop_signature: bytes, device_name: str, origin: str | None = None,
        hardware_binding: bool = False, source_ip: str = "unknown",
    ) -> dict[str, Any]:
        if origin is not None and origin != self.auth.expected_origin:
            raise AuthError("invalid_origin", status_code=403)
        if not self.auth.rl.allow(f"rec_acc:{account_id}", 5, 3600) or not self.auth.rl.allow(f"rec_src:{source_ip}", 5, 900):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        policy = self.store.get_server_policy()
        zone = resolve_network_zone(source_ip, policy["allowed_networks"], self.auth.trusted_proxies)
        if zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)

        err: AuthError | None = None
        out: dict[str, Any] = {}
        set_id_log = ""
        with self.store.transaction() as conn:
            acc = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
            if not acc or acc["role"] != "owner" or acc["state"] != "active":
                err = AuthError("recovery_account_ineligible", status_code=403)
            else:
                eff = self.auth.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=2, network_zone=zone)
                if eff == 4:
                    err = AuthError("mode_4_remote_recovery_forbidden", status_code=403)
                elif eff == 3 and self.store.count_active_owners(conn, require_active_key=True) < 2:
                    err = AuthError("mode_3_single_owner_console_only", status_code=403)
                elif MODE_DEFAULTS[eff]["hardware_key_required"] and not hardware_binding:
                    err = AuthError("new_key_incompatible_with_mode", status_code=403)
                else:
                    chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
                    if not chal or chal["state"] != "issued" or chal["purpose"] != "recovery" or chal["account_id"] != account_id:
                        err = AuthError("invalid_challenge", status_code=401)
                    elif now > chal["expires_at"]:
                        conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("challenge_expired", status_code=401)
                    else:
                        domain_msg = f"locugard:recovery:{chal['rp_id']}:{account_id}:".encode() + chal["challenge_bytes"]
                        try:
                            _verify_ecdsa_p256(new_public_key_pem, domain_msg, pop_signature)
                        except Exception:
                            conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                            err = AuthError("pop_verification_failed", status_code=401)
                        else:
                            rc = conn.execute("SELECT * FROM recovery_codes WHERE account_id = ? AND code_hash = ? AND state = 'active'", (account_id, hash_secret(recovery_code, self.store.pepper))).fetchone()
                            if not rc:
                                # MED-03: инвалидируем challenge при неверном коде (коммит до raise!)
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                err = AuthError("recovery_code_invalid", status_code=401)
            if err is None:
                dev_id, cred_id, rreq_id = f"dev_{secrets.token_hex(8)}", f"cred_{secrets.token_hex(8)}", f"rec_{secrets.token_hex(8)}"
                confirm_chal_id, confirm_bytes = f"chal_{secrets.token_hex(12)}", secrets.token_bytes(32)
                fp = key_fingerprint(new_public_key_pem)
                scope = "revoke_all_sessions_devices_and_recovery_codes"
                set_id_log = rc["set_id"]
                conn.execute("UPDATE recovery_codes SET state = 'used', used_at = ? WHERE recovery_code_id = ?", (now, rc["recovery_code_id"]))
                conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                conn.execute("INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at) VALUES (?, ?, ?, 'app_install', 'pending', ?, ?, ?)", (dev_id, account_id, device_name, "direct" if hardware_binding else "none", int(hardware_binding), now))
                conn.execute("INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, user_verification, attestation_level, backup_state, state, created_at) VALUES (?, ?, ?, ?, ?, 'ES256', 'os_keystore', ?, 1, ?, 'single_device', 'pending', ?)", (cred_id, dev_id, account_id, f"rec_{cred_id}", new_public_key_pem, fp, "direct" if hardware_binding else "none", now))
                conn.execute("INSERT INTO recovery_requests (recovery_request_id, account_id, basis, recovery_code_id, device_id, credential_id, key_fingerprint, challenge_id, revocation_scope, policy_version, created_at, expires_at, state) VALUES (?, ?, 'recovery_code', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')", (rreq_id, account_id, rc["recovery_code_id"], dev_id, cred_id, fp, confirm_chal_id, scope, policy["policy_version"], now, now + RECOVERY_REQ_TTL_S))
                conn.execute("INSERT INTO challenges (challenge_id, purpose, account_id, recovery_request_id, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'recovery_confirm', ?, ?, ?, ?, ?, ?, ?, 'issued')", (confirm_chal_id, account_id, rreq_id, confirm_bytes, self.auth.expected_origin, self.auth.rp_id, now, now + RECOVERY_REQ_TTL_S))
                out = {"recovery_request_id": rreq_id, "confirm_challenge_id": confirm_chal_id, "confirm_challenge_hex": confirm_bytes.hex(), "revocation_scope": scope, "key_fingerprint": fp, "device_id": dev_id}
        if err is not None:
            self.store.audit("recovery_submit_denied", "denied", reason_code=err.code, account_id=account_id, network_zone=zone)
            raise err
        self.store.audit("recovery_initiated", "ok", account_id=account_id, device_id=out["device_id"], extra={"recovery_request_id": out["recovery_request_id"], "key_fingerprint": out["key_fingerprint"], "set_id": set_id_log})
        self.store.notify("recovery_initiated", [account_id], {"recovery_request_id": out["recovery_request_id"], "key_fingerprint": out["key_fingerprint"], "revocation_scope": out["revocation_scope"]})
        return {k: out[k] for k in ("recovery_request_id", "confirm_challenge_id", "confirm_challenge_hex", "revocation_scope", "key_fingerprint")}

    def recovery_confirm(
        self, *, recovery_request_id: str, confirm_signature: bytes, origin: str, second_verification_id: str | None = None,
    ) -> dict[str, Any]:
        if origin != self.auth.expected_origin:
            raise AuthError("invalid_origin", status_code=403)
        now = time.time()
        policy = self.store.get_server_policy()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            rreq = conn.execute("SELECT * FROM recovery_requests WHERE recovery_request_id = ?", (recovery_request_id,)).fetchone()
            if not rreq or rreq["state"] != "pending":
                err = AuthError("recovery_request_not_pending", status_code=409)
            elif now > rreq["expires_at"]:
                conn.execute("UPDATE recovery_requests SET state = 'expired', resolved_at = ? WHERE recovery_request_id = ?", (now, recovery_request_id))
                err = AuthError("recovery_request_expired", status_code=410)
            elif rreq["policy_version"] != policy["policy_version"]:
                conn.execute("UPDATE recovery_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = 'policy_changed' WHERE recovery_request_id = ?", (now, recovery_request_id))
                err = AuthError("policy_changed", status_code=409)
            else:
                acc = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (rreq["account_id"],)).fetchone()
                new_dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (rreq["device_id"],)).fetchone()
                if not acc or not new_dev:
                    err = AuthError("recovery_account_ineligible", status_code=403)
                else:
                    eff = max(policy["min_mode"], acc["min_mode"], 2)
                    if eff == 4:
                        err = AuthError("mode_4_remote_recovery_forbidden", status_code=403)
                    elif MODE_DEFAULTS[eff]["hardware_key_required"] and not new_dev["hardware_binding"]:
                        err = AuthError("new_key_incompatible_with_mode", status_code=403)
                    else:
                        if eff == 3:
                            if not second_verification_id:
                                err = AuthError("second_owner_approval_required", status_code=403)
                            else:
                                info = self.auth.verify_verification_active_conn(conn, second_verification_id, require_owner=True)
                                ver2 = info["ver"]
                                # CRIT-06: ЗАПРЕТ Telegram как второго фактора в P10 + проверка hardware_binding, purpose и одноразовости!
                                if ver2["channel"] not in ("web", "app", "local_console"):
                                    err = AuthError("second_approval_channel_forbidden", status_code=403)
                                elif ver2["account_id"] == acc["account_id"]:
                                    err = AuthError("second_owner_must_be_other_owner", status_code=403)
                                elif ver2["consumed_by_approval_id"] is not None:
                                    err = AuthError("second_approval_already_used", status_code=403)
                                elif (now - ver2["verified_at"]) > MODE_DEFAULTS[3]["freshness_ttl_s"]:
                                    err = AuthError("second_approval_stale", status_code=403)
                                elif ver2["channel"] != "local_console" and not info["dev"]["hardware_binding"]:
                                    err = AuthError("second_approval_hardware_key_required", status_code=403)
                        if err is None:
                            chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (rreq["challenge_id"],)).fetchone()
                            cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ?", (rreq["credential_id"],)).fetchone()
                            if not chal or chal["state"] != "issued" or chal["purpose"] != "recovery_confirm" or not cred:
                                err = AuthError("invalid_challenge", status_code=401)
                            elif now > chal["expires_at"]:
                                conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (chal["challenge_id"],))
                                err = AuthError("challenge_expired", status_code=401)
                            else:
                                msg = f"locugard:recovery_confirm:{recovery_request_id}:{rreq['revocation_scope']}:".encode() + chal["challenge_bytes"]
                                try:
                                    _verify_ecdsa_p256(cred["public_key"], msg, confirm_signature)
                                except Exception:
                                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (chal["challenge_id"],))
                                    err = AuthError("confirm_signature_failed", status_code=401)
            if err is None:
                if second_verification_id:
                    conn.execute("UPDATE identity_verifications SET consumed_by_approval_id = ? WHERE verification_id = ? AND consumed_by_approval_id IS NULL", (recovery_request_id, second_verification_id))
                conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, chal["challenge_id"]))
                # Полный каскадный отзыв всего старого (CRIT-06)
                self._revoke_all_owner_state_conn(conn, acc["account_id"], now, "recovery_completed", keep_device_id=rreq["device_id"], keep_cred_id=rreq["credential_id"], keep_rreq_id=recovery_request_id)
                conn.execute("UPDATE devices SET state = 'active', activated_at = ? WHERE device_id = ?", (now, rreq["device_id"]))
                conn.execute("UPDATE credentials SET state = 'active', activated_at = ? WHERE credential_id = ?", (now, rreq["credential_id"]))
                conn.execute("UPDATE recovery_requests SET state = 'completed', second_verification_id = ?, resolved_at = ? WHERE recovery_request_id = ?", (second_verification_id, now, recovery_request_id))
                out = {"recovery_request_id": recovery_request_id, "account_id": acc["account_id"], "device_id": rreq["device_id"], "credential_id": rreq["credential_id"], "key_fingerprint": rreq["key_fingerprint"], "state": "completed"}
        if err is not None:
            self.store.audit("recovery_confirm_denied", "denied", reason_code=err.code, extra={"recovery_request_id": recovery_request_id})
            raise err
        self.store.emit_revocation_signal()
        self.store.audit("recovery_completed", "ok", account_id=out["account_id"], device_id=out["device_id"], credential_id=out["credential_id"], extra={"recovery_request_id": recovery_request_id, "key_fingerprint": out["key_fingerprint"]})
        self.store.notify("recovery_completed", [out["account_id"]], {"recovery_request_id": recovery_request_id, "new_device_id": out["device_id"], "key_fingerprint": out["key_fingerprint"]})
        return {"recovery_request_id": out["recovery_request_id"], "device_id": out["device_id"], "state": "completed"}

    def _revoke_all_owner_state_conn(self, conn, account_id: str, now: float, reason: str, *, keep_device_id: str | None = None, keep_cred_id: str | None = None, keep_rreq_id: str | None = None) -> None:
        conn.execute("UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = ? WHERE account_id = ? AND state = 'active'", (now, reason, account_id))
        conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = ? WHERE state = 'active' AND session_id IN (SELECT session_id FROM sessions WHERE account_id = ?)", (now, reason, account_id))
        conn.execute("UPDATE devices SET state = 'revoked', revoked_at = ?, revocation_reason = ? WHERE account_id = ? AND (? IS NULL OR device_id != ?) AND state != 'revoked'", (now, reason, account_id, keep_device_id, keep_device_id))
        conn.execute("UPDATE credentials SET state = 'revoked', revoked_at = ?, revocation_reason = ? WHERE account_id = ? AND (? IS NULL OR credential_id != ?) AND state != 'revoked'", (now, reason, account_id, keep_cred_id, keep_cred_id))
        conn.execute("UPDATE recovery_codes SET state = 'revoked', revoked_at = ? WHERE account_id = ? AND state = 'active'", (now, account_id))
        conn.execute("UPDATE enrollment_codes SET state = 'revoked', revoked_at = ? WHERE (created_by_account_id = ? OR target_account_id = ?) AND state = 'issued'", (now, account_id, account_id))
        conn.execute("UPDATE registration_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = ? WHERE target_account_id = ? AND state = 'pending'", (now, reason, account_id))
        conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = ? WHERE account_id = ? AND state IN ('pending', 'approved')", (reason, account_id))
        conn.execute("UPDATE telegram_callbacks SET state = 'revoked' WHERE account_id = ? AND state = 'issued'", (account_id,))
        conn.execute("UPDATE recovery_requests SET state = 'cancelled', resolved_at = ?, resolution_reason = ? WHERE account_id = ? AND (? IS NULL OR recovery_request_id != ?) AND state = 'pending'", (now, reason, account_id, keep_rreq_id, keep_rreq_id))
        self.store.record_revocation_event_conn(conn, "account_sessions_revoked", reason=reason, account_id=account_id, occurred_at=now)

    def console_recover_owner(self, *, account_id: str, new_public_key_pem: bytes, device_name: str, hardware_binding: bool = True) -> dict[str, Any]:
        now = time.time()
        policy = self.store.get_server_policy()
        dev_id, cred_id, rreq_id = f"dev_{secrets.token_hex(8)}", f"cred_{secrets.token_hex(8)}", f"rec_{secrets.token_hex(8)}"
        fp = key_fingerprint(new_public_key_pem)
        with self.store.transaction() as conn:
            acc = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND role = 'owner'", (account_id,)).fetchone()
            if not acc:
                raise AuthError("owner_not_found", status_code=404)
            conn.execute("UPDATE accounts SET state = 'active', updated_at = ? WHERE account_id = ?", (now, account_id))
            self._revoke_all_owner_state_conn(conn, account_id, now, "console_recovery")
            conn.execute("INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at, activated_at) VALUES (?, ?, ?, 'app_install', 'active', ?, ?, ?, ?)", (dev_id, account_id, device_name, "direct" if hardware_binding else "none", int(hardware_binding), now, now))
            conn.execute("INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, user_verification, attestation_level, backup_state, state, created_at, activated_at) VALUES (?, ?, ?, ?, ?, 'ES256', 'os_keystore', ?, 1, ?, 'single_device', 'active', ?, ?)", (cred_id, dev_id, account_id, f"con_{cred_id}", new_public_key_pem, fp, "direct" if hardware_binding else "none", now, now))
            conn.execute(
                "INSERT INTO recovery_requests (recovery_request_id, account_id, basis, device_id, credential_id, key_fingerprint, revocation_scope, policy_version, created_at, expires_at, state, resolved_at) VALUES (?, ?, 'local_console', ?, ?, ?, 'revoke_all', ?, ?, ?, 'completed', ?)",
                (rreq_id, account_id, dev_id, cred_id, fp, policy["policy_version"], now, now, now),
            )
        self.store.emit_revocation_signal()
        self.store.audit("console_recovery_completed", "ok", account_id=account_id, device_id=dev_id, network_zone="local_console", policy_version=policy["policy_version"], extra={"key_fingerprint": fp})
        self.store.notify("recovery_completed", [account_id], {"basis": "local_console", "new_device_id": dev_id, "key_fingerprint": fp})
        return {"recovery_request_id": rreq_id, "device_id": dev_id, "credential_id": cred_id, "key_fingerprint": fp}

    # =========================================================================
    # Device Pairing (Apogeus / Flutter Windows & Android — PoP + SAS + Polling)
    # =========================================================================

    def app_pair_start(
        self,
        *,
        device_name: str,
        hardware_binding: bool = False,
        source_key: str = "unknown",
    ) -> dict[str, Any]:
        """Шаг 1 Device Pairing: клиент запрашивает pair_id, poll_secret, PoP challenge и SAS user_code."""
        if not self.auth.rl.allow(f"pair_start:{source_key}", 10, 3600):
            raise AuthError("rate_limited", status_code=429)
        policy = self.store.get_server_policy()
        if not MODE_DEFAULTS[policy["min_mode"]]["new_device_access"]:
            raise AuthError("new_devices_forbidden_in_mode_4", status_code=403)
        if MODE_DEFAULTS[policy["min_mode"]]["hardware_key_required"] and not hardware_binding:
            raise AuthError("hardware_key_required", status_code=403)

        now = time.time()
        pair_id = f"pair_{secrets.token_hex(10)}"
        poll_secret = secrets.token_urlsafe(32)
        chal_bytes = secrets.token_bytes(32)
        user_code = _gen_user_code()
        expires_at = now + PAIRING_TTL_S
        clean_name = (device_name or "Native Device").strip()[:80] or "Native Device"

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE app_pairing_sessions SET state = 'expired', resolved_at = ? WHERE state IN ('initiated', 'pending_approval') AND expires_at < ?",
                (now, now),
            )
            active_cnt = conn.execute(
                "SELECT COUNT(*) FROM app_pairing_sessions WHERE state IN ('initiated', 'pending_approval')"
            ).fetchone()[0]
            if active_cnt >= PAIRING_MAX_PENDING:
                raise AuthError("too_many_pending_pairings", status_code=429)
            conn.execute(
                """
                INSERT INTO app_pairing_sessions (
                    pair_id, poll_secret_hash, user_code, failed_code_attempts, challenge_bytes, rp_id,
                    device_name, hardware_binding, state, created_at, expires_at
                ) VALUES (?, ?, ?, 0, ?, ?, ?, ?, 'initiated', ?, ?)
                """,
                (
                    pair_id, hash_secret(poll_secret, self.store.pepper), user_code,
                    chal_bytes, self.auth.rp_id, clean_name, int(bool(hardware_binding)), now, expires_at,
                ),
            )
        self.store.audit("app_pairing_started", "ok", extra={"pair_id": pair_id, "device_name": clean_name})
        return {
            "pair_id": pair_id,
            "poll_secret": poll_secret,
            "challenge_hex": chal_bytes.hex(),
            "rp_id": self.auth.rp_id,
            "user_code": user_code,
            "verification_url": f"{self.auth.expected_origin}/pair?id={pair_id}",
            "expires_at": expires_at,
        }

    def app_pair_submit_key(
        self,
        *,
        pair_id: str,
        poll_secret: str,
        public_key_pem: bytes,
        signature: bytes,
    ) -> dict[str, Any]:
        """Шаг 2 Device Pairing: клиент подтверждает владение ключом (PoP ECDSA P-256) и переводит заявку в pending_approval."""
        now = time.time()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM app_pairing_sessions WHERE pair_id = ?", (pair_id,)).fetchone()
            if not row or not hmac.compare_digest(row["poll_secret_hash"], hash_secret(poll_secret, self.store.pepper)):
                err = AuthError("pairing_invalid", status_code=401)
            elif row["state"] != "initiated":
                err = AuthError(f"pairing_{row['state']}", status_code=409)
            elif now > row["expires_at"]:
                conn.execute("UPDATE app_pairing_sessions SET state = 'expired', resolved_at = ? WHERE pair_id = ?", (now, pair_id))
                err = AuthError("pairing_expired", status_code=410)
            else:
                domain_msg = f"locugard:app_pair:{row['rp_id']}:{pair_id}:".encode() + row["challenge_bytes"]
                try:
                    _verify_ecdsa_p256(public_key_pem, domain_msg, signature)
                except Exception:
                    conn.execute("UPDATE app_pairing_sessions SET state = 'rejected', resolved_at = ? WHERE pair_id = ?", (now, pair_id))
                    err = AuthError("invalid_signature", status_code=401)
                else:
                    fp = key_fingerprint(public_key_pem)
                    conn.execute(
                        "UPDATE app_pairing_sessions SET public_key = ?, key_fingerprint = ?, state = 'pending_approval' WHERE pair_id = ?",
                        (public_key_pem, fp, pair_id),
                    )
                    out = {
                        "pair_id": pair_id,
                        "key_fingerprint": fp,
                        "user_code": row["user_code"],
                        "verification_url": f"{self.auth.expected_origin}/pair?id={pair_id}",
                        "status": "pending_approval",
                        "expires_at": row["expires_at"],
                    }
        if err is not None:
            self.store.audit("app_pairing_key_denied", "denied", reason_code=err.code, extra={"pair_id": pair_id})
            raise err
        self.store.audit("app_pairing_key_submitted", "ok", extra={"pair_id": pair_id, "key_fingerprint": out["key_fingerprint"]})
        return out

    def app_pair_status(self, *, pair_id: str, poll_secret: str) -> dict[str, Any]:
        """Polling-статус Device Pairing для нативного клиента (без 127.0.0.1 callback)."""
        if not self.auth.rl.allow(f"pair_poll:{pair_id}", 60, 60):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM app_pairing_sessions WHERE pair_id = ?", (pair_id,)).fetchone()
            if not row or not hmac.compare_digest(row["poll_secret_hash"], hash_secret(poll_secret, self.store.pepper)):
                err = AuthError("pairing_invalid", status_code=401)
            elif row["state"] in ("initiated", "pending_approval") and now > row["expires_at"]:
                conn.execute("UPDATE app_pairing_sessions SET state = 'expired', resolved_at = ? WHERE pair_id = ?", (now, pair_id))
                out = {"status": "expired"}
            elif row["state"] == "approved":
                acc = conn.execute("SELECT role FROM accounts WHERE account_id = ?", (row["target_account_id"],)).fetchone()
                out = {
                    "status": "approved",
                    "device_id": row["device_id"],
                    "credential_id": row["credential_id"],
                    "account_id": row["target_account_id"],
                    "role": acc["role"] if acc else "",
                    "key_fingerprint": row["key_fingerprint"],
                }
            else:
                out = {"status": row["state"], "expires_at": row["expires_at"]}
        if err is not None:
            raise err
        return out

    def app_pair_inspect(self, ctx: VerifiedContext, *, pair_id: str) -> dict[str, Any]:
        """Безопасный просмотр заявки pairing для owner (НЕ раскрывает user_code и poll_secret)."""
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        now = time.time()
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM app_pairing_sessions WHERE pair_id = ?", (pair_id,)).fetchone()
            if not row:
                raise AuthError("pairing_not_found", status_code=404)
            state = row["state"]
            if state in ("initiated", "pending_approval") and now > row["expires_at"]:
                conn.execute("UPDATE app_pairing_sessions SET state = 'expired', resolved_at = ? WHERE pair_id = ?", (now, pair_id))
                state = "expired"
            return {
                "pair_id": row["pair_id"],
                "device_name": row["device_name"],
                "hardware_binding": bool(row["hardware_binding"]),
                "key_fingerprint": row["key_fingerprint"],
                "state": state,
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
            }

    def app_pair_approve(
        self,
        ctx: VerifiedContext,
        *,
        pair_id: str,
        user_code: str,
        target_account_id: str | None = None,
        second_verification_id: str | None = None,
    ) -> dict[str, Any]:
        """Одобрение Device Pairing владельцем после сверки SAS user_code и свежей проверки Passkey."""
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if not self.auth.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        now = time.time()
        policy = self.store.get_server_policy()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM app_pairing_sessions WHERE pair_id = ?", (pair_id,)).fetchone()
            if not row:
                err = AuthError("pairing_not_found", status_code=404)
            elif row["state"] != "pending_approval":
                err = AuthError(f"pairing_{row['state']}", status_code=409)
            elif now > row["expires_at"]:
                conn.execute("UPDATE app_pairing_sessions SET state = 'expired', resolved_at = ? WHERE pair_id = ?", (now, pair_id))
                err = AuthError("pairing_expired", status_code=410)
            elif not hmac.compare_digest(_norm_user_code(row["user_code"]), _norm_user_code(user_code)):
                fails = int(row["failed_code_attempts"]) + 1
                if fails >= PAIRING_MAX_CODE_FAILS:
                    conn.execute("UPDATE app_pairing_sessions SET failed_code_attempts = ?, state = 'rejected', resolved_at = ? WHERE pair_id = ?", (fails, now, pair_id))
                else:
                    conn.execute("UPDATE app_pairing_sessions SET failed_code_attempts = ? WHERE pair_id = ?", (fails, pair_id))
                err = AuthError("invalid_user_code", status_code=403)
            else:
                tgt_id = (target_account_id or ctx.account_id).strip()
                actor = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active' AND role = 'owner'", (ctx.account_id,)).fetchone()
                target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (tgt_id,)).fetchone()
                if not actor or not target:
                    err = AuthError("target_account_invalid", status_code=404)
                else:
                    eff = self.auth.compute_effective_mode(
                        policy, actor_min_mode=actor["min_mode"], target_min_mode=target["min_mode"], action_min_mode=2, network_zone=ctx.network_zone,
                    )
                    mcfg = MODE_DEFAULTS[eff]
                    if not mcfg["new_device_access"]:
                        err = AuthError("new_devices_forbidden_in_mode_4", status_code=403)
                    elif mcfg["hardware_key_required"] and not row["hardware_binding"]:
                        err = AuthError("hardware_key_required", status_code=403)
                    else:
                        if eff >= 3:
                            self.auth.verify_independent_second_approval_conn(
                                conn, ctx, second_verification_id, consume_op_id=pair_id, require_owner=True, effective_mode=eff,
                            )
                        self.auth.consume_primary_verification_mode4_conn(conn, ctx, pair_id, effective_mode=eff)
                        dev_id = f"dev_{secrets.token_hex(8)}"
                        cred_id = f"cred_{secrets.token_hex(8)}"
                        hw = bool(row["hardware_binding"])
                        conn.execute(
                            "INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at, activated_at) VALUES (?, ?, ?, 'app_install', 'active', ?, ?, ?, ?)",
                            (dev_id, target["account_id"], row["device_name"], "direct" if hw else "none", int(hw), now, now),
                        )
                        conn.execute(
                            "INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, user_verification, attestation_level, backup_state, state, created_at, activated_at) VALUES (?, ?, ?, ?, ?, 'ES256', 'os_keystore', ?, 1, ?, 'single_device', 'active', ?, ?)",
                            (cred_id, dev_id, target["account_id"], f"app_{cred_id}", row["public_key"], row["key_fingerprint"], "direct" if hw else "none", now, now),
                        )
                        conn.execute(
                            """
                            UPDATE app_pairing_sessions
                            SET target_account_id = ?, device_id = ?, credential_id = ?, approved_by_account_id = ?,
                                approval_verification_id = ?, second_approval_id = ?, state = 'approved', resolved_at = ?
                            WHERE pair_id = ?
                            """,
                            (target["account_id"], dev_id, cred_id, ctx.account_id, ctx.identity_verification_id, second_verification_id, now, pair_id),
                        )
                        out = {
                            "pair_id": pair_id,
                            "device_id": dev_id,
                            "credential_id": cred_id,
                            "account_id": target["account_id"],
                            "role": target["role"],
                            "key_fingerprint": row["key_fingerprint"],
                            "status": "approved",
                        }
        if err is not None:
            self.store.audit("app_pairing_approve_denied", "denied", reason_code=err.code, account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, extra={"pair_id": pair_id})
            raise err
        self.store.audit("app_pairing_approved", "ok", account_id=out["account_id"], device_id=out["device_id"], credential_id=out["credential_id"], session_id=ctx.session_id, network_zone=ctx.network_zone, extra={"pair_id": pair_id, "approved_by": ctx.account_id, "key_fingerprint": out["key_fingerprint"]})
        return out

    def app_pair_reject(self, ctx: VerifiedContext, *, pair_id: str) -> dict[str, Any]:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        now = time.time()
        with self.store.transaction() as conn:
            row = conn.execute("SELECT state FROM app_pairing_sessions WHERE pair_id = ?", (pair_id,)).fetchone()
            if not row:
                raise AuthError("pairing_not_found", status_code=404)
            if row["state"] in ("initiated", "pending_approval"):
                conn.execute("UPDATE app_pairing_sessions SET state = 'rejected', resolved_at = ? WHERE pair_id = ?", (now, pair_id))
        self.store.audit("app_pairing_rejected", "ok", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, extra={"pair_id": pair_id})
        return {"pair_id": pair_id, "status": "rejected"}

    # =========================================================================
    # Browser SSO (Authorization Code + PKCE S256 для Docalaizer и веб-сервисов)
    # =========================================================================

    def sso_issue_code(
        self,
        ctx: VerifiedContext,
        *,
        client_id: str,
        audience: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        state_param: str | None = None,
    ) -> dict[str, Any]:
        """Выпуск одноразового 60-секундного SSO-кода (PKCE S256) после подтверждения в браузере на LocuGard."""
        aud = _validate_audience(audience)
        if code_challenge_method != "S256" or not _PKCE_CHALLENGE_RE.match(code_challenge or ""):
            raise AuthError("invalid_pkce_challenge", status_code=400)
        if not self.auth.rl.allow(f"sso_issue:{ctx.account_id}", 30, 300):
            raise AuthError("rate_limited", status_code=429)
        now = time.time()
        policy = self.store.get_server_policy()
        raw_code = secrets.token_urlsafe(32)
        code_id = f"ssoc_{secrets.token_hex(8)}"
        expires_at = now + SSO_CODE_TTL_S

        with self.store.transaction() as conn:
            acc = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (ctx.account_id,)).fetchone()
            dev = conn.execute("SELECT * FROM devices WHERE device_id = ? AND state = 'active'", (ctx.device_id,)).fetchone()
            cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ? AND state = 'active'", (ctx.credential_id,)).fetchone()
            sess = conn.execute("SELECT * FROM sessions WHERE session_id = ? AND state = 'active'", (ctx.session_id,)).fetchone()
            if not acc or not dev or not cred or not sess:
                raise AuthError("context_revoked_or_inactive", status_code=401)
            eff = self.auth.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=2, network_zone=ctx.network_zone)
            mcfg = MODE_DEFAULTS[eff]
            if acc["role"] not in mcfg["allowed_roles"]:
                raise AuthError("role_forbidden_in_mode", status_code=403)
            if mcfg["hardware_key_required"] and not dev["hardware_binding"]:
                raise AuthError("hardware_key_required", status_code=403)
            conn.execute(
                """
                INSERT INTO sso_auth_codes (
                    code_id, code_hash, client_id, audience, redirect_uri, code_challenge, code_challenge_method,
                    state_param, account_id, device_id, credential_id, source_session_id, identity_verification_id,
                    network_zone, mode_at_issue, issued_at, expires_at, state
                ) VALUES (?, ?, ?, ?, ?, ?, 'S256', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued')
                """,
                (
                    code_id, hash_secret(raw_code, self.store.pepper), client_id, aud, redirect_uri, code_challenge,
                    state_param, ctx.account_id, ctx.device_id, ctx.credential_id, ctx.session_id,
                    ctx.identity_verification_id, ctx.network_zone, eff, now, expires_at,
                ),
            )
        self.store.audit("sso_code_issued", "ok", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, network_zone=ctx.network_zone, extra={"client_id": client_id, "audience": aud, "code_id": code_id})
        return {"code": raw_code, "code_id": code_id, "expires_at": expires_at}

    def sso_exchange_code(
        self,
        *,
        client_id: str,
        allowed_audiences: set[str],
        code: str,
        redirect_uri: str,
        code_verifier: str,
        peer_ip: str | None = None,
        forwarded_for: str | None = None,
    ) -> dict[str, Any]:
        """Серверный обмен одноразового SSO-кода + PKCE verifier на сессию/токены с привязкой к audience."""
        if not code or not _PKCE_VERIFIER_RE.match(code_verifier or ""):
            raise AuthError("invalid_grant", status_code=400)
        now = time.time()
        policy = self.store.get_server_policy()
        code_hash = hash_secret(code, self.store.pepper)
        err: AuthError | None = None
        out: dict[str, Any] = {}

        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM sso_auth_codes WHERE code_hash = ?", (code_hash,)).fetchone()
            if not row or row["state"] != "issued":
                err = AuthError("invalid_grant", status_code=401)
            elif now > row["expires_at"]:
                conn.execute("UPDATE sso_auth_codes SET state = 'expired' WHERE code_id = ?", (row["code_id"],))
                err = AuthError("code_expired", status_code=401)
            elif row["client_id"] != client_id or row["audience"] not in allowed_audiences or row["redirect_uri"] != redirect_uri:
                conn.execute("UPDATE sso_auth_codes SET state = 'revoked' WHERE code_id = ?", (row["code_id"],))
                err = AuthError("invalid_grant", status_code=401)
            elif not hmac.compare_digest(_pkce_s256(code_verifier), row["code_challenge"]):
                conn.execute("UPDATE sso_auth_codes SET state = 'revoked' WHERE code_id = ?", (row["code_id"],))
                err = AuthError("pkce_verification_failed", status_code=401)
            else:
                acc = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (row["account_id"],)).fetchone()
                dev = conn.execute("SELECT * FROM devices WHERE device_id = ? AND state = 'active'", (row["device_id"],)).fetchone()
                cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ? AND state = 'active'", (row["credential_id"],)).fetchone()
                src_sess = conn.execute("SELECT * FROM sessions WHERE session_id = ? AND state = 'active'", (row["source_session_id"],)).fetchone()
                if not acc or not dev or not cred or not src_sess:
                    conn.execute("UPDATE sso_auth_codes SET state = 'revoked' WHERE code_id = ?", (row["code_id"],))
                    err = AuthError("context_revoked_or_inactive", status_code=401)
                else:
                    zone = row["network_zone"]
                    if peer_ip:
                        cur_zone = resolve_network_zone(peer_ip, policy["allowed_networks"], self.auth.trusted_proxies, forwarded_for)
                        if cur_zone == "outside_lan":
                            zone = "outside_lan"
                    if zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
                        conn.execute("UPDATE sso_auth_codes SET state = 'revoked' WHERE code_id = ?", (row["code_id"],))
                        err = AuthError("outside_allowed_network", status_code=403)
                    else:
                        eff = self.auth.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=2, network_zone=zone)
                        mcfg = MODE_DEFAULTS[eff]
                        if acc["role"] not in mcfg["allowed_roles"]:
                            conn.execute("UPDATE sso_auth_codes SET state = 'revoked' WHERE code_id = ?", (row["code_id"],))
                            err = AuthError("role_forbidden_in_mode", status_code=403)
                        elif mcfg["hardware_key_required"] and not dev["hardware_binding"]:
                            conn.execute("UPDATE sso_auth_codes SET state = 'revoked' WHERE code_id = ?", (row["code_id"],))
                            err = AuthError("hardware_key_required", status_code=403)
                        else:
                            sess_id, chain_id = f"sess_{secrets.token_hex(8)}", f"chn_{secrets.token_hex(8)}"
                            access_token, refresh_token, csrf_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                            abs_ttl = min(policy["session_ttl_s"], mcfg["session_ttl_s"])
                            idle_ttl = min(policy["idle_ttl_s"], mcfg["idle_ttl_s"])
                            abs_exp, idle_exp = now + abs_ttl, min(now + abs_ttl, now + idle_ttl)
                            access_exp = min(abs_exp, now + ACCESS_TOKEN_TTL_S)
                            conn.execute("UPDATE sso_auth_codes SET state = 'consumed', consumed_at = ? WHERE code_id = ?", (now, row["code_id"]))
                            conn.execute(
                                "INSERT INTO sessions (session_id, session_token_hash, csrf_token_hash, account_id, device_id, credential_id, auth_method, authenticated_at, identity_verification_id, created_at, last_activity_at, absolute_expires_at, idle_expires_at, access_token_expires_at, audience, network_zone_at_login, mode_at_login, state) VALUES (?, ?, ?, ?, ?, ?, 'sso_webauthn', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                                (sess_id, hash_secret(access_token, self.store.pepper), hash_secret(csrf_token, self.store.pepper), acc["account_id"], dev["device_id"], cred["credential_id"], now, row["identity_verification_id"], now, now, abs_exp, idle_exp, access_exp, row["audience"], zone, eff),
                            )
                            conn.execute(
                                "INSERT INTO refresh_token_chains (chain_id, session_id, generation, current_token_hash, rotated_at, state) VALUES (?, ?, 1, ?, ?, 'active')",
                                (chain_id, sess_id, hash_secret(refresh_token, self.store.pepper), now),
                            )
                            out = {
                                "session_id": sess_id,
                                "chain_id": chain_id,
                                "audience": row["audience"],
                                "account_id": acc["account_id"],
                                "display_name": acc["display_name"],
                                "role": acc["role"],
                                "device_id": dev["device_id"],
                                "access_token": access_token,
                                "access_expires_in": ACCESS_TOKEN_TTL_S,
                                "access_expires_at": access_exp,
                                "refresh_token": refresh_token,
                                "generation": 1,
                                "session_expires_at": abs_exp,
                                "idle_expires_at": idle_exp,
                                "effective_mode": eff,
                                "network_zone": zone,
                                "policy_version": policy["policy_version"],
                            }
        if err is not None:
            self.store.audit("sso_exchange_denied", "denied", reason_code=err.code, extra={"client_id": client_id})
            raise err
        self.store.audit("sso_token_issued", "ok", account_id=out["account_id"], device_id=out["device_id"], session_id=out["session_id"], network_zone=out["network_zone"], extra={"client_id": client_id, "audience": out["audience"]})
        return out
