"""Ядро сервиса аутентификации LocuGard: 4 режима строгости, P0, P1, P3, P5, P8 (усилено по итогам L4-аудита)."""
from __future__ import annotations

import hmac
import ipaddress
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from .auth_ratelimit import RateLimiter
from .auth_store import AuthStore, hash_secret, key_fingerprint

CHALLENGE_TTL_S = 120
REG_CHALLENGE_TTL_S = 300
ENROLLMENT_TTL_S = 300
REG_REQUEST_TTL_S = 600
ENROLLMENT_MAX_FAILS = 5
MAX_PENDING_REG_PER_ACCOUNT = 10

MODE_DEFAULTS: dict[int, dict[str, Any]] = {
    1: {"session_ttl_s": 30 * 86400, "idle_ttl_s": 14 * 86400, "freshness_ttl_s": 600, "uv_required": False, "hardware_key_required": False, "allowed_roles": ("owner", "member", "guest", "readonly"), "new_device_access": True, "second_approval_required": False},
    2: {"session_ttl_s": 7 * 86400, "idle_ttl_s": 12 * 3600, "freshness_ttl_s": 600, "uv_required": True, "hardware_key_required": False, "allowed_roles": ("owner", "member", "guest", "readonly"), "new_device_access": True, "second_approval_required": False},
    3: {"session_ttl_s": 8 * 3600, "idle_ttl_s": 1800, "freshness_ttl_s": 120, "uv_required": True, "hardware_key_required": True, "allowed_roles": ("owner", "member", "guest", "readonly"), "new_device_access": True, "second_approval_required": True},
    4: {"session_ttl_s": 2 * 3600, "idle_ttl_s": 900, "freshness_ttl_s": 120, "uv_required": True, "hardware_key_required": True, "allowed_roles": ("owner",), "new_device_access": False, "second_approval_required": True},
}


class AuthError(Exception):
    def __init__(self, code: str, status_code: int = 401):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class VerifiedContext:
    request_id: str
    request_time: float
    account_id: str
    device_id: str
    credential_id: str
    session_id: str
    role: str
    auth_method: str
    authenticated_at: float
    identity_verification_id: str
    last_identity_verified_at: float
    network_zone: str
    effective_mode: int
    policy_version: int
    granted_scopes: tuple[str, ...]
    audience: str = "locugard"
    absolute_expires_at: float | None = None
    idle_expires_at: float | None = None
    access_token_expires_at: float | None = None


def _in_cidr(ip: Any, cidr: str) -> bool:
    try:
        return ip in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def extract_client_ip(
    peer_ip: str | None,
    trusted_proxies: list[str] | None = None,
    forwarded_for: str | None = None,
) -> Any | None:
    """Извлекает реальный IP клиента: X-Forwarded-For разбирается СПРАВА НАЛЕВО, пропуская trusted_proxies (CRIT-02)."""
    if not peer_ip:
        return None
    try:
        actual_ip = ipaddress.ip_address(peer_ip.strip())
    except ValueError:
        return None
    if not (forwarded_for and trusted_proxies and any(_in_cidr(actual_ip, c) for c in trusted_proxies)):
        return actual_ip
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    if not hops:
        return None
    # Идём справа налево и берём самый правый IP, НЕ входящий в trusted_proxies
    for raw_hop in reversed(hops):
        try:
            hop_ip = ipaddress.ip_address(raw_hop)
        except ValueError:
            return None
        if not any(_in_cidr(hop_ip, c) for c in trusted_proxies):
            return hop_ip
    return None


def resolve_network_zone(
    peer_ip: str | None,
    allowed_networks: list[str],
    trusted_proxies: list[str] | None = None,
    forwarded_for: str | None = None,
) -> str:
    client_ip = extract_client_ip(peer_ip, trusted_proxies, forwarded_for)
    if client_ip is None:
        return "outside_lan"
    return "lan" if any(_in_cidr(client_ip, c) for c in allowed_networks) else "outside_lan"


def _require_webauthn():
    try:
        import webauthn
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )
        return webauthn, base64url_to_bytes, bytes_to_base64url, AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, UserVerificationRequirement
    except ImportError as e:
        raise RuntimeError("Для WebAuthn требуется опциональный extra [web]") from e


class AuthService:
    def __init__(
        self,
        store: AuthStore,
        *,
        rp_id: str = "locugard.home.arpa",
        rp_name: str = "LocuGard",
        expected_origin: str = "https://locugard.home.arpa:8443",
        trusted_proxies: list[str] | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self.store = store
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.expected_origin = expected_origin
        self.trusted_proxies = list(trusted_proxies or [])
        self.rl = rate_limiter or RateLimiter()

    def compute_effective_mode(
        self,
        policy: dict[str, Any],
        *,
        actor_min_mode: int,
        action_min_mode: int,
        network_zone: str,
        target_min_mode: int | None = None,
    ) -> int:
        if network_zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)
        base = max(policy["min_mode"], actor_min_mode, action_min_mode, target_min_mode or 1)
        if base not in MODE_DEFAULTS:
            raise AuthError("unknown_security_mode", status_code=403)
        return 2 if (network_zone == "outside_lan" and base == 1) else base

    def is_fresh(self, ctx: VerifiedContext) -> bool:
        policy = self.store.get_server_policy()
        ttl = min(MODE_DEFAULTS[ctx.effective_mode]["freshness_ttl_s"], policy["freshness_ttl_s"])
        return (time.time() - ctx.last_identity_verified_at) <= ttl

    def verify_verification_active_conn(self, conn, verification_id: str, *, require_owner: bool = False) -> dict[str, Any]:
        ver = conn.execute("SELECT * FROM identity_verifications WHERE verification_id = ?", (verification_id,)).fetchone()
        if not ver:
            raise AuthError("verification_not_found", status_code=403)
        acc = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (ver["account_id"],)).fetchone()
        if not acc or acc["state"] != "active":
            raise AuthError("approver_account_inactive", status_code=403)
        if require_owner and acc["role"] != "owner":
            raise AuthError("approver_not_owner", status_code=403)
        ch = ver["channel"]
        if ch in ("web", "app"):
            dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (ver["device_id"],)).fetchone()
            cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ?", (ver["credential_id"],)).fetchone()
            if not dev or not cred or dev["state"] != "active" or cred["state"] != "active":
                raise AuthError("approver_device_revoked", status_code=403)
            return {"ver": dict(ver), "acc": dict(acc), "dev": dict(dev), "cred": dict(cred)}
        if ch == "telegram":
            ext = conn.execute("SELECT * FROM external_identities WHERE identity_id = ?", (ver["external_identity_id"],)).fetchone()
            if not ext or ext["state"] != "active":
                raise AuthError("external_identity_revoked", status_code=403)
            return {"ver": dict(ver), "acc": dict(acc), "ext": dict(ext)}
        return {"ver": dict(ver), "acc": dict(acc)}

    def verify_independent_second_approval_conn(
        self,
        conn,
        ctx: VerifiedContext,
        second_verification_id: str | None,
        *,
        consume_op_id: str,
        candidate_device_id: str | None = None,
        require_owner: bool = True,
        expected_target_digest: str | None = None,
        effective_mode: int | None = None,
    ) -> dict[str, Any]:
        """Атомарная проверка и одноразовое расходование second_verification_id внутри транзакции (CRIT-05)."""
        if not second_verification_id:
            raise AuthError("second_approval_required", status_code=403)
        now = time.time()
        eff = max(effective_mode or ctx.effective_mode, 3)
        info = self.verify_verification_active_conn(conn, second_verification_id, require_owner=require_owner)
        ver2 = info["ver"]
        if ver2["consumed_by_approval_id"] is not None:
            raise AuthError("second_approval_already_used", status_code=403)
        if (now - ver2["verified_at"]) > MODE_DEFAULTS[eff]["freshness_ttl_s"]:
            raise AuthError("second_approval_stale", status_code=403)
        if ver2["purpose"] == "login":
            raise AuthError("second_approval_must_not_be_login", status_code=403)
        if expected_target_digest is not None and ver2["target_digest"] != expected_target_digest:
            raise AuthError("second_approval_target_mismatch", status_code=403)
        if ver2["channel"] != "local_console":
            if ver2["channel"] not in ("web", "app"):
                raise AuthError("second_approval_channel_forbidden", status_code=403)
            if ver2["method"] == "webauthn_no_uv":
                raise AuthError("second_approval_uv_required", status_code=403)
            if MODE_DEFAULTS[eff]["hardware_key_required"] and not info["dev"]["hardware_binding"]:
                raise AuthError("second_approval_hardware_key_required", status_code=403)
            cred1 = conn.execute("SELECT external_credential_id FROM credentials WHERE credential_id = ?", (ctx.credential_id,)).fetchone()
            cred2 = info["cred"]
            if (
                ver2["device_id"] == ctx.device_id
                or ver2["credential_id"] == ctx.credential_id
                or (cred1 and cred2["external_credential_id"] == cred1["external_credential_id"])
                or (candidate_device_id and ver2["device_id"] == candidate_device_id)
            ):
                raise AuthError("second_approval_not_independent", status_code=403)
        cur = conn.execute(
            "UPDATE identity_verifications SET consumed_by_approval_id = ? WHERE verification_id = ? AND consumed_by_approval_id IS NULL",
            (consume_op_id, second_verification_id),
        )
        if cur.rowcount != 1:
            raise AuthError("second_approval_already_used", status_code=403)
        return info

    def consume_primary_verification_mode4_conn(self, conn, ctx: VerifiedContext, op_id: str, *, effective_mode: int | None = None) -> None:
        """В режиме 4 любая R3/R4-операция одноразово расходует основную IdentityVerification (CRIT-08)."""
        if (effective_mode or ctx.effective_mode) != 4:
            return
        cur = conn.execute(
            "UPDATE identity_verifications SET consumed_by_approval_id = ? WHERE verification_id = ? AND consumed_by_approval_id IS NULL",
            (op_id, ctx.identity_verification_id),
        )
        if cur.rowcount != 1:
            raise AuthError("mode_4_verification_already_used", status_code=403)

    def create_console_verification(self, account_id: str, purpose: str, *, target_digest: str | None = None) -> str:
        ver_id = f"ver_{secrets.token_hex(8)}"
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO identity_verifications (verification_id, account_id, channel, method, verified_at, assurance_level, purpose, target_digest) VALUES (?, ?, 'local_console', 'local_console', ?, 4, ?, ?)",
                (ver_id, account_id, time.time(), purpose, target_digest),
            )
        return ver_id

    # --- P0: Первый владелец (только локальная консоль) ---

    def bootstrap_owner_begin(self, display_name: str) -> dict[str, Any]:
        if self.store.has_active_owner_with_key():
            self.store.audit("bootstrap_owner", "denied", reason_code="owner_already_exists", network_zone="local_console")
            raise AuthError("owner_already_exists", status_code=409)
        webauthn, _, _, AuthSel, _, UVReq = _require_webauthn()
        chal_bytes, chal_id, now = secrets.token_bytes(32), f"chal_{secrets.token_hex(12)}", time.time()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO challenges (challenge_id, purpose, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'bootstrap_owner', ?, ?, ?, ?, ?, 'issued')",
                (chal_id, chal_bytes, self.expected_origin, self.rp_id, now, now + REG_CHALLENGE_TTL_S),
            )
        opts = webauthn.generate_registration_options(
            rp_id=self.rp_id, rp_name=self.rp_name, user_id=f"boot_{chal_id}".encode(),
            user_name=display_name, challenge=chal_bytes,
            authenticator_selection=AuthSel(user_verification=UVReq.REQUIRED),
        )
        return {"challenge_id": chal_id, "options": json.loads(webauthn.options_to_json(opts))}

    def bootstrap_owner_complete(
        self, *, challenge_id: str, display_name: str, device_name: str, credential_payload: dict[str, Any], hardware_binding: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(credential_payload, dict):
            raise AuthError("invalid_payload", status_code=400)
        if self.store.has_active_owner_with_key():
            raise AuthError("owner_already_exists", status_code=409)
        webauthn, _, bytes_to_b64u, _, _, _ = _require_webauthn()
        now = time.time()
        err: AuthError | None = None
        result: dict[str, Any] = {}
        with self.store.transaction() as conn:
            chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
            if not chal or chal["state"] != "issued" or chal["purpose"] != "bootstrap_owner":
                err = AuthError("invalid_challenge", status_code=401)
            elif now > chal["expires_at"]:
                conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("challenge_expired", status_code=401)
            else:
                try:
                    verified = webauthn.verify_registration_response(
                        credential=credential_payload, expected_challenge=chal["challenge_bytes"],
                        expected_origin=chal["origin"], expected_rp_id=chal["rp_id"], require_user_verification=True,
                    )
                except Exception:
                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                    err = AuthError("verification_failed", status_code=401)
            if err is None:
                if conn.execute("SELECT 1 FROM accounts a JOIN devices d ON d.account_id=a.account_id AND d.state='active' JOIN credentials c ON c.device_id=d.device_id AND c.state='active' WHERE a.role='owner' AND a.state='active' LIMIT 1").fetchone():
                    err = AuthError("owner_already_exists", status_code=409)
                else:
                    # Синхронизированный passkey не может иметь hardware_binding=True (CRIT-10)
                    hw_flag = bool(hardware_binding and not verified.credential_backed_up)
                    acc_id, dev_id, cred_id = f"acc_{secrets.token_hex(8)}", f"dev_{secrets.token_hex(8)}", f"cred_{secrets.token_hex(8)}"
                    ext_id = bytes_to_b64u(verified.credential_id)
                    fp = key_fingerprint(verified.credential_public_key)
                    bstate = "backed_up" if verified.credential_backed_up else "single_device"
                    conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                    conn.execute("INSERT INTO accounts (account_id, display_name, role, state, min_mode, policy_version, created_at, updated_at) VALUES (?, ?, 'owner', 'active', 2, 1, ?, ?)", (acc_id, display_name, now, now))
                    conn.execute("INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at, activated_at) VALUES (?, ?, ?, 'web_profile', 'active', ?, ?, ?, ?)", (dev_id, acc_id, device_name, "direct" if hw_flag else "none", int(hw_flag), now, now))
                    conn.execute(
                        "INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, sign_count, user_verification, attestation_level, backup_state, state, created_at, activated_at) VALUES (?, ?, ?, ?, ?, 'webauthn', 'passkey', ?, ?, 1, ?, ?, 'active', ?, ?)",
                        (cred_id, dev_id, acc_id, ext_id, verified.credential_public_key, fp, verified.sign_count, "direct" if hw_flag else "none", bstate, now, now),
                    )
                    result = {"account_id": acc_id, "device_id": dev_id, "credential_id": cred_id, "key_fingerprint": fp}
        if err is not None:
            self.store.audit("bootstrap_owner_denied", "denied", reason_code=err.code, network_zone="local_console")
            raise err
        self.store.audit("bootstrap_owner_completed", "ok", account_id=result["account_id"], device_id=result["device_id"], credential_id=result["credential_id"], network_zone="local_console", extra={"key_fingerprint": result["key_fingerprint"]})
        return result

    # --- P1: Вход и повторная проверка личности ---

    def login_begin(self, *, source_key: str = "unknown") -> dict[str, Any]:
        if not self.rl.allow(f"login_chal:{source_key}", 10, 60):
            raise AuthError("rate_limited", status_code=429)
        webauthn, _, _, _, _, UVReq = _require_webauthn()
        chal_bytes, chal_id, now = secrets.token_bytes(32), f"chal_{secrets.token_hex(12)}", time.time()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO challenges (challenge_id, purpose, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'login', ?, ?, ?, ?, ?, 'issued')",
                (chal_id, chal_bytes, self.expected_origin, self.rp_id, now, now + CHALLENGE_TTL_S),
            )
        opts = webauthn.generate_authentication_options(rp_id=self.rp_id, challenge=chal_bytes, user_verification=UVReq.REQUIRED)
        return {"challenge_id": chal_id, "options": json.loads(webauthn.options_to_json(opts))}

    def login_verify(
        self, *, challenge_id: str, credential_payload: dict[str, Any], peer_ip: str | None,
        forwarded_for: str | None = None, old_session_token: str | None = None, require_uv: bool | None = None,
    ) -> dict[str, Any]:
        if not isinstance(credential_payload, dict):
            raise AuthError("invalid_payload", status_code=400)
        webauthn, _, _, _, _, _ = _require_webauthn()
        now = time.time()
        policy = self.store.get_server_policy()
        client_ip_obj = extract_client_ip(peer_ip, self.trusted_proxies, forwarded_for)
        client_ip_str = str(client_ip_obj) if client_ip_obj else "unknown"
        zone = "lan" if (client_ip_obj is not None and any(_in_cidr(client_ip_obj, c) for c in policy["allowed_networks"])) else "outside_lan"
        if zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
            self.store.audit("login_denied", "denied", reason_code="outside_allowed_network", network_zone=zone)
            raise AuthError("outside_allowed_network", status_code=403)

        ext_id = str(credential_payload.get("rawId") or credential_payload.get("id") or "")
        err: AuthError | None = None
        audit_fail: tuple[str, str | None, str | None] = ("authentication_failed", None, None)
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
            if not chal or chal["state"] != "issued":
                err = AuthError("authentication_failed", status_code=401)
                audit_fail = (f"challenge_{chal['state']}" if chal else "challenge_not_found", None, None)
            elif now > chal["expires_at"]:
                conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("authentication_failed", status_code=401)
                audit_fail = ("challenge_expired", None, None)
            elif chal["purpose"] != "login":
                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("authentication_failed", status_code=401)
                audit_fail = ("challenge_purpose_mismatch", None, None)
            else:
                cred = conn.execute("SELECT * FROM credentials WHERE external_credential_id = ?", (ext_id,)).fetchone()
                if not cred or cred["state"] != "active":
                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                    err = AuthError("authentication_failed", status_code=401)
                    audit_fail = ("credential_inactive_or_unknown", None, None)
                else:
                    dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (cred["device_id"],)).fetchone()
                    acc = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (cred["account_id"],)).fetchone()
                    if not dev or not acc or dev["state"] != "active" or acc["state"] != "active" or dev["account_id"] != acc["account_id"]:
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("authentication_failed", status_code=401)
                        audit_fail = ("account_or_device_inactive", acc["account_id"] if acc else None, dev["device_id"] if dev else None)
                    elif self.rl.count(f"login_fail:{acc['account_id']}:{client_ip_str}", 900) >= 5:
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("rate_limited", status_code=429)
                        audit_fail = ("login_rate_limited", acc["account_id"], dev["device_id"])
                    else:
                        eff_mode = self.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=1, network_zone=zone)
                        # CRIT-09: require_uv=False НЕ может ослабить UV в режимах >= 2!
                        uv_req = MODE_DEFAULTS[eff_mode]["uv_required"] or bool(require_uv)
                        # MED-04: сначала проверяем криптографическую подпись (исключаем pre-auth oracle 403)
                        try:
                            verified = webauthn.verify_authentication_response(
                                credential=credential_payload, expected_challenge=chal["challenge_bytes"],
                                expected_origin=chal["origin"], expected_rp_id=chal["rp_id"],
                                credential_public_key=cred["public_key"], credential_current_sign_count=cred["sign_count"],
                                require_user_verification=uv_req,
                            )
                        except Exception:
                            conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                            self.rl.allow(f"login_fail:{acc['account_id']}:{client_ip_str}", 5, 900)
                            audit_fail = ("webauthn_verification_failed", acc["account_id"], dev["device_id"])
                            err = AuthError("authentication_failed", status_code=401)
                        else:
                            # После доказательства владения ключом проверяем политику роли и аппаратного ключа
                            actual_uv = bool(verified.user_verified)
                            session_mode = max(eff_mode, 2) if actual_uv else eff_mode
                            mode_cfg = MODE_DEFAULTS[session_mode]
                            if acc["role"] not in mode_cfg["allowed_roles"]:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                audit_fail = ("role_forbidden_in_mode", acc["account_id"], dev["device_id"])
                                err = AuthError("role_forbidden_in_mode", status_code=403)
                            elif mode_cfg["hardware_key_required"] and not dev["hardware_binding"]:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                audit_fail = ("hardware_key_required", acc["account_id"], dev["device_id"])
                                err = AuthError("hardware_key_required", status_code=403)

            if err is None:
                if old_session_token:
                    conn.execute(
                        "UPDATE sessions SET state = 'closed', ended_at = ?, end_reason = 'replaced_by_new_login' WHERE session_token_hash = ? AND state = 'active'",
                        (now, hash_secret(old_session_token, self.store.pepper)),
                    )
                ver_id, sess_id = f"ver_{secrets.token_hex(8)}", f"sess_{secrets.token_hex(8)}"
                session_token, csrf_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                abs_ttl = min(policy["session_ttl_s"], mode_cfg["session_ttl_s"])
                idle_ttl = min(policy["idle_ttl_s"], mode_cfg["idle_ttl_s"])
                abs_exp, idle_exp = now + abs_ttl, min(now + abs_ttl, now + idle_ttl)
                auth_method = "webauthn_uv" if actual_uv else "webauthn_no_uv"

                conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                conn.execute("UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?", (verified.new_sign_count, now, cred["credential_id"]))
                conn.execute("UPDATE devices SET last_used_at = ? WHERE device_id = ?", (now, dev["device_id"]))
                conn.execute(
                    "INSERT INTO identity_verifications (verification_id, account_id, channel, device_id, credential_id, session_id, method, challenge_id, verified_at, assurance_level, purpose) VALUES (?, ?, 'web', ?, ?, ?, ?, ?, ?, ?, 'login')",
                    (ver_id, acc["account_id"], dev["device_id"], cred["credential_id"], sess_id, auth_method, challenge_id, now, session_mode),
                )
                conn.execute(
                    "INSERT INTO sessions (session_id, session_token_hash, csrf_token_hash, account_id, device_id, credential_id, auth_method, authenticated_at, identity_verification_id, created_at, last_activity_at, absolute_expires_at, idle_expires_at, network_zone_at_login, mode_at_login, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                    (sess_id, hash_secret(session_token, self.store.pepper), hash_secret(csrf_token, self.store.pepper), acc["account_id"], dev["device_id"], cred["credential_id"], auth_method, now, ver_id, now, now, abs_exp, idle_exp, zone, session_mode),
                )
                out = {"session_id": sess_id, "session_token": session_token, "csrf_token": csrf_token, "account_id": acc["account_id"], "role": acc["role"], "device_id": dev["device_id"], "max_age_s": int(abs_ttl), "effective_mode": session_mode}
        if err is not None:
            self.store.audit("login_denied", "denied", reason_code=audit_fail[0], account_id=audit_fail[1], device_id=audit_fail[2], network_zone=zone)
            raise err
        self.store.audit("login_succeeded", "ok", account_id=out["account_id"], device_id=out["device_id"], session_id=out["session_id"], network_zone=zone, policy_version=policy["policy_version"])
        return out

    def reauth_begin(self, ctx: VerifiedContext) -> dict[str, Any]:
        if not self.rl.allow(f"reauth_chal:{ctx.account_id}", 30, 60):
            raise AuthError("rate_limited", status_code=429)
        webauthn, b64u_to_bytes, _, _, CredDesc, UVReq = _require_webauthn()
        chal_bytes, chal_id, now = secrets.token_bytes(32), f"chal_{secrets.token_hex(12)}", time.time()
        with self.store.transaction() as conn:
            cred = conn.execute("SELECT external_credential_id FROM credentials WHERE credential_id = ? AND state = 'active'", (ctx.credential_id,)).fetchone()
            if not cred:
                raise AuthError("credential_inactive", status_code=401)
            conn.execute(
                "INSERT INTO challenges (challenge_id, purpose, account_id, device_id, credential_id, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'reauth', ?, ?, ?, ?, ?, ?, ?, ?, 'issued')",
                (chal_id, ctx.account_id, ctx.device_id, ctx.credential_id, chal_bytes, self.expected_origin, self.rp_id, now, now + CHALLENGE_TTL_S),
            )
        opts = webauthn.generate_authentication_options(rp_id=self.rp_id, challenge=chal_bytes, user_verification=UVReq.REQUIRED, allow_credentials=[CredDesc(id=b64u_to_bytes(cred["external_credential_id"]))])
        return {"challenge_id": chal_id, "options": json.loads(webauthn.options_to_json(opts))}

    def reauth_verify(
        self, ctx: VerifiedContext, *, challenge_id: str, credential_payload: dict[str, Any],
        purpose: str = "reauth", target_digest: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(credential_payload, dict):
            raise AuthError("invalid_payload", status_code=400)
        webauthn, _, _, _, _, _ = _require_webauthn()
        now = time.time()
        err: AuthError | None = None
        ver_id = f"ver_{secrets.token_hex(8)}"
        with self.store.transaction() as conn:
            chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
            if not chal or chal["state"] != "issued" or chal["purpose"] != "reauth" or chal["account_id"] != ctx.account_id or chal["credential_id"] != ctx.credential_id:
                if chal and chal["state"] == "issued":
                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("reauth_failed", status_code=401)
            elif now > chal["expires_at"]:
                conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                err = AuthError("challenge_expired", status_code=401)
            else:
                # MED-08: перепроверяем активность session, account, device и credential внутри транзакции
                sess = conn.execute("SELECT * FROM sessions WHERE session_id = ? AND state = 'active'", (ctx.session_id,)).fetchone()
                acc = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (ctx.account_id,)).fetchone()
                dev = conn.execute("SELECT * FROM devices WHERE device_id = ? AND state = 'active'", (ctx.device_id,)).fetchone()
                cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ? AND state = 'active'", (ctx.credential_id,)).fetchone()
                if not sess or not acc or not dev or not cred:
                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                    err = AuthError("context_revoked_or_inactive", status_code=401)
                else:
                    try:
                        verified = webauthn.verify_authentication_response(
                            credential=credential_payload, expected_challenge=chal["challenge_bytes"],
                            expected_origin=chal["origin"], expected_rp_id=chal["rp_id"],
                            credential_public_key=cred["public_key"], credential_current_sign_count=cred["sign_count"], require_user_verification=True,
                        )
                    except Exception:
                        conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                        err = AuthError("reauth_failed", status_code=401)
            if err is None:
                conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                conn.execute("UPDATE credentials SET sign_count = ?, last_used_at = ? WHERE credential_id = ?", (verified.new_sign_count, now, cred["credential_id"]))
                conn.execute(
                    "INSERT INTO identity_verifications (verification_id, account_id, channel, device_id, credential_id, session_id, method, challenge_id, verified_at, assurance_level, purpose, target_digest) VALUES (?, ?, 'web', ?, ?, ?, 'webauthn_uv', ?, ?, ?, ?, ?)",
                    (ver_id, ctx.account_id, ctx.device_id, ctx.credential_id, ctx.session_id, challenge_id, now, ctx.effective_mode, purpose, target_digest),
                )
                cur = conn.execute("UPDATE sessions SET identity_verification_id = ? WHERE session_id = ? AND state = 'active'", (ver_id, ctx.session_id))
                if cur.rowcount != 1:
                    err = AuthError("session_invalid_or_revoked", status_code=401)
        if err is not None:
            self.store.audit("reauth_denied", "denied", reason_code=err.code, account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, network_zone=ctx.network_zone)
            raise err
        self.store.audit("reauth_succeeded", "ok", account_id=ctx.account_id, device_id=ctx.device_id, credential_id=ctx.credential_id, session_id=ctx.session_id, network_zone=ctx.network_zone, policy_version=ctx.policy_version)
        return {"verification_id": ver_id, "verified_at": now}

    def verify_session(
        self,
        session_token: str | None,
        *,
        peer_ip: str | None,
        forwarded_for: str | None = None,
        action_min_mode: int = 2,
        touch_activity: bool = True,
        expected_audience: str | None = None,
    ) -> VerifiedContext:
        if not session_token:
            raise AuthError("unauthorized", status_code=401)
        now = time.time()
        policy = self.store.get_server_policy()
        zone = resolve_network_zone(peer_ip, policy["allowed_networks"], self.trusted_proxies, forwarded_for)
        if zone == "outside_lan" and policy["outside_lan_behavior"] == "deny":
            raise AuthError("outside_allowed_network", status_code=403)
        tok_hash = hash_secret(session_token, self.store.pepper)
        err: AuthError | None = None
        ctx_out: VerifiedContext | None = None
        with self.store.transaction() as conn:
            sess = conn.execute("SELECT * FROM sessions WHERE session_token_hash = ?", (tok_hash,)).fetchone()
            if not sess or sess["state"] != "active":
                err = AuthError("session_invalid_or_revoked", status_code=401)
            else:
                acc = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (sess["account_id"],)).fetchone()
                dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (sess["device_id"],)).fetchone()
                cred = conn.execute("SELECT * FROM credentials WHERE credential_id = ?", (sess["credential_id"],)).fetchone()
                ver = conn.execute("SELECT * FROM identity_verifications WHERE verification_id = ?", (sess["identity_verification_id"],)).fetchone()
                if not acc or not dev or not cred or not ver or acc["state"] != "active" or dev["state"] != "active" or cred["state"] != "active" or dev["account_id"] != acc["account_id"] or cred["account_id"] != acc["account_id"]:
                    err = AuthError("context_revoked_or_inactive", status_code=401)
                else:
                    eff_mode = self.compute_effective_mode(policy, actor_min_mode=acc["min_mode"], action_min_mode=action_min_mode, network_zone=zone)
                    mode_cfg = MODE_DEFAULTS[eff_mode]
                    eff_abs = min(sess["absolute_expires_at"], sess["created_at"] + min(policy["session_ttl_s"], mode_cfg["session_ttl_s"]))
                    eff_idle = min(sess["idle_expires_at"], sess["last_activity_at"] + min(policy["idle_ttl_s"], mode_cfg["idle_ttl_s"]))
                    if now > eff_abs or now > eff_idle:
                        conn.execute("UPDATE sessions SET state = 'expired', ended_at = ?, end_reason = 'ttl_expired' WHERE session_id = ?", (now, sess["session_id"]))
                        err = AuthError("session_expired", status_code=401)
                    elif sess["access_token_expires_at"] is not None and now > sess["access_token_expires_at"]:
                        # CRIT-10: проверка 10-минутного TTL access-токена приложения
                        err = AuthError("access_token_expired", status_code=401)
                    elif acc["role"] not in mode_cfg["allowed_roles"]:
                        err = AuthError("role_forbidden_in_mode", status_code=403)
                    elif eff_mode >= 2 and sess["mode_at_login"] < 2:
                        err = AuthError("step_up_relogin_required", status_code=401)
                    elif mode_cfg["hardware_key_required"] and not dev["hardware_binding"]:
                        err = AuthError("hardware_key_required", status_code=403)
                    elif expected_audience is not None and sess["audience"] != expected_audience:
                        err = AuthError("audience_mismatch", status_code=403)
                    else:
                        new_idle = eff_idle
                        if touch_activity:
                            new_idle = min(eff_abs, now + min(policy["idle_ttl_s"], mode_cfg["idle_ttl_s"]))
                            conn.execute("UPDATE sessions SET last_activity_at = ?, idle_expires_at = ? WHERE session_id = ?", (now, new_idle, sess["session_id"]))
                        # CRIT-07: роль readonly получает только read-only скоуп
                        scopes = (f"personal_ro:{acc['account_id']}",) if acc["role"] == "readonly" else (f"personal:{acc['account_id']}",)
                        ctx_out = VerifiedContext(
                            request_id=f"req_{secrets.token_hex(6)}", request_time=now,
                            account_id=acc["account_id"], device_id=dev["device_id"], credential_id=cred["credential_id"],
                            session_id=sess["session_id"], role=acc["role"], auth_method=sess["auth_method"],
                            authenticated_at=sess["authenticated_at"], identity_verification_id=ver["verification_id"],
                            last_identity_verified_at=ver["verified_at"], network_zone=zone, effective_mode=eff_mode,
                            policy_version=policy["policy_version"], granted_scopes=scopes,
                            audience=sess["audience"], absolute_expires_at=eff_abs,
                            idle_expires_at=new_idle, access_token_expires_at=sess["access_token_expires_at"],
                        )
        if err is not None:
            raise err
        assert ctx_out is not None
        return ctx_out

    def verify_csrf(self, session_id: str, csrf_token: str | None) -> None:
        if not csrf_token:
            raise AuthError("csrf_failed", status_code=403)
        with self.store.readonly() as conn:
            row = conn.execute("SELECT csrf_token_hash FROM sessions WHERE session_id = ? AND state = 'active'", (session_id,)).fetchone()
            if not row or not hmac.compare_digest(row["csrf_token_hash"], hash_secret(csrf_token, self.store.pepper)):
                raise AuthError("csrf_failed", status_code=403)

    # --- P3: Регистрация нового устройства/ключа ---

    def create_enrollment_code(self, ctx: VerifiedContext, *, target_account_id: str) -> dict[str, Any]:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if not self.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        if not self.rl.allow(f"enr_create:{ctx.account_id}", 5, 3600):
            raise AuthError("rate_limited", status_code=429)
        policy = self.store.get_server_policy()
        enr_id, raw_secret, now = f"enr_{secrets.token_hex(8)}", secrets.token_urlsafe(32), time.time()
        with self.store.transaction() as conn:
            actor = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (ctx.account_id,)).fetchone()
            target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (target_account_id,)).fetchone()
            if not actor or not target:
                raise AuthError("target_account_invalid", status_code=404)
            eff = self.compute_effective_mode(policy, actor_min_mode=actor["min_mode"], target_min_mode=target["min_mode"], action_min_mode=2, network_zone=ctx.network_zone)
            if not MODE_DEFAULTS[eff]["new_device_access"]:
                raise AuthError("new_devices_forbidden_in_mode_4", status_code=403)
            conn.execute(
                "INSERT INTO enrollment_codes (enrollment_id, created_by_account_id, target_account_id, allowed_role, code_hash, failed_attempts, issued_at, expires_at, state) VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'issued')",
                (enr_id, ctx.account_id, target_account_id, target["role"], hash_secret(raw_secret, self.store.pepper), now, now + ENROLLMENT_TTL_S),
            )
            allowed_role = target["role"]
        self.store.audit("enrollment_code_issued", "ok", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, network_zone=ctx.network_zone, extra={"enrollment_id": enr_id, "target_account_id": target_account_id, "allowed_role": allowed_role})
        return {"enrollment_id": enr_id, "secret": raw_secret, "target_account_id": target_account_id, "allowed_role": allowed_role, "expires_at": now + ENROLLMENT_TTL_S}

    def _validate_enrollment_code(self, conn, enrollment_id: str, secret: str, now: float) -> tuple[Any, AuthError | None]:
        row = conn.execute("SELECT * FROM enrollment_codes WHERE enrollment_id = ?", (enrollment_id,)).fetchone()
        if not row or row["state"] != "issued":
            return None, AuthError("enrollment_code_invalid", status_code=401)
        if now > row["expires_at"]:
            conn.execute("UPDATE enrollment_codes SET state = 'expired' WHERE enrollment_id = ?", (enrollment_id,))
            return None, AuthError("enrollment_code_expired", status_code=401)
        if not hmac.compare_digest(row["code_hash"], hash_secret(secret, self.store.pepper)):
            fails = row["failed_attempts"] + 1
            if fails >= ENROLLMENT_MAX_FAILS:
                conn.execute("UPDATE enrollment_codes SET failed_attempts = ?, state = 'revoked', revoked_at = ? WHERE enrollment_id = ?", (fails, now, enrollment_id))
            else:
                conn.execute("UPDATE enrollment_codes SET failed_attempts = ? WHERE enrollment_id = ?", (fails, enrollment_id))
            return None, AuthError("enrollment_code_invalid", status_code=401)
        return row, None

    def register_begin(self, *, enrollment_id: str, secret: str, source_key: str = "unknown") -> dict[str, Any]:
        if not self.rl.allow(f"reg_src:{source_key}", 10, 3600):
            raise AuthError("rate_limited", status_code=429)
        webauthn, _, _, AuthSel, _, UVReq = _require_webauthn()
        now = time.time()
        err: AuthError | None = None
        chal_bytes, chal_id, target_row, allowed_role = b"", "", None, ""
        with self.store.transaction() as conn:
            code, err = self._validate_enrollment_code(conn, enrollment_id, secret, now)
            if err is None:
                allowed_role = code["allowed_role"]
                target_row = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (code["target_account_id"],)).fetchone()
                if not target_row:
                    err = AuthError("target_account_invalid", status_code=401)
                else:
                    chal_bytes, chal_id = secrets.token_bytes(32), f"chal_{secrets.token_hex(12)}"
                    conn.execute(
                        "INSERT INTO challenges (challenge_id, purpose, account_id, challenge_bytes, origin, rp_id, issued_at, expires_at, state) VALUES (?, 'registration', ?, ?, ?, ?, ?, ?, 'issued')",
                        (chal_id, target_row["account_id"], chal_bytes, self.expected_origin, self.rp_id, now, now + REG_CHALLENGE_TTL_S),
                    )
        if err is not None:
            self.store.audit("registration_begin_denied", "denied", reason_code=err.code, extra={"enrollment_id": enrollment_id})
            raise err
        opts = webauthn.generate_registration_options(rp_id=self.rp_id, rp_name=self.rp_name, user_id=target_row["account_id"].encode(), user_name=target_row["display_name"], challenge=chal_bytes, authenticator_selection=AuthSel(user_verification=UVReq.REQUIRED))
        return {"challenge_id": chal_id, "allowed_role": allowed_role, "options": json.loads(webauthn.options_to_json(opts))}

    def submit_registration(
        self, *, enrollment_id: str, secret: str, challenge_id: str, device_name: str,
        requested_role: str, credential_payload: dict[str, Any], hardware_binding: bool = False, source_key: str = "unknown",
    ) -> dict[str, Any]:
        if not isinstance(credential_payload, dict):
            raise AuthError("invalid_payload", status_code=400)
        if not self.rl.allow(f"reg_submit:{source_key}", 10, 3600):
            raise AuthError("rate_limited", status_code=429)
        webauthn, _, bytes_to_b64u, _, _, _ = _require_webauthn()
        now = time.time()
        policy = self.store.get_server_policy()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            code, err = self._validate_enrollment_code(conn, enrollment_id, secret, now)
            if err is None:
                target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (code["target_account_id"],)).fetchone()
                pending_cnt = conn.execute("SELECT COUNT(*) FROM registration_requests WHERE target_account_id = ? AND state = 'pending'", (code["target_account_id"],)).fetchone()[0]
                if not target:
                    err = AuthError("target_account_invalid", status_code=401)
                elif pending_cnt >= MAX_PENDING_REG_PER_ACCOUNT:
                    err = AuthError("too_many_pending_requests", status_code=429)
                elif requested_role != code["allowed_role"] or requested_role != target["role"]:
                    err = AuthError("role_mismatch", status_code=403)
                else:
                    eff = max(policy["min_mode"], target["min_mode"], 2)
                    if not MODE_DEFAULTS[eff]["new_device_access"]:
                        err = AuthError("new_devices_forbidden_in_mode_4", status_code=403)
                    else:
                        chal = conn.execute("SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)).fetchone()
                        if not chal or chal["state"] != "issued" or chal["purpose"] != "registration" or chal["account_id"] != target["account_id"]:
                            err = AuthError("invalid_challenge", status_code=401)
                        elif now > chal["expires_at"]:
                            conn.execute("UPDATE challenges SET state = 'expired' WHERE challenge_id = ?", (challenge_id,))
                            err = AuthError("challenge_expired", status_code=401)
                        else:
                            try:
                                verified = webauthn.verify_registration_response(
                                    credential=credential_payload, expected_challenge=chal["challenge_bytes"],
                                    expected_origin=chal["origin"], expected_rp_id=chal["rp_id"], require_user_verification=True,
                                )
                            except Exception:
                                conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                err = AuthError("verification_failed", status_code=401)
                            else:
                                # CRIT-10: проверка hardware_key_required и запрет hardware_binding для synced passkey
                                hw_flag = bool(hardware_binding and not verified.credential_backed_up)
                                if MODE_DEFAULTS[eff]["hardware_key_required"] and not hw_flag:
                                    conn.execute("UPDATE challenges SET state = 'invalidated', attempt_count = 1 WHERE challenge_id = ?", (challenge_id,))
                                    err = AuthError("hardware_key_required", status_code=403)
            if err is None:
                dev_id, cred_id, req_id = f"dev_{secrets.token_hex(8)}", f"cred_{secrets.token_hex(8)}", f"rreq_{secrets.token_hex(8)}"
                ext_id, fp = bytes_to_b64u(verified.credential_id), key_fingerprint(verified.credential_public_key)
                bstate = "backed_up" if verified.credential_backed_up else "single_device"
                try:
                    conn.execute("UPDATE enrollment_codes SET state = 'consumed', consumed_at = ? WHERE enrollment_id = ? AND state = 'issued'", (now, enrollment_id))
                    conn.execute("UPDATE challenges SET state = 'consumed', attempt_count = 1, consumed_at = ? WHERE challenge_id = ?", (now, challenge_id))
                    conn.execute("INSERT INTO devices (device_id, account_id, display_name, kind, state, attestation_level, hardware_binding, created_at) VALUES (?, ?, ?, 'web_profile', 'pending', ?, ?, ?)", (dev_id, target["account_id"], device_name, "direct" if hw_flag else "none", int(hw_flag), now))
                    conn.execute(
                        "INSERT INTO credentials (credential_id, device_id, account_id, external_credential_id, public_key, algorithm, key_type, key_fingerprint, sign_count, user_verification, attestation_level, backup_state, state, created_at) VALUES (?, ?, ?, ?, ?, 'webauthn', 'passkey', ?, ?, 1, ?, ?, 'pending', ?)",
                        (cred_id, dev_id, target["account_id"], ext_id, verified.credential_public_key, fp, verified.sign_count, "direct" if hw_flag else "none", bstate, now),
                    )
                    conn.execute(
                        "INSERT INTO registration_requests (request_id, enrollment_id, target_account_id, device_id, credential_id, requested_role, key_fingerprint, created_at, expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                        (req_id, enrollment_id, target["account_id"], dev_id, cred_id, requested_role, fp, now, now + REG_REQUEST_TTL_S),
                    )
                    out = {"request_id": req_id, "device_id": dev_id, "state": "pending", "key_fingerprint": fp, "account_id": target["account_id"], "credential_id": cred_id}
                except sqlite3.IntegrityError:
                    # MED-07: дубликат external_credential_id не даёт 500
                    err = AuthError("credential_already_registered", status_code=409)
        if err is not None:
            self.store.audit("registration_submit_denied", "denied", reason_code=err.code, extra={"enrollment_id": enrollment_id})
            raise err
        self.store.audit("registration_request_created", "ok", account_id=out["account_id"], device_id=out["device_id"], credential_id=out["credential_id"], extra={"request_id": out["request_id"], "requested_role": requested_role, "key_fingerprint": out["key_fingerprint"]})
        return {"request_id": out["request_id"], "device_id": out["device_id"], "state": "pending", "key_fingerprint": out["key_fingerprint"]}

    def approve_registration(self, ctx: VerifiedContext, *, request_id: str, second_verification_id: str | None = None) -> dict[str, Any]:
        if ctx.role != "owner":
            raise AuthError("owner_required", status_code=403)
        if not self.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        now = time.time()
        policy = self.store.get_server_policy()
        err: AuthError | None = None
        out: dict[str, Any] = {}
        with self.store.transaction() as conn:
            req = conn.execute("SELECT * FROM registration_requests WHERE request_id = ?", (request_id,)).fetchone()
            if not req or req["state"] != "pending":
                err = AuthError("registration_request_not_pending", status_code=409)
            elif now > req["expires_at"]:
                conn.execute("UPDATE registration_requests SET state = 'expired', resolved_at = ? WHERE request_id = ?", (now, request_id))
                conn.execute("UPDATE devices SET state = 'revoked', revoked_at = ?, revocation_reason = 'expired' WHERE device_id = ?", (now, req["device_id"]))
                conn.execute("UPDATE credentials SET state = 'revoked', revoked_at = ?, revocation_reason = 'expired' WHERE credential_id = ?", (now, req["credential_id"]))
                err = AuthError("registration_request_expired", status_code=410)
            else:
                code = conn.execute("SELECT * FROM enrollment_codes WHERE enrollment_id = ?", (req["enrollment_id"],)).fetchone()
                target = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (req["target_account_id"],)).fetchone()
                actor = conn.execute("SELECT * FROM accounts WHERE account_id = ? AND state = 'active'", (ctx.account_id,)).fetchone()
                cand_dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (req["device_id"],)).fetchone()
                if not target or not actor or not code or not cand_dev or req["requested_role"] != target["role"] or code["allowed_role"] != target["role"]:
                    err = AuthError("role_or_target_changed", status_code=409)
                else:
                    eff = self.compute_effective_mode(policy, actor_min_mode=actor["min_mode"], target_min_mode=target["min_mode"], action_min_mode=2, network_zone=ctx.network_zone)
                    if not MODE_DEFAULTS[eff]["new_device_access"]:
                        err = AuthError("new_devices_forbidden_in_mode_4", status_code=403)
                    elif MODE_DEFAULTS[eff]["hardware_key_required"] and not cand_dev["hardware_binding"]:
                        err = AuthError("hardware_key_required", status_code=403)
                    else:
                        if eff >= 3:
                            self.verify_independent_second_approval_conn(
                                conn, ctx, second_verification_id,
                                consume_op_id=request_id, candidate_device_id=req["device_id"],
                                require_owner=True, effective_mode=eff,
                            )
                        self.consume_primary_verification_mode4_conn(conn, ctx, request_id, effective_mode=eff)
                        conn.execute("UPDATE devices SET state = 'active', activated_at = ? WHERE device_id = ? AND state = 'pending'", (now, req["device_id"]))
                        conn.execute("UPDATE credentials SET state = 'active', activated_at = ? WHERE credential_id = ? AND state = 'pending'", (now, req["credential_id"]))
                        conn.execute(
                            "UPDATE registration_requests SET state = 'approved', approved_by_account_id = ?, approval_verification_id = ?, second_approval_id = ?, resolved_at = ? WHERE request_id = ?",
                            (ctx.account_id, ctx.identity_verification_id, second_verification_id, now, request_id),
                        )
                        out = {"request_id": request_id, "device_id": req["device_id"], "credential_id": req["credential_id"], "target_account_id": req["target_account_id"], "key_fingerprint": req["key_fingerprint"], "state": "active"}
        if err is not None:
            self.store.audit("registration_approve_denied", "denied", reason_code=err.code, account_id=ctx.account_id, extra={"request_id": request_id})
            raise err
        self.store.audit("registration_approved", "ok", account_id=out["target_account_id"], device_id=out["device_id"], credential_id=out["credential_id"], session_id=ctx.session_id, network_zone=ctx.network_zone, extra={"request_id": request_id, "approved_by": ctx.account_id, "key_fingerprint": out["key_fingerprint"]})
        return {"request_id": out["request_id"], "device_id": out["device_id"], "state": "active"}

    # --- P5: Выход и отзыв устройства ---

    def logout(self, ctx: VerifiedContext) -> None:
        now = time.time()
        with self.store.transaction() as conn:
            conn.execute("UPDATE sessions SET state = 'closed', ended_at = ?, end_reason = 'user_logout' WHERE session_id = ? AND state = 'active'", (now, ctx.session_id))
            conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = 'user_logout' WHERE session_id = ? AND state = 'active'", (now, ctx.session_id))
            self.store.record_revocation_event_conn(
                conn, "session_closed", reason="user_logout", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, audience=ctx.audience, occurred_at=now,
            )
        self.store.emit_revocation_signal()
        self.store.audit("session_closed", "ok", reason_code="user_logout", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id, network_zone=ctx.network_zone)

    def logout_by_token(self, session_token: str | None, csrf_token: str | None) -> None:
        """Облегчённый выход (CRIT-09): работает в любом режиме (включая режим 1, режим 3 с программным ключом и вне LAN)."""
        if not session_token:
            raise AuthError("unauthorized", status_code=401)
        if not csrf_token:
            raise AuthError("csrf_failed", status_code=403)
        now = time.time()
        tok_hash = hash_secret(session_token, self.store.pepper)
        csrf_hash = hash_secret(csrf_token, self.store.pepper)
        with self.store.transaction() as conn:
            sess = conn.execute("SELECT * FROM sessions WHERE session_token_hash = ? AND state = 'active'", (tok_hash,)).fetchone()
            if not sess:
                raise AuthError("session_invalid_or_revoked", status_code=401)
            if not hmac.compare_digest(sess["csrf_token_hash"], csrf_hash):
                raise AuthError("csrf_failed", status_code=403)
            conn.execute("UPDATE sessions SET state = 'closed', ended_at = ?, end_reason = 'user_logout' WHERE session_id = ?", (now, sess["session_id"]))
            conn.execute("UPDATE refresh_token_chains SET state = 'revoked', revoked_at = ?, revocation_reason = 'user_logout' WHERE session_id = ? AND state = 'active'", (now, sess["session_id"]))
            self.store.record_revocation_event_conn(
                conn, "session_closed", reason="user_logout", account_id=sess["account_id"], device_id=sess["device_id"], session_id=sess["session_id"], audience=sess["audience"], occurred_at=now,
            )
        self.store.emit_revocation_signal()
        self.store.audit("session_closed", "ok", reason_code="user_logout", account_id=sess["account_id"], device_id=sess["device_id"], session_id=sess["session_id"])

    def revoke_device(self, ctx: VerifiedContext, *, device_id: str, reason: str = "user_revoked") -> None:
        with self.store.readonly() as conn:
            dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not dev:
                raise AuthError("device_not_found", status_code=404)
            if dev["account_id"] != ctx.account_id and ctx.role != "owner":
                raise AuthError("forbidden", status_code=403)
        if device_id != ctx.device_id and not self.is_fresh(ctx):
            raise AuthError("fresh_verification_required", status_code=403)
        self.store.revoke_device_cascade(device_id, reason, initiated_by=ctx.account_id, network_zone=ctx.network_zone)
