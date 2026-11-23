"""SQLite-хранилище и аудит-журнал подсистемы аутентификации (чистая стандартная библиотека).

Полная схема сущностей этапов 2–4: Account, ExternalIdentity, Device, Credential, Session,
Challenge, EnrollmentCode, RegistrationRequest, RecoveryCode, RecoveryRequest,
RefreshTokenChain + RefreshTokenHistory, IdentityVerification, ActionApproval,
TelegramLinkRequest, TelegramCallback, ServerPolicy.
Сырые секреты в БД и журнале не хранятся — только HMAC-SHA256 и безопасные отпечатки.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

SCHEMA_VERSION = 3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS server_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    min_mode INTEGER NOT NULL DEFAULT 2,
    session_ttl_s INTEGER NOT NULL DEFAULT 604800,
    idle_ttl_s INTEGER NOT NULL DEFAULT 43200,
    freshness_ttl_s INTEGER NOT NULL DEFAULT 600,
    allowed_networks_json TEXT NOT NULL DEFAULT '["127.0.0.0/8"]',
    outside_lan_behavior TEXT NOT NULL DEFAULT 'upgrade_to_2',
    telegram_approval_enabled INTEGER NOT NULL DEFAULT 0,
    policy_version INTEGER NOT NULL DEFAULT 1,
    updated_at REAL NOT NULL,
    updated_by_account_id TEXT
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member', 'guest', 'readonly')),
    state TEXT NOT NULL CHECK (state IN ('active', 'suspended')),
    min_mode INTEGER NOT NULL DEFAULT 2,
    policy_version INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS external_identities (
    identity_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    verified_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    bound_at REAL NOT NULL,
    revoked_at REAL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ext_identity_active_unique
    ON external_identities(provider, provider_subject)
    WHERE state = 'active';

CREATE TABLE IF NOT EXISTS telegram_link_requests (
    link_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    session_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    telegram_subject TEXT,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'received', 'confirmed', 'expired', 'cancelled'))
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked')),
    attestation_level TEXT NOT NULL DEFAULT 'none',
    hardware_binding INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    activated_at REAL,
    last_used_at REAL,
    revoked_at REAL,
    revocation_reason TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    external_credential_id TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    algorithm TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    user_verification INTEGER NOT NULL DEFAULT 1,
    attestation_level TEXT NOT NULL DEFAULT 'none',
    backup_state TEXT NOT NULL DEFAULT 'unknown',
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked')),
    created_at REAL NOT NULL,
    activated_at REAL,
    last_used_at REAL,
    revoked_at REAL,
    revocation_reason TEXT
);

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    account_id TEXT,
    device_id TEXT,
    credential_id TEXT,
    registration_request_id TEXT,
    recovery_request_id TEXT,
    challenge_bytes BLOB NOT NULL,
    origin TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count <= 1),
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired', 'invalidated')),
    consumed_at REAL
);

CREATE TABLE IF NOT EXISTS identity_verifications (
    verification_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    channel TEXT NOT NULL CHECK (channel IN ('web', 'app', 'telegram', 'local_console')),
    device_id TEXT REFERENCES devices(device_id),
    credential_id TEXT REFERENCES credentials(credential_id),
    session_id TEXT,
    external_identity_id TEXT REFERENCES external_identities(identity_id),
    method TEXT NOT NULL,
    challenge_id TEXT,
    verified_at REAL NOT NULL,
    assurance_level INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    target_digest TEXT,
    consumed_by_approval_id TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    session_token_hash TEXT NOT NULL UNIQUE,
    csrf_token_hash TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
    auth_method TEXT NOT NULL,
    authenticated_at REAL NOT NULL,
    identity_verification_id TEXT NOT NULL REFERENCES identity_verifications(verification_id),
    created_at REAL NOT NULL,
    last_activity_at REAL NOT NULL,
    absolute_expires_at REAL NOT NULL,
    idle_expires_at REAL NOT NULL,
    access_token_expires_at REAL,
    network_zone_at_login TEXT NOT NULL,
    mode_at_login INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'closed', 'expired', 'revoked')),
    ended_at REAL,
    end_reason TEXT
);

CREATE TABLE IF NOT EXISTS refresh_token_chains (
    chain_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE REFERENCES sessions(session_id),
    generation INTEGER NOT NULL DEFAULT 1,
    current_token_hash TEXT NOT NULL UNIQUE,
    rotated_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    revoked_at REAL,
    revocation_reason TEXT,
    reuse_detected_at REAL
);

CREATE TABLE IF NOT EXISTS refresh_token_history (
    chain_id TEXT NOT NULL REFERENCES refresh_token_chains(chain_id),
    generation INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    rotated_at REAL NOT NULL,
    PRIMARY KEY (chain_id, generation)
);

CREATE TABLE IF NOT EXISTS enrollment_codes (
    enrollment_id TEXT PRIMARY KEY,
    created_by_account_id TEXT NOT NULL REFERENCES accounts(account_id),
    target_account_id TEXT NOT NULL REFERENCES accounts(account_id),
    allowed_role TEXT NOT NULL CHECK (allowed_role IN ('owner', 'member', 'guest', 'readonly')),
    code_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired', 'revoked')),
    consumed_at REAL,
    revoked_at REAL
);

CREATE TABLE IF NOT EXISTS registration_requests (
    request_id TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL UNIQUE REFERENCES enrollment_codes(enrollment_id),
    target_account_id TEXT NOT NULL REFERENCES accounts(account_id),
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
    requested_role TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    approved_by_account_id TEXT REFERENCES accounts(account_id),
    approval_verification_id TEXT REFERENCES identity_verifications(verification_id),
    second_approval_id TEXT REFERENCES identity_verifications(verification_id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'cancelled')),
    resolved_at REAL,
    resolution_reason TEXT
);

CREATE TABLE IF NOT EXISTS telegram_callbacks (
    callback_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES registration_requests(request_id),
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    external_identity_id TEXT NOT NULL REFERENCES external_identities(identity_id),
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired', 'revoked')),
    consumed_at REAL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    recovery_code_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    set_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    generated_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'used', 'revoked')),
    used_at REAL,
    revoked_at REAL
);

CREATE TABLE IF NOT EXISTS recovery_requests (
    recovery_request_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    basis TEXT NOT NULL CHECK (basis IN ('recovery_code', 'local_console')),
    recovery_code_id TEXT REFERENCES recovery_codes(recovery_code_id),
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
    key_fingerprint TEXT NOT NULL,
    challenge_id TEXT,
    revocation_scope TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    second_verification_id TEXT REFERENCES identity_verifications(verification_id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed', 'rejected', 'expired', 'cancelled')),
    resolved_at REAL,
    resolution_reason TEXT
);

CREATE TABLE IF NOT EXISTS action_approvals (
    approval_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(account_id),
    channel TEXT NOT NULL CHECK (channel IN ('web', 'app', 'telegram', 'local_console')),
    session_id TEXT REFERENCES sessions(session_id),
    device_id TEXT REFERENCES devices(device_id),
    action_type TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    exact_description TEXT NOT NULL,
    resource_scope TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    identity_verification_id TEXT NOT NULL REFERENCES identity_verifications(verification_id),
    second_verification_id TEXT REFERENCES identity_verifications(verification_id),
    permissions_pid TEXT,
    approved_at REAL,
    expires_at REAL NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'executed', 'rejected', 'expired', 'revoked')),
    executed_at REAL,
    resolution_reason TEXT
);
"""


def hash_secret(secret: str, pepper: bytes) -> str:
    return hmac.new(pepper, secret.encode("utf-8"), hashlib.sha256).hexdigest()


def key_fingerprint(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).hexdigest()[:32]
    return ":".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def load_or_create_pepper(data_dir: Path, *, pepper_path: Path | None = None, allow_create: bool = True) -> bytes:
    """Загружает постоянный 256-битный pepper из LOCUGARD_AUTH_PEPPER или файла секретов."""
    env_val = os.environ.get("LOCUGARD_AUTH_PEPPER", "").strip()
    if env_val:
        raw = bytes.fromhex(env_val) if len(env_val) == 64 else env_val.encode("utf-8")
        if len(raw) < 32:
            raise ValueError("LOCUGARD_AUTH_PEPPER должен содержать не менее 32 байт")
        return raw
    p = pepper_path or (Path(data_dir).resolve().parent / "secrets" / "auth_pepper.key")
    if p.exists():
        raw = bytes.fromhex(p.read_text(encoding="utf-8").strip())
        if len(raw) < 32:
            raise ValueError(f"Повреждённый pepper в {p}")
        return raw
    if not allow_create:
        raise RuntimeError(f"Постоянный pepper не найден ({p} или LOCUGARD_AUTH_PEPPER); запуск отклонён (fail-closed)")
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    p.write_text(raw.hex() + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return raw


class AuthStore:
    """Атомарное SQLite-хранилище подсистемы аутентификации, аудит и уведомления."""

    def __init__(
        self,
        data_dir: Path,
        pepper: bytes | None = None,
        on_notify: Callable[[str, list[str], dict[str, Any]], None] | None = None,
        *,
        pepper_path: Path | None = None,
        allow_create_pepper: bool = True,
    ):
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "state" / "auth.sqlite3"
        self.audit_path = self.data_dir / "logs" / "auth_audit.jsonl"
        self.pepper = pepper if pepper is not None else load_or_create_pepper(
            self.data_dir, pepper_path=pepper_path, allow_create=allow_create_pepper
        )
        if len(self.pepper) < 32:
            raise ValueError("pepper должен быть не короче 32 байт")
        self.on_notify = on_notify
        self._audit_lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    @contextmanager
    def readonly(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_SQL)
        finally:
            conn.close()
        with self.transaction() as conn:
            ver = conn.execute("PRAGMA user_version").fetchone()[0]
            if ver < SCHEMA_VERSION:
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            now = time.time()
            conn.execute("INSERT OR IGNORE INTO server_policy (id, updated_at) VALUES (1, ?)", (now,))

    def audit(
        self,
        event_type: str,
        outcome: str,
        *,
        reason_code: str = "",
        account_id: str | None = None,
        device_id: str | None = None,
        credential_id: str | None = None,
        session_id: str | None = None,
        network_zone: str = "unknown",
        policy_version: int | None = None,
        correlation_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        rec: dict[str, Any] = {
            "event_id": f"evt_{secrets.token_hex(8)}",
            "event_type": event_type,
            "occurred_at": round(time.time(), 3),
            "correlation_id": correlation_id or f"cor_{secrets.token_hex(6)}",
            "outcome": outcome,
            "reason_code": reason_code,
            "account_id": account_id,
            "device_id": device_id,
            "credential_id": credential_id,
            "session_id": session_id,
            "network_zone": network_zone,
            "policy_version": policy_version,
        }
        if extra:
            rec["meta"] = extra
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with self._audit_lock:
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(line)

    def notify(self, event_type: str, recipients: list[str], payload: dict[str, Any]) -> None:
        if self.on_notify is None:
            return
        try:
            self.on_notify(event_type, recipients, payload)
        except Exception as e:
            self.audit(
                "notification_delivery_failed",
                "failed",
                reason_code=type(e).__name__,
                extra={"original_event": event_type, "recipients_count": len(recipients)},
            )

    def has_active_owner_with_key(self) -> bool:
        with self.readonly() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM accounts a
                JOIN devices d ON d.account_id = a.account_id AND d.state = 'active'
                JOIN credentials c ON c.device_id = d.device_id AND c.state = 'active'
                WHERE a.role = 'owner' AND a.state = 'active'
                LIMIT 1
                """
            ).fetchone()
            return row is not None

    def count_active_owners(self, conn: sqlite3.Connection | None = None, *, require_active_key: bool = True) -> int:
        sql = (
            """
            SELECT COUNT(DISTINCT a.account_id)
            FROM accounts a
            JOIN devices d ON d.account_id = a.account_id AND d.state = 'active'
            JOIN credentials c ON c.device_id = d.device_id AND c.state = 'active'
            WHERE a.role = 'owner' AND a.state = 'active'
            """
            if require_active_key
            else "SELECT COUNT(*) FROM accounts WHERE role = 'owner' AND state = 'active'"
        )
        if conn is not None:
            return int(conn.execute(sql).fetchone()[0])
        with self.readonly() as c:
            return int(c.execute(sql).fetchone()[0])

    def get_server_policy(self) -> dict[str, Any]:
        with self.readonly() as conn:
            row = conn.execute("SELECT * FROM server_policy WHERE id = 1").fetchone()
            out = dict(row)
            out["allowed_networks"] = json.loads(out.pop("allowed_networks_json"))
            out["telegram_approval_enabled"] = bool(out["telegram_approval_enabled"])
            return out

    def update_server_policy(
        self,
        *,
        min_mode: int | None = None,
        allowed_networks: list[str] | None = None,
        outside_lan_behavior: str | None = None,
        telegram_approval_enabled: bool | None = None,
        session_ttl_s: int | None = None,
        idle_ttl_s: int | None = None,
        freshness_ttl_s: int | None = None,
        updated_by_account_id: str | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as conn:
            cur = dict(conn.execute("SELECT * FROM server_policy WHERE id = 1").fetchone())
            new_ver = cur["policy_version"] + 1
            conn.execute(
                """
                UPDATE server_policy
                SET min_mode = ?,
                    allowed_networks_json = ?,
                    outside_lan_behavior = ?,
                    telegram_approval_enabled = ?,
                    session_ttl_s = ?,
                    idle_ttl_s = ?,
                    freshness_ttl_s = ?,
                    policy_version = ?,
                    updated_at = ?,
                    updated_by_account_id = ?
                WHERE id = 1
                """,
                (
                    min_mode if min_mode is not None else cur["min_mode"],
                    json.dumps(allowed_networks) if allowed_networks is not None else cur["allowed_networks_json"],
                    outside_lan_behavior if outside_lan_behavior is not None else cur["outside_lan_behavior"],
                    int(telegram_approval_enabled) if telegram_approval_enabled is not None else cur["telegram_approval_enabled"],
                    session_ttl_s if session_ttl_s is not None else cur["session_ttl_s"],
                    idle_ttl_s if idle_ttl_s is not None else cur["idle_ttl_s"],
                    freshness_ttl_s if freshness_ttl_s is not None else cur["freshness_ttl_s"],
                    new_ver,
                    time.time(),
                    updated_by_account_id,
                ),
            )
        return self.get_server_policy()

    def create_account(self, display_name: str, role: str, *, min_mode: int = 2) -> dict[str, Any]:
        acc_id = f"acc_{secrets.token_hex(8)}"
        now = time.time()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO accounts (account_id, display_name, role, state, min_mode, policy_version, created_at, updated_at)
                VALUES (?, ?, ?, 'active', ?, 1, ?, ?)
                """,
                (acc_id, display_name, role, min_mode, now, now),
            )
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (acc_id,)).fetchone()
            return dict(row)

    def get_account(self, account_id: str) -> dict[str, Any] | None:
        with self.readonly() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
            return dict(row) if row else None

    def list_devices(self, account_id: str | None = None) -> list[dict[str, Any]]:
        with self.readonly() as conn:
            if account_id:
                rows = conn.execute(
                    "SELECT * FROM devices WHERE account_id = ? ORDER BY created_at DESC",
                    (account_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM devices ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def revoke_all_account_sessions(self, account_id: str, reason: str, *, initiated_by: str | None = None) -> int:
        now = time.time()
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = ? WHERE account_id = ? AND state = 'active'",
                (now, reason, account_id),
            )
            conn.execute(
                """
                UPDATE refresh_token_chains
                SET state = 'revoked', revoked_at = ?, revocation_reason = ?
                WHERE state = 'active' AND session_id IN (SELECT session_id FROM sessions WHERE account_id = ?)
                """,
                (now, reason, account_id),
            )
            count = cur.rowcount
        self.audit("account_sessions_revoked", "ok", reason_code=reason, account_id=account_id, extra={"count": count, "initiated_by": initiated_by})
        self.notify("sessions_revoked", [account_id], {"account_id": account_id, "reason": reason, "count": count})
        return count

    def revoke_device_cascade(
        self,
        device_id: str,
        reason: str,
        *,
        initiated_by: str | None = None,
        network_zone: str = "unknown",
    ) -> bool:
        now = time.time()
        with self.transaction() as conn:
            dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not dev:
                return False
            account_id = dev["account_id"]
            conn.execute(
                "UPDATE devices SET state = 'revoked', revoked_at = ?, revocation_reason = ? WHERE device_id = ?",
                (now, reason, device_id),
            )
            conn.execute(
                "UPDATE credentials SET state = 'revoked', revoked_at = ?, revocation_reason = ? WHERE device_id = ? AND state != 'revoked'",
                (now, reason, device_id),
            )
            conn.execute(
                "UPDATE sessions SET state = 'revoked', ended_at = ?, end_reason = ? WHERE device_id = ? AND state = 'active'",
                (now, reason, device_id),
            )
            conn.execute(
                """
                UPDATE refresh_token_chains
                SET state = 'revoked', revoked_at = ?, revocation_reason = ?
                WHERE state = 'active' AND session_id IN (SELECT session_id FROM sessions WHERE device_id = ?)
                """,
                (now, reason, device_id),
            )
            conn.execute(
                """
                UPDATE action_approvals
                SET state = 'revoked', resolution_reason = ?
                WHERE state IN ('pending', 'approved')
                  AND (
                    device_id = ?
                    OR identity_verification_id IN (SELECT verification_id FROM identity_verifications WHERE device_id = ?)
                    OR second_verification_id IN (SELECT verification_id FROM identity_verifications WHERE device_id = ?)
                  )
                """,
                (reason, device_id, device_id, device_id),
            )
            conn.execute(
                """
                UPDATE registration_requests
                SET state = 'cancelled', resolved_at = ?, resolution_reason = ?
                WHERE state = 'pending'
                  AND (
                    device_id = ?
                    OR approval_verification_id IN (SELECT verification_id FROM identity_verifications WHERE device_id = ?)
                    OR second_approval_id IN (SELECT verification_id FROM identity_verifications WHERE device_id = ?)
                  )
                """,
                (now, reason, device_id, device_id, device_id),
            )
            conn.execute(
                """
                UPDATE recovery_requests
                SET state = 'cancelled', resolved_at = ?, resolution_reason = ?
                WHERE state = 'pending'
                  AND (
                    device_id = ?
                    OR second_verification_id IN (SELECT verification_id FROM identity_verifications WHERE device_id = ?)
                  )
                """,
                (now, reason, device_id, device_id),
            )
        self.audit(
            "device_revoked",
            "ok",
            reason_code=reason,
            account_id=account_id,
            device_id=device_id,
            network_zone=network_zone,
            extra={"initiated_by": initiated_by},
        )
        self.notify("device_revoked", [account_id], {"account_id": account_id, "device_id": device_id, "reason": reason})
        return True

    def revoke_external_identity_cascade(self, identity_id: str, reason: str, *, initiated_by: str | None = None) -> bool:
        now = time.time()
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM external_identities WHERE identity_id = ?", (identity_id,)).fetchone()
            if not row:
                return False
            acc_id = row["account_id"]
            conn.execute(
                "UPDATE external_identities SET state = 'revoked', revoked_at = ? WHERE identity_id = ?",
                (now, identity_id),
            )
            conn.execute(
                "UPDATE telegram_callbacks SET state = 'revoked' WHERE external_identity_id = ? AND state = 'issued'",
                (identity_id,),
            )
            conn.execute(
                """
                UPDATE action_approvals
                SET state = 'revoked', resolution_reason = ?
                WHERE state IN ('pending', 'approved')
                  AND identity_verification_id IN (SELECT verification_id FROM identity_verifications WHERE external_identity_id = ?)
                """,
                (reason, identity_id),
            )
        self.audit("external_identity_revoked", "ok", reason_code=reason, account_id=acc_id, extra={"identity_id": identity_id, "initiated_by": initiated_by})
        return True
