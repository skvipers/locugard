"""Мост между проверенным контекстом (ActionApproval) и Permissions (P9, усилено по L4-аудиту)."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Callable

from .auth_store import AuthStore
from .permissions_adapter import Action, Level, Outcome, Risk

APPROVAL_TTL_S = 120
MAX_PENDING_APPROVALS_PER_SESSION = 10

# Серверный каталог опасных действий (CRIT-04): класс критичности задаётся ТОЛЬКО сервером!
SERVER_ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "web.protected_dangerous_action": {"critical": True, "allowed_roles": ("owner", "member")},
    "web.protected_standard_r3": {"critical": False, "allowed_roles": ("owner", "member")},
    "web.demo": {"critical": False, "allowed_roles": ("owner", "member")},
}


def compute_action_digest(action_type: str, resource_scope: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"action_type": action_type, "resource_scope": resource_scope, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuthPermissionsBridge:
    def __init__(self, store: AuthStore, auth: Any, permissions: Any):
        self.store = store
        self.auth = auth
        self.permissions = permissions

    def request_dangerous_action(
        self,
        ctx: Any,
        *,
        action_type: str,
        description: str,
        resource_scope: str,
        payload: dict[str, Any],
        run: Callable[[], str],
        second_verification_id: str | None = None,
        critical: bool | None = None,
    ) -> dict[str, Any]:
        from .auth_service import AuthError

        # CRIT-07: роль readonly никогда не может запрашивать изменяющие/опасные действия
        if ctx.role == "readonly":
            self.store.audit("action_request_denied", "denied", reason_code="readonly_forbidden", account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id)
            raise AuthError("readonly_forbidden", status_code=403)

        # CRIT-04: серверный каталог (fail-closed: неклассифицированное действие -> critical=True и только owner)
        spec = SERVER_ACTION_CATALOG.get(action_type)
        if spec is None:
            is_critical = True if critical is None else True
            allowed_roles = ("owner",)
        else:
            is_critical = bool(spec["critical"]) if critical is None else bool(spec["critical"] or critical)
            allowed_roles = spec["allowed_roles"]

        if ctx.role not in allowed_roles:
            raise AuthError("role_insufficient", status_code=403)
        if not self.auth.is_fresh(ctx):
            self.store.audit(
                "action_request_denied", "denied", reason_code="fresh_verification_required",
                account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id,
                network_zone=ctx.network_zone, policy_version=ctx.policy_version,
            )
            raise AuthError("fresh_verification_required", status_code=403)
        if resource_scope not in ctx.granted_scopes and ctx.role != "owner":
            raise AuthError("scope_forbidden", status_code=403)
        if not self.auth.rl.allow(f"appr_req:{ctx.session_id}", 5, 60):
            raise AuthError("rate_limited", status_code=429)

        digest = compute_action_digest(action_type, resource_scope, payload)
        approval_id = f"appr_{secrets.token_hex(8)}"
        now = time.time()
        expires_at = now + APPROVAL_TTL_S

        # LOW-05: сначала проверяем лимит pending и атомарно фиксируем верификации в БД, затем submit в Permissions
        outcome: Outcome | None = None
        try:
            with self.store.transaction() as conn:
                pending_cnt = conn.execute(
                    "SELECT COUNT(*) FROM action_approvals WHERE session_id = ? AND state = 'pending'",
                    (ctx.session_id,),
                ).fetchone()[0]
                if pending_cnt >= MAX_PENDING_APPROVALS_PER_SESSION:
                    raise AuthError("too_many_pending_approvals", status_code=429)
                if ctx.effective_mode >= 3 and is_critical:
                    self.auth.verify_independent_second_approval_conn(
                        conn, ctx, second_verification_id, consume_op_id=approval_id, require_owner=(ctx.role == "owner"),
                    )
                self.auth.consume_primary_verification_mode4_conn(conn, ctx, approval_id)

                action = Action(
                    name=action_type, level=Level.ASK, description=description,
                    run=run, external=True, risk=Risk.HIGH, fingerprint=digest[:16],
                )
                outcome = self.permissions.submit(action)
                if outcome.status != "pending" or outcome.pending_id is None:
                    raise AuthError(f"permissions_rejected:{outcome.status}", status_code=403)

                conn.execute(
                    """
                    INSERT INTO action_approvals (
                        approval_id, account_id, channel, session_id, device_id,
                        action_type, action_digest, exact_description, resource_scope,
                        policy_version, identity_verification_id, second_verification_id, permissions_pid,
                        expires_at, state
                    ) VALUES (?, ?, 'web', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                    """,
                    (
                        approval_id, ctx.account_id, ctx.session_id, ctx.device_id,
                        action_type, digest, description, resource_scope, ctx.policy_version,
                        ctx.identity_verification_id, second_verification_id, str(outcome.pending_id), expires_at,
                    ),
                )
        except Exception:
            if outcome is not None and outcome.pending_id is not None:
                self.permissions.reject(outcome.pending_id)
            raise

        self.store.audit(
            "action_approval_created", "ok",
            account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id,
            network_zone=ctx.network_zone, policy_version=ctx.policy_version,
            extra={"approval_id": approval_id, "action_type": action_type, "action_digest": digest, "critical": is_critical},
        )
        return {
            "approval_id": approval_id,
            "action_type": action_type,
            "action_digest": digest,
            "description": description,
            "expires_at": expires_at,
            "state": "pending",
        }

    def confirm_and_execute(
        self,
        *,
        session_token: str | None,
        peer_ip: str | None,
        approval_id: str,
        expected_digest: str,
        forwarded_for: str | None = None,
        verified_ctx: Any = None,
    ) -> dict[str, Any]:
        """Шаг 5–6 P9: полная повторная проверка контекста, прав и action_digest; коммит отказов до raise (CRIT-01)."""
        from .auth_service import AuthError

        ctx = verified_ctx if verified_ctx is not None else self.auth.verify_session(
            session_token, peer_ip=peer_ip, forwarded_for=forwarded_for, action_min_mode=2,
        )
        if ctx.role == "readonly":
            raise AuthError("readonly_forbidden", status_code=403)

        now = time.time()
        pid: int | None = None
        reject_pid: int | None = None
        err: AuthError | None = None

        with self.store.transaction() as conn:
            appr = conn.execute("SELECT * FROM action_approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            if not appr:
                err = AuthError("approval_not_found", status_code=404)
            elif appr["state"] != "pending":
                err = AuthError(f"approval_{appr['state']}", status_code=409)
            elif now > appr["expires_at"]:
                conn.execute("UPDATE action_approvals SET state = 'expired', resolution_reason = 'ttl_expired' WHERE approval_id = ?", (approval_id,))
                reject_pid = int(appr["permissions_pid"]) if appr["permissions_pid"] is not None else None
                err = AuthError("approval_expired", status_code=410)
            elif appr["account_id"] != ctx.account_id or appr["session_id"] != ctx.session_id or appr["device_id"] != ctx.device_id:
                err = AuthError("approval_context_mismatch", status_code=403)
            elif appr["action_digest"] != expected_digest:
                err = AuthError("action_digest_mismatch", status_code=409)
            elif appr["policy_version"] != ctx.policy_version:
                conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = 'policy_changed' WHERE approval_id = ?", (approval_id,))
                reject_pid = int(appr["permissions_pid"]) if appr["permissions_pid"] is not None else None
                err = AuthError("policy_changed", status_code=409)
            elif appr["resource_scope"] not in ctx.granted_scopes and ctx.role != "owner":
                conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = 'scope_revoked' WHERE approval_id = ?", (approval_id,))
                reject_pid = int(appr["permissions_pid"]) if appr["permissions_pid"] is not None else None
                err = AuthError("scope_forbidden", status_code=403)
            else:
                ver = conn.execute("SELECT * FROM identity_verifications WHERE verification_id = ?", (appr["identity_verification_id"],)).fetchone()
                if not ver or not self.auth.is_fresh(ctx):
                    err = AuthError("fresh_verification_required", status_code=403)
                else:
                    if appr["second_verification_id"]:
                        try:
                            self.auth.verify_verification_active_conn(conn, appr["second_verification_id"], require_owner=(ctx.role == "owner"))
                        except AuthError as e:
                            conn.execute("UPDATE action_approvals SET state = 'revoked', resolution_reason = ? WHERE approval_id = ?", (e.code, approval_id))
                            reject_pid = int(appr["permissions_pid"]) if appr["permissions_pid"] is not None else None
                            err = e
            if err is None:
                pid = int(appr["permissions_pid"]) if appr["permissions_pid"] is not None else None
                conn.execute(
                    "UPDATE action_approvals SET state = 'executed', approved_at = ?, executed_at = ? WHERE approval_id = ? AND state = 'pending'",
                    (now, now, approval_id),
                )

        if err is not None:
            if reject_pid is not None:
                self.permissions.reject(reject_pid)
            self.store.audit(
                "action_execution_denied", "denied", reason_code=err.code,
                account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id,
                network_zone=ctx.network_zone, extra={"approval_id": approval_id},
            )
            raise err

        assert pid is not None
        outcome = self.permissions.confirm(pid, always=False)
        self.store.audit(
            "action_executed", "ok" if outcome.status in ("done", "reported") else "failed",
            account_id=ctx.account_id, device_id=ctx.device_id, session_id=ctx.session_id,
            network_zone=ctx.network_zone, policy_version=ctx.policy_version,
            extra={"approval_id": approval_id, "action_digest": expected_digest, "outcome_status": outcome.status},
        )
        return {"approval_id": approval_id, "status": outcome.status, "result": outcome.text}
