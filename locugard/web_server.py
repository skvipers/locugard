"""HTTPS веб-сервер LocuGard (Starlette + WebAuthn + __Host- cookie + CSRF + заголовки безопасности)."""
from __future__ import annotations

import json
from typing import Any

from .auth_permissions import AuthPermissionsBridge
from .auth_service import AuthError, AuthService, extract_client_ip

SESSION_COOKIE = "__Host-locugard_sid"


def create_web_app(auth: AuthService, perm_bridge: AuthPermissionsBridge):
    from starlette.applications import Starlette
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    executed_actions: list[dict[str, Any]] = []

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            resp = await call_next(request)
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
            return resp

    def _peer_ip(req: Request) -> str | None:
        return req.client.host if req.client else None

    def _source_key(req: Request) -> str:
        ip = extract_client_ip(_peer_ip(req), auth.trusted_proxies, req.headers.get("x-forwarded-for"))
        return str(ip) if ip is not None else "unknown"

    def _check_origin(req: Request) -> None:
        if req.headers.get("origin") != auth.expected_origin:
            auth.store.audit("origin_rejected", "denied", reason_code="invalid_origin", extra={"path": req.url.path})
            raise AuthError("invalid_origin", status_code=403)

    async def _json_obj(req: Request, *, allow_empty: bool = False) -> dict[str, Any]:
        raw = await req.body()
        if not raw and allow_empty:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthError("invalid_json", status_code=400)
        if not isinstance(data, dict):
            raise AuthError("invalid_json", status_code=400)
        return data

    def _verify_csrf_audited(session_id: str, req: Request) -> None:
        try:
            auth.verify_csrf(session_id, req.headers.get("x-csrf-token"))
        except AuthError as e:
            auth.store.audit("csrf_rejected", "denied", reason_code=e.code, session_id=session_id, extra={"path": req.url.path})
            raise

    def _err(e: AuthError) -> JSONResponse:
        return JSONResponse({"error": e.code}, status_code=e.status_code)

    async def login_options(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            return JSONResponse(auth.login_begin(source_key=_source_key(req)))
        except AuthError as e:
            return _err(e)

    async def login_verify(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            body = await _json_obj(req)
            cred = body.get("credential")
            if not isinstance(cred, dict):
                raise AuthError("invalid_payload", status_code=400)
            res = auth.login_verify(
                challenge_id=str(body.get("challenge_id", "")),
                credential_payload=cred,
                peer_ip=_peer_ip(req),
                forwarded_for=req.headers.get("x-forwarded-for"),
                old_session_token=req.cookies.get(SESSION_COOKIE),
            )
            resp = JSONResponse({
                "status": "authenticated",
                "account_id": res["account_id"],
                "role": res["role"],
                "device_id": res["device_id"],
                "csrf_token": res["csrf_token"],
            })
            resp.set_cookie(
                SESSION_COOKIE, res["session_token"],
                httponly=True, secure=True, samesite="lax", max_age=res["max_age_s"], path="/",
            )
            return resp
        except AuthError as e:
            return _err(e)

    async def reauth_options(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            return JSONResponse(auth.reauth_begin(ctx))
        except AuthError as e:
            return _err(e)

    async def reauth_verify(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req)
            cred = body.get("credential")
            if not isinstance(cred, dict):
                raise AuthError("invalid_payload", status_code=400)
            return JSONResponse(auth.reauth_verify(
                ctx, challenge_id=str(body.get("challenge_id", "")), credential_payload=cred,
                purpose=str(body.get("purpose", "reauth")), target_digest=body.get("target_digest"),
            ))
        except AuthError as e:
            return _err(e)

    async def logout(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            # CRIT-09: облегчённый выход без блокировки в режиме 1/3 или вне LAN
            auth.logout_by_token(req.cookies.get(SESSION_COOKIE), req.headers.get("x-csrf-token"))
            resp = JSONResponse({"status": "logged_out"})
            resp.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
            return resp
        except AuthError as e:
            return _err(e)

    async def create_enrollment(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req, allow_empty=True)
            return JSONResponse(auth.create_enrollment_code(ctx, target_account_id=str(body.get("target_account_id") or ctx.account_id)))
        except AuthError as e:
            return _err(e)

    async def register_options(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            body = await _json_obj(req)
            return JSONResponse(auth.register_begin(enrollment_id=str(body.get("enrollment_id", "")), secret=str(body.get("secret", "")), source_key=_source_key(req)))
        except AuthError as e:
            return _err(e)

    async def register_submit(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            body = await _json_obj(req)
            cred = body.get("credential")
            if not isinstance(cred, dict):
                raise AuthError("invalid_payload", status_code=400)
            return JSONResponse(auth.submit_registration(
                enrollment_id=str(body.get("enrollment_id", "")),
                secret=str(body.get("secret", "")),
                challenge_id=str(body.get("challenge_id", "")),
                device_name=str(body.get("device_name", "New Device")),
                requested_role=str(body.get("requested_role", "")),
                credential_payload=cred,
                source_key=_source_key(req),
            ))
        except AuthError as e:
            return _err(e)

    async def approve_registration(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req, allow_empty=True)
            return JSONResponse(auth.approve_registration(
                ctx, request_id=req.path_params["request_id"],
                second_verification_id=body.get("second_verification_id"),
            ))
        except AuthError as e:
            return _err(e)

    async def revoke_device(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            auth.revoke_device(ctx, device_id=req.path_params["device_id"])
            return JSONResponse({"status": "revoked", "device_id": req.path_params["device_id"]})
        except AuthError as e:
            return _err(e)

    async def protected_profile(req: Request) -> JSONResponse:
        try:
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"), action_min_mode=1)
            acc = auth.store.get_account(ctx.account_id)
            return JSONResponse({
                "account_id": ctx.account_id,
                "display_name": acc["display_name"] if acc else "",
                "role": ctx.role,
                "device_id": ctx.device_id,
                "network_zone": ctx.network_zone,
                "effective_mode": ctx.effective_mode,
            })
        except AuthError as e:
            return _err(e)

    async def dangerous_action_request(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req)
            target = str(body.get("target", ""))
            note = str(body.get("note", ""))

            def _do_run() -> str:
                executed_actions.append({"account_id": ctx.account_id, "target": target, "note": note})
                return f"executed:{target}"

            # CRIT-04: critical НЕ читается из клиентского JSON — определяется строго серверным каталогом!
            res = perm_bridge.request_dangerous_action(
                ctx,
                action_type="web.protected_dangerous_action",
                description=f"Выполнить опасное действие для цели '{target}'",
                resource_scope=f"personal:{ctx.account_id}",
                payload={"target": target, "note": note},
                run=_do_run,
                second_verification_id=body.get("second_verification_id"),
            )
            return JSONResponse(res)
        except AuthError as e:
            return _err(e)

    async def dangerous_action_confirm(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req)
            # LOW-03: передаём уже проверенный свежий ctx (без двойной пишущей транзакции verify_session)
            res = perm_bridge.confirm_and_execute(
                session_token=req.cookies.get(SESSION_COOKIE),
                peer_ip=_peer_ip(req),
                forwarded_for=req.headers.get("x-forwarded-for"),
                approval_id=str(body.get("approval_id", "")),
                expected_digest=str(body.get("action_digest", "")),
                verified_ctx=ctx,
            )
            return JSONResponse(res)
        except AuthError as e:
            return _err(e)

    app = Starlette(
        routes=[
            Route("/auth/login/options", login_options, methods=["POST"]),
            Route("/auth/login/verify", login_verify, methods=["POST"]),
            Route("/auth/reauth/options", reauth_options, methods=["POST"]),
            Route("/auth/reauth/verify", reauth_verify, methods=["POST"]),
            Route("/auth/logout", logout, methods=["POST"]),
            Route("/api/devices/enrollment-codes", create_enrollment, methods=["POST"]),
            Route("/auth/register/options", register_options, methods=["POST"]),
            Route("/auth/register/submit", register_submit, methods=["POST"]),
            Route("/api/devices/registrations/{request_id}/approve", approve_registration, methods=["POST"]),
            Route("/api/devices/{device_id}/revoke", revoke_device, methods=["POST"]),
            Route("/api/protected/profile", protected_profile, methods=["GET"]),
            Route("/api/protected/dangerous-action/request", dangerous_action_request, methods=["POST"]),
            Route("/api/protected/dangerous-action/confirm", dangerous_action_confirm, methods=["POST"]),
        ]
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.executed_actions = executed_actions
    return app
