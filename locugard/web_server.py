"""HTTPS веб-сервер LocuGard (Starlette + WebAuthn + __Host- cookie + CSRF + нативный и сервисный API + опциональный UI)."""
from __future__ import annotations

import base64
import hmac
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .auth_channels import AuthChannels
from .auth_permissions import AuthPermissionsBridge
from .auth_service import AuthError, AuthService, extract_client_ip
from .web_flows_ui import render_pair_ui, render_sso_ui
from .web_ui import render_bootstrap_ui, render_enroll_ui, render_web_ui, resolve_ui_lang

SESSION_COOKIE = "__Host-locugard_sid"
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"
_ASSET_MIME: dict[str, str] = {
    "favicon.svg": "image/svg+xml",
    "logo.svg": "image/svg+xml",
    "favicon.ico": "image/x-icon",
    "favicon-16.png": "image/png",
    "favicon-32.png": "image/png",
    "favicon-48.png": "image/png",
    "favicon-192.png": "image/png",
    "favicon-512.png": "image/png",
    "apple-touch-icon.png": "image/png",
    "logo.png": "image/png",
}


def _decode_b64_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise AuthError("invalid_payload", status_code=400)
    s = value.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        try:
            return base64.b64decode(s + pad)
        except Exception:
            raise AuthError("invalid_payload", status_code=400)


def _extract_bearer(req: Any) -> str | None:
    raw = req.headers.get("authorization", "").strip()
    if not raw.lower().startswith("bearer "):
        return None
    tok = raw[7:].strip()
    return tok or None


def _normalize_service_tokens(service_tokens: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not service_tokens:
        return out
    for svc_id, cfg in service_tokens.items():
        if isinstance(cfg, str) and cfg:
            out[svc_id] = {"token": cfg, "audiences": {svc_id}, "redirect_uris": set(), "display_name": svc_id}
        elif isinstance(cfg, dict) and isinstance(cfg.get("token"), str) and cfg["token"]:
            auds = cfg.get("audiences")
            aud_set = set(auds) if isinstance(auds, (list, tuple, set)) and auds else {svc_id}
            ruris = cfg.get("redirect_uris")
            ruri_set = {str(u).strip() for u in ruris if str(u).strip()} if isinstance(ruris, (list, tuple, set)) else set()
            display_name = str(cfg.get("display_name") or svc_id)
            out[svc_id] = {"token": cfg["token"], "audiences": aud_set, "redirect_uris": ruri_set, "display_name": display_name}
    return out


def _append_query_params(url: str, extra: dict[str, str]) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q.update({k: v for k, v in extra.items() if v is not None and v != ""})
    return urlunparse(parsed._replace(query=urlencode(q)))


def create_web_app(
    auth: AuthService,
    perm_bridge: AuthPermissionsBridge,
    *,
    channels: AuthChannels | None = None,
    include_ui: bool = False,
    service_tokens: dict[str, Any] | None = None,
):
    import anyio
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
    from starlette.routing import Route

    ch = channels or AuthChannels(auth.store, auth)
    svc_registry = _normalize_service_tokens(service_tokens)
    executed_actions: list[dict[str, Any]] = []

    def _authenticate_service(req: Request) -> tuple[str, set[str]]:
        if not svc_registry:
            raise AuthError("service_api_disabled", status_code=403)
        bearer = _extract_bearer(req)
        if not bearer:
            raise AuthError("service_unauthorized", status_code=401)
        matched_id: str | None = None
        matched_auds: set[str] = set()
        for svc_id, cfg in svc_registry.items():
            if hmac.compare_digest(cfg["token"], bearer):
                matched_id = svc_id
                matched_auds = cfg["audiences"]
        if matched_id is None:
            auth.store.audit("service_auth_denied", "denied", reason_code="service_unauthorized", extra={"path": req.url.path})
            raise AuthError("service_unauthorized", status_code=401)
        return matched_id, matched_auds

    class SecurityHeadersMiddleware:
        """Чистый ASGI middleware (без буферизации BaseHTTPMiddleware, совместим с SSE)."""

        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    extra = [
                        (b"cache-control", b"no-store"),
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"content-security-policy", b"frame-ancestors 'none'"),
                    ]
                    existing_keys = {k.lower() for k, _ in headers}
                    for k, v in extra:
                        if k not in existing_keys:
                            headers.append((k, v))
                    message = {**message, "headers": headers}
                await send(message)

            await self.app(scope, receive, send_with_headers)

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

    async def list_devices_ep(req: Request) -> JSONResponse:
        try:
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"), action_min_mode=1)
            devices = auth.store.list_devices(None if ctx.role == "owner" else ctx.account_id)
            return JSONResponse({"devices": devices})
        except AuthError as e:
            return _err(e)

    async def list_registrations_ep(req: Request) -> JSONResponse:
        try:
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            if ctx.role != "owner":
                raise AuthError("owner_required", status_code=403)
            return JSONResponse({"requests": auth.store.list_registration_requests(state="pending")})
        except AuthError as e:
            return _err(e)

    async def gen_recovery_codes_ep(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req, allow_empty=True)
            return JSONResponse(ch.generate_recovery_codes(
                ctx,
                second_verification_id=body.get("second_verification_id"),
                target_digest=body.get("target_digest"),
            ))
        except AuthError as e:
            return _err(e)

    # --- Нативный клиент (P2 / P3 / P5 / P7, без cookie и без browser Origin) ---

    async def app_register_options(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            return JSONResponse(ch.app_register_begin(
                enrollment_id=str(body.get("enrollment_id", "")),
                secret=str(body.get("secret", "")),
                source_key=_source_key(req),
            ))
        except AuthError as e:
            return _err(e)

    async def app_register_submit(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            pub_pem = body.get("public_key_pem")
            if not isinstance(pub_pem, str) or "BEGIN PUBLIC KEY" not in pub_pem:
                raise AuthError("invalid_payload", status_code=400)
            sig = _decode_b64_signature(body.get("signature_b64"))
            return JSONResponse(ch.app_register_submit(
                enrollment_id=str(body.get("enrollment_id", "")),
                secret=str(body.get("secret", "")),
                challenge_id=str(body.get("challenge_id", "")),
                device_name=str(body.get("device_name", "Native Device")),
                requested_role=str(body.get("requested_role", "")),
                public_key_pem=pub_pem.encode("utf-8"),
                signature=sig,
                hardware_binding=bool(body.get("hardware_binding", False)),
                source_key=_source_key(req),
            ))
        except AuthError as e:
            return _err(e)

    async def app_login_options(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            dev_id = str(body.get("device_id", "")).strip()
            if not dev_id:
                raise AuthError("invalid_payload", status_code=400)
            return JSONResponse(ch.app_login_begin(device_id=dev_id, source_key=_source_key(req)))
        except AuthError as e:
            return _err(e)

    async def app_login_verify(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            sig = _decode_b64_signature(body.get("signature_b64"))
            return JSONResponse(ch.app_login_verify(
                challenge_id=str(body.get("challenge_id", "")),
                device_id=str(body.get("device_id", "")),
                signature=sig,
                user_verified=bool(body.get("user_verified", False)),
                peer_ip=_peer_ip(req),
                forwarded_for=req.headers.get("x-forwarded-for"),
                audience=str(body.get("audience") or "locugard"),
            ))
        except AuthError as e:
            return _err(e)

    async def app_refresh_ep(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            rt = str(body.get("refresh_token", "")).strip()
            if not rt:
                raise AuthError("invalid_payload", status_code=400)
            return JSONResponse(ch.app_refresh(
                refresh_token=rt,
                peer_ip=_peer_ip(req),
                forwarded_for=req.headers.get("x-forwarded-for"),
            ))
        except AuthError as e:
            return _err(e)

    async def app_logout_ep(req: Request) -> JSONResponse:
        try:
            ch.app_logout(access_token=_extract_bearer(req))
            return JSONResponse({"status": "logged_out"})
        except AuthError as e:
            return _err(e)

    # --- Сервисный API (интроспекция токенов и поток отзывов для Apogeus / Docalaizer) ---

    async def service_introspect(req: Request) -> JSONResponse:
        try:
            svc_id, allowed_auds = _authenticate_service(req)
            body = await _json_obj(req)
            token = body.get("token") or body.get("access_token")
            if not isinstance(token, str) or not token.strip():
                raise AuthError("invalid_payload", status_code=400)
            req_aud = str(body.get("audience") or svc_id).strip()
            if req_aud not in allowed_auds:
                return JSONResponse({"active": False, "reason": "audience_not_allowed"}, status_code=403)
            res = ch.introspect_token(
                access_token=token.strip(),
                expected_audience=req_aud,
                peer_ip=body.get("peer_ip") or _peer_ip(req),
                forwarded_for=body.get("forwarded_for"),
                touch_activity=bool(body.get("touch_activity", False)),
            )
            return JSONResponse(res)
        except AuthError as e:
            return _err(e)

    async def service_revocations(req: Request) -> JSONResponse:
        try:
            _, allowed_auds = _authenticate_service(req)
            try:
                since_seq = max(0, int(req.query_params.get("since_seq", "0")))
                limit = max(1, min(500, int(req.query_params.get("limit", "100"))))
            except ValueError:
                raise AuthError("invalid_payload", status_code=400)
            events = auth.store.list_revocation_events(since_seq=since_seq, limit=limit, allowed_audiences=allowed_auds)
            last_seq = events[-1]["seq"] if events else max(since_seq, auth.store.latest_revocation_seq())
            return JSONResponse({"events": events, "last_seq": last_seq})
        except AuthError as e:
            return _err(e)

    async def service_events_sse(req: Request):
        try:
            _, allowed_auds = _authenticate_service(req)
            try:
                since_seq = max(0, int(req.query_params.get("since_seq", str(auth.store.latest_revocation_seq()))))
                heartbeat_s = max(1.0, min(30.0, float(req.query_params.get("heartbeat_s", "15"))))
                max_events = int(req.query_params.get("max_events", "0"))
            except ValueError:
                raise AuthError("invalid_payload", status_code=400)
        except AuthError as e:
            return _err(e)

        async def _stream():
            cursor = since_seq
            sent = 0
            yield f": connected since_seq={cursor}\n\n"
            while True:
                if await req.is_disconnected():
                    break
                events, cursor = await anyio.to_thread.run_sync(
                    lambda c=cursor: auth.store.wait_for_revocation_events(
                        since_seq=c, timeout_s=heartbeat_s, allowed_audiences=allowed_auds,
                    )
                )
                if events:
                    for ev in events:
                        yield f"id: {ev['seq']}\nevent: revocation\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
                        sent += 1
                        if max_events > 0 and sent >= max_events:
                            return
                else:
                    yield f": heartbeat seq={cursor}\n\n"

        return StreamingResponse(
            _stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    async def list_accounts_ep(req: Request) -> JSONResponse:
        try:
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            if ctx.role != "owner":
                raise AuthError("owner_required", status_code=403)
            return JSONResponse({"accounts": auth.store.list_accounts(active_only=True)})
        except AuthError as e:
            return _err(e)

    # --- Device Pairing (Apogeus / Flutter Windows & Android — PoP + SAS + Polling) ---

    async def app_pair_start_ep(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            return JSONResponse(ch.app_pair_start(
                device_name=str(body.get("device_name", "Native Device")),
                hardware_binding=bool(body.get("hardware_binding", False)),
                source_key=_source_key(req),
            ))
        except AuthError as e:
            return _err(e)

    async def app_pair_submit_key_ep(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            pub_pem = body.get("public_key_pem")
            if not isinstance(pub_pem, str) or "BEGIN PUBLIC KEY" not in pub_pem:
                raise AuthError("invalid_payload", status_code=400)
            sig = _decode_b64_signature(body.get("signature_b64"))
            return JSONResponse(ch.app_pair_submit_key(
                pair_id=str(body.get("pair_id", "")),
                poll_secret=str(body.get("poll_secret", "")),
                public_key_pem=pub_pem.encode("utf-8"),
                signature=sig,
            ))
        except AuthError as e:
            return _err(e)

    async def app_pair_status_ep(req: Request) -> JSONResponse:
        try:
            body = await _json_obj(req)
            return JSONResponse(ch.app_pair_status(
                pair_id=str(body.get("pair_id", "")),
                poll_secret=str(body.get("poll_secret", "")),
            ))
        except AuthError as e:
            return _err(e)

    async def pair_inspect_ep(req: Request) -> JSONResponse:
        try:
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            return JSONResponse(ch.app_pair_inspect(ctx, pair_id=req.path_params["pair_id"]))
        except AuthError as e:
            return _err(e)

    async def pair_approve_ep(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req)
            return JSONResponse(ch.app_pair_approve(
                ctx,
                pair_id=req.path_params["pair_id"],
                user_code=str(body.get("user_code", "")),
                target_account_id=body.get("target_account_id"),
                second_verification_id=body.get("second_verification_id"),
            ))
        except AuthError as e:
            return _err(e)

    async def pair_reject_ep(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            return JSONResponse(ch.app_pair_reject(ctx, pair_id=req.path_params["pair_id"]))
        except AuthError as e:
            return _err(e)

    # --- Browser SSO (Authorization Code + PKCE S256 для Docalaizer и веб-сервисов) ---

    def _validate_sso_client(client_id: str, redirect_uri: str, code_challenge: str, method: str) -> dict[str, Any]:
        cfg = svc_registry.get(client_id)
        if not cfg or not cfg["redirect_uris"]:
            raise AuthError("unknown_sso_client", status_code=400)
        if redirect_uri not in cfg["redirect_uris"]:
            auth.store.audit("sso_redirect_rejected", "denied", reason_code="invalid_redirect_uri", extra={"client_id": client_id})
            raise AuthError("invalid_redirect_uri", status_code=400)
        if method != "S256" or not code_challenge or len(code_challenge) < 43:
            raise AuthError("invalid_pkce_challenge", status_code=400)
        return cfg

    async def sso_authorize_ep(req: Request) -> Response:
        try:
            client_id = str(req.query_params.get("client_id", "")).strip()
            redirect_uri = str(req.query_params.get("redirect_uri", "")).strip()
            code_challenge = str(req.query_params.get("code_challenge", "")).strip()
            method = str(req.query_params.get("code_challenge_method", "S256")).strip()
            state_param = str(req.query_params.get("state", "")).strip()
            cfg = _validate_sso_client(client_id, redirect_uri, code_challenge, method)
            lang = resolve_ui_lang(req.query_params.get("lang"), req.headers.get("accept-language"))
            return HTMLResponse(render_sso_ui(
                lang=lang,
                client_id=client_id,
                client_display_name=cfg["display_name"],
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                state_param=state_param,
            ))
        except AuthError as e:
            return _err(e)

    async def sso_approve_ep(req: Request) -> JSONResponse:
        try:
            _check_origin(req)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=_peer_ip(req), forwarded_for=req.headers.get("x-forwarded-for"))
            _verify_csrf_audited(ctx.session_id, req)
            body = await _json_obj(req)
            client_id = str(body.get("client_id", "")).strip()
            redirect_uri = str(body.get("redirect_uri", "")).strip()
            code_challenge = str(body.get("code_challenge", "")).strip()
            method = str(body.get("code_challenge_method", "S256")).strip()
            state_param = str(body.get("state", "")).strip()
            cfg = _validate_sso_client(client_id, redirect_uri, code_challenge, method)
            audience = client_id if client_id in cfg["audiences"] else next(iter(cfg["audiences"]))
            issued = ch.sso_issue_code(
                ctx,
                client_id=client_id,
                audience=audience,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=method,
                state_param=state_param or None,
            )
            redirect_url = _append_query_params(redirect_uri, {"code": issued["code"], "state": state_param})
            return JSONResponse({"redirect_url": redirect_url, "expires_at": issued["expires_at"]})
        except AuthError as e:
            return _err(e)

    async def service_sso_token_ep(req: Request) -> JSONResponse:
        try:
            svc_id, allowed_auds = _authenticate_service(req)
            body = await _json_obj(req)
            return JSONResponse(ch.sso_exchange_code(
                client_id=svc_id,
                allowed_audiences=allowed_auds,
                code=str(body.get("code", "")).strip(),
                redirect_uri=str(body.get("redirect_uri", "")).strip(),
                code_verifier=str(body.get("code_verifier", "")).strip(),
                peer_ip=body.get("peer_ip") or _peer_ip(req),
                forwarded_for=body.get("forwarded_for"),
            ))
        except AuthError as e:
            return _err(e)

    async def web_ui_pair(req: Request) -> HTMLResponse:
        lang = resolve_ui_lang(req.query_params.get("lang"), req.headers.get("accept-language"))
        return HTMLResponse(render_pair_ui(lang=lang))

    async def web_ui_index(req: Request) -> HTMLResponse:
        lang = resolve_ui_lang(req.query_params.get("lang"), req.headers.get("accept-language"))
        return HTMLResponse(render_web_ui(lang=lang))

    async def web_ui_bootstrap(req: Request) -> Response:
        # P0 инвариант: помощник bootstrap доступен ТОЛЬКО пока не создан первый активный owner с ключом
        if auth.store.has_active_owner_with_key():
            return JSONResponse({"error": "bootstrap_closed"}, status_code=404)
        lang = resolve_ui_lang(req.query_params.get("lang"), req.headers.get("accept-language"))
        return HTMLResponse(render_bootstrap_ui(lang=lang))

    async def web_ui_enroll(req: Request) -> HTMLResponse:
        lang = resolve_ui_lang(req.query_params.get("lang"), req.headers.get("accept-language"))
        return HTMLResponse(render_enroll_ui(lang=lang))

    async def web_ui_asset(req: Request) -> Response:
        name = req.path_params.get("filename", "favicon.ico")
        mime = _ASSET_MIME.get(name)
        if not mime:
            return JSONResponse({"error": "not_found"}, status_code=404)
        p = _ASSETS_DIR / name
        if not p.is_file():
            return JSONResponse({"error": "not_found"}, status_code=404)
        return Response(content=p.read_bytes(), media_type=mime)

    routes = [
        Route("/auth/login/options", login_options, methods=["POST"]),
        Route("/auth/login/verify", login_verify, methods=["POST"]),
        Route("/auth/reauth/options", reauth_options, methods=["POST"]),
        Route("/auth/reauth/verify", reauth_verify, methods=["POST"]),
        Route("/auth/logout", logout, methods=["POST"]),
        Route("/api/accounts", list_accounts_ep, methods=["GET"]),
        Route("/api/devices", list_devices_ep, methods=["GET"]),
        Route("/api/devices/enrollment-codes", create_enrollment, methods=["POST"]),
        Route("/api/devices/registrations", list_registrations_ep, methods=["GET"]),
        Route("/api/devices/pairings/{pair_id}", pair_inspect_ep, methods=["GET"]),
        Route("/api/devices/pairings/{pair_id}/approve", pair_approve_ep, methods=["POST"]),
        Route("/api/devices/pairings/{pair_id}/reject", pair_reject_ep, methods=["POST"]),
        Route("/auth/register/options", register_options, methods=["POST"]),
        Route("/auth/register/submit", register_submit, methods=["POST"]),
        Route("/api/devices/registrations/{request_id}/approve", approve_registration, methods=["POST"]),
        Route("/api/devices/{device_id}/revoke", revoke_device, methods=["POST"]),
        Route("/api/recovery-codes", gen_recovery_codes_ep, methods=["POST"]),
        Route("/api/protected/profile", protected_profile, methods=["GET"]),
        Route("/api/protected/dangerous-action/request", dangerous_action_request, methods=["POST"]),
        Route("/api/protected/dangerous-action/confirm", dangerous_action_confirm, methods=["POST"]),
        # Нативный клиент (Flutter Windows / Android)
        Route("/auth/app/register/options", app_register_options, methods=["POST"]),
        Route("/auth/app/register/submit", app_register_submit, methods=["POST"]),
        Route("/auth/app/pair/start", app_pair_start_ep, methods=["POST"]),
        Route("/auth/app/pair/submit-key", app_pair_submit_key_ep, methods=["POST"]),
        Route("/auth/app/pair/status", app_pair_status_ep, methods=["POST"]),
        Route("/auth/app/login/options", app_login_options, methods=["POST"]),
        Route("/auth/app/login/verify", app_login_verify, methods=["POST"]),
        Route("/auth/app/refresh", app_refresh_ep, methods=["POST"]),
        Route("/auth/app/logout", app_logout_ep, methods=["POST"]),
        # Browser SSO (Docalaizer и внутренние веб-сервисы)
        Route("/sso/authorize", sso_authorize_ep, methods=["GET"]),
        Route("/sso/approve", sso_approve_ep, methods=["POST"]),
        # Сервисный API (Apogeus, Docalaizer)
        Route("/api/service/sso/token", service_sso_token_ep, methods=["POST"]),
        Route("/api/service/introspect", service_introspect, methods=["POST"]),
        Route("/api/service/revocations", service_revocations, methods=["GET"]),
        Route("/api/service/events", service_events_sse, methods=["GET"]),
    ]
    if include_ui:
        routes.insert(0, Route("/assets/{filename}", web_ui_asset, methods=["GET"]))
        routes.insert(0, Route("/favicon.ico", web_ui_asset, methods=["GET"]))
        routes.insert(0, Route("/pair", web_ui_pair, methods=["GET"]))
        routes.insert(0, Route("/enroll", web_ui_enroll, methods=["GET"]))
        routes.insert(0, Route("/bootstrap", web_ui_bootstrap, methods=["GET"]))
        routes.insert(0, Route("/", web_ui_index, methods=["GET"]))

    app = Starlette(routes=routes)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.executed_actions = executed_actions
    app.state.channels = ch
    return app
