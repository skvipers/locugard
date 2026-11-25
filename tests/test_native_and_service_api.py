"""Интеграционные тесты v0.2.0: встроенный Web UI, нативный HTTPS API (/auth/app/*) и сервисный контракт (/api/service/*)."""
from __future__ import annotations

import base64
import json
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from locugard.auth_channels import AuthChannels
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthService
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from locugard.web_server import SESSION_COOKIE, create_web_app

from tests.test_auth_scenarios import HAS_WEB, _gen_ec_key, _gen_tls, _make_assert, _make_reg, _sign_ec


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _https_json(
    url: str,
    *,
    method: str = "GET",
    body: dict | None = None,
    headers: dict[str, str] | None = None,
    ctx: ssl.SSLContext,
) -> tuple[int, dict, dict[str, str]]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req_headers = dict(headers or {})
    if data is not None:
        req_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5.0) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw and resp.headers.get("content-type", "").startswith("application/json") else {"raw": raw}
            return resp.status, parsed, dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"raw": raw}
        return e.code, parsed, dict(e.headers.items())


@unittest.skipUnless(HAS_WEB, "Требуется опциональный extra [web]")
class TestNativeAndServiceContract(unittest.TestCase):
    def test_end_to_end_native_apogeus_docalaizer_sse_and_builtin_ui(self) -> None:
        import uvicorn

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            port = _free_port()
            rp_id = "localhost"
            origin = f"https://localhost:{port}"
            ca_crt, srv_crt, srv_key = _gen_tls(root / "certs")

            store = AuthStore(root / "data", pepper=secrets.token_bytes(32))
            auth = AuthService(store, rp_id=rp_id, expected_origin=origin)
            channels = AuthChannels(store, auth)
            perms = LocalPermissions(root / "data")
            bridge = AuthPermissionsBridge(store, auth, perms)

            apogeus_svc_token = secrets.token_urlsafe(32)
            docalaizer_svc_token = secrets.token_urlsafe(32)
            app = create_web_app(
                auth,
                bridge,
                channels=channels,
                include_ui=True,
                service_tokens={
                    "apogeus": {"token": apogeus_svc_token, "audiences": ["apogeus"]},
                    "docalaizer": {"token": docalaizer_svc_token, "audiences": ["docalaizer"]},
                },
            )

            # Bootstrap owner via local console
            owner_priv, _ = _gen_ec_key()
            owner_cid = secrets.token_bytes(16)
            b = auth.bootstrap_owner_begin("Dima")
            boot = auth.bootstrap_owner_complete(
                challenge_id=b["challenge_id"],
                display_name="Dima",
                device_name="Owner-Browser",
                credential_payload=_make_reg(b["options"]["challenge"], origin, rp_id, owner_priv, owner_cid),
                hardware_binding=True,
            )
            owner_acc_id = boot["account_id"]

            # Start real HTTPS server
            cfg = uvicorn.Config(
                app, host="127.0.0.1", port=port,
                ssl_certfile=str(srv_crt), ssl_keyfile=str(srv_key),
                log_level="error",
            )
            server = uvicorn.Server(cfg)
            th = threading.Thread(target=server.run, daemon=True)
            th.start()
            for _ in range(50):
                if server.started:
                    break
                time.sleep(0.05)
            self.assertTrue(server.started)

            ssl_ctx = ssl.create_default_context(cafile=str(ca_crt))
            try:
                # 1. Built-in Web UI (GET /) + brand assets with security headers and zero localStorage token usage
                st, ui_res, ui_hdrs = _https_json(f"{origin}/", ctx=ssl_ctx)
                self.assertEqual(st, 200)
                self.assertIn("LocuGard", ui_res["raw"])
                self.assertIn("/assets/favicon.svg", ui_res["raw"])
                self.assertNotIn("localStorage.setItem", ui_res["raw"])
                self.assertEqual(ui_hdrs.get("x-frame-options") or ui_hdrs.get("X-Frame-Options"), "DENY")

                st_ico, _, ico_hdrs = _https_json(f"{origin}/assets/favicon.svg", ctx=ssl_ctx)
                self.assertEqual(st_ico, 200)
                self.assertIn("image/svg+xml", ico_hdrs.get("content-type") or ico_hdrs.get("Content-Type", ""))

                # 2. Owner web login to obtain __Host-locugard_sid cookie & CSRF token
                st, lo, _ = _https_json(f"{origin}/auth/login/options", method="POST", headers={"Origin": origin}, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                st, lv, lv_hdrs = _https_json(
                    f"{origin}/auth/login/verify",
                    method="POST",
                    headers={"Origin": origin},
                    body={
                        "challenge_id": lo["challenge_id"],
                        "credential": _make_assert(lo["options"]["challenge"], origin, rp_id, owner_priv, owner_cid, 2, uv=True),
                    },
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                csrf = lv["csrf_token"]
                set_cookie = lv_hdrs.get("set-cookie") or lv_hdrs.get("Set-Cookie", "")
                self.assertIn(SESSION_COOKIE, set_cookie)
                cookie_val = set_cookie.split(f"{SESSION_COOKIE}=", 1)[1].split(";", 1)[0]
                owner_hdrs = {"Origin": origin, "Cookie": f"{SESSION_COOKIE}={cookie_val}", "X-CSRF-Token": csrf}

                # 3. Owner issues EnrollmentCode for native Flutter client
                st, enr, _ = _https_json(
                    f"{origin}/api/devices/enrollment-codes",
                    method="POST",
                    headers=owner_hdrs,
                    body={"target_account_id": owner_acc_id},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)

                # 4. Native client enrolls via HTTPS (no Origin / no cookie)
                st, ro, _ = _https_json(
                    f"{origin}/auth/app/register/options",
                    method="POST",
                    body={"enrollment_id": enr["enrollment_id"], "secret": enr["secret"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(ro["allowed_role"], "owner")

                app_priv, app_pub_pem_bytes = _gen_ec_key()
                app_pub_pem = app_pub_pem_bytes.decode("utf-8")
                reg_msg = f"locugard:app_register:{ro['rp_id']}:{enr['enrollment_id']}:".encode() + bytes.fromhex(ro["challenge_hex"])
                reg_sig = base64.urlsafe_b64encode(_sign_ec(app_priv, reg_msg)).decode("ascii")

                st, rs, _ = _https_json(
                    f"{origin}/auth/app/register/submit",
                    method="POST",
                    body={
                        "enrollment_id": enr["enrollment_id"],
                        "secret": enr["secret"],
                        "challenge_id": ro["challenge_id"],
                        "device_name": "Flutter-Windows",
                        "requested_role": "owner",
                        "public_key_pem": app_pub_pem,
                        "signature_b64": reg_sig,
                        "hardware_binding": True,
                    },
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(rs["state"], "pending")
                native_dev_id = rs["device_id"]
                req_id = rs["request_id"]

                # Pending list endpoint shows the new native device
                st, pend, _ = _https_json(f"{origin}/api/devices/registrations", headers=owner_hdrs, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                self.assertEqual(len(pend["requests"]), 1)
                self.assertEqual(pend["requests"][0]["request_id"], req_id)

                # Login before approval must fail
                st, alo_pre, _ = _https_json(f"{origin}/auth/app/login/options", method="POST", body={"device_id": native_dev_id}, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                pre_msg = f"locugard:app_login:{alo_pre['rp_id']}:{native_dev_id}:".encode() + bytes.fromhex(alo_pre["challenge_hex"])
                pre_sig = base64.urlsafe_b64encode(_sign_ec(app_priv, pre_msg)).decode("ascii")
                st, _, _ = _https_json(
                    f"{origin}/auth/app/login/verify",
                    method="POST",
                    body={"challenge_id": alo_pre["challenge_id"], "device_id": native_dev_id, "signature_b64": pre_sig, "user_verified": True, "audience": "apogeus"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)

                # 5. Owner approves native device
                st, appr, _ = _https_json(
                    f"{origin}/api/devices/registrations/{req_id}/approve",
                    method="POST",
                    headers=owner_hdrs,
                    body={},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(appr["state"], "active")

                # Devices list endpoint shows both devices
                st, devs, _ = _https_json(f"{origin}/api/devices", headers=owner_hdrs, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                self.assertEqual(len(devs["devices"]), 2)

                # 6. Native client logs in for audience="apogeus" and refreshes session
                st, alo, _ = _https_json(f"{origin}/auth/app/login/options", method="POST", body={"device_id": native_dev_id}, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                login_msg = f"locugard:app_login:{alo['rp_id']}:{native_dev_id}:".encode() + bytes.fromhex(alo["challenge_hex"])
                login_sig = base64.urlsafe_b64encode(_sign_ec(app_priv, login_msg)).decode("ascii")
                st, alv, _ = _https_json(
                    f"{origin}/auth/app/login/verify",
                    method="POST",
                    body={
                        "challenge_id": alo["challenge_id"],
                        "device_id": native_dev_id,
                        "signature_b64": login_sig,
                        "user_verified": True,
                        "audience": "apogeus",
                    },
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(alv["audience"], "apogeus")
                self.assertEqual(alv["generation"], 1)

                st, ref, _ = _https_json(
                    f"{origin}/auth/app/refresh",
                    method="POST",
                    body={"refresh_token": alv["refresh_token"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(ref["generation"], 2)
                self.assertEqual(ref["audience"], "apogeus")
                active_access = ref["access_token"]

                # 7. Service introspection: Apogeus succeeds, Docalaizer rejected (audience_mismatch), bad token 401
                st, intr_ok, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": f"Bearer {apogeus_svc_token}"},
                    body={"token": active_access, "audience": "apogeus"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertTrue(intr_ok["active"])
                self.assertEqual(intr_ok["account_id"], owner_acc_id)
                self.assertEqual(intr_ok["device_id"], native_dev_id)
                self.assertEqual(intr_ok["role"], "owner")
                self.assertEqual(intr_ok["audience"], "apogeus")
                self.assertIsNotNone(intr_ok["session_expires_at"])

                st, intr_wrong_svc, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_svc_token}"},
                    body={"token": active_access, "audience": "docalaizer"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertFalse(intr_wrong_svc["active"])
                self.assertEqual(intr_wrong_svc["reason"], "audience_mismatch")

                st, _, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": "Bearer wrong-secret"},
                    body={"token": active_access},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)

                # 8. Real-time SSE revocation push for open WebSocket in Apogeus
                sse_received: list[dict] = []
                sse_connected = threading.Event()

                def _sse_reader() -> None:
                    req = urllib.request.Request(
                        f"{origin}/api/service/events?since_seq=0&heartbeat_s=5&max_events=1",
                        headers={"Authorization": f"Bearer {apogeus_svc_token}"},
                    )
                    with urllib.request.urlopen(req, context=ssl_ctx, timeout=8.0) as resp:
                        for raw_line in resp:
                            line = raw_line.decode("utf-8").strip()
                            if line.startswith(": connected"):
                                sse_connected.set()
                            elif line.startswith("data: "):
                                sse_received.append(json.loads(line[6:]))
                                break

                sse_th = threading.Thread(target=_sse_reader, daemon=True)
                sse_th.start()
                self.assertTrue(sse_connected.wait(timeout=3.0), "SSE stream did not connect")

                st, rev, _ = _https_json(
                    f"{origin}/api/devices/{native_dev_id}/revoke",
                    method="POST",
                    headers=owner_hdrs,
                    ctx=ssl_ctx,
                )
                t_after_revoke = time.monotonic()
                self.assertEqual(st, 200)
                self.assertEqual(rev["status"], "revoked")

                sse_th.join(timeout=3.0)
                latency_s = time.monotonic() - t_after_revoke
                self.assertEqual(len(sse_received), 1)
                self.assertEqual(sse_received[0]["event_type"], "device_revoked")
                self.assertEqual(sse_received[0]["device_id"], native_dev_id)
                self.assertLess(latency_s, 1.0, f"SSE revocation took too long: {latency_s:.3f}s")

                # Immediately after revocation, Apogeus introspect rejects the token
                st, intr_after, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": f"Bearer {apogeus_svc_token}"},
                    body={"token": active_access, "audience": "apogeus"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertFalse(intr_after["active"])

                # Polling fallback also contains the revocation event
                st, poll, _ = _https_json(
                    f"{origin}/api/service/revocations?since_seq=0",
                    headers={"Authorization": f"Bearer {apogeus_svc_token}"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertTrue(any(e["device_id"] == native_dev_id and e["event_type"] == "device_revoked" for e in poll["events"]))

                # Revoked device cannot refresh anymore
                st, _, _ = _https_json(
                    f"{origin}/auth/app/refresh",
                    method="POST",
                    body={"refresh_token": ref["refresh_token"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)
            finally:
                server.should_exit = True
                th.join(timeout=5.0)


if __name__ == "__main__":
    unittest.main()
