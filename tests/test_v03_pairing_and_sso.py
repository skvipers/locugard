"""Интеграционные тесты v0.3.0: Device Pairing (Apogeus) и Browser SSO с PKCE S256 (Docalaizer)."""
from __future__ import annotations

import base64
import hashlib
import secrets
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from locugard.auth_channels import AuthChannels
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthService
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from locugard.web_server import SESSION_COOKIE, create_web_app

from tests.test_auth_scenarios import HAS_WEB, _gen_ec_key, _gen_tls, _make_assert, _make_reg, _sign_ec
from tests.test_native_and_service_api import _free_port, _https_json


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


@unittest.skipUnless(HAS_WEB, "Требуется опциональный extra [web]")
class TestPairingAndBrowserSSO(unittest.TestCase):
    def test_device_pairing_and_browser_sso_end_to_end(self) -> None:
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

            apogeus_tok = secrets.token_urlsafe(32)
            docalaizer_tok = secrets.token_urlsafe(32)
            docalaizer_cb = "https://apogeus.home.arpa:3443/auth/locugard/callback"

            app = create_web_app(
                auth,
                bridge,
                channels=channels,
                include_ui=True,
                service_tokens={
                    "apogeus": {"token": apogeus_tok, "audiences": ["apogeus"], "display_name": "Apogeus"},
                    "docalaizer": {
                        "token": docalaizer_tok,
                        "audiences": ["docalaizer"],
                        "redirect_uris": [docalaizer_cb],
                        "display_name": "Docalaizer",
                    },
                },
            )

            # Bootstrap owner via console
            owner_priv, _ = _gen_ec_key()
            owner_cid = secrets.token_bytes(16)
            b = auth.bootstrap_owner_begin("Dima")
            boot = auth.bootstrap_owner_complete(
                challenge_id=b["challenge_id"],
                display_name="Dima",
                device_name="Owner-Laptop",
                credential_payload=_make_reg(b["options"]["challenge"], origin, rp_id, owner_priv, owner_cid),
                hardware_binding=True,
            )
            owner_acc_id = boot["account_id"]
            owner_dev_id = boot["device_id"]

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
                # Owner logs into LocuGard browser UI
                st, lo, _ = _https_json(f"{origin}/auth/login/options", method="POST", headers={"Origin": origin}, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                st, lv, lv_hdrs = _https_json(
                    f"{origin}/auth/login/verify",
                    method="POST",
                    headers={"Origin": origin},
                    body={"challenge_id": lo["challenge_id"], "credential": _make_assert(lo["options"]["challenge"], origin, rp_id, owner_priv, owner_cid, 2, uv=True)},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                csrf = lv["csrf_token"]
                sc = lv_hdrs.get("set-cookie") or lv_hdrs.get("Set-Cookie", "")
                cookie_val = sc.split(f"{SESSION_COOKIE}=", 1)[1].split(";", 1)[0]
                owner_hdrs = {"Origin": origin, "Cookie": f"{SESSION_COOKIE}={cookie_val}", "X-CSRF-Token": csrf}

                # =====================================================================
                # PART 1: Device Pairing (Apogeus Flutter — PoP + SAS + Polling)
                # =====================================================================
                st, ps_bad, _ = _https_json(
                    f"{origin}/auth/app/pair/start",
                    method="POST",
                    body={"device_name": "Bad-PoP", "hardware_binding": True},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertNotIn(ps_bad["poll_secret"], ps_bad["verification_url"])
                self.assertNotIn(ps_bad["user_code"], ps_bad["verification_url"])
                bad_priv, bad_pub = _gen_ec_key()
                st, _, _ = _https_json(
                    f"{origin}/auth/app/pair/submit-key",
                    method="POST",
                    body={
                        "pair_id": ps_bad["pair_id"],
                        "poll_secret": ps_bad["poll_secret"],
                        "public_key_pem": bad_pub.decode("utf-8"),
                        "signature_b64": base64.urlsafe_b64encode(b"bad-sig").decode("ascii"),
                    },
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)
                st, bad_poll, _ = _https_json(
                    f"{origin}/auth/app/pair/status",
                    method="POST",
                    body={"pair_id": ps_bad["pair_id"], "poll_secret": ps_bad["poll_secret"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(bad_poll["status"], "rejected")

                # Happy path pairing
                st, ps, _ = _https_json(
                    f"{origin}/auth/app/pair/start",
                    method="POST",
                    body={"device_name": "Apogeus-Windows", "hardware_binding": True},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                app_priv, app_pub = _gen_ec_key()
                pair_msg = f"locugard:app_pair:{ps['rp_id']}:{ps['pair_id']}:".encode() + bytes.fromhex(ps["challenge_hex"])
                pair_sig = base64.urlsafe_b64encode(_sign_ec(app_priv, pair_msg)).decode("ascii")
                st, psub, _ = _https_json(
                    f"{origin}/auth/app/pair/submit-key",
                    method="POST",
                    body={
                        "pair_id": ps["pair_id"],
                        "poll_secret": ps["poll_secret"],
                        "public_key_pem": app_pub.decode("utf-8"),
                        "signature_b64": pair_sig,
                    },
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(psub["status"], "pending_approval")

                # Polling before approval -> pending_approval; wrong poll_secret -> 401
                st, pwait, _ = _https_json(
                    f"{origin}/auth/app/pair/status",
                    method="POST",
                    body={"pair_id": ps["pair_id"], "poll_secret": ps["poll_secret"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(pwait["status"], "pending_approval")
                st, _, _ = _https_json(
                    f"{origin}/auth/app/pair/status",
                    method="POST",
                    body={"pair_id": ps["pair_id"], "poll_secret": "wrong"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)

                # Owner opens /pair UI and inspects pairing (user_code must NOT be leaked!)
                st, pair_html, _ = _https_json(f"{origin}/pair?id={ps['pair_id']}&lang=ru", ctx=ssl_ctx)
                self.assertEqual(st, 200)
                self.assertIn('<html lang="ru">', pair_html["raw"])
                self.assertNotIn("localStorage.setItem", pair_html["raw"])

                st, pinsp, _ = _https_json(f"{origin}/api/devices/pairings/{ps['pair_id']}", headers=owner_hdrs, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                self.assertNotIn("user_code", pinsp)
                self.assertEqual(pinsp["device_name"], "Apogeus-Windows")

                # Wrong SAS user_code rejected
                st, _, _ = _https_json(
                    f"{origin}/api/devices/pairings/{ps['pair_id']}/approve",
                    method="POST",
                    headers=owner_hdrs,
                    body={"user_code": "AAAA-BBBB", "target_account_id": owner_acc_id},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 403)

                # Correct SAS user_code approves device
                st, pappr, _ = _https_json(
                    f"{origin}/api/devices/pairings/{ps['pair_id']}/approve",
                    method="POST",
                    headers=owner_hdrs,
                    body={"user_code": ps["user_code"], "target_account_id": owner_acc_id},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(pappr["status"], "approved")

                # Native app polls -> gets device_id -> logs in immediately via /auth/app/login/*
                st, pdone, _ = _https_json(
                    f"{origin}/auth/app/pair/status",
                    method="POST",
                    body={"pair_id": ps["pair_id"], "poll_secret": ps["poll_secret"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(pdone["status"], "approved")
                paired_dev_id = pdone["device_id"]

                st, alo, _ = _https_json(f"{origin}/auth/app/login/options", method="POST", body={"device_id": paired_dev_id}, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                lmsg = f"locugard:app_login:{alo['rp_id']}:{paired_dev_id}:".encode() + bytes.fromhex(alo["challenge_hex"])
                lsig = base64.urlsafe_b64encode(_sign_ec(app_priv, lmsg)).decode("ascii")
                st, alv, _ = _https_json(
                    f"{origin}/auth/app/login/verify",
                    method="POST",
                    body={"challenge_id": alo["challenge_id"], "device_id": paired_dev_id, "signature_b64": lsig, "user_verified": True, "audience": "apogeus"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(alv["audience"], "apogeus")

                # =====================================================================
                # PART 2: Browser SSO (Docalaizer Authorization Code + PKCE S256)
                # =====================================================================
                ver1, chal1 = _pkce_pair()
                # Open-redirect protection: unregistered redirect_uri rejected with 400
                q_evil = urlencode({"client_id": "docalaizer", "redirect_uri": "https://evil.example/cb", "code_challenge": chal1, "code_challenge_method": "S256"})
                st, evil_res, _ = _https_json(f"{origin}/sso/authorize?{q_evil}", ctx=ssl_ctx)
                self.assertEqual(st, 400)
                self.assertEqual(evil_res.get("error"), "invalid_redirect_uri")

                # Valid /sso/authorize renders consent page
                q_ok = urlencode({"client_id": "docalaizer", "redirect_uri": docalaizer_cb, "code_challenge": chal1, "code_challenge_method": "S256", "state": "st_123"})
                st, sso_html, _ = _https_json(f"{origin}/sso/authorize?{q_ok}", headers={"Accept-Language": "en-US"}, ctx=ssl_ctx)
                self.assertEqual(st, 200)
                self.assertIn("Docalaizer", sso_html["raw"])
                self.assertNotIn("localStorage.setItem", sso_html["raw"])

                # Approve SSO -> wrong PKCE verifier invalidates code immediately
                st, sso_a1, _ = _https_json(
                    f"{origin}/sso/approve",
                    method="POST",
                    headers=owner_hdrs,
                    body={"client_id": "docalaizer", "redirect_uri": docalaizer_cb, "code_challenge": chal1, "code_challenge_method": "S256", "state": "st_123"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                qs1 = parse_qs(urlparse(sso_a1["redirect_url"]).query)
                self.assertEqual(qs1["state"][0], "st_123")
                code1 = qs1["code"][0]

                st, _, _ = _https_json(
                    f"{origin}/api/service/sso/token",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_tok}"},
                    body={"code": code1, "redirect_uri": docalaizer_cb, "code_verifier": secrets.token_urlsafe(48)},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)
                # Even right verifier now fails because code1 was invalidated!
                st, _, _ = _https_json(
                    f"{origin}/api/service/sso/token",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_tok}"},
                    body={"code": code1, "redirect_uri": docalaizer_cb, "code_verifier": ver1},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)

                # Happy path SSO exchange
                ver2, chal2 = _pkce_pair()
                st, sso_a2, _ = _https_json(
                    f"{origin}/sso/approve",
                    method="POST",
                    headers=owner_hdrs,
                    body={"client_id": "docalaizer", "redirect_uri": docalaizer_cb, "code_challenge": chal2, "code_challenge_method": "S256", "state": "st_456"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                code2 = parse_qs(urlparse(sso_a2["redirect_url"]).query)["code"][0]

                st, tok, _ = _https_json(
                    f"{origin}/api/service/sso/token",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_tok}"},
                    body={"code": code2, "redirect_uri": docalaizer_cb, "code_verifier": ver2},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(tok["audience"], "docalaizer")
                self.assertEqual(tok["account_id"], owner_acc_id)
                self.assertEqual(tok["device_id"], owner_dev_id)

                # Replay of code2 rejected
                st, _, _ = _https_json(
                    f"{origin}/api/service/sso/token",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_tok}"},
                    body={"code": code2, "redirect_uri": docalaizer_cb, "code_verifier": ver2},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 401)

                # Introspect: Docalaizer accepts, Apogeus rejects (audience_mismatch)
                st, intr_doc, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_tok}"},
                    body={"token": tok["access_token"], "audience": "docalaizer"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertTrue(intr_doc["active"])
                self.assertEqual(intr_doc["audience"], "docalaizer")

                st, intr_apo, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": f"Bearer {apogeus_tok}"},
                    body={"token": tok["access_token"], "audience": "apogeus"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertFalse(intr_apo["active"])
                self.assertEqual(intr_apo["reason"], "audience_mismatch")

                # Refresh SSO session works cleanly
                st, sso_ref, _ = _https_json(
                    f"{origin}/auth/app/refresh",
                    method="POST",
                    body={"refresh_token": tok["refresh_token"]},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertEqual(sso_ref["generation"], 2)
                self.assertEqual(sso_ref["audience"], "docalaizer")

                # Revoking owner browser device immediately terminates Docalaizer SSO session too!
                st, _, _ = _https_json(
                    f"{origin}/api/devices/{owner_dev_id}/revoke",
                    method="POST",
                    headers=owner_hdrs,
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                st, intr_after, _ = _https_json(
                    f"{origin}/api/service/introspect",
                    method="POST",
                    headers={"Authorization": f"Bearer {docalaizer_tok}"},
                    body={"token": sso_ref["access_token"], "audience": "docalaizer"},
                    ctx=ssl_ctx,
                )
                self.assertEqual(st, 200)
                self.assertFalse(intr_after["active"])
            finally:
                server.should_exit = True
                th.join(timeout=5.0)


if __name__ == "__main__":
    unittest.main()
