"""LocuGard Quickstart HTTPS Server with minimal WebAuthn browser UI.

Demonstrates:
- HTTPS + __Host-locugard_sid cookie (HttpOnly; Secure; SameSite=Lax)
- Zero localStorage token usage
- Browser WebAuthn bootstrap helper, login, step-up reauth, dangerous action approval, and offline recovery codes
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if (_REPO_ROOT / "locugard").is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import uvicorn
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from locugard.auth_channels import AuthChannels
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthError, AuthService
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from locugard.web_server import SESSION_COOKIE, create_web_app

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LOCUGARD_DATA_DIR", str(BASE_DIR / "data")))
SECRETS_DIR = Path(os.environ.get("LOCUGARD_SECRETS_DIR", str(BASE_DIR / "secrets")))
RP_ID = os.environ.get("LOCUGARD_RP_ID", "locugard.home.arpa")
HOST = os.environ.get("LOCUGARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("LOCUGARD_PORT", "8443"))
ORIGIN = os.environ.get("LOCUGARD_ORIGIN", f"https://{RP_ID}:{PORT}")

QUICKSTART_UI = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>LocuGard — Quickstart HTTPS + WebAuthn</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 780px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
    .card { border: 1px solid #3334; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
    button { padding: 0.5rem 0.9rem; margin: 0.25rem; cursor: pointer; }
    input { padding: 0.45rem; margin: 0.2rem; width: 280px; }
    pre { background: #111; color: #7f7; padding: 1rem; border-radius: 6px; overflow: auto; max-height: 360px; }
  </style>
</head>
<body>
  <h1>LocuGard — Quickstart HTTPS + WebAuthn</h1>
  <p>Session cookie: <code>__Host-locugard_sid</code> (<code>HttpOnly; Secure; SameSite=Lax</code>). No tokens are stored in <code>localStorage</code>.</p>

  <div class="card">
    <h3>1. Sign In &amp; Session (Passkey / Platform Authenticator / FIDO2)</h3>
    <button onclick="doLogin()">Sign in with WebAuthn</button>
    <button onclick="doProfile()">Check Profile (/api/protected/profile)</button>
    <button onclick="doReauth()">Step-up Reauth</button>
    <button onclick="doLogout()">Sign Out</button>
  </div>

  <div class="card">
    <h3>2. First-Owner Bootstrap Helper (for local console CLI)</h3>
    <input id="bootChal" placeholder="Paste challenge from auth_cli bootstrap-begin" />
    <button onclick="makeBootstrapCred()">Create WebAuthn JSON for CLI</button>
  </div>

  <div class="card">
    <h3>3. Dangerous Action Approval (Permissions) &amp; Recovery Codes</h3>
    <input id="actTarget" value="demo-target" />
    <button onclick="doDangerReq()">Request Dangerous Action</button>
    <button onclick="doDangerConf()">Confirm &amp; Execute Action</button>
    <button onclick="doGenRecovery()">Generate 10 Recovery Codes</button>
  </div>

  <pre id="log"></pre>
  <script>
    let csrf = "";
    let lastApproval = null;
    const log = (m) => { const el = document.getElementById('log'); el.textContent += m + "\\n"; el.scrollTop = el.scrollHeight; };
    log("isSecureContext=" + window.isSecureContext + " | origin=" + window.location.origin + " | localStorage.length=" + localStorage.length);
    const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

    async function makeBootstrapCred() {
      const chal = document.getElementById('bootChal').value.trim();
      if (!chal) return log("Paste the base64url challenge printed by auth_cli bootstrap-begin");
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: b64uToBuf(chal),
          rp: { name: "LocuGard", id: window.location.hostname },
          user: { id: new TextEncoder().encode("owner_bootstrap"), name: "Owner", displayName: "Owner" },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
          authenticatorSelection: { userVerification: "required" },
          timeout: 60000
        }
      });
      const out = {
        id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
        response: {
          attestationObject: bufToB64u(cred.response.attestationObject),
          clientDataJSON: bufToB64u(cred.response.clientDataJSON)
        }
      };
      log("BOOTSTRAP_CRED_JSON (save to cred.json and pass to auth_cli bootstrap-complete):\\n" + JSON.stringify(out));
    }

    async function doLogin() {
      const r1 = await fetch('/auth/login/options', { method: 'POST' });
      const { challenge_id, options } = await r1.json();
      options.challenge = b64uToBuf(options.challenge);
      const cred = await navigator.credentials.get({ publicKey: options });
      const r2 = await fetch('/auth/login/verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challenge_id,
          credential: {
            id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
            response: {
              authenticatorData: bufToB64u(cred.response.authenticatorData),
              clientDataJSON: bufToB64u(cred.response.clientDataJSON),
              signature: bufToB64u(cred.response.signature),
              userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
            }
          }
        })
      });
      const body = await r2.json();
      if (body.csrf_token) csrf = body.csrf_token;
      log("LOGIN " + r2.status + ": " + JSON.stringify(body));
    }

    async function doProfile() {
      const r = await fetch('/api/protected/profile');
      log("PROFILE " + r.status + ": " + await r.text());
    }

    async function doReauth() {
      const r1 = await fetch('/auth/reauth/options', { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
      const { challenge_id, options } = await r1.json();
      options.challenge = b64uToBuf(options.challenge);
      if (options.allowCredentials) options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: b64uToBuf(c.id) }));
      const cred = await navigator.credentials.get({ publicKey: options });
      const r2 = await fetch('/auth/reauth/verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          challenge_id,
          credential: {
            id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
            response: {
              authenticatorData: bufToB64u(cred.response.authenticatorData),
              clientDataJSON: bufToB64u(cred.response.clientDataJSON),
              signature: bufToB64u(cred.response.signature),
              userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
            }
          }
        })
      });
      log("REAUTH " + r2.status + ": " + await r2.text());
    }

    async function doDangerReq() {
      const target = document.getElementById('actTarget').value;
      const r = await fetch('/api/protected/dangerous-action/request', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ target, note: "quickstart-check" })
      });
      const body = await r.json();
      if (r.ok) lastApproval = body;
      log("DANGER_REQ " + r.status + ": " + JSON.stringify(body));
    }

    async function doDangerConf() {
      if (!lastApproval) return log("Request a dangerous action first");
      const r = await fetch('/api/protected/dangerous-action/confirm', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ approval_id: lastApproval.approval_id, action_digest: lastApproval.action_digest })
      });
      log("DANGER_CONF " + r.status + ": " + await r.text());
    }

    async function doGenRecovery() {
      const r = await fetch('/api/recovery-codes', { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
      log("RECOVERY " + r.status + ": " + await r.text());
    }

    async function doLogout() {
      const r = await fetch('/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
      csrf = "";
      log("LOGOUT " + r.status + ": " + await r.text());
    }
  </script>
</body>
</html>
"""


def build_app():
    store = AuthStore(DATA_DIR, pepper_path=SECRETS_DIR / "auth_pepper.key", allow_create_pepper=False)
    auth = AuthService(store, rp_id=RP_ID, expected_origin=ORIGIN)
    channels = AuthChannels(store, auth)
    perms = LocalPermissions(DATA_DIR)
    bridge = AuthPermissionsBridge(store, auth, perms)
    app = create_web_app(auth, bridge)

    async def index(req: Request) -> HTMLResponse:
        return HTMLResponse(QUICKSTART_UI)

    async def gen_recovery(req: Request) -> JSONResponse:
        try:
            if req.headers.get("origin") != ORIGIN:
                raise AuthError("invalid_origin", status_code=403)
            ctx = auth.verify_session(req.cookies.get(SESSION_COOKIE), peer_ip=req.client.host if req.client else None)
            auth.verify_csrf(ctx.session_id, req.headers.get("x-csrf-token"))
            return JSONResponse(channels.generate_recovery_codes(ctx))
        except AuthError as e:
            return JSONResponse({"error": e.code}, status_code=e.status_code)

    app.routes.insert(0, Route("/", index, methods=["GET"]))
    app.routes.append(Route("/api/recovery-codes", gen_recovery, methods=["POST"]))
    return app


if __name__ == "__main__":
    uvicorn.run(
        build_app(),
        host=HOST,
        port=PORT,
        ssl_certfile=str(SECRETS_DIR / "web_tls.crt"),
        ssl_keyfile=str(SECRETS_DIR / "web_tls.key"),
    )
