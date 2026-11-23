# Deployment & Integration Guide (For Developers and AI Agents)

This guide provides the exact commands, HTTP API contract, and Python embedding patterns needed to deploy LocuGard from scratch or integrate it into an existing Python service.

---

## 1. Deployment Checklist (Hard Rules)

Follow every rule below when assisting a user with deployment:

1. **Always use HTTPS + a stable hostname** (e.g., `locugard.home.arpa` or a real domain). Never deploy over plain `http://` or raw LAN IPs (`192.168.x.x`): WebAuthn and `__Host-` cookies require a secure context with a hostname.
2. **Store secrets on an ACL-capable filesystem (`NTFS`, `ext4`, `APFS`), never `exFAT`/`FAT32`.** Keep `auth_pepper.key` and TLS private keys `0600` / owner-only.
3. **Never auto-create an owner from a web request.** The first `owner` must be bootstrapped strictly via local console (`python -m locugard.auth_cli`). Check status first with `auth_cli status`.
4. **Keep `rp_id` and `expected_origin` exact:** `rp_id` is the bare hostname (e.g., `locugard.home.arpa`), and `expected_origin` includes scheme + host + non-default port (e.g., `https://locugard.home.arpa:8443`).
5. **If behind a reverse proxy (Caddy/Nginx/Traefik):** pass `trusted_proxies=["127.0.0.1"]` (or the proxy IP) into `AuthService(...)`. Never trust `X-Forwarded-For` from arbitrary peers.
6. **Never store session tokens in `localStorage` or disable auth as a troubleshooting shortcut.**

---

## 2. 5-Minute End-to-End Quickstart

### Step 1: Install with `[web]` extra

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e ".[web]"
```

### Step 2: Generate Local CA, TLS Cert, Persistent Pepper & DB

```bash
python examples/quickstart/setup.py --rp-id locugard.home.arpa
```

*(Alternatively, use `mkcert -install && mkcert locugard.home.arpa` and place the cert/key in `examples/quickstart/secrets/web_tls.crt` and `web_tls.key`.)*

### Step 3: Trust the Local CA & Map Hostname

- **Local DNS / hosts:** map `127.0.0.1 locugard.home.arpa` (or your server's LAN IP on your router/Pi-hole):
  - Linux/macOS: `/etc/hosts`
  - Windows (Admin PowerShell): `Add-Content C:\Windows\System32\drivers\etc\hosts "`r`n127.0.0.1 locugard.home.arpa"`
- **Install Root CA** (`examples/quickstart/secrets/locugard-local-ca.crt`):
  - Windows (current user, no admin required): `certutil -user -addstore Root examples\quickstart\secrets\locugard-local-ca.crt`
  - macOS: `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db examples/quickstart/secrets/locugard-local-ca.crt`
  - Linux (Debian/Ubuntu): copy `.crt` to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`.

### Step 4: Start the HTTPS Server

```bash
python examples/quickstart/server.py
```

Open `https://locugard.home.arpa:8443/` in your browser and verify `isSecureContext=true`.

### Step 5: Bootstrap the First Owner (Local Console)

```bash
# 1. Generate a bootstrap challenge:
python -m locugard.auth_cli \
  --data-dir examples/quickstart/data \
  --pepper-path examples/quickstart/secrets/auth_pepper.key \
  --rp-id locugard.home.arpa \
  --origin https://locugard.home.arpa:8443 \
  bootstrap-begin --name "Alice"
```

Paste the printed `challenge` into the browser's **Bootstrap Helper**, click **Create WebAuthn JSON for CLI**, save the JSON output to `cred.json`, then complete registration:

```bash
python -m locugard.auth_cli \
  --data-dir examples/quickstart/data \
  --pepper-path examples/quickstart/secrets/auth_pepper.key \
  --rp-id locugard.home.arpa \
  --origin https://locugard.home.arpa:8443 \
  bootstrap-complete \
  --challenge-id <challenge_id> \
  --name "Alice" \
  --device-name "Main-Laptop" \
  --credential-json cred.json \
  --hardware-binding
```

Verify initialization (`{"initialized": true}`):

```bash
python -m locugard.auth_cli \
  --data-dir examples/quickstart/data \
  --pepper-path examples/quickstart/secrets/auth_pepper.key \
  status
```

Now click **Sign in with WebAuthn** in the browser, verify `/api/protected/profile`, test a dangerous action, and immediately generate & store your 10 offline recovery codes.

---

## 3. HTTP API Reference (`locugard.web_server`)

All mutating (`POST`) endpoints require an exact `Origin` header matching `expected_origin`. Authenticated mutating endpoints additionally require the `__Host-locugard_sid` cookie and the `X-CSRF-Token` header returned by `/auth/login/verify`.

| Method & Path | Auth Required | CSRF | Purpose / Request JSON |
| --- | --- | --- | --- |
| `POST /auth/login/options` | No | No | Returns `{challenge_id, options}` for `navigator.credentials.get()`. |
| `POST /auth/login/verify` | No | No | `{challenge_id, credential}` → sets `__Host-locugard_sid` cookie and returns `{account_id, role, device_id, csrf_token}`. |
| `POST /auth/reauth/options` | Session | Yes | Step-up challenge `{challenge_id, options}` for fresh verification. |
| `POST /auth/reauth/verify` | Session | Yes | `{challenge_id, credential, purpose?, target_digest?}` → `{verification_id, verified_at}`. |
| `POST /auth/logout` | Session | Yes | Revokes current session and clears `__Host-locugard_sid`. |
| `POST /api/devices/enrollment-codes` | Owner + fresh | Yes | `{target_account_id?, role?, ttl_s?}` → one-time `{code, code_id, expires_at}`. |
| `POST /auth/register/options` | No (code) | No | `{code, device_name}` → returns `{challenge_id, registration_request_id, options}`. |
| `POST /auth/register/submit` | No (challenge) | No | `{challenge_id, registration_request_id, credential, hardware_binding?}` → submits pending device for owner approval. |
| `POST /api/devices/registrations/{request_id}/approve` | Owner + fresh | Yes | `{second_verification_id?}` → activates pending device & credential. |
| `POST /api/devices/{device_id}/revoke` | Owner + fresh | Yes | `{reason?, second_verification_id?}` → immediately revokes device, credentials, sessions, and refresh chains. |
| `GET /api/protected/profile` | Session | No | Returns `{account_id, role, device_id, effective_mode, network_zone}`. |
| `POST /api/protected/dangerous-action/request` | Session + fresh | Yes | `{target, note?, second_verification_id?}` → `{approval_id, action_digest, permissions_pid, expires_at}`. |
| `POST /api/protected/dangerous-action/confirm` | Session + fresh | Yes | `{approval_id, action_digest}` → re-verifies auth state live and executes via `Permissions.confirm()`. |

---

## 4. Embedding LocuGard in Your Own App

### Protecting Your Own Starlette / FastAPI Route

```python
from starlette.requests import Request
from starlette.responses import JSONResponse
from locugard.auth_service import AuthError
from locugard.web_server import SESSION_COOKIE

async def my_protected_endpoint(req: Request) -> JSONResponse:
    try:
        if req.method != "GET" and req.headers.get("origin") != auth.expected_origin:
            raise AuthError("invalid_origin", status_code=403)

        ctx = auth.verify_session(
            req.cookies.get(SESSION_COOKIE),
            peer_ip=req.client.host if req.client else None,
            forwarded_for=req.headers.get("x-forwarded-for"),
        )
        if req.method != "GET":
            auth.verify_csrf(ctx.session_id, req.headers.get("x-csrf-token"))

        return JSONResponse({"ok": True, "account_id": ctx.account_id, "role": ctx.role})
    except AuthError as e:
        return JSONResponse({"error": e.code}, status_code=e.status_code)
```

### Registering Custom Dangerous Actions & Custom `Permissions`

1. **Register server-side risk classes** in `SERVER_ACTION_CATALOG` (unlisted actions fail closed as `critical=True`, `owner`-only):

```python
from locugard.auth_permissions import SERVER_ACTION_CATALOG

SERVER_ACTION_CATALOG["deploy.restart_service"] = {
    "critical": True,
    "allowed_roles": ("owner",),
}
```

2. **Use your own `Permissions` dispatcher** by passing any object implementing `submit(action) -> Outcome`, `confirm(pid, always=False) -> Outcome`, and `reject(pid) -> Outcome` (matching `locugard.permissions_adapter.LocalPermissions`) into `AuthPermissionsBridge(store, auth, your_permissions)`.
