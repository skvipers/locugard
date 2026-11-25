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
| `GET /` *(when `include_ui=True`)* | No | No | Built-in Web UI (sign-in, session card, devices/enrollment/approvals, dangerous actions, offline recovery codes). |
| `POST /auth/login/options` | No | No | Returns `{challenge_id, options}` for `navigator.credentials.get()`. |
| `POST /auth/login/verify` | No | No | `{challenge_id, credential}` → sets `__Host-locugard_sid` cookie and returns `{account_id, role, device_id, csrf_token}`. |
| `POST /auth/reauth/options` | Session | Yes | Step-up challenge `{challenge_id, options}` for fresh verification. |
| `POST /auth/reauth/verify` | Session | Yes | `{challenge_id, credential, purpose?, target_digest?}` → `{verification_id, verified_at}`. |
| `POST /auth/logout` | Session | Yes | Revokes current session and clears `__Host-locugard_sid`. |
| `GET /api/devices` | Session | No | Returns `{devices: [...]}` (all devices for `owner`, own devices for non-`owner`). |
| `POST /api/devices/enrollment-codes` | Owner + fresh | Yes | `{target_account_id?}` → one-time `{enrollment_id, secret, target_account_id, allowed_role, expires_at}`. |
| `GET /api/devices/registrations` | Owner | No | Returns `{requests: [...]}` of pending device registrations with `key_fingerprint`. |
| `POST /auth/register/options` | No (code) | No | `{enrollment_id, secret}` → returns `{challenge_id, options, allowed_role, target_account_id}`. |
| `POST /auth/register/submit` | No (challenge) | No | `{enrollment_id, secret, challenge_id, device_name, requested_role, credential}` → submits pending device for owner approval. |
| `POST /api/devices/registrations/{request_id}/approve` | Owner + fresh | Yes | `{second_verification_id?}` → activates pending device & credential. |
| `POST /api/devices/{device_id}/revoke` | Owner / self | Yes | Immediately revokes device, credentials, sessions, refresh chains, and emits a real-time revocation event. |
| `POST /api/recovery-codes` | Owner + fresh | Yes | `{second_verification_id?, target_digest?}` → generates 10 one-time offline recovery codes. |
| `GET /api/protected/profile` | Session | No | Returns `{account_id, display_name, role, device_id, effective_mode, network_zone}`. |
| `POST /api/protected/dangerous-action/request` | Session + fresh | Yes | `{target, note?, second_verification_id?}` → `{approval_id, action_digest, description, expires_at, state}`. |
| `POST /api/protected/dangerous-action/confirm` | Session + fresh | Yes | `{approval_id, action_digest}` → re-verifies auth state live and executes via `Permissions.confirm()`. |

---

## 3.1 Native Client HTTPS Contract (`v0.2.0` — Flutter Windows / Android)

Native clients use OS-keystore ECDSA P-256 keys (Windows CNG / Android Keystore), do **not** use browser cookies, and do **not** require `Origin` or CSRF headers. All endpoints run over HTTPS and reuse `locugard.auth_channels.AuthChannels`.

### Enrollment (binding a new device to an existing account)

1. Owner creates a one-time enrollment code (`POST /api/devices/enrollment-codes` or Web UI → **Устройства**) and passes `{enrollment_id, secret}` to the native device (QR / copy).
2. **`POST /auth/app/register/options`**
   - Request: `{"enrollment_id": "enr_...", "secret": "..."}`
   - Response `200`: `{"challenge_id": "chal_...", "challenge_hex": "...", "rp_id": "locugard.home.arpa", "allowed_role": "owner", "target_account_id": "acc_...", "expires_at": 1764000300.0}`
   - Errors: `401 enrollment_code_invalid | enrollment_code_expired`, `429 rate_limited`.
3. Native client generates ECDSA P-256 keypair in OS keystore and signs the domain-separated PoP bytes:
   `utf8("locugard:app_register:{rp_id}:{enrollment_id}:") + bytes.fromhex(challenge_hex)` (SHA-256, ASN.1 DER signature, base64url or base64 encoded).
4. **`POST /auth/app/register/submit`**
   - Request: `{"enrollment_id", "secret", "challenge_id", "device_name", "requested_role", "public_key_pem", "signature_b64", "hardware_binding": true}`
   - Response `200`: `{"request_id": "rreq_...", "device_id": "dev_...", "credential_id": "cred_...", "key_fingerprint": "a1b2:...", "state": "pending", "expires_at": ...}`
   - Errors: `400 invalid_payload`, `401 challenge_invalid | challenge_expired | invalid_signature`, `403 role_mismatch | hardware_key_required | new_devices_forbidden_in_mode_4`, `429 rate_limited | too_many_pending_registrations`.
5. Owner verifies `key_fingerprint` and approves `request_id` on a trusted device (`POST /api/devices/registrations/{request_id}/approve` or Web UI).

### Login, Session Refresh & Logout

1. **`POST /auth/app/login/options`**
   - Request: `{"device_id": "dev_..."}`
   - Response `200`: `{"challenge_id": "chal_...", "challenge_hex": "...", "rp_id": "locugard.home.arpa", "expires_at": ...}`
2. Native client signs `utf8("locugard:app_login:{rp_id}:{device_id}:") + bytes.fromhex(challenge_hex)` after OS biometric/PIN verification (`user_verified: true`).
3. **`POST /auth/app/login/verify`**
   - Request: `{"challenge_id", "device_id", "signature_b64", "user_verified": true, "audience": "apogeus"}`
   - Response `200`:
     ```json
     {
       "session_id": "sess_...",
       "chain_id": "chn_...",
       "account_id": "acc_...",
       "role": "owner",
       "device_id": "dev_...",
       "audience": "apogeus",
       "access_token": "...",
       "access_expires_in": 600,
       "access_expires_at": 1764000600.0,
       "session_expires_at": 1764604800.0,
       "idle_expires_at": 1764043200.0,
       "refresh_token": "...",
       "generation": 1
     }
     ```
   - Errors: `400 invalid_payload | invalid_audience`, `401 authentication_failed | challenge_expired`, `403 outside_allowed_network | role_forbidden_in_mode | user_verification_required | hardware_key_required`.
4. **`POST /auth/app/refresh`**
   - Request: `{"refresh_token": "..."}`
   - Response `200`: `{"session_id", "audience", "access_token", "refresh_token", "generation": 2, "access_expires_in": 600, "access_expires_at", "session_expires_at", "idle_expires_at"}`
   - Errors: `401 refresh_invalid | refresh_reuse_detected | refresh_chain_revoked | session_invalid_or_revoked | context_revoked_or_inactive | session_expired`, `403 outside_allowed_network | role_forbidden_in_mode | hardware_key_required`, `429 rate_limited`.
   - **Reuse protection:** replaying any previously rotated `refresh_token` immediately revokes the entire `RefreshTokenChain` and `Session` and emits a `refresh_reuse_detected` revocation event.
5. **`POST /auth/app/logout`**
   - Header: `Authorization: Bearer <access_token>`
   - Response `200`: `{"status": "logged_out"}`

---

## 3.2 Service-to-Service Contract (`v0.2.0` — Apogeus & Docalaizer)

External application backends (such as **Apogeus** and **Docalaizer**) NEVER access LocuGard's SQLite database or `auth_pepper.key`. Instead, each service is configured with its own 256-bit bearer secret in `create_web_app(..., service_tokens={"apogeus": {"token": "...", "audiences": ["apogeus"]}, "docalaizer": {"token": "...", "audiences": ["docalaizer"]}})`.

### 1. Token Introspection & Audience Isolation

- **`POST /api/service/introspect`**
  - Header: `Authorization: Bearer <service_token>`
  - Request: `{"token": "<user_access_token>", "audience": "apogeus", "peer_ip": "192.168.10.42", "touch_activity": true}`
  - Response `200` (valid):
    ```json
    {
      "active": true,
      "account_id": "acc_...",
      "display_name": "Dima",
      "role": "owner",
      "device_id": "dev_...",
      "session_id": "sess_...",
      "audience": "apogeus",
      "effective_mode": 2,
      "network_zone": "lan",
      "access_expires_at": 1764000600.0,
      "session_expires_at": 1764604800.0,
      "idle_expires_at": 1764043200.0,
      "policy_version": 1
    }
    ```
  - Response `200` (revoked / expired / wrong service): `{"active": false, "reason": "session_invalid_or_revoked | access_token_expired | audience_mismatch | ..."}`.
  - **Multi-service isolation:** a token issued with `audience="apogeus"` is strictly rejected when Docalaizer introspects it (`active: false, reason: "audience_mismatch"`). Each app obtains its own audience-scoped session using the same underlying account and device key.

### 2. Real-Time Revocation Stream (Open WebSockets) & Max Latency

- **Push stream (SSE):** `GET /api/service/events?since_seq=<last_seq>` (`Authorization: Bearer <service_token>`).
  - Emits `event: revocation` with `data: {"seq", "event_type", "account_id", "device_id", "session_id", "audience", "reason", "occurred_at"}` immediately upon SQLite commit (`device_revoked`, `session_closed`, `account_sessions_revoked`, `account_suspended`, `refresh_reuse_detected`).
  - Apogeus keeps one persistent HTTPS SSE connection and closes any open WebSocket whose `device_id` / `session_id` / `account_id` matches the event.
- **Catch-up / polling fallback:** `GET /api/service/revocations?since_seq=<last_seq>&limit=100` → `{"events": [...], "last_seq": N}`.
- **Documented maximum revocation latency:**
  - **Normal operation (SSE connected):** **≤ 1 second** (pushed immediately upon commit).
  - **Degraded operation (SSE temporarily disconnected):** **≤ 30 seconds** (recommended periodic re-introspect / catch-up poll interval on active WebSockets; hard ceiling **600 s** at `access_token` expiry).

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
