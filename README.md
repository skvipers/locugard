# LocuGard

**Embeddable multi-level WebAuthn/passkey authentication, strictness policies, and dangerous-action approval guard for self-hosted Python apps and AI agents.**

LocuGard fills the gap between *"no auth because it's on my LAN"* and heavy enterprise identity providers (Keycloak, Authentik). It embeds cleanly into any Python 3.11+ service with a single SQLite database, **zero core dependencies**, and an optional Starlette/WebAuthn HTTPS layer.

> **Status (`v0.3.0`):** Built-in EN/RU Web UI (`include_ui=True`, `/`, `/bootstrap`, `/enroll`, `/pair`), browser-assisted native Device Pairing (`/auth/app/pair/*` for Flutter Windows/Android), centralized Browser SSO with PKCE S256 (`/sso/authorize` + `/api/service/sso/token` for Docalaizer & internal web apps), native HTTPS API (`/auth/app/*`), and service introspection + real-time SSE revocation (`/api/service/*`). Internally red-team audited with automated integration tests covering all threat scenarios, but not yet externally audited by a third-party firm. See [SECURITY.md](SECURITY.md).

---

## Key Features

- **Unified Identity Model (`Account ↔ Device ↔ Credential ↔ Session`):** One internal `account_id` and shared device/key registry across web, native apps, and optional verified bot channels (e.g., Telegram).
- **Zero Primary Passwords:** Browser login via WebAuthn/passkeys (`py_webauthn`); native app login via OS-keystore ECDSA P-256 keys with short-lived access tokens (≤ 10 min) and rotating `RefreshTokenChain` (replaying any prior generation immediately revokes the chain and session).
- **Four Strictness Modes (one protocol, monotonic `max(server, actor, target, action)`):**
  1. **Mode 1 (Trusted LAN):** low-risk `R1` inside explicit LAN CIDRs; automatically upgrades to Mode 2 (or denies) outside LAN.
  2. **Mode 2 (Standard — recommended default):** 7d / 12h session, UV required, 10 min identity freshness for dangerous actions.
  3. **Mode 3 (Strict):** 8h / 30m session, 2 min freshness, hardware-bound keys required, independent second trusted device (or local console) for all `R4` security changes and critical `R3` actions. Synced passkeys cannot spoof two independent devices.
  4. **Mode 4 (Isolated):** 2h / 15m session, `owner` + hardware key only (non-owner sessions and pending enrollments revoked immediately), single-use `IdentityVerification` per action, remote recovery disabled.
- **Action-Approval Guard (`Permissions` bridge):** Separates *who logged in* from *explicit approval of a dangerous action* (`action_digest` over canonical payload, server-side `SERVER_ACTION_CATALOG`, re-verification of session/device/role/policy at execution time, instant block if revoked while waiting).
- **Safe Bootstrap & Recovery:** First `owner` is created strictly via local console (`python -m locugard.auth_cli`), never by the first visitor in LAN. Offline 10-code recovery sets revoke all prior sessions, keys, and remaining old codes upon completion; no secret questions or hidden master passwords.
- **Browser Hardening:** `__Host-locugard_sid` cookie (`HttpOnly; Secure; SameSite=Lax`), exact `Origin` + session-bound CSRF token, `Cache-Control: no-store`, `HSTS`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `CSP: frame-ancestors 'none'`, zero `localStorage` tokens.

---

## Installation

Core SQLite store, rate limiter, and `Permissions` bridge require **Python 3.11+ standard library only**:

```bash
pip install -e .
```

With the optional HTTPS/WebAuthn web server stack (`starlette`, `uvicorn`, `webauthn`):

```bash
pip install -e ".[web]"
```

---

## Quick Start

### 1. Initialize Storage and First Owner (Local Console Only)

Set a persistent 256-bit pepper (`LOCUGARD_AUTH_PEPPER` env var or a `0600` file on an ACL-capable filesystem):

```bash
python -m locugard.auth_cli --data-dir ./data --rp-id locugard.home.arpa --origin https://locugard.home.arpa:8443 bootstrap-begin --name "Alice"
# Complete WebAuthn registration in your browser and pass the JSON response:
python -m locugard.auth_cli --data-dir ./data --rp-id locugard.home.arpa --origin https://locugard.home.arpa:8443 bootstrap-complete \
  --challenge-id <chal_id> --name "Alice" --device-name "Main-Laptop" --credential-json ./cred.json --hardware-binding
```

### 2. Embed in Python (Starlette / Custom App)

```python
from pathlib import Path
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthService
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from locugard.web_server import create_web_app

store = AuthStore(Path("./data"), pepper_path=Path("./secrets/auth_pepper.key"))
auth = AuthService(store, rp_id="locugard.home.arpa", expected_origin="https://locugard.home.arpa:8443")
perms = LocalPermissions(Path("./data"))  # or pass your own Permissions implementation
bridge = AuthPermissionsBridge(store, auth, perms)

app = create_web_app(auth, bridge)
# Run with uvicorn over HTTPS (--ssl-certfile / --ssl-keyfile)
```

---

## Running Tests

Full suite (including real HTTPS TLS + WebAuthn + all 8 security scenarios and red-team regressions):

```bash
python -m unittest discover -s tests -v
```

Pure standard-library tests run even without `[web]` installed (WebAuthn/HTTPS tests are skipped cleanly when optional extras are absent).

---

## Documentation

- [docs/INTEGRATION.md](docs/INTEGRATION.md) — 5-minute quickstart, deployment checklist for developers & AI agents, full HTTP API reference, and embedding recipes.
- [examples/quickstart/](examples/quickstart/) — runnable local HTTPS + WebAuthn quickstart (`setup.py` + `server.py` with live browser UI).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — logical domain model, lifecycles, and strictness algorithm.
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — trust boundaries, protocols `P0`–`P10`, 34 threats (`T01`–`T34`), and residual risks.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — HTTPS/local DNS setup, secret storage, SQLite online backups, recovery, and rollback rules.
- [SECURITY.md](SECURITY.md) — security invariants and vulnerability reporting.

## License

[MIT](LICENSE)
