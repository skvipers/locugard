# Operations & Deployment Guide

This guide covers safe deployment, local HTTPS/DNS setup, secret management, online SQLite backups, recovery, and rollback practices for LocuGard.

## 1. Local DNS & HTTPS (Required Even in LAN)

WebAuthn/passkeys and `__Host-` cookies require a **secure context (`https://`) with a stable hostname**. Do not deploy LocuGard over plain `http://` or raw LAN IP addresses (`192.168.x.x`).

1. **Choose a stable local hostname** under RFC 8375 `.home.arpa` (for example, `locugard.home.arpa`) or your own domain:
   - On a local router/DNS server (Pi-hole, Unbound, dnsmasq): map `locugard.home.arpa` → your server's LAN IP.
   - For single-machine local testing: add `127.0.0.1 locugard.home.arpa` to `/etc/hosts` (Linux/macOS) or `C:\Windows\System32\drivers\etc\hosts` (Windows, Administrator shell).
2. **Issue a trusted TLS certificate:**
   - Recommended options: a private local CA (e.g., `mkcert` or an internal ECDSA P-256 CA) whose root certificate is installed into your client devices' trust stores, or Let's Encrypt via DNS-01 for a real domain.
   - Include `DNS:locugard.home.arpa` in the certificate's Subject Alternative Name (SAN).
3. **Configure matching `rp_id` and `expected_origin`:**
   - `rp_id = "locugard.home.arpa"`
   - `expected_origin = "https://locugard.home.arpa:8443"` (include the port if non-443).
4. **Reverse proxy (optional):**
   - If terminating TLS in Caddy/Nginx/Traefik, pass the proxy's exact IP(s) in `trusted_proxies` so `extract_client_ip()` resolves client IPs right-to-left from `X-Forwarded-For` without trusting client-spoofed headers.

---

## 2. Secret Storage & Filesystem Requirements

LocuGard requires two secret materials on disk/env:

1. **TLS private key** (e.g., `server.key`)
2. **Persistent 256-bit HMAC pepper** (`LOCUGARD_AUTH_PEPPER` environment variable or `secrets/auth_pepper.key`)

> **Important filesystem warning:** Store secrets **only on an ACL-capable filesystem** (`NTFS`, `ext4`, `APFS`) with strict owner-only permissions (`chmod 0600` on Unix, or `icacls` restricted to the service user on Windows NTFS). **Never store secrets on `exFAT` or `FAT32` volumes**, which do not enforce per-user file ACLs.

- Do not rotate or delete `auth_pepper.key` casually: changing the pepper invalidates all active session hashes, refresh chains, and previously printed offline recovery codes.
- Never commit `*.key`, `*.crt`, `*.pem`, `*.sqlite3*`, `*.jsonl`, or `.env` files to version control.

---

## 3. Bootstrap & Local Console Administration

The first `owner` account can only be created from the local server console (`python -m locugard.auth_cli`):

```bash
# 1. Start bootstrap challenge (prints challenge_id and WebAuthn creation options)
python -m locugard.auth_cli \
  --data-dir ./data \
  --pepper-path ./secrets/auth_pepper.key \
  --rp-id locugard.home.arpa \
  --origin https://locugard.home.arpa:8443 \
  bootstrap-begin --name "Alice"

# 2. Complete bootstrap with the browser's WebAuthn attestation JSON
python -m locugard.auth_cli \
  --data-dir ./data \
  --pepper-path ./secrets/auth_pepper.key \
  --rp-id locugard.home.arpa \
  --origin https://locugard.home.arpa:8443 \
  bootstrap-complete \
  --challenge-id <challenge_id> \
  --name "Alice" \
  --device-name "Main-Laptop" \
  --credential-json ./cred.json \
  --hardware-binding
```

Immediately after first login:
- Generate and print/store offline **10 one-time recovery codes** in a physically secure location.
- Register a second trusted device if you plan to enable **Mode 3 (Strict)**.

---

## 4. Online Backups & Restore

Because `auth.sqlite3` runs in `WAL` mode, **never back it up by raw file copy while the server is running**. Use Python's `sqlite3.Connection.backup()` API so WAL pages are captured consistently:

```python
import sqlite3
from pathlib import Path

src = sqlite3.connect("file:./data/auth.sqlite3?mode=ro", uri=True)
dst = sqlite3.connect("./backups/auth-backup.sqlite3")
with dst:
    src.backup(dst)
dst.close()
src.close()
```

- Protect backups with the same confidentiality level as `auth.sqlite3`.
- Keep `auth_pepper.key` backed up separately in encrypted offline storage; without the matching pepper, stored recovery code hashes cannot be verified after a restore.

---

## 5. Audit Monitoring

LocuGard writes structured JSONL events to `<data_dir>/logs/auth_audit.jsonl`. Recommended operational checks:

- Alert on repeated `login_failed`, `enrollment_claim_failed`, `refresh_reuse_detected`, `sign_count_rollback`, and `action_blocked_revoked` events.
- Periodically rotate `auth_audit.jsonl` (copytruncate or restart-safe logrotate) and verify that no raw secrets, cookies, or tokens appear in log lines.

---

## 6. Safe Rollback Rules

If a deployment or upgrade misbehaves:

1. **Never bypass or disable authentication** as a "quick fix" to restore access.
2. Stop the web listener first, restore the previous verified package version and consistent SQLite backup (if schema changed), and restart over HTTPS.
3. If an account or device is suspected compromised during an incident, revoke the device immediately via web UI or `auth_cli` (or switch `server_policy.min_mode` to `4` to isolate to owner hardware sessions only).
