# Architecture & Domain Model

LocuGard implements a unified authentication, authorization, and dangerous-action approval subsystem designed to embed cleanly into self-hosted Python applications and AI agent services.

## 1. Design Principles

1. **Unified identity across channels:** Web browsers, native apps, and optional verified bot channels (such as Telegram) share one `Account ↔ Device ↔ Credential ↔ Session` registry. External IDs are bindings, never primary keys.
2. **Cryptographic possession over passwords:** Primary login relies on WebAuthn/passkeys (`web`) or OS-keystore ECDSA P-256 keys (`app`). Private keys never leave the client.
3. **Honest device semantics:** A `Device` represents an installation or browser profile + credential registration, not a guaranteed physical machine. Synced passkeys (`backup_state = 'synced'`) are explicitly tracked and cannot satisfy hardware-bound requirements or impersonate two independent devices in Strict mode.
4. **Network metadata is context, not identity:** IP address, MAC, hostname, and `User-Agent` are audit/UI hints only. LAN membership never grants owner access or lowers strictness below server/account/action minimums.
5. **Separation of concerns:** Authentication (`IdentityVerification`), authorization (role + policy checks), and explicit dangerous-action approval (`ActionApproval` + `Permissions`) are distinct layers, all re-verified at execution time.

---

## 2. Core Entities (SQLite Schema v3)

All state is stored in a single WAL-mode SQLite database (`auth.sqlite3`) with foreign keys enforced. Raw secrets (session tokens, CSRF tokens, enrollment codes, recovery codes, refresh tokens) are never stored in plaintext—only HMAC-SHA256 hashes keyed with a persistent 256-bit `LOCUGARD_AUTH_PEPPER`.

| Entity / Table | Purpose | Lifecycle States |
| --- | --- | --- |
| `server_policy` | Global strictness floor (`min_mode`), TTLs, `allowed_networks_json`, `outside_lan_behavior`, `policy_version`. | Singleton row (`id = 1`) |
| `accounts` | Immutable internal `account_id`, `display_name`, `role` (`owner`, `member`, `guest`, `readonly`), `min_mode`, `policy_version`. | `active` ↔ `suspended` |
| `external_identities` | Verified bindings to external providers (e.g., Telegram subject). Unique active `(provider, provider_subject)`. | `active` → `revoked` |
| `devices` | Registered client installation/profile with `hardware_binding` flag and `attestation_level`. | `pending` → `active` → `revoked` |
| `credentials` | Public key (`public_key`, `external_credential_id`, `key_fingerprint`, `sign_count`, `backup_state`). | `pending` → `active` → `revoked` |
| `challenges` | Single-use cryptographic challenge bound to `purpose`, `origin`, `rp_id`, and optional account/device/request. | `issued` → `consumed` \| `expired` \| `invalidated` |
| `identity_verifications` | Immutable proof of a completed cryptographic or console verification (`method`, `verified_at`, `purpose`, `target_digest`, `consumed_by_approval_id`). | Immutable (single-use in Mode 4) |
| `sessions` | Active web or app session bound to `account_id`, `device_id`, `credential_id`, `csrf_token_hash`, `policy_version`, `network_zone`, `expires_at`, `idle_expires_at`, and `access_token_expires_at` (for `app`). | `active` → `expired` \| `revoked` |
| `refresh_token_chains` & `refresh_token_history` | Rotating native-app refresh chains (`generation`). Reusing any historical token revokes the entire chain and its session. | `active` → `revoked` |
| `enrollment_codes` & `registration_requests` | Short-lived one-time enrollment codes (`5 min`, max 5 failed attempts) and pending device approvals awaiting owner confirmation. | `issued` → `claimed` → `approved` \| `rejected` \| `expired` |
| `recovery_codes` & `recovery_requests` | Offline 10-code recovery sets (`128-bit` base32) and high-risk recovery flows that revoke all prior credentials, sessions, and unused old codes. | `active` → `used` \| `revoked` |
| `action_approvals` | Server-side record bridging an authenticated request to a host `Permissions` pending ID (`TEXT` to support >64-bit IDs) with canonical `action_digest`. | `pending` → `approved` \| `rejected` \| `expired` \| `blocked` |
| `telegram_link_requests` & `telegram_callbacks` | Interactive Telegram account binding and replay-protected callback deduplication. | `issued` → `received` → `confirmed` \| `expired` \| `cancelled` |

---

## 3. Strictness Modes & `effective_mode` Algorithm

LocuGard uses **one protocol** configured by four strictness levels:

| Parameter | Mode 1 (Trusted LAN) | Mode 2 (Standard, default) | Mode 3 (Strict) | Mode 4 (Isolated) |
| --- | --- | --- | --- | --- |
| Session max TTL | 14 days | 7 days | 8 hours | 2 hours |
| Idle TTL | 24 hours | 12 hours | 30 min | 15 min |
| Identity freshness (`R3`/`R4`) | 30 min | 10 min | 2 min | Single-use per action |
| User Verification (UV) | Preferred in LAN (`R1`), required for `R3`/`R4` | Always required | Always required | Always required |
| Hardware-bound key required | No | No | Yes | Yes |
| Second independent device / console | No | No | Required for `R4` & critical `R3` | Local console / hardware only |
| Roles permitted | All active | All active | All active | `owner` only |
| Remote recovery | Allowed | Allowed | Two-factor / console | Local console only |

### Monotonic Calculation

For every action or request, the effective strictness is strictly monotonic:

```text
effective_mode = max(
    server_policy.min_mode,
    actor_account.min_mode,
    target_account.min_mode,   # when operating on another account
    action_min_mode,           # derived from server-side risk class R1..R4
    network_upgrade(zone),     # outside LAN upgrades Mode 1 → Mode 2 (or denies)
)
```

- Neither a client, a network change, nor a newly registered device can lower `effective_mode`.
- Switching `server_policy.min_mode` to Mode 4 immediately revokes all non-owner sessions, non-hardware sessions, and pending enrollments/recoveries, and increments `policy_version`.

---

## 4. Action-Approval Bridge (`AuthPermissionsBridge`)

LocuGard separates **identity verification** from **dangerous-action execution**:

1. **Server-side risk catalog (`SERVER_ACTION_CATALOG`):** The server classifies actions into risk levels `R1` (read), `R2` (state-changing safe), `R3` (dangerous / critical), and `R4` (security administration). Clients cannot downgrade an action's risk or `critical` flag.
2. **Submission:** `submit_action()` verifies session, role (`readonly` is blocked from mutating actions), freshness, and Mode 3/4 constraints, computes a canonical `action_digest`, creates a `Permissions` pending item, and links it in `action_approvals`.
3. **Confirmation & Execution:** `confirm_action()` re-verifies in real time that the session, device, credential, account, and `policy_version` are still valid and that `action_digest` matches before calling `Permissions.confirm()`. If a device or session was revoked while waiting, execution is immediately blocked (`blocked`).

---

## 5. Package Layout

- `locugard/auth_store.py` — SQLite WAL persistence, atomic `BEGIN IMMEDIATE` transactions, persistent HMAC pepper loading, and thread-safe JSONL audit logger (pure stdlib).
- `locugard/auth_ratelimit.py` — In-memory sliding-window rate limiter (pure stdlib).
- `locugard/auth_service.py` — Core authentication protocols (`P0`–`P10`), WebAuthn & ECDSA P-256 verification, strictness enforcement, and proxy-safe `extract_client_ip()`.
- `locugard/auth_channels.py` — Optional Telegram binding and verified approval helpers.
- `locugard/auth_permissions.py` & `locugard/permissions_adapter.py` — `AuthPermissionsBridge` and built-in `LocalPermissions` adapter (pure stdlib).
- `locugard/web_server.py` — Optional Starlette HTTPS API with `__Host-locugard_sid` cookie, CSRF/Origin checks, and security headers.
- `locugard/auth_cli.py` — Local console CLI for `bootstrap-owner`, recovery, revocation, and policy changes.
