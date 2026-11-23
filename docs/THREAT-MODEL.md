# Threat Model & Security Protocols

This document summarizes LocuGard's trust boundaries, protocol suite (`P0`–`P10`), mitigated threats (`T01`–`T34`), and known residual risks.

## 1. Trust Boundaries

| Boundary | Description | Enforcement |
| --- | --- | --- |
| **B1: Network → TLS Listener** | Untrusted LAN/WAN traffic entering the HTTPS endpoint. | Mandatory HTTPS with stable local DNS (`*.home.arpa`); plain HTTP / raw LAN IPs are unsupported. `X-Forwarded-For` parsed right-to-left only across explicit `trusted_proxies`. |
| **B2: Browser / Native Client → Auth API** | Client-controlled headers, JSON payloads, cookies, and WebAuthn assertions. | Exact `Origin` + `rp_id` verification, `__Host-` cookie (`HttpOnly; Secure; SameSite=Lax`), session-bound CSRF token, strict JSON validation, server-side `SERVER_ACTION_CATALOG`. |
| **B3: Auth Service → SQLite Store** | Concurrent requests mutating single-use challenges, codes, and token chains. | `BEGIN IMMEDIATE` transactions; failed attempt counters and invalidations commit even when returning `AuthError` (never rolled back on rejection). |
| **B4: Auth Service → Action Execution (`Permissions`)** | Gap between proposing a dangerous action and executing it. | Canonical `action_digest`, real-time re-verification of account/device/credential/session/`policy_version` at execution, immediate block on revocation. |
| **B5: Local Server Console** | Direct administrative CLI (`python -m locugard.auth_cli`). | Trusted administrative boundary for first-owner bootstrap, Mode 4 administration, and last-resort recovery. |

---

## 2. Protocol Suite (`P0`–`P10`)

- **P0 — First-Owner Bootstrap:** Local console only (`bootstrap-begin` → WebAuthn registration → `bootstrap-complete`). Refuses to run once an active `owner` exists. First LAN visitor never becomes owner.
- **P1 — Web Login (WebAuthn/Passkeys):** Server issues single-use 32-byte challenge (`120 s` TTL, max 1 attempt). Verifies `origin`, `rp_id`, `user_verification`, signature, and `sign_count` (rollback alerts/blocks). Sets `__Host-locugard_sid` cookie and returns session-bound CSRF token.
- **P2 — Step-Up Re-Authentication:** Fresh WebAuthn/app assertion bound to `purpose` (e.g. `step_up`, `confirm_action`, `security_change`) and optional `target_digest`. In Mode 4, each `IdentityVerification` is atomically consumed by a single action (`consumed_by_approval_id`).
- **P3 — Native App Auth & Rotating Refresh:** OS-keystore ECDSA P-256 signature over server challenge → short-lived `access_token` (`≤ 10 min`) + `RefreshTokenChain` (`generation = 1`). Refresh rotates generation; replaying any prior generation immediately revokes the chain and session.
- **P4 — Device Enrollment:** Owner (with fresh verification) issues a one-time enrollment code (`5 min`, max 5 attempts) → candidate claims code and submits key → owner explicitly approves device fingerprint (Mode 3 requires an independent second hardware device or local console; synced passkeys cannot count as two independent devices).
- **P5 — Device / Session Revocation:** Immediate revocation of device, its credentials, its active sessions, and its refresh chains. Subsequent requests fail immediately, including in-flight `Permissions` confirmations.
- **P6 — Role & Policy Change:** Owner-only `R4` operation with fresh verification (and independent second approval in Mode 3). Monotonic upgrades to Mode 4 immediately terminate incompatible sessions and pending enrollments.
- **P7 — Dangerous Action Approval (`Permissions`):** `submit_action` checks role, mode, freshness, and server-side risk catalog; `confirm_action` re-checks all auth state and `action_digest` atomically before execution.
- **P8 — Offline Recovery:** Owner generates 10 one-time 128-bit recovery codes (shown once, stored as HMAC-SHA256). Redeeming a valid code + registering a new key revokes all prior sessions, credentials, devices, and remaining old recovery codes (disabled remotely in Mode 4; Telegram cannot confirm recovery in Mode 3).
- **P9 — Verified Bot Channel (Telegram):** Optional out-of-band binding via time-limited nonce verified from an authenticated web/app session. Plain text messages or spoofed user IDs are never accepted as authentication; callback deduplication prevents replay.
- **P10 — Audit Logging:** Thread-safe append-only JSONL log (`auth_audit.jsonl`) recording logins, failures, enrollments, revocations, policy changes, and action approvals with strict redaction of secrets, tokens, private keys, and message contents.

---

## 3. Threat Coverage Summary (`T01`–`T34`)

LocuGard's design and automated regression test suites (`tests/test_auth_scenarios.py`, `tests/test_audit_regressions.py`) address 34 threat classes across 7 categories:

| Range | Threat Category | Key Mitigations |
| --- | --- | --- |
| **T01–T05** | **First-run & LAN spoofing** (first-visitor takeover, `X-Forwarded-For` / IP / MAC / UA spoofing, LAN exit downgrade) | Local-console-only bootstrap; right-to-left `trusted_proxies` IP extraction; `network_zone` is context only; automatic upgrade to Mode 2 (or deny) outside LAN. |
| **T06–T10** | **Challenge & WebAuthn attacks** (replay, expired challenge, brute-force, wrong origin/phishing, cloned authenticator) | Atomic single-use challenges (`attempt_count <= 1`, `120 s` TTL); strict `origin`/`rp_id` check; `sign_count` monotonicity checks; persistent state commit on failure. |
| **T11–T15** | **Session & browser attacks** (XSS token theft, CSRF, cookie tossing, clickjacking, stale cache) | `__Host-` `HttpOnly; Secure; SameSite=Lax` cookies; zero `localStorage` tokens; exact `Origin` + session-bound CSRF token; `X-Frame-Options: DENY`, `CSP: frame-ancestors 'none'`, `Cache-Control: no-store`, `HSTS`. |
| **T16–T20** | **Native app & token rotation** (refresh token replay, long-lived access token abuse, hardware-key bypass on refresh) | `≤ 10 min` access token expiry enforced on every call; rotating `RefreshTokenChain` with reuse detection revoking the whole chain + session; `hardware_binding` re-checked on refresh. |
| **T21–T25** | **Shared device & privilege escalation** (role inheritance on shared PC, client-forged `critical=false`, `readonly` mutation, Mode 4 bypass) | Explicit per-account login; server-side `SERVER_ACTION_CATALOG`; `readonly` blocked at bridge; Mode 4 revokes non-owner/non-hardware sessions and enforces single-use `IdentityVerification`. |
| **T26–T30** | **Enrollment, Mode 3 & revocation races** (enrollment brute-force, synced passkey posing as 2 devices, confirming dangerous action after device revocation) | 5-attempt enrollment lockout committed outside rollback; `backup_state` & `hardware_binding` checks; `purpose='login'` rejected for second approval; live re-verification in `confirm_action`. |
| **T31–T34** | **Recovery, Telegram & audit leaks** (old session surviving recovery, Telegram spoofing, restart wiping pepper/rate limits, secret leakage into logs) | Recovery revokes all prior keys/sessions/codes; verified `ExternalIdentity` binding + callback dedup + Mode 3 Telegram recovery block; persistent `LOCUGARD_AUTH_PEPPER`; audit redaction tests. |

---

## 4. Residual Risks

- **Compromised host OS or local console:** An attacker with root/administrator access on the server host can read `auth_pepper.key`, TLS private keys, or run `auth_cli`.
- **Unlocked physical device:** Anyone with physical access to an unlocked logged-in browser/device can act within the idle/freshness window until revoked or re-authentication is required.
- **Social engineering of the owner:** If the owner explicitly approves a malicious device fingerprint or dangerous action prompt, cryptographic controls cannot override human consent.
- **Non-ACL filesystems:** Storing `auth_pepper.key` or TLS keys on `exFAT`/`FAT32` removes OS file permission enforcement (see [docs/OPERATIONS.md](OPERATIONS.md)).
- **In-memory rate limiter across restarts:** Rate-limit buckets reset when the server process restarts (persistent DB attempt limits on challenges and enrollment codes still apply).
