# Security Policy

## Project Status

LocuGard `v0.1.0` is an early open-source release. Its architecture, threat model, and Python implementation have undergone internal multi-round red-team audits and automated integration testing across all core security scenarios, **but have not yet received an independent third-party cryptographic/security audit**. Evaluate carefully before deploying in high-risk environments.

## Core Security Invariants

LocuGard is designed around non-weakening security rules:
- **No primary passwords or hidden backdoors:** authentication relies on registered cryptographic keys (`Account ↔ Device ↔ Credential ↔ Session`). If all keys, offline recovery codes, and local console access are lost, access is intentionally unrecoverable.
- **Network metadata is context, not identity:** IP, MAC, User-Agent, and LAN membership never grant ownership or elevate roles. `X-Forwarded-For` is parsed right-to-left only from explicitly configured `trusted_proxies`.
- **Separation of concerns:** Authentication, authorization, and explicit dangerous-action approval (`Permissions` + `action_digest`) are strictly separated and re-verified at execution time.
- **No tokens in `localStorage`:** Web sessions use server-side random tokens in `__Host-` cookies (`Secure; HttpOnly; SameSite=Lax`), exact `Origin` checks, and session-bound CSRF tokens.
- **No custom cryptography:** WebAuthn verification uses [`py_webauthn`](https://github.com/duo-labs/py_webauthn); ECDSA P-256 verification uses `cryptography`.

## Out of Scope / Residual Risks

- Full compromise of the host OS or local server console.
- Physical access to an already unlocked device within an active session window (mitigated by short idle TTLs, fresh re-authentication for dangerous actions, and explicit `Permissions`).
- Social engineering where an owner knowingly approves a malicious device fingerprint.
- Filesystem permissions on non-ACL filesystems (e.g., `exFAT`/`FAT32`) — always store `auth_pepper.key` and TLS private keys on a filesystem supporting per-user ACLs (`NTFS`, `ext4`, `APFS`) with `0600` / owner-only permissions.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities. Instead, use GitHub Private Vulnerability Reporting (Security Advisories) in the repository and include:
1. Affected module and version.
2. Minimal reproduction steps or failing test case.
3. Security impact and suggested fix (if known).
