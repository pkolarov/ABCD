# Security Gaps

Date: 2026-04-12

## Findings

### ~~Critical: Local HTTP API can mint signed session tokens without proof-of-possession~~

**FIXED.** The unauthenticated `POST /v1/session` endpoint has been removed. Session issuance now requires FIDO2 proof-of-possession via `POST /v1/session/assert`. The internal `issue_session` method remains for use by the assertion flow only.

Additionally, session duration is now capped at 24 hours (86,400 seconds) regardless of what the caller requests.

### ~~High: Assertion-based auth is not bound to the enrolled subject and skips key WebAuthn checks~~

**FIXED.**

- Caller-supplied `subject_urn` is now **ignored** in `issue_session_from_assertion`. The session is always bound to the identity that owns the verified credential.
- The `user_present` (UP) flag from the authenticator is now **enforced** — assertions without physical presence are rejected.
- `mfa_verified` in the session token now reflects the actual `user_verified` (UV) flag from the authenticator, not a caller-supplied claim.
- Session duration requested via assertion is capped at 24 hours.
- **RP ID binding enforced**: the `rp_id_hash` in the assertion's `authenticatorData` is verified against `SHA-256(enrolled_rp_id)`. Cross-site assertion replay is rejected.
- Sign count is logged per-assertion for future replay detection. Full enforcement requires per-credential counter persistence (tracked in remaining work).

### ~~High: Device enrollment and policy/software scoping trust attacker-supplied device attributes~~

**PARTIALLY MITIGATED.**

- Input validation added: tags must be 1-128 printable characters, max 32 tags, org_unit must be 1-128 printable characters.
- Self-attested device enrollment is now logged with a warning.
- **Remaining risk**: tags and org_unit are still self-attested by the enrolling device. A future version should require admin-signed device enrollment to prevent a rogue local process from claiming privileged tags. The real fix needs admin-vouched device enrollment, which is a bigger architectural change.

### ~~Medium: Enrolled-user enumeration leaks all users and credential IDs~~

**ACCEPTED RISK (by design).** The `credential_id` field is retained in the response because the Windows Credential Provider and Auth Bridge require it to initiate WebAuthn assertions for the correct credential. The endpoint is localhost-only and protected by OS process isolation.

The `device_urn` parameter is accepted but intentionally not used for filtering: the Credential Provider needs the **full** list of enrolled users to display logon tiles for every user who can authenticate on this machine. Filtering by device would break the CP tile enumeration flow. The design decision is documented in the code.

### ~~Medium: Secrets and provisioning material fail open to plaintext/default filesystem permissions~~

**PARTIALLY MITIGATED.**

- Key files (`node_key.bin`, `domain_key.bin`, `p2p_key.bin`) are now written with **0600 permissions** (owner-only read/write) on Unix systems.
- FIDO2-protected domain keys also get restricted permissions.
- **Remaining risk**: when passphrases are not set, keys are still stored unencrypted (with a warning). Failing closed (refusing to write without a passphrase) would break development workflows. The warning is the intended design — production deployments should always set `DDS_DOMAIN_PASSPHRASE` and `DDS_NODE_PASSPHRASE`, or use `--fido2` protection.
- **Windows**: no ACL hardening yet (the `set_permissions` call is Unix-only).
- Provision bundles still embed the domain key blob — but it is already encrypted (passphrase or FIDO2), and the bundle is documented as a sensitive artifact.

### ~~Provision bundle admission cert TTL~~

**FIXED.** Admission certificates issued during provisioning now have a **1-year TTL** (was 10 years). Nodes must be re-provisioned or re-admitted to renew.

## Additional Exposure

- The node listens on `/ip4/0.0.0.0/tcp/4001` by default in `dds-node/src/config.rs:120`.
- mDNS is enabled by default in `dds-node/src/config.rs:82`.

Impact:
- This broadens discovery and denial-of-service surface on local networks.
- I did not find a direct admission-cert bypass in the libp2p path, but the default exposure is wider than necessary for hardened deployments.

This is intentional for ease of deployment — hardened deployments should bind to specific interfaces and disable mDNS via `dds.toml` configuration.

## Dependency Audit Gap

- I could not run `cargo audit` in this environment because `cargo` is not installed.
- Dependency advisory coverage is therefore still outstanding.

## Remaining Work

1. **Sign count enforcement** — persist per-credential assertion counters to detect replay attacks.
2. **Admin-signed device enrollment** — require a vouch from an admin to validate device tags/org_unit, preventing self-enrollment with privileged scope.
3. **Windows ACL hardening** — set restrictive ACLs on key files on Windows.
4. **Passphrase-required mode** — optional config flag to refuse key storage without encryption.
5. **Dependency audit** — run `cargo audit` when the Rust toolchain is available.
