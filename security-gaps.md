# Security Gaps

Date: 2026-04-12

> **SUPERSEDED (2026-04-21).** This document captures the state of the
> security review as of 2026-04-12. A fuller independent review — with
> per-finding severity, source-validated attack vectors, and
> remediation status — lives in [Claude_sec_review.md](Claude_sec_review.md)
> and is current as of 2026-04-21. Every finding flagged in this file
> has been subsumed by the newer review:
>
> | Here | New review |
> |---|---|
> | Unauthenticated session mint | ✅ still fixed (`/v1/session` endpoint removed) |
> | Assertion not bound to subject | ✅ still fixed (I-3 in new review) |
> | Self-attested device scope | M-7 + M-8 step-1/2 + H-8 addressed it end-to-end |
> | Enrolled-user enumeration | C-2, H-8 tightened admin bootstrap + vouch capability |
> | Plaintext key fallback | M-14 (encrypted-marker refuses silent plaintext downgrade) |
> | Windows ACL hardening | H-5 (named-pipe SDDL), L-16 (AppliedStateStore DACL) |
> | `0.0.0.0:4001` default | M-4 (mDNS rate caps); H-12 now gates peers post-Noise |
> | mDNS default-on | M-4 caps + hard peer-table ceiling |
> | Sign count enforcement | L-18 (atomic `bump_sign_count`) + I-4 |
> | Dependency audit | Out-of-scope for review; still tracked operationally |
>
> Prefer the newer review for all day-to-day operator / dev decisions.
> This file is retained only for historical context.

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
- ~~**Windows**: no ACL hardening yet (the `set_permissions` call is Unix-only).~~ **FIXED (2026-04-28).** See Remaining Work item #3.
- Provision bundles still embed the domain key blob — but it is already encrypted (passphrase or FIDO2), and the bundle is documented as a sensitive artifact. **2026-04-29 follow-on (L-5 idiom):** `save_bundle` now also sets `0o600` on the written `.dds` file under `cfg(unix)`, mirroring `dds export` and `dds-cli audit export --out`, so a co-tenant cannot copy the bundle off disk for an offline passphrase-unwrap attempt. Regression test in `dds-node::provision::tests::save_bundle_writes_owner_only_mode`.

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

- ~~I could not run `cargo audit` in this environment because `cargo` is not installed.~~
- ~~Dependency advisory coverage is therefore still outstanding.~~

**RESOLVED (2026-04-28).** `cargo audit` (cargo-audit v0.22.1) was run
against `Cargo.lock` on the macOS dev host. Three vulnerabilities were
flagged in `rustls-webpki 0.103.10` and closed by bumping the lockfile to
`rustls-webpki 0.103.13` (a SemVer-compatible patch picked up via
`cargo update -p rustls-webpki`):

| ID | Title |
|---|---|
| RUSTSEC-2026-0098 | Name constraints for URI names were incorrectly accepted |
| RUSTSEC-2026-0099 | Name constraints were accepted for certificates asserting a wildcard name |
| RUSTSEC-2026-0104 | Reachable panic in certificate revocation list parsing |

Post-update `cargo audit` reports **0 vulnerabilities**; the remaining 8
warnings are unmaintained / yanked transitive crates from upstream
ecosystems (`atomic-polyfill` via `postcard`/`heapless`, `core2` via
`multihash`/`libp2p-noise`, `paste` via `axum-macros`, `lru` via
`hickory-proto`, `rand 0.8/0.9` via `quinn-proto`/`yamux`/`hickory-*`,
`fastrand` via `tempfile`) which are not fixable in this tree without
upstream releases.

Full workspace test run after the bump: **701 / 701** passing
(macOS 25.3 dev host, `cargo test --workspace`, 1 ignored test).

**CI HOOK LANDED 2026-04-29 (supply-chain-plan.md Phase C.4).** A new
`audit` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml)
installs `cargo-audit` via `taiki-e/install-action@v2` and runs
`cargo audit` on every PR and every push to `main`. Default behaviour:
exit non-zero on any RUSTSEC *vulnerability* advisory; the eight
informational warnings above (unmaintained / unsound / yanked) surface
in the build log but do not block — they are upstream-blocked
transitive deps tracked here. When upstream releases land and clear
those warnings, graduate the CI step to `cargo audit -D warnings` so a
fresh advisory immediately surfaces a PR. Pre-commit `cargo audit`
re-run on the macOS dev host: **0 vulnerabilities, 8 informational
warnings** (matches the 2026-04-28 baseline above).

## Remaining Work

1. ~~**Sign count enforcement** — persist per-credential assertion counters to detect replay attacks.~~ **DONE (already shipped via L-18).** `dds-store::traits::CredentialStateStore::bump_sign_count(credential, new)` is an atomic check-and-set primitive (single redb write transaction); `StoreError::SignCountReplay { stored, attempted }` distinguishes the replay branch from generic I/O. `LocalService::verify_assertion_common` (`dds-node/src/service.rs:1910-1920`) calls `bump_sign_count` on every assertion with `parsed.sign_count > 0` and surfaces the replay outcome through the `dds_fido2_assertions_total{result="sign_count"}` metric bucket. Authenticators reporting `sign_count == 0` skip the check (logged at warn).
2. **Admin-signed device enrollment** — require a vouch from an admin to validate device tags/org_unit, preventing self-enrollment with privileged scope.
3. ~~**Windows ACL hardening** — set restrictive ACLs on key files on Windows.~~ **FIXED (2026-04-28).** Defense-in-depth on top of the existing data-dir DACL applied by the MSI custom action `CA_RestrictDataDirAcl`. New module [`dds-node/src/file_acl.rs`](dds-node/src/file_acl.rs) exposes a private `restrict_to_owner(path)` helper that — on Windows — applies the protected DACL `D:PAI(A;;FA;;;SY)(A;;FA;;;BA)` (Full-Access for `LocalSystem` and `BUILTIN\Administrators`, no inheritance from parent) via `ConvertStringSecurityDescriptorToSecurityDescriptorW` + `SetNamedSecurityInfoW` with `PROTECTED_DACL_SECURITY_INFORMATION`. On Unix it keeps the existing `chmod 0o600` semantics. The three duplicated `set_owner_only_permissions` helpers in [`identity_store.rs`](dds-node/src/identity_store.rs), [`p2p_identity.rs`](dds-node/src/p2p_identity.rs), and [`domain_store.rs`](dds-node/src/domain_store.rs) now all delegate to the shared helper, so every per-file save path (node Ed25519 key, libp2p keypair, domain key v=1/v=4 plain + v=2/v=3/v=5 encrypted, encrypted-marker sidecar) gets the Windows DACL applied at write time. Failures are logged at warn (best-effort) since the data-dir DACL is the production-grade hardening; the per-file call exists so non-MSI deployments and pre-existing files still get locked down. SDDL matches `apply_windows_data_dir_dacl` in [`dds-node/src/main.rs`](dds-node/src/main.rs) without the `OICI` container-inheritance flags. Three new unit tests pin the cross-platform contract (existing-file no-panic, missing-file no-panic, Unix-only `0o600` assertion); the Windows DACL path itself requires a Windows host to exercise end-to-end. Cross-compile to `x86_64-pc-windows-gnu` is clean.
4. ~~**Passphrase-required mode** — optional config flag to refuse key storage without encryption.~~ **FIXED (2026-04-28).** New env var `DDS_REQUIRE_ENCRYPTED_KEYS` (recognised truthy values: `1`, `true`, `yes`, case-insensitive) gates the three node-side plaintext save paths: `identity_store::save` (node Ed25519 signing key, v=1 plain), `p2p_identity::save` (libp2p Ed25519 keypair, v=1 plain), and `domain_store::save_domain_key` (Ed25519-only v=1 plain and v=4 plain hybrid; the v=3 FIDO2 path is already encrypted and unaffected). When set with `DDS_NODE_PASSPHRASE` / `DDS_DOMAIN_PASSPHRASE` empty, each save returns a `Crypto` error and writes nothing — operators get fail-closed posture instead of the warn-and-write default. Default off so existing dev workflows keep working. Three new regression tests cover the gate for each module.
5. ~~**Dependency audit** — run `cargo audit` when the Rust toolchain is available.~~ **DONE (2026-04-28).** See "Dependency Audit Gap" above — 3 CVEs closed via `rustls-webpki` 0.103.10 → 0.103.13 lockfile bump.
