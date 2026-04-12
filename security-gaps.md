# Security Gaps

Date: 2026-04-12

## Findings

### Critical: Local HTTP API can mint signed session tokens without proof-of-possession

- `POST /v1/session` is exposed on the localhost router in `dds-node/src/http.rs:72`.
- The handler accepts caller-controlled `subject_urn`, `duration_secs`, `mfa_verified`, and `tls_binding` in `dds-node/src/http.rs:303`.
- `LocalService::issue_session` signs those claims into a session token in `dds-node/src/service.rs:435`.

Impact:
- Any unprivileged local process on a managed host can request a token for a trusted subject URN and obtain a signed session token.
- The caller can also falsely assert MFA state or inject a chosen TLS binding.

Attack vector:
- Malware or an untrusted local user calls `http://127.0.0.1:5551/v1/session` directly and mints an admin-scoped token.

### High: Assertion-based auth is not bound to the enrolled subject and skips key WebAuthn checks

- `subject_urn` is optional user input in `dds-node/src/http.rs:152`.
- `issue_session_from_assertion` uses `req.subject_urn.unwrap_or(subject_urn)` in `dds-node/src/service.rs:771`, so the caller can override the enrolled subject.
- The verifier parses `rp_id_hash`, `user_present`, `user_verified`, and `sign_count` in `dds-domain/src/fido2.rs:277`.
- The service ignores those parsed values in `dds-node/src/service.rs:757`.
- The Windows client requests only `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED` in `platform/windows/native/DdsCredentialProvider/DdsBridgeClient.cpp:498`.

Impact:
- A valid credential can be used to request a session for a different principal.
- Presence-only assertions can be upgraded to `mfa_verified=true`.
- Replays are harder to detect because the assertion counter is parsed but not enforced.

Attack vector:
- Replay a captured assertion to `/v1/session/assert`.
- Use one credential’s proof to request a session token for another `subject_urn`.

### High: Device enrollment and policy/software scoping trust attacker-supplied device attributes

- `POST /v1/enroll/device` is unauthenticated in `dds-node/src/http.rs:277`.
- `enroll_device` stores caller-provided `org_unit` and `tags` in `dds-node/src/service.rs:393`.
- Policy and software selection trust those self-attested values in `dds-node/src/service.rs:547`, `dds-node/src/service.rs:634`, and `dds-node/src/service.rs:916`.

Impact:
- A local caller can enroll a fake device with privileged tags or org-unit values.
- That device can then receive targeted policy documents, software assignments, URLs, and other deployment metadata.

Attack vector:
- Self-enroll a fake device with `tags=["server"]` or `org_unit="finance"` and query the localhost policy/software endpoints.

### Medium: Enrolled-user enumeration leaks all users and credential IDs

- The endpoint requires a `device_urn` in `dds-node/src/http.rs:373`.
- The service ignores it as `_device_urn` in `dds-node/src/service.rs:784`.
- It returns every enrolled subject and credential ID in `dds-node/src/service.rs:802`.

Impact:
- Any local caller can enumerate enrolled users, their display names, and credential identifiers.
- This makes target selection and follow-on impersonation attempts easier.

Attack vector:
- Query `GET /v1/enrolled-users?device_urn=anything` from any local process.

### Medium: Secrets and provisioning material fail open to plaintext/default filesystem permissions

- Node signing keys are written unencrypted when `DDS_NODE_PASSPHRASE` is unset in `dds-node/src/identity_store.rs:78`.
- Domain keys are written unencrypted when `DDS_DOMAIN_PASSPHRASE` is unset in `dds-node/src/domain_store.rs:118`.
- libp2p keys are written unencrypted when `DDS_NODE_PASSPHRASE` is unset in `dds-node/src/p2p_identity.rs:62`.
- These paths use ordinary `create_dir_all` and `write` calls, with no explicit file mode or ACL hardening.
- Provision bundles embed the raw `domain_key.bin` blob in `dds-node/src/provision.rs:206`.
- Provisioning decrypts that blob in memory in `dds-node/src/provision.rs:323` and issues 10-year admission certs in `dds-node/src/provision.rs:343`.

Impact:
- Readable key files or stolen `.dds` bundles can become full domain compromise.
- Default operator setups are likely to be weaker than intended if passphrases or FIDO2 protection are omitted.

Attack vector:
- Copy a provisioning bundle or plaintext key file from disk or backup media, then mint rogue-node admission or recover signing authority.

## Additional Exposure

- The node listens on `/ip4/0.0.0.0/tcp/4001` by default in `dds-node/src/config.rs:120`.
- mDNS is enabled by default in `dds-node/src/config.rs:82`.

Impact:
- This broadens discovery and denial-of-service surface on local networks.
- I did not find a direct admission-cert bypass in the libp2p path, but the default exposure is wider than necessary for hardened deployments.

## Dependency Audit Gap

- I could not run `cargo audit` in this environment because `cargo` is not installed.
- Dependency advisory coverage is therefore still outstanding.

## Recommended Next Fixes

1. Add local API authentication and authorization for every HTTP endpoint that returns identities, policies, software, or session tokens.
2. Remove the unauthenticated `/v1/session` issuance path or require proof-of-possession bound to the requested subject.
3. In `/v1/session/assert`, ignore caller-supplied `subject_urn` and bind the session to the enrolled credential owner.
4. Enforce WebAuthn `rp_id_hash`, `user_verified`, and assertion counter validation.
5. Stop trusting self-declared `tags` and `org_unit` values for enrollment-driven policy targeting.
6. Scope `/v1/enrolled-users` to the requesting device or remove credential IDs from that response.
7. Fail closed when key-encryption env vars are absent, or move key storage to OS-protected keystores / hardware-backed storage.
8. Treat provision bundles as highly sensitive secrets and reduce admission-cert TTLs.
