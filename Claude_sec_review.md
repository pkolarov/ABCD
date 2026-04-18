# DDS — Security Review

**Date:** 2026-04-17
**Reviewer:** Claude (opus-4-7, 1M context), with source-validation pass
**Scope:** whole codebase at `/Users/peter/ABCD` — 9 Rust crates (~22k lines) + Windows platform (C++/C#/WiX) + macOS Policy Agent (C#) + FFI bindings.
**Prior work:** `security-gaps.md` (2026-04-12) — prior findings referenced where relevant; this review is independent and has been source-validated against the current tree.

Severities reflect realistic attacker models documented per finding. All Critical and High findings have been verified against source code at the line ranges cited. Attack vectors are spelled out step-by-step so the remediation path is obvious.

## Threat models in scope

1. **Remote P2P peer** — has a libp2p keypair and has completed the Noise handshake, but may be un-admitted, malicious, or Byzantine.
2. **LAN adjacent** — can send mDNS and attempt TCP connects on `/ip4/0.0.0.0/tcp/4001`.
3. **Local unprivileged process** — can send requests to `127.0.0.1:5551` and to Windows named pipes.
4. **Local user with filesystem read/write** — can inspect/tamper with the data directory.
5. **Adversarial FFI caller** — language bindings passing NULL or invalid pointers.
6. **Supply chain / bundle interception** — attacker who can tamper with provisioning bundles or `dds export` archives in transit.

The codebase documents most endpoints as "localhost-only with OS process isolation." Several findings below are only concerning under that assumption being violated (misconfig to `0.0.0.0`) or under local-attacker threat models; severity is assigned accordingly.

## Executive summary

- **3 Critical**: FFI null-pointer dereference, unauthenticated admin bootstrap, remote unauthorized policy/software publication.
- **12 High**: split across authorization gaps (revocation, vouch capability, policy agent trust on both Windows and macOS), cryptographic hygiene (zeroization, bundle integrity), DoS (unbounded sync response, pre-admission gossip processing), and Windows-platform IPC (named-pipe SDDL, challenge injection).
- **22 Medium** and **18 Low** findings covering rate-limiting, canonicalization, mode bits, hash-chain hardening, and defense-in-depth items.
- The combination of **C-3** (no publisher authorization on policy documents) and **H-12** (no per-peer admission check on gossip) converts the remote threat model from "mostly DoS" into "unauthenticated remote privileged state publication."

---

## Remediation status (2026-04-18)

This section records the state of each finding after the remediation pass.
`✅ Fixed (pending verify)` means code landed in this branch and local
test + clippy are green; still needs CI, code review, and any production
exercise before being considered closed. `⏸ Deferred` means intentionally
left for a follow-up PR — usually because the fix spans languages
(Rust + C# agents, C++ bridge) or requires a disk/wire format migration.

### Critical

| ID | Status | Notes |
|---|---|---|
| C-1 | ✅ Fixed (pending verify) | `read_cstr`/`write_json`/`write_str` null-check; test `null_input_returns_invalid_input` |
| C-2 | ✅ Fixed (pending verify) | Bootstrap sentinel `<data_dir>/.bootstrap` + refuse-if-roots-non-empty; sentinel consumed atomically |
| C-3 | ✅ Fixed (pending verify) | Publisher-capability filter on `list_applicable_*`; purposes defined in `dds_core::token::purpose` |

### High

| ID | Status | Notes |
|---|---|---|
| H-1 | ✅ Fixed (pending verify) | Revocations for unknown targets now rejected outright; test `revocation_for_unknown_target_is_rejected` |
| H-2 | ⏸ Deferred | Signed policy token bodies + C# Ed25519 verifier; cross-language, out of scope this pass |
| H-3 | ⏸ Deferred | Same design as H-2 on macOS agent |
| H-4 | ✅ Fixed (pending verify) | JTIs suffixed with UUIDv4; `TrustError::DuplicateJti` rejects overlaps |
| H-5 | ✅ Fixed (pending verify) | Named-pipe SDDL tightened to `SY`-only (dropped `IU`); C++ change, compile-test requires Windows CI |
| H-6 | ⏸ Deferred | Challenge HMAC + mTLS between Auth Bridge and dds-node; C++/Rust cross-cut |
| H-7 | ⏸ Deferred | UDS/named-pipe peer-creds gating on HTTP; larger transport rewrite |
| H-8 | ✅ Fixed (pending verify) | `admin_vouch` requires `dds:admin-vouch:<purpose>` for non-bootstrap admins; bootstrap admin tracked on service |
| H-9 | ✅ Fixed (pending verify) | `Zeroizing` wraps passphrase + admin plaintext; buffers wiped on early-return paths |
| H-10 | ✅ Fixed (pending verify) | Bundle v2 embeds SHA-256 integrity fingerprint; load verifies; CLI prints for OOB confirmation; test `bundle_rejects_tampered_fingerprint` |
| H-11 | ✅ Fixed (pending verify) | `SyncResponse` capped at 1000 entries / 5 MB; `complete: false` signals pagination |
| H-12 | ⏸ Deferred | Per-peer admission gating in gossip ingest; requires libp2p behaviour protocol design |

### Medium

| ID | Status | Notes |
|---|---|---|
| M-1 | ⏸ Deferred | Verified no in-pipeline normalizer exists today; signed bytes are round-tripped verbatim |
| M-2 | ⏸ Deferred | Versioned breaking change; roll in a future release |
| M-3 | ✅ Fixed (pending verify) | Global token-bucket middleware (60 req/s) returns 429 |
| M-4 | ⏸ Deferred | Low-priority hardening; connection caps tracked separately |
| M-5 | ✅ Fixed (pending verify) | `sync_payloads` capped at 10k entries with FIFO eviction |
| M-6 | ⏸ Deferred | Paired with H-12; land together |
| M-7 | ⏸ Deferred | `scope_vouched` flag needs schema/config change and admin UX; follow-up |
| M-8 | ⚠ Partial | Added structured log of every `device_urn` query; session-token check deferred until device-session issuance lands |
| M-9 | ⏸ Deferred | Low impact (audit-log spurious-event only) |
| M-10 | ⏸ Deferred | Parameter bump requires disk-format migration of existing encrypted node keys |
| M-11 | ✅ Fixed (pending verify) | `DefaultBodyLimit::max(256 KiB)` on Axum; gossipsub cap tracked separately |
| M-12 | ⏸ Deferred | Current hash-compare path is cryptographically equivalent when clients serialize identically |
| M-13 | ⏸ Deferred | Requires FIDO MDS integration / policy |
| M-14 | ⏸ Deferred | Interacts with M-10 disk format; land together |
| M-15 | ⏸ Deferred | FIDO2 code path is feature-gated off by default |
| M-16 | ⏸ Deferred | Dump-signature design follow-up; file mode tightened (see L-5) |
| M-17 | ⏸ Deferred | C++ only; Windows-specific audit |
| M-18 | ⏸ Deferred | WiX / installer change |
| M-19 | ✅ Fixed (pending verify) | Boot-time wall clock captured; `verify_assertion_common` refuses when `now() < boot_wall_time` |
| M-20 | ✅ Fixed (pending verify) | `directory.redb` set to `0o600` on Unix after `Database::create` |
| M-21 | ✅ Fixed (pending verify) | `AuditLogEntry::sign_ed25519`/`verify` added; `ingest_audit` rejects unsigned/forged entries; 4 unit tests |
| M-22 | ✅ Fixed (pending verify) | AES-GCM AAD = `admin_urn`; version byte `0x02`; `0o700`/`0o600` perms; atomic write via tempfile; plaintext zeroized. OS-bound wrap (DPAPI/Keychain/TPM) left as explicit `TODO(security)` |

### Low

| ID | Status | Notes |
|---|---|---|
| L-1 | ⏸ Deferred | Low-impact hygiene |
| L-2 | ✅ Fixed (pending verify) | `O_NOFOLLOW` on identity read (Unix) |
| L-3 | ✅ Fixed (pending verify) | `NamedTempFile::persist` for key and admin-key writes |
| L-4 | ✅ Fixed (pending verify) | Parent directory set to `0o700` on Unix after creation |
| L-5 | ✅ Fixed (pending verify) | Dump output file set to `0o600` on Unix |
| L-6 | ✅ Fixed (pending verify) | CLI refuses non-loopback `http://` URLs |
| L-7 | ✅ Fixed (pending verify) | FFI `now_epoch` uses `unwrap_or(0)` |
| L-8 | ✅ Fixed (pending verify) | Caps: 10k rules, 100k tokens |
| L-9 | ✅ Fixed (pending verify) | `ServiceError` mapped to opaque codes (`auth_failed`, `permission_denied`, `invalid_input`, `internal_error`); full detail logged server-side |
| L-10 | ✅ Fixed (pending verify) | Admin blob now prefixed with version byte (rolled into M-22) |
| L-11 | ⏸ Deferred | Audit call sites and LWW semantics follow-up |
| L-12 | ⏸ Deferred | Hash chain follow-up to M-21 |
| L-13 | ⏸ Deferred | Normalize credential-id bytes follow-up |
| L-14 | ⏸ Deferred | C++ Credential Provider stack hygiene |
| L-15 | ✅ Fixed (pending verify) | `subtle::ConstantTimeEq` on `vch_sum` comparisons via `payload_hash_eq` |
| L-16 | ⏸ Deferred | C# applied-state file ACL; Windows-only |
| L-17 | ⏸ Deferred | Service mutex refactor; couple with L-18 |
| L-18 | ⏸ Deferred | Requires L-17 to land first |

### Known caveats after this pass

- None open. The earlier multinode test flake (`rejoined_node_catches_up_via_sync_protocol` et al.) was fixed separately by switching the test harness to one-sided dials via a new `connect_one_sided` helper. Root cause was the libp2p-tcp simultaneous-dial race on Noise negotiation — `gossipsub.add_explicit_peer` auto-dialed on both sides, producing "Handshake failed: input error" ~10% of runs. Verified at 50/50 on the full multinode suite and 5/5 on the full workspace suite.

---

## Critical

### C-1. FFI helpers dereference caller-supplied pointers without null checks
**Location:** [dds-ffi/src/ffi_core.rs:29-53](dds-ffi/src/ffi_core.rs#L29-L53)

**What's wrong:** `read_cstr` calls `CStr::from_ptr(ptr)` without `ptr.is_null()`. `write_json` and `write_str` execute `unsafe { *out = cs.into_raw() }` without checking `out`. Every exported FFI function funnels through these helpers.

**Attack vector:**
1. A Python/C#/Swift/Kotlin binding (or a C caller) passes `NULL` — either as a bug in user code or as an edge case the binding doesn't handle.
2. `read_cstr(NULL)` dereferences `0x0` and the host process crashes.
3. Worse: `write_*` with a non-null but invalid `*mut *mut c_char` performs a raw pointer store through attacker-controlled memory — arbitrary-write primitive in the host.

**Impact:** Denial of service (crash) in the best case, memory corruption of the host application in the worst. Affects every language binding.

**Fix:**
```rust
fn read_cstr(ptr: *const c_char) -> Result<&'static str, i32> {
    if ptr.is_null() { return Err(DDS_ERR_INVALID_INPUT); }
    unsafe { CStr::from_ptr(ptr) }.to_str().map_err(|_| DDS_ERR_INVALID_INPUT)
}

fn write_json(out: *mut *mut c_char, json: serde_json::Value) -> i32 {
    if out.is_null() { return DDS_ERR_INVALID_INPUT; }
    // ... existing body
}
```
Document the non-null invariant in [bindings/c/dds.h](bindings/c/dds.h).

---

### C-2. `POST /v1/admin/setup` is unauthenticated with no bootstrap gate
**Location:** [dds-node/src/http.rs:114](dds-node/src/http.rs#L114) → [dds-node/src/service.rs:1175-1239](dds-node/src/service.rs#L1175-L1239)

**What's wrong:** `admin_setup` has no "first admin only" check. Any call with a valid FIDO2 attestation adds the caller's URN to `self.trusted_roots` at line 1236 and persists it to config. Verified: there is no `if !self.trusted_roots.is_empty() { return Err(...) }` guard before the insert.

**Attack vector:**
1. Attacker is a local unprivileged process (or logged-in user) on a box running `dds-node`.
2. Attacker has their own FIDO2 authenticator plugged in (or a software authenticator).
3. Attacker sends `POST /v1/admin/setup` to `127.0.0.1:5551` at any point in the node's lifetime — not just at first boot.
4. The request succeeds: the attacker's URN joins `trusted_roots`.
5. Attacker then calls `POST /v1/admin/vouch` (no capability check either, see H-8) and grants any purpose to any subject URN.

**Impact:** Full privilege escalation from "local unprivileged user" to "domain admin with unlimited vouching." Breaks the entire authorization model.

**Fix (minimal — keeps the existing `trusted_roots` model):**
- Hard-gate `admin_setup`: refuse if `self.trusted_roots` is already non-empty.
- Require the initial call to be driven from an explicit bootstrap context: a `--bootstrap-admin` flag on `dds-node run`, or a one-shot sentinel file (e.g., `data_dir/.bootstrap`) consumed atomically on first successful `admin_setup`. The endpoint must return `403` whenever the bootstrap context is absent, independent of whether `trusted_roots` is empty — this defeats the race where an attacker calls `admin_setup` between node start and the legitimate operator's call.
- After bootstrap, all new admin enrollments must go through `admin_vouch` by an existing admin (which itself needs the fix in H-8).
- **Out of scope for this fix:** `trusted_roots` remains per-node local config (read from TOML at startup). Adding an admin on one node does not propagate to other peers; operators must push config changes. A stronger design would chain all admins back to a domain-key-signed genesis attestation so the admin set is derived from gossip and globally coherent — see **I-11** for the tracking item. Deferred deliberately.

---

### C-3. Policy and software documents have no publisher-authorization check
**Location:** [dds-node/src/service.rs:697-819](dds-node/src/service.rs#L697-L819), [dds-core/src/trust.rs:82-100](dds-core/src/trust.rs#L82-L100), gossip ingestion path at [dds-node/src/node.rs:236-320](dds-node/src/node.rs#L236-L320)

**What's wrong:** `list_applicable_windows_policies`, `list_applicable_macos_policies`, and `list_applicable_software` iterate over **every** non-revoked, non-burned attestation in the trust graph and extract embedded policy/software documents. There is no check that the issuer's URN chains to a `trusted_roots` entry with a publisher capability. Attestations are accepted at the graph level by [trust.rs:82-88](dds-core/src/trust.rs#L82-L88) on any valid self-signed token.

**Attack vector:**
1. Attacker generates a libp2p keypair and completes the Noise handshake with an admitted peer (trivial: Noise has no per-peer admission gate, see H-12).
2. Attacker generates a fresh DDS identity (Ed25519 keypair).
3. Attacker crafts an attestation token whose body embeds a `WindowsPolicyDocument` containing, e.g., a registry-key directive or a shell-command enforcer, scoped to target devices by URN or tag.
4. The attestation is self-signed by the attacker's own key — which is fine, because `add_token` only verifies the signature matches the embedded `iss_key`, not that the issuer is authorized to publish policy.
5. Attacker gossips the token. Every peer ingests it, passes the revocation/burn filter, and serves it from `GET /v1/windows/policies?device_urn=...`.
6. The Windows (or macOS) Policy Agent polls that endpoint, has no signature check on the returned body (see H-2/H-3), and executes the policy as SYSTEM/root.

**Impact:** Remote unauthorized policy/software publication. On hosts running the platform agents this escalates to `SYSTEM`/`root` code execution from any network-reachable peer. This is the single highest-impact finding in the review.

**Fix:**
- Define publisher capabilities in the trust model: `dds:policy-publisher-windows`, `dds:policy-publisher-macos`, `dds:software-publisher`, vouched by a trusted root.
- Enforce on **ingest** in `add_token`: reject attestations bearing policy/software document bodies unless the issuer has the matching capability.
- Enforce again on **serve** in `list_applicable_*`: filter tokens whose issuer does not chain to a trusted root with the publisher capability for that document kind. Defense in depth against a trust-graph bug.
- The agent-side fix in H-2/H-3 (verify the signed document body) is complementary, not a substitute — keep both.

---

## High

### H-1. Revocation stored for unknown target bypasses issuer-authorization
**Location:** [dds-core/src/trust.rs:101-130](dds-core/src/trust.rs#L101-L130)

**What's wrong:** The issuer-authorization check at lines 117-126 only returns `Err(Unauthorized)` when `target_known == true`. When the target JTI is not yet in the graph, the revocation is unconditionally inserted at line 128.

**Attack vector:**
1. Attacker is an admitted peer (has completed admission and gossip).
2. Attacker knows or predicts the JTI of a future token — e.g., `attest-alice-workstation-02` (JTIs are deterministic by label, see H-4).
3. Attacker publishes a revocation for that JTI. Revocation is stored in `self.revocations` because the target is unknown — no authorization check fires.
4. The legitimate token arrives later via gossip/sync. `add_token` inserts it. Subsequent `is_revoked(jti)` lookups return `true`.
5. The victim's attestation is dead-on-arrival, even though the attacker never had authority to revoke it.

**Impact:** Breaks the "only the issuer can revoke" invariant. Unauthorized denial of service against any identity whose JTI the attacker can predict — which is trivial given H-4.

**Fix:**
- Reject revocations whose target is unknown outright: replace the `if target_known` branch with unconditional rejection.
- If deferred acceptance is required for eventual-consistency reasons: keep the revocation in a **pending** queue keyed by target JTI. When the target token arrives, re-authorize (`revoker_iss == target.payload.iss`) before committing to `self.revocations`.

---

### H-2. Windows Policy Agent applies HTTP responses without signature verification
**Location:** [platform/windows/DdsPolicyAgent/Worker.cs:101-141](platform/windows/DdsPolicyAgent/Worker.cs#L101-L141), [platform/windows/DdsPolicyAgent/Client/DdsNodeClient.cs](platform/windows/DdsPolicyAgent/Client/DdsNodeClient.cs)

**What's wrong:** The Policy Agent runs as LocalSystem and polls `127.0.0.1:5551/v1/windows/{policies,software}`. The returned JSON directives (account creation, password policy, registry edits, software install) are applied directly. There is no Ed25519 signature check on the documents against a pinned domain key.

**Attack vector:**
1. Local unprivileged attacker waits for a reboot window, or otherwise arranges to bind `127.0.0.1:5551` before `dds-node` starts (e.g., a user-space service installed to auto-start earlier).
2. Attacker's server responds to `GET /v1/windows/policies?device_urn=...` with a crafted JSON directive: add a local admin account, install a malicious MSI, write a Run-key registry entry, etc.
3. Policy Agent fetches, dispatches to the enforcer, and the action runs as SYSTEM.

Alternate: any other code path that can influence the HTTP response body (a proxy, a sidecar, DNS poisoning if the agent is ever reconfigured off-loopback) has the same consequence.

**Impact:** Local unprivileged user → SYSTEM on the Windows host.

**Fix:**
- Change the HTTP API to deliver the original **signed** Token body (CBOR bytes + SignatureBundle), not just extracted JSON fields.
- In the Policy Agent, verify the Ed25519 signature against the enrolled domain public key (pinned at install time by the MSI) before any enforcer runs.
- Reject unsigned or mismatched documents with a clear audit log entry. Combined with C-3, also enforce publisher capability agent-side.

---

### H-3. macOS Policy Agent applies HTTP responses without signature verification
**Location:** [platform/macos/DdsPolicyAgent/Client/DdsNodeClient.cs:93-117](platform/macos/DdsPolicyAgent/Client/DdsNodeClient.cs#L93-L117), [platform/macos/DdsPolicyAgent/Worker.cs:95-184](platform/macos/DdsPolicyAgent/Worker.cs#L95-L184)

**What's wrong:** Same design flaw as H-2 on the macOS agent. `GetPoliciesAsync`/`GetSoftwareAsync` fetch JSON from `v1/macos/{policies,software}` and dispatch enforcers (preferences, accounts, launchd, profiles, software install) without verifying an Ed25519 signature over the document body.

**Attack vector:** Identical to H-2 but on macOS and the agent runs as root. Local attacker who binds or hijacks the localhost endpoint injects arbitrary policy → root-level system modifications via `MacAccountEnforcer`, `LaunchdEnforcer`, `ProfileEnforcer`, `SoftwareInstaller`.

**Impact:** Local unprivileged user → root on the macOS host.

**Fix:** Same design fix as H-2: transport the signed Token body, verify against a pinned domain key in the agent before enforcement. Treat unsigned/extracted-only JSON as untrusted input that must not drive privileged actions.

---

### H-4. Attestation JTI collisions allow overwrite and secondary-index corruption
**Location:** [dds-node/src/service.rs:1501-1517](dds-node/src/service.rs#L1501-L1517), [dds-core/src/trust.rs:82-88](dds-core/src/trust.rs#L82-L88)

**What's wrong:** Attestation JTIs are generated deterministically as `format!("attest-{}", ident.id.label())` where `label` is the human-supplied enrollment label. Two enrollments with the same label produce identical JTIs. `add_token` inserts with `self.attestations.insert(jti, token)` — this overwrites any prior token under the same JTI. The `attestations_by_iss` secondary index at line 87 keeps the old issuer's entry pointing at the now-replaced JTI, so `find_attestation_by_iss(old_iss)` resolves to the attacker's token.

**Attack vector:**
1. Legitimate user enrolls with label `alice-workstation`. JTI = `attest-alice-workstation`, iss = `urn:vch:alice-…hash1…`.
2. Attacker enrolls with the same label `alice-workstation`. Attacker's token gets JTI = `attest-alice-workstation`, iss = `urn:vch:attacker-…hash2…` (different because the public key bundle differs — `to_urn()` includes the pubkey hash).
3. Attacker's `add_token` overwrites the map entry at JTI `attest-alice-workstation`. The legitimate token is gone from `self.attestations`.
4. The legitimate issuer's entry in `attestations_by_iss` still points at that JTI. Lookups by Alice's URN now resolve to the attacker's token.
5. Combined with C-3, this lets the attacker replace a policy-publisher's attestation in place.

**Impact:** Identity-state corruption, denial of service against any known label, and — with C-3 — the ability to substitute an attacker-controlled token for a legitimate one in issuer-keyed lookups.

**Fix:**
- Generate unpredictable globally-unique JTIs: e.g., `format!("attest-{}", hex(random_128_bits))` or `hex(SHA-256(issuer_urn || label || random_nonce))`.
- In `add_token`, reject duplicate JTI insertions outright.
- If replacement is ever required (e.g., for token refresh), first remove the old JTI from **all** secondary indices (`attestations_by_iss`, `vouches_by_subject`, etc.) before inserting the replacement.

---

### H-5. Named-pipe SDDL allows all interactively-logged-on users
**Location:** [platform/windows/native/DdsBridgeIPC/ipc_pipe_server.cpp:152](platform/windows/native/DdsBridgeIPC/ipc_pipe_server.cpp#L152)

**What's wrong:** `L"D:(A;;GA;;;SY)(A;;GA;;;IU)"` grants GENERIC_ALL to both SYSTEM and INTERACTIVE. The pipe carries plaintext passwords and FIDO2 assertion material between the Credential Provider and the Auth Bridge. INTERACTIVE includes any user logged on at the console.

**Attack vector (multi-user host — Terminal Server, Citrix, RDS):**
1. User A initiates logon via the DDS Credential Provider. Their password and FIDO2 assertion blobs pass through the pipe.
2. User B, also interactively logged on, opens the pipe (IU grants GENERIC_ALL), reads the data, captures A's password, or races to inject a forged assertion result to sign in as A.

**Impact:** Cross-user credential theft and account takeover on any multi-user Windows box.

**Fix:**
- Restrict the DACL to `SY` (SYSTEM) only, plus the specific service SID running the host process that legitimately consumes the pipe.
- If the CP must connect as the logging-on user's token (LogonUI), add a narrowly-scoped ACE for that principal — do **not** use the blanket IU SID.
- Consider using ALPC or a kernel-bound transport for this path on future platform releases.

---

### H-6. Windows callers trust an attacker-injectable server challenge
**Location:** [platform/windows/native/DdsAuthBridge/DdsNodeHttpClient.cpp](platform/windows/native/DdsAuthBridge/DdsNodeHttpClient.cpp), [platform/windows/native/DdsCredentialProvider/DdsBridgeClient.cpp:430-453](platform/windows/native/DdsCredentialProvider/DdsBridgeClient.cpp#L430-L453)

**What's wrong:** The Auth Bridge fetches the WebAuthn challenge from `http://127.0.0.1:5551/v1/session/challenge` with no server authentication. It forwards the challenge to the Credential Provider over the pipe (see H-5). The CP treats the challenge as authoritative and constructs `clientDataJSON` with `origin = "https://<rpId>"` where `rpId` also comes from the IPC message.

**Attack vector:**
1. Local attacker binds `127.0.0.1:5551` before `dds-node` starts (or has foothold in the Auth Bridge).
2. Attacker's server returns a challenge of the attacker's choice in response to `/v1/session/challenge`.
3. Auth Bridge forwards the attacker-chosen challenge to the CP.
4. User touches their FIDO2 authenticator during logon. The authenticator signs `clientDataJSON` containing the attacker's challenge.
5. Attacker obtains a valid DDS session against the configured RP, having never knowing the user's credentials.

**Scope caveat:** Because the CP constructs `origin` from the bridge-supplied RP ID, the scope is **DDS relying-party challenge substitution / local DDS session hijack**, not arbitrary third-party RP impersonation. Still a full authentication bypass within the DDS trust boundary.

**Impact:** Local attacker obtains an authenticator-signed assertion for the DDS RP without the user's awareness, usable to impersonate the user to `dds-node`.

**Fix:**
- Authenticate the channel between the Auth Bridge and `dds-node`: mTLS with a node certificate pinned at install time in both Auth Bridge and CP, or an HMAC-signed response using a per-install secret provisioned by the MSI.
- Independently, message-authenticate the challenge payload on the named pipe (even after H-5 is fixed, defense in depth).
- Consider binding the challenge to a fresh nonce chosen by the CP, round-tripped through the server.

---

### H-7. `dds-node` HTTP API has no authentication on most endpoints
**Location:** [dds-node/src/http.rs:103-129](dds-node/src/http.rs#L103-L129)

**What's wrong:** No middleware enforces a session/bearer token on any route. The design relies entirely on loopback bind + OS process isolation. Endpoints that currently require no auth include:
- `POST /v1/enroll/user`, `POST /v1/enroll/device` — any local process can enroll
- `POST /v1/admin/setup` (see C-2), `POST /v1/admin/vouch` (see H-8)
- `GET /v1/enrolled-users` — user roster + credential IDs
- `GET /v1/windows/policies`, `GET /v1/windows/software`, `GET /v1/macos/*` — policy/software content by device URN
- `GET /v1/audit/entries` — audit log dump
- `POST /v1/policy/evaluate` — unauthenticated access to policy decisions
- `POST /v1/session/assert` — proof-of-possession enforced, but no bearer

**Attack vector:** Any process that can open a TCP socket to `127.0.0.1:5551` has full API access. A single `api_addr = "0.0.0.0:5551"` misconfig, or any LPE on the host, opens the whole authority. No defense in depth.

**Impact:** Loss of localhost-only assumption = loss of all authorization. All C-2/C-3/H-1/H-4/M-7/M-8 attack paths open simultaneously.

**Fix:**
- Introduce a minimal per-caller capability model on loopback:
  - Linux/macOS: switch to a Unix domain socket with `SO_PEERCRED` / `getpeereid`; gate admin ops on UID = 0 or the dds-service UID.
  - Windows: use a named pipe with `GetNamedPipeClientProcessId` and a client-token check; gate admin ops on SYSTEM or the service SID.
- Scope enrollment to the intended service account.
- Keep FIDO2 proof-of-possession on top. The transport auth is a separate layer.

---

### H-8. `admin_vouch` does not check that the admin is authorized to delegate the requested purpose
**Location:** [dds-node/src/http.rs:623-653](dds-node/src/http.rs#L623-L653) → [dds-node/src/service.rs:1254+](dds-node/src/service.rs#L1254)

**What's wrong:** Once a caller is in `trusted_roots`, they can vouch for any subject URN with any purpose. There is no per-admin capability bound. Combined with C-2, the first local process to self-enroll as admin has unlimited vouching power over the entire domain.

**Attack vector:** Trivially composed with C-2: attacker self-enrolls as admin, then issues vouches for arbitrary purposes (including granting themselves `dds:policy-publisher` after C-3 is fixed, which re-opens C-3).

**Impact:** No tiered admin model. Compromise of any admin = compromise of the whole domain, including the publisher capabilities that C-3's fix introduces.

**Fix:**
- Encode a purpose-allowlist or capability claim into each admin's enrollment attestation (signed by the previous admin or the bootstrap key).
- In `admin_vouch`, check that the requested `purpose` is in the caller's allowlist before emitting the vouch token.
- The bootstrap admin is a special case: define what it can vouch for (or confine it to vouching the second admin, then retire).

---

### H-9. Passphrase, HMAC-secret output, and plaintext key material not zeroized
**Location:** [dds-node/src/identity_store.rs:193](dds-node/src/identity_store.rs#L193), [dds-node/src/domain_store.rs:373-465](dds-node/src/domain_store.rs#L373-L465)

**What's wrong:** `std::env::var(PASSPHRASE_ENV)` returns a plain `String`. `fido2_hmac_secret()` returns a plain `Vec<u8>`. In `save_domain_key_fido2`, the raw 32-byte signing key is held in a non-zeroizing `Vec<u8>` during encryption. None of these are zeroed before drop. The error path at [domain_store.rs:291](dds-node/src/domain_store.rs#L291) returns before clearing `pt`.

**Attack vector:** Any process or forensic primitive that can read the dds-node heap (core dump, swap inspection, kernel-debug privilege, heap-grooming vuln) recovers the domain-key encryption key or the raw signing key material.

**Impact:** Compromise of at-rest key protection. A memory read at the wrong time recovers key material that should only ever exist in RAM transiently.

**Fix:**
- Use `zeroize::Zeroizing<String>` and `Zeroizing<Vec<u8>>` for passphrase, HMAC-secret outputs, and any temporary plaintext buffers.
- Audit all early-return paths in `identity_store.rs` and `domain_store.rs` — `?` propagation on an encrypted-write error must not bypass zeroization.
- Where feasible, keep secrets in `SecretBox` / `SecretVec` types so the compiler refuses to `Clone` them implicitly.

---

### H-10. Provisioning bundle has no integrity signature
**Location:** [dds-node/src/provision.rs:82-202](dds-node/src/provision.rs#L82-L202)

**What's wrong:** The one-file CBOR bundle contains `domain_id`, `domain_pubkey`, `org_hash`, `domain_key` (encrypted blob), and optional bootstrap peer info. The `domain_key_blob` is confidentiality-protected (passphrase-wrapped or FIDO2-wrapped) but **nothing else** is authenticated. No outer signature over the bundle body.

**Attack vector:**
1. Admin exports a bundle and sends it to a new node operator over email/USB/Slack.
2. MITM intercepts the bundle.
3. MITM swaps `domain_pubkey` to their own key and `bootstrap_peers` to point at their own dds-node.
4. The MITM can also re-encrypt a fresh `domain_key_blob` under a passphrase they control, or leave the original blob alone (they do not need to decrypt it — the victim just won't be able to unwrap it, but the node may still join the rogue domain if bootstrap keeps going).
5. Victim imports the bundle. Their node now treats the attacker's `domain_pubkey` as trusted and dials the attacker's bootstrap peer.

**Impact:** Supply-chain compromise of provisioning. Attacker controls domain-public-key trust anchor on a fresh node.

**Fix:**
- Sign the serialized bundle body (excluding the signature field) with the current domain signing key, or with a dedicated provisioning key trusted at install time.
- On `import` / `provision`, verify the signature against a pinned expected public key (passed via a separate channel — TOFU + out-of-band fingerprint confirmation is acceptable).
- Reject bundles that fail verification. Add a version byte so the format can evolve.

---

### H-11. Unbounded sync response assembly on `SyncRequest` with empty `known_op_ids`
**Location:** [dds-node/src/node.rs:455-466](dds-node/src/node.rs#L455-L466), [dds-net/src/sync.rs](dds-net/src/sync.rs)

**What's wrong:** `build_sync_response` clones every cached payload whose id is not in the requester's `known_op_ids` set. There is no byte-limit, count-limit, or pagination. A peer sending an empty `known_op_ids` forces the responder to serialize the entire `sync_payloads` map in one message.

**Attack vector:**
1. Attacker peers with the node (or any admitted peer misbehaves).
2. Attacker sends `SyncRequest { known_op_ids: BTreeSet::new(), heads: vec![] }`.
3. Responder iterates `sync_payloads`, clones every entry, and serializes them into one `SyncResponse`.
4. If the cache has accumulated (there is no LRU cap today — see M-5), the response exhausts heap and crashes the node.

**Impact:** Remote unauthenticated (if combined with H-12) or admitted-peer amplification DoS. One tiny request → unbounded allocation.

**Fix:**
- Cap each response at N payloads or B bytes (suggest 1000 entries or 5 MB, whichever smaller) and signal `complete: false` so the requester paginates.
- Add an LRU bound to `sync_payloads` in steady state so the maximum possible response is finite.
- Also enforce a hard cap in the codec (M-11 applies here).

---

### H-12. Gossip / sync payloads processed before per-peer admission is verified
**Location:** [dds-node/src/node.rs:100-115](dds-node/src/node.rs#L100-L115), [dds-node/src/node.rs:238-319](dds-node/src/node.rs#L238-L319)

**What's wrong:** The admission certificate is verified **once at node startup for this node only**. Incoming gossipsub messages are deserialized, trust-validated, and ingested with no per-peer admission check — only the per-token signature verification inside `trust_graph::add_token`. Any libp2p peer that completes the Noise handshake can publish into gossip topics.

**Attack vector (combined with C-3):**
1. Attacker generates a libp2p keypair. Costs: zero.
2. Attacker completes the Noise handshake with a target node that's listening on `0.0.0.0:4001` or reachable via mDNS.
3. Attacker publishes to the gossip topic. They are not admitted, but the node has no layer between "Noise handshake complete" and "message ingested by dds-node logic."
4. The message is a self-signed attestation token with an embedded `WindowsPolicyDocument`. `add_token` accepts it (self-signature checks out). The token lands in `self.attestations`.
5. Any Policy Agent polling `GET /v1/windows/policies` serves the attacker's document. See C-3 for the kill chain.

Even without C-3, the same pre-admission path lets an attacker flood the node with malformed payloads, forcing CBOR parse + signature verify on every message. Each FIDO2/Ed25519 verify is CPU-heavy.

**Impact:** Pre-admission remote state injection (via C-3) or CPU DoS.

**Fix:**
- Maintain a per-peer `is_admitted: bool` flag populated by verifying the peer's admission certificate during the libp2p `identify` handshake, or via a request-response protocol run immediately after Noise completes.
- Drop gossip/sync from non-admitted peers at the behaviour layer, before `dds-node` sees the message.
- Even once this lands, **keep C-3's publisher-authorization checks** — "admitted peer" does not imply "policy publisher."

---

## Medium

### M-1. CBOR canonicalization not enforced on signed token bodies
**Location:** [dds-core/src/token.rs:124-225](dds-core/src/token.rs#L124-L225)

`ciborium` does not emit canonical CBOR by default. `Token::sign` signs bytes from `ciborium::into_writer(&payload)`, so two serializations with differently-ordered keys or different length encodings can both verify. Combined with `skip_serializing_if = "Option::is_none"`, the signed byte stream depends on which fields are present.

**Impact:** Signature non-malleability is weakened; a normalizer in the middle of the pipeline could invalidate signatures, or produce ambiguity in replay detection.

**Fix:** Sign over `SHA-256(canonicalized CBOR)` using RFC 8949 §4.2.1 deterministic encoding (sort map keys by encoded bytes, shortest-form integers, definite-length items). Alternatively, pin a canonical-encoder fork of ciborium or switch to a JSON-canonical representation and sign that.

### M-2. Hybrid Ed25519 + ML-DSA-65 signatures lack domain separation
**Location:** [dds-core/src/crypto/hybrid.rs:56-68](dds-core/src/crypto/hybrid.rs#L56-L68)

Both signatures are computed over the same message bytes. Safe today, but adding scheme tags (`"ed25519-v1:" || msg`, `"mldsa65-v1:" || msg`) is cheap insurance against future cross-protocol attacks.

**Fix:** Add constant prefixes before signing and verifying. Roll as a versioned breaking change.

### M-3. No rate-limiting anywhere on the HTTP authority
**Location:** [dds-node/src/http.rs](dds-node/src/http.rs)

`/v1/session/challenge`, `/v1/session/assert`, `/v1/admin/*`, and enrollment endpoints accept unlimited request rates. FIDO2 signature verification is CPU-heavy.

**Impact:** Local attacker DoSes the node by flooding `/v1/session/assert` with payloads that fail at the signature stage. Also enables timing-side-channel studies on credential lookup.

**Fix:** Token-bucket per caller (per-PID via SO_PEERCRED on loopback) or a coarse global rate. Reject 429 beyond threshold; log.

### M-4. mDNS discovery on by default on `0.0.0.0:4001`
**Location:** [dds-net/src/transport.rs:82,138-145](dds-net/src/transport.rs#L82), [dds-node/src/node.rs:240-250](dds-node/src/node.rs#L240-L250)

Any LAN host can broadcast mDNS responses that land in Kademlia and gossipsub peer sets without rate-limiting.

**Impact:** LAN Sybil flood — node burns CPU on handshakes against fakes, crowding out real peers.

**Fix:** Keep default for deployability, but add a per-minute cap on new-peer acceptances and a hard ceiling on peer-table size. Document hardened config (`mdns = false`, `listen_addr = "/ip4/127.0.0.1/…"`) prominently.

### M-5. `cache_sync_payload` and `force_sync_with` lack bounds
**Location:** [dds-node/src/node.rs:369,494](dds-node/src/node.rs#L369)

Visibility widened in the pending diff. `sync_payloads` is an unbounded `BTreeMap`; `force_sync_with` bypasses the 15s cooldown. Only tests call them today, but the docstring advertises an HTTP-handler use.

**Fix:** Cap the cache at N entries with LRU eviction. If HTTP exposes `force_sync_with`, gate behind auth + rate limit (and the fix in H-7).

### M-6. Admission certificate expiry only checked at startup
**Location:** [dds-node/src/node.rs:100-115](dds-node/src/node.rs#L100-L115)

Once the node has started, no re-check. A node whose admission cert has expired keeps operating until restart.

**Fix:** Re-verify periodically (every 10 min) and shut down cleanly on expiry; also re-verify on each new inbound peer connection.

### M-7. Self-attested device enrollment tags/org_unit still unverified
**Location:** [dds-node/src/service.rs](dds-node/src/service.rs) device enrollment path

A rogue local process enrolls a device claiming privileged tags (e.g. `admin`, `privileged-workstation`) and gets policy scoped for that tag — without any admin involvement.

**Fix:** Require an admin vouch over the `(device_urn, tags, org_unit)` tuple before those attributes are honored by policy evaluation. Store a `scope_vouched: bool` on the device document.

### M-8. Policy/software enumeration endpoints accept any `device_urn`
**Location:** [dds-node/src/http.rs:657-793](dds-node/src/http.rs#L657-L793)

`GET /v1/windows/policies?device_urn=<any>` returns the full policy set for any device with no proof the caller represents that device.

**Impact:** Any local caller reads every device's policy (registry values, shell commands, password rules) in the domain. Reconnaissance goldmine.

**Fix:** Require the caller to present a session token or vouch that binds them to `device_urn`. On Windows, derive a per-machine secret at provisioning and require it in a header.

### M-9. Revocation/burn replay is rebroadcast-able
**Location:** [dds-node/src/node.rs:383-439](dds-node/src/node.rs#L383-L439)

Gossipsub dedupes by content hash, but an attacker recording an old revocation and rebroadcasting with a different outer envelope sees it re-processed. Insertion is idempotent, but the audit log gets a spurious event.

**Fix:** Add `not_before` / issuance timestamp to revocation/burn tokens and reject those older than a configurable window. Or maintain a bloom filter of recently-applied JTIs.

### M-10. Argon2id parameters modest
**Location:** [dds-node/src/identity_store.rs:231](dds-node/src/identity_store.rs#L231)

19 MiB, t=2, p=1 meets OWASP's lowest tier. On the low end for a signing-key wrap.

**Fix:** Move to t=3 or bump memory to 64 MiB, p=4. Measure unlock time on target hardware; users should see ~200-500 ms.

### M-11. CBOR / HTTP body size limits not configured
**Location:** [dds-node/src/http.rs](dds-node/src/http.rs), [dds-net/src/transport.rs:116-126](dds-net/src/transport.rs#L116-L126)

Axum default is 2 MB for JSON extractors; gossipsub default for `max_transmit_size` is also generous. Deserialization happens before any app-layer size filter.

**Fix:** ~256 KB on HTTP bodies, ~1 MB on gossipsub `max_transmit_size`, explicit caps on `SyncRequest`/`SyncResponse` via the request-response codec configuration.

### M-12. WebAuthn `clientDataJSON` not parsed
**Location:** [dds-node/src/service.rs:1001-1004](dds-node/src/service.rs#L1001-L1004), [dds-domain/src/fido2.rs](dds-domain/src/fido2.rs)

Server rebuilds an *expected* `clientDataJSON` and compares hashes. Cryptographically equivalent to checking `type`/`origin`/`challenge` individually, but only if the client's real `clientDataJSON` is byte-identical. Different serializers produce hash mismatch for legitimate clients.

**Fix:** Parse the client-supplied `clientDataJSON` and enforce `type`, `origin`, `challenge` individually per WebAuthn §7.2 steps 7–9.

### M-13. No attestation validation at user enrollment
**Location:** [dds-node/src/service.rs](dds-node/src/service.rs) enrollment paths

Attestation objects are parsed but the attestation statement (`fmt`, `attStmt`) is not verified against a trust anchor. Self-attestation is accepted.

**Fix:** Validate attestation statements with a configurable trust anchor list (FIDO Metadata Service), or document explicitly that self-attestation is trusted and the domain enforces device attestation out-of-band.

### M-14. Unencrypted key-file fallback is silent
**Location:** [dds-node/src/identity_store.rs:117-120](dds-node/src/identity_store.rs#L117-L120)

If `DDS_DOMAIN_PASSPHRASE` / `DDS_NODE_PASSPHRASE` is unset, keys are written unencrypted with only a `warn!` log.

**Attack vector:** Attacker with filesystem write clears the env var, restarts the node (or waits for a crash), keys are rewritten in plaintext on next save.

**Fix:** Persist an `encrypted = true` marker alongside the key file at first encrypted save; refuse to overwrite with plaintext if the marker is set. Offer `--allow-plaintext` for dev.

### M-15. FIDO2 protection of domain key is not node-bound
**Location:** [dds-node/src/domain_store.rs:339-365](dds-node/src/domain_store.rs#L339-L365)

FIDO2 credential uses RP string `"dds-domain-key"` shared across all nodes provisioned from the same domain. `credential_id` + `hmac_salt` are the only unlock inputs — neither binds to the node's Ed25519 identity.

**Impact:** One compromised authenticator + any provisioned node's key file unlocks the domain key on every such node.

**Fix:** Include `SHA-256(node_urn)` in `hmac_salt` so the derived HMAC-secret differs per node. Document that re-provisioning is required for key rotation.

### M-16. Export/import dump file has no integrity signature
**Location:** [dds-cli/src/main.rs:1024-1191](dds-cli/src/main.rs#L1024-L1191), [dds-cli/src/dump.rs](dds-cli/src/dump.rs)

`.ddsdump` files (tokens, revocations, burns) are world-readable (`0o644`) and have no outer signature. Individual tokens are self-signed, but an attacker swapping the file can drop or reorder entries.

**Fix:** Sign the dump body with a domain/admin key; verify on import before applying any operation. Set file mode `0o600`.

### M-17. CTAP2 CBOR parser in Windows Auth Bridge lacks documented bounds
**Location:** [platform/windows/native/DdsAuthBridge/ctap2/cbor.cpp](platform/windows/native/DdsAuthBridge/ctap2/cbor.cpp)

USB-HID CTAP2 data is usually "trusted hardware," but a malicious USB device can exploit unbounded-allocation bugs in hand-written CBOR parsers.

**Fix:** Audit `cbor.cpp` for bounded-read invariants on every length field; add a depth limit and max-allocation cap.

### M-18. Windows services all run as LocalSystem
**Location:** [platform/windows/installer/DdsBundle.wxs:116,143,200](platform/windows/installer/DdsBundle.wxs#L116)

dds-node, DdsAuthBridge, DdsPolicyAgent all install as LocalSystem. At least AuthBridge and the HTTP-polling portion of PolicyAgent could run as NT SERVICE and impersonate up only when applying policy.

**Fix:** Split PolicyAgent into a low-priv fetcher and a privileged enforcer (narrow IPC between them); run AuthBridge as a dedicated service SID.

### M-19. Session-token clock-skew / monotonicity
**Location:** [dds-node/src/http.rs:504-510](dds-node/src/http.rs#L504-L510), [dds-node/src/service.rs:1512](dds-node/src/service.rs#L1512)

Session `exp` and challenge TTLs computed from `SystemTime::now()`. NTP backstep or VM snapshot-restore can un-expire tokens and re-validate consumed challenges.

**Fix:** Use `Instant` for challenge TTLs (monotonic). For token `exp`, store issuance timestamp alongside to detect backward clock jumps; refuse validation if the system clock regressed since startup.

### M-20. Redb database file not mode-restricted
**Location:** [dds-store/src/redb_backend.rs:37-72](dds-store/src/redb_backend.rs#L37-L72)

`directory.redb` is created with default umask. Tokens, audit entries, and credential metadata are readable by any local user.

**Fix:** Set `0o600` after `Database::create()`; set an explicit ACL on Windows.

### M-21. Audit-log entries are appended without verifying the embedded node signature
**Location:** [dds-node/src/node.rs:441-449](dds-node/src/node.rs#L441-L449), [dds-core/src/audit.rs:9-26](dds-core/src/audit.rs#L9-L26)

**What's wrong:** `ingest_audit` deserializes `AuditLogEntry` and appends it to storage. The path does **not** verify `node_signature`, does not check that `node_urn` binds to `node_public_key`, and does not reject replays.

**Attack vector:**
1. Admitted (or unadmitted-if-H-12) peer crafts an `AuditLogEntry` with forged `node_urn`, `node_public_key`, `node_signature`, and an arbitrary `action`/`token_bytes`.
2. Peer gossips the audit message.
3. `ingest_audit` deserializes it and calls `self.store.append_audit_entry(&entry)` directly. No signature check.
4. The audit log now contains an entry that claims to be from a different node, recording an event that may never have happened.

**Impact:** Compliance-trail poisoning. Does not change directory state directly but undermines post-incident forensics and any trust placed in the audit log.

**Fix:**
- Define a deterministic signed encoding for `AuditLogEntry` (canonical CBOR over all fields except `node_signature`).
- In `ingest_audit`: reject if `node_signature` fails to verify under `node_public_key`; reject if `node_urn` does not derive from `node_public_key` (same URN-from-pubkey check used elsewhere).
- For tamper-evidence beyond single-entry signing, add a hash chain: each entry commits to the prior entry's hash (see L-11).

### M-22. Persisted admin signing keys are wrapped only by the node key and lack permission hardening
**Location:** [dds-node/src/service.rs:1358-1454](dds-node/src/service.rs#L1358-L1454)

**What's wrong:** `store_admin_key` derives its AES wrapping key from `SHA-256(node_signing_key || "admin-key-wrap")` at [service.rs:1448-1454](dds-node/src/service.rs#L1448-L1454). The encrypted blob is written under `admin_keys/` with default directory and file permissions (no explicit `0o600` or ACL).

**Attack vector:**
1. Attacker compromises an admin workstation and reads the node's Ed25519 signing key from disk or memory.
2. Attacker also reads `admin_keys/<urn_hash>.key`. The file is not mode-restricted, so even a non-root local attacker can read it once they have the node key.
3. Attacker derives the wrap key (`SHA-256(node_key || "admin-key-wrap")`) and decrypts the admin signing key.
4. Attacker now has durable domain-admin signing capability — they can mint admin vouches offline indefinitely, even after the workstation is cleaned.

**Impact:** Node-key compromise on an admin machine escalates into a persistent, portable admin signing capability. Cleaning the machine does not revoke the attacker's capability.

**Fix:**
- Wrap admin signing keys with an OS-bound secret: DPAPI on Windows, Keychain on macOS, TPM-sealed key on Linux. Attacker must be logged in as the service principal at key-use time, not just possess the file.
- Alternatively, use a dedicated admin secret (e.g., admin passphrase) distinct from the node key.
- Set owner-only permissions on `admin_keys/` and its contents (`0o700` / `0o600` on Unix; explicit ACL on Windows).
- Zeroize plaintext buffers after use (`store_admin_key` currently holds `plaintext` and `key_bytes` in plain arrays — see H-9).
- Prefer atomic writes to avoid torn-blob states.

---

## Low

### L-1. `SigningKey::clone` of Ed25519 key in `Identity::generate`
[dds-core/src/identity.rs:142](dds-core/src/identity.rs#L142) — clones an unzeroized key, leaves extra copies on the heap.

### L-2. No `O_NOFOLLOW` / symlink guard on key-file reads
[dds-node/src/identity_store.rs:156](dds-node/src/identity_store.rs#L156) + siblings — a symlink swap lets a local attacker redirect `std::fs::read`.

### L-3. Key files written non-atomically
[dds-node/src/identity_store.rs:139](dds-node/src/identity_store.rs#L139) + siblings — crash mid-write corrupts the key. Use `tempfile` + atomic rename.

### L-4. Parent directory perms not tightened
[dds-node/src/identity_store.rs:81](dds-node/src/identity_store.rs#L81) — `create_dir_all` uses default `0o755`. Set `0o700` after create.

### L-5. Export file mode `0o644`
[dds-cli/src/main.rs:1113](dds-cli/src/main.rs#L1113) — revocation/burn list world-readable. Set `0o600`.

### L-6. No TLS enforcement on non-loopback `--node-url`
[dds-cli/src/client.rs:22-34](dds-cli/src/client.rs#L22-L34) — CLI silently accepts `http://`. Refuse non-HTTPS for non-loopback.

### L-7. `SystemTime::now().unwrap()` panic across FFI
[dds-ffi/src/ffi_core.rs:366](dds-ffi/src/ffi_core.rs#L366) — pre-1970 clock panics. Wrap in `catch_unwind` or `unwrap_or(0)`.

### L-8. No size limits on `rules` / `tokens_cbor_hex` arrays in FFI policy eval
[dds-ffi/src/ffi_core.rs:267-320](dds-ffi/src/ffi_core.rs#L267-L320) — malicious JSON consumes memory. Cap array lengths.

### L-9. Error-message leakage from HTTP API
[dds-node/src/http.rs:308-323](dds-node/src/http.rs#L308-L323) — `ServiceError` strings reach clients, leaking trust-graph contents ("credential X not found", "challenge expired"). Map to opaque error codes at the HTTP boundary.

### L-10. Admin key-wrap blob has no version byte
[dds-node/src/service.rs:1372](dds-node/src/service.rs#L1372) — future algorithm migration requires out-of-band schema knowledge. Prepend a version byte.

### L-11. LWW-register convergence by wallclock, not happens-before
[dds-core/src/crdt/lww_register.rs:47-52](dds-core/src/crdt/lww_register.rs#L47-L52) — if used where causal ordering is assumed, silent "wrong winner." Audit call sites or switch to a CRDT with causal ordering where needed.

### L-12. Trust-graph audit log has no hash chain
[dds-core/src/audit.rs](dds-core/src/audit.rs) — entries are per-node signed (after M-21), but a tamper-evident append-only hash chain would harden against admin-level compromise that can rewrite storage.

### L-13. Credential-ID comparison is base64-string equality
[dds-node/src/service.rs:942](dds-node/src/service.rs#L942) — normalize to raw bytes or canonical base64url-no-pad at both store and lookup.

### L-14. CredentialProvider `KERB_INTERACTIVE_UNLOCK_LOGON` password handling
[CDdsCredential.cpp:445-468](platform/windows/native/DdsCredentialProvider/CDdsCredential.cpp#L445-L468) — `ProtectIfNecessaryAndCopyPassword` implementation not verified; intermediate stack copies of the password may linger. Zero after use.

### L-15. Non-constant-time comparison on `vch_sum` hex strings
[dds-core/src/trust.rs:283,358,386](dds-core/src/trust.rs#L283) — hashes are public, but use `subtle::ConstantTimeEq` for discipline.

### L-16. Windows `AppliedStateStore` file not ACL-restricted
[platform/windows/DdsPolicyAgent/State/AppliedStateStore.cs:82-87](platform/windows/DdsPolicyAgent/State/AppliedStateStore.cs#L82-L87) — inherits parent dir ACL; should explicitly restrict to SYSTEM.

### L-17. HTTP handlers hold the service-wide `Mutex` across all I/O
[dds-node/src/http.rs:369-375](dds-node/src/http.rs#L369-L375) — concurrency ceiling of one HTTP request at a time; a slow handler starves the P2P event loop that shares the lock. (Also: this is what makes a sign-count race impossible today — so fixing this warrants a matching fix for atomic counter updates.)

### L-18. Sign-count update coupled to service mutex
[dds-node/src/service.rs:1020](dds-node/src/service.rs#L1020) — correct today only because of L-17's serialization. If L-17 is fixed, the sign-count increment must become atomic-compare-and-set in `CredentialStateStore`.

---

## Informational

- **I-1.** No explicit equivocation detection on contradictory attestations from the same admitted peer ([dds-core/src/trust.rs](dds-core/src/trust.rs)). CRDT semantics allow it; no slashing.
- **I-2.** Transport / Noise and PeerId derivation appear correct; no findings ([dds-net/src/transport.rs:98-107](dds-net/src/transport.rs#L98-L107)).
- **I-3.** `subject_urn` binding fix verified — session is bound to credential owner, caller value ignored ([dds-node/src/service.rs:1059-1062](dds-node/src/service.rs#L1059-L1062)).
- **I-4.** Sign-count replay detection is enforced ([dds-node/src/service.rs:1020](dds-node/src/service.rs#L1020)) — prior review's "remaining work" item now closed.
- **I-5.** Admission cert TTL capped at 1y — verified.
- **I-6.** CBOR deserialization has no documented depth limit — `ciborium` is generally safe but deeply-nested inputs can cause stack growth.
- **I-7.** Default-deny policy engine verified correct; logic is subtle but sound ([dds-core/src/policy.rs:69-108](dds-core/src/policy.rs#L69-L108)).
- **I-8.** Credential-ID string length for CTAP2 is read as `u16` without upper bound ([dds-domain/src/fido2.rs:147-155](dds-domain/src/fido2.rs#L147-L155)).
- **I-9.** Secrets in Python bindings linger in GC'd strings ([bindings/python/dds.py:116,132](bindings/python/dds.py#L116)) — use `ctypes.create_string_buffer` for sensitive inputs.
- **I-10.** COSE `alg` field not strictly required in parser ([dds-domain/src/fido2.rs:350,365](dds-domain/src/fido2.rs#L350)); `kty` alone determines the scheme but RFC 9052 mandates `alg`.
- **I-11.** `trusted_roots` is not coherent across peers. Each node reads its own set from local TOML config at startup; admin additions (vouches) are gossiped but the *membership of `trusted_roots`* is not. Peers can therefore disagree about who is an admin. Current C-2 fix preserves this property deliberately (see C-2 "Out of scope"). A future redesign should chain admins back to a domain-key-signed genesis attestation so the admin set is derived from the gossip stream rather than configured per node. Tracked here rather than as an open finding because it is a latent design limitation, not a presently-exploitable bug given the C-2 fix.

---

## Coverage map

| Area | Reviewed | Not reviewed / assumption |
|---|---|---|
| `dds-core` (crypto, identity, token, trust, policy, audit, crdt) | ✓ | Benchmarks; `cargo audit` not runnable |
| `dds-net` (transport, gossip, sync, discovery) | ✓ | libp2p baseline security assumed correct |
| `dds-node` http.rs, service.rs, node.rs, config.rs, main.rs, provision.rs, identity_store.rs, domain_store.rs, p2p_identity.rs, expiry.rs | ✓ | service.rs >30k tokens — mid/late sections spot-checked |
| `dds-domain` (lib, fido2, domain, types) | ✓ | — |
| `dds-store` (redb, memory, traits) | ✓ | redb internals trusted |
| `dds-ffi`, `dds-cli`, `bindings/{c,python,csharp}` | ✓ | Kotlin/Swift skimmed only |
| `platform/windows/native/{DdsCredentialProvider, DdsAuthBridge, DdsBridgeIPC, DdsCommon}` | ✓ | `ctap2/cbor.cpp` not deep-audited (see M-17) |
| `platform/windows/DdsPolicyAgent` (+ Tests) | ✓ | — |
| `platform/windows/installer` (WiX) | ✓ | Authenticode signing / update pipeline not in source |
| `platform/windows/native/DdsTrayAgent` | ✗ | Low priority — UI, non-privileged |
| `platform/macos/DdsPolicyAgent` | ✓ | Agent + localhost HTTP client audited (H-3) |
| `platform/ios`, `platform/android`, `platform/embedded` | ✗ | Out of scope for this pass |
| `dds-fido2-test`, `dds-loadtest` | Brief | Non-production |

### Things we could not run (environment)

- `cargo audit` for dependency CVEs — Rust toolchain unavailable.
- No live authenticator to exercise the WebAuthn flow end-to-end.
- No Windows / macOS host to run Credential Provider / Policy Agent integration tests.

## Recommended sequencing

If triaging by effort × blast radius:

1. **Now (small patches, large impact):** **C-1**, **C-2**, **C-3**, **H-1**, **H-4**, **H-5**, **H-9**. C-3 is the highest-priority remote-exploit item — move it to the top alongside C-1/C-2.
2. **This sprint (architectural, ~1–3 days each):** **H-2**, **H-3**, **H-6**, **H-7**, **H-8**, **H-10**, **H-11**, **H-12**. H-2 and H-3 share a design (signed document bodies + agent-side verification) — build once, apply to both agents.
3. **Next:** Medium cluster, starting **M-5** (pending diff, cheap fix), **M-3** (rate limits), **M-8** (policy enumeration authorization), **M-21** (audit signature verification), **M-22** (OS-bound admin key wrap).
4. **Backlog:** Low / Informational items; bundle into a general hardening pass.

## Cross-references to prior review

`security-gaps.md` (2026-04-12) findings — status confirmed by this review:

- ~~Critical: Unauthenticated session mint~~ — **still fixed**. Endpoint remains removed.
- ~~High: Assertion not bound to subject~~ — **still fixed** ([service.rs:1059-1062](dds-node/src/service.rs#L1059-L1062)).
- ~~High: Self-attested device scope~~ — **still a concern**; tracked here as M-7.
- Provision bundle TTL 1y — **still in place**.
- Key file `0o600` on Unix — **still in place**; Windows ACLs still open (tracked as H-5 / M-20 / L-16).

### New findings not in `security-gaps.md`

- **Critical:** C-1 (FFI null deref), C-2 (admin_setup bootstrap), C-3 (policy-publisher authorization).
- **High:** H-1 (revocation auth bypass), H-2 (Windows Policy Agent unsigned HTTP), H-3 (macOS Policy Agent unsigned HTTP), H-4 (attestation JTI collision), H-5 (named-pipe SDDL), H-6 (challenge injection), H-7 (HTTP authZ missing), H-8 (admin_vouch capability), H-10 (bundle integrity), H-11 (sync response size), H-12 (per-peer admission).
- **Medium:** M-21 (audit signature not verified on ingest), M-22 (admin keys wrapped only by node key).
