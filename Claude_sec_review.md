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

## Remediation status (latest pass 2026-04-21; Windows host verification 2026-04-24)

This section records the state of each finding after the remediation pass.
`✅ Fixed (pending verify)` means code landed in this branch and local
test + clippy are green; still needs CI, code review, and any production
exercise before being considered closed. `⏸ Deferred` means intentionally
left for a follow-up PR — usually because the fix spans languages
(Rust + C# agents, C++ bridge) or requires a disk/wire format migration.

**Shipped this pass (commits `2442953`, `ae9d33e`, `a8035ff`, `1c19206`, `e66d696`):**
all 3 Critical (C-1, C-2, C-3), 7 High (H-1, H-4, H-5, H-8, H-9, H-10, H-11),
10 Medium (M-3, M-5, M-6, M-7, M-9, M-11, M-16, M-19, M-20, M-21, M-22),
and 12 Low (L-1, L-2, L-3, L-4, L-5, L-6, L-7, L-8, L-9, L-10, L-11 audit,
L-12, L-13, L-15).

**Shipped this pass (2026-04-18 follow-up):** H-2 and H-3 (Rust signer +
C# BouncyCastle verifier across Windows + macOS agents, with a
cross-language test vector pinned on both sides); M-4 (mDNS Sybil
caps); M-12 (WebAuthn §7.2 field-level clientDataJSON parser, with
backward-compat fallback); M-14 (encrypted-marker refuses silent
plaintext downgrade); L-18 (atomic `bump_sign_count` primitive —
defense-in-depth if L-17 lands).

**Still deferred (after the 2026-04-20 passes)** — 0 High, 3 Medium,
1 Low: **M-13** (FIDO MDS attestation policy — needs external MDS
integration design); **M-15** (node-bound FIDO2 `hmac_salt` via
bundle re-wrap — re-deferred 2026-04-18, blocked on a bundle
re-wrap design decision); **M-18** (WiX service-account split —
multi-day Windows-side refactor authoring is feasible, but
verification requires a Windows CI host + pilot deployment); **L-17**
(service mutex refactor — 29 lock sites in HTTP handlers need
per-field lock redesign; L-18's atomic `bump_sign_count` already
closed the underlying replay race, so the remaining gain is
throughput, not security). All High and previously-partial items
(H-6, H-7 step-2a/2b, H-12, M-8) are Fixed-pending-verify as of
2026-04-20 — Windows CI runs are required for the C++ / MSI
portions of H-6 and H-7.

**2026-04-25 independent follow-up — new open findings:** 3 High,
3 Medium. These were found after reviewing the source first and only
then comparing against `security-gaps.md`, this review, and
`docs/threat-model-review.md`. They are not duplicates of H-6/H-7/M-8,
L-9, A-1, A-3, A-4, or A-6.

- **B-1 (High)**: sync response application writes tokens and
  revocation/burn side effects to persistent storage before the trust
  graph accepts them. `apply_sync_payloads_with_graph` stores each token
  at `dds-net/src/sync.rs:316` before `trust_graph.add_token`, while
  `TokenStore::put_token` explicitly overwrites existing JTIs. An
  admitted peer can send a validly signed duplicate-JTI token that the
  in-memory graph rejects, but the store retains for the next restart;
  malformed or unauthorized revoke/burn side effects can likewise be
  persisted even after graph rejection. **Fix:** validate with the trust
  graph first, make store insertion put-if-absent or exact-byte
  idempotent, and apply `store.revoke` / `store.burn` only when graph
  insertion succeeds.
- **B-2 (High)**: purpose checks are not tied to a live target
  attestation, and inbound token validation does not enforce the shape
  invariants enforced by `Token::create`. `has_purpose` /
  `purposes_for` use `attestation_for_iss` only for `vch_sum` hash
  comparison and do not reject revoked or expired target attestations.
  Separately, `Token::validate` accepts signed vouches missing
  `vch_sum` / `vch_iss`, even though local construction rejects them.
  **Fix:** share one structural validator between `Token::create`,
  `Token::validate`, and graph ingest; require a matching active
  attestation for every purpose grant; and prefer exact target-token
  references over "first attestation for issuer" lookup.
- **B-3 (High)**: failed policy/software enforcement can be recorded as
  applied and skipped forever. The Windows worker records `"ok"` after
  dispatch even when an enforcer returned `Failed`; the macOS worker
  records failure status, but `HasChanged` ignores status and therefore
  skips unchanged failed documents on later polls. **Fix:** record
  success only for successful outcomes, include status in `HasChanged`,
  and retry failed entries until they succeed or are superseded.
- **B-4 (Medium)**: active policy/software versions are not resolved
  deterministically. The node returns every matching policy/software
  attestation in implementation-defined order; agents key applied state
  by logical `policy_id` / `package_id`. Multiple active documents for
  the same logical ID can therefore apply in the wrong final order or
  flap across restarts. **Fix:** add explicit supersession semantics,
  require revocation of old versions, or select one latest valid
  document per logical ID at serve time.
- **B-5 (Medium) ✅ landed 2026-04-25**: challenge records can accumulate
  without production cleanup. `/v1/session/challenge` and
  `/v1/admin/challenge` persisted challenge rows, expired rows were not
  deleted on failed consume, and `sweep_expired_challenges` had no
  production caller. **Fix shipped:** the issue path
  (`http::issue_challenge`) now calls `sweep_expired_challenges` before
  every `put_challenge`, then enforces a global
  `MAX_OUTSTANDING_CHALLENGES = 4096` cap (returning `503 Service
  Unavailable` if the backlog is full). `consume_challenge` deletes
  expired and malformed rows in the same write transaction so a probe
  of a stale id contributes to cleanup rather than leaking the row. A
  new `count_challenges` method on `ChallengeStore` backs the cap
  check. New tests:
  `dds-store/src/memory_backend.rs::b5_challenge_cleanup_tests` (2),
  `dds-store/src/redb_backend.rs::b5_challenge_cleanup_tests` (2), and
  `dds-node/src/http.rs::tests::test_issue_challenge_caps_outstanding`
  / `::test_consume_expired_drops_row`.
- **B-6 (Medium)**: the Windows software installer has a post-hash
  TOCTOU window. Packages are staged under `%TEMP%\dds-software`,
  hashed, closed, then later executed as SYSTEM. On typical Windows temp
  ACLs, a local user may be able to swap or delete the staged file
  between verification and `Process.Start`. **Fix:** stage under a
  SYSTEM/Admin-only cache, preserve a protected verified handle where
  practical, or rehash immediately before launch.

**Reviewer follow-ups already closed this round** (previously flagged
as partial):

- **M-9**: replay window now enforced on BOTH gossip AND sync paths.
- **M-16**: v1 dumps refused by default; `--allow-unsigned` required
  for legacy migration (closes the v2 → v1 downgrade attack).
- **L-12**: store-side append-time chain verification landed in both
  `MemoryBackend` and `RedbBackend`; `DdsNode::emit_local_audit` is
  the production chained-emit hook.
- **C-3**: ingest-side reject added to complement the serve-side filter.
- **H-8**: bootstrap admin rehydrated from config at startup;
  `admin_vouch` with `purpose::ADMIN` promotes the subject to
  `trusted_roots` and persists.

**2026-04-18 second follow-up pass — new fixes:**

- **L-14**: `ProtectAndCopyString` and `ProtectIfNecessaryAndCopyPassword`
  now `SecureZeroMemory` their plaintext-password `SHStrDupW` copies
  before `CoTaskMemFree`. Both `CDdsCredential::GetSerializationDds`
  and `GetSerializationBridge` zero `pwzProtectedPassword` before
  freeing it (the CredUI / already-encrypted paths hand back plaintext
  through that pointer, so zeroing is not merely defense-in-depth).
- **L-16**: `AppliedStateStore.WriteToDisk` sets an explicit,
  non-inherited DACL on `applied-state.json` granting only
  `LocalSystem` and `BUILTIN\Administrators`. No-op on non-Windows
  builds so existing xUnit tests keep passing cross-platform.
- **M-17**: `CborDecoder` adds `kMaxCborDepth = 16` and bounded-alloc
  guards. Array/map element counts rejected when they exceed the
  remaining wire bytes (each element ≥ 1 byte; map entries ≥ 2
  bytes). `ReadBytes` compares against `Remaining()` rather than
  computing `m_pos + count`, which closes a size_t-wrap on
  attacker-chosen lengths. Depth carried as a parameter through
  `DecodeValue` instead of a member to avoid state bleed between
  `Decode` calls.

**2026-04-18 follow-up pass — new fixes:**

- **H-2 / H-3**: Signed policy/software envelopes. Rust signs each
  `/v1/{windows,macos}/{policies,software}` response with the node's
  Ed25519 signing key; Windows and macOS C# agents (BouncyCastle
  pure-managed Ed25519) verify against a pinned pubkey before any
  enforcer runs. Fails closed when the pubkey isn't configured.
  Cross-language interop vector pinned bilaterally (Rust emits → C#
  verifies). 19 new unit tests across `dds-core`, `dds-node`,
  `DdsPolicyAgent.Tests`, `DdsPolicyAgent.MacOS.Tests`.
- **M-4**: mDNS Sybil caps on the node swarm (per-minute new-peer
  rate + hard peer-table ceiling).
- **M-12**: Client-supplied `clientDataJSON` is now parsed per
  WebAuthn §7.2 field-by-field instead of reconstruct-and-hash.
  Legacy fallback preserves backward compat.
- **M-14**: Sticky encrypted marker refuses silent plaintext
  downgrade of the node identity file.
- **L-18**: Atomic `bump_sign_count` primitive (redb write-txn
  enclosed); service switched over. Race-free even without L-17.

**2026-04-19 follow-up pass — new fixes:**

- **M-1**: Canonical-CBOR encoder landed as `dds-core::cbor_canonical`
  (RFC 8949 §4.2.1 deterministic encoding: shortest-form integer args,
  definite-length items, text-string map keys sorted by encoded bytes).
  Token wire bumped to `v=2`; signed bytes are
  `"dds-token-v2\x00" || canonical_cbor(payload)`. The v=2 verify path
  recanonicalises and rejects any wire whose payload bytes aren't
  byte-identical, which closes the key-reorder / length-encoding
  signature malleability. Legacy `Token::sign_v1` / `verify_signature`
  v=1 path stays so pinned vectors and on-disk pre-v2 blobs keep
  decoding. New errors: `TokenError::NonCanonicalPayload`,
  `UnsupportedWireVersion(u8)`. Commit `60050ce`. See also the M-1/M-2
  downgrade guard below.
- **M-2**: Hybrid and triple-hybrid signatures are now domain-separated
  per component. Ed25519 signs
  `"dds-hybrid-v2/ed25519\x00" || msg`; ML-DSA-65 signs
  `"dds-hybrid-v2/mldsa65\x00" || msg`; triple-hybrid uses the matching
  `"dds-triple-v2/{ed25519,p256,mldsa65}\x00"` prefixes. Regression
  test asserts the Ed25519 (and P-256) component of a v2 hybrid
  signature cannot be lifted out and verified standalone. `sign` /
  `verify_hybrid` are v2 aliases; `sign_v1` / `verify_*_v1` kept for
  pinning legacy vectors. Commit `60050ce`.
- **M-10**: Keyfile schema `v=3` now carries Argon2id
  `(m_cost, t_cost, p_cost)` in the blob. Defaults raised to m=64 MiB,
  t=3, p=4 (OWASP tier-2; target unlock ~200–500 ms on modern
  hardware). `load()` accepts v=2 (legacy 19 MiB / t=2 / p=1) and v=3;
  a v=2 success triggers a transparent rewrap to v=3 so operators see
  no disruption. `derive_key` takes `KdfParams`; `save()` always emits
  v=3. Tests pin on-disk bytes at v=3 and the lazy v2→v3 rewrap
  preserves identity URN. M-14 plaintext-downgrade guard unchanged.
  Commit `1b5f51d`.
- **M-1 / M-2 downgrade guard**: `NetworkConfig.allow_legacy_v1_tokens`
  (default `false`) gates every inbound token path:
  `DdsNode::legacy_token_refused` drops v=1 envelopes at gossip
  (`ingest_operation`, `ingest_revocation`, `ingest_burn`) and at the
  sync-response filter. Persisted v=1 tokens already on the local
  store continue to verify and serve — only fresh ingest is gated.
  Operators flip the flag on for a domain-wide cutover and back off
  once legacy publishers are retired. Commit `1b5f51d`. Pairs with M-1
  and M-2 above.
- **H-6 / H-7 / M-8 step-1 (Rust plumbing)**: Transport-neutral
  scaffolding ready for the UDS/named-pipe follow-up. TCP listener
  stays the default so existing deployments are unchanged.
  - `ApiAuthConfig` on `NetworkConfig` carries
    `trust_loopback_tcp_admin` (default `true` for backward compat),
    `unix_admin_uids`, `windows_admin_sids`, `node_hmac_secret_path`.
  - `CallerIdentity {Anonymous, Uds{uid,gid,pid}, Pipe{sid,pid}}` +
    `FromRequestParts` extractor. Note: the `Uds` / `Pipe` variants
    are defined but never constructed in production — step 2 will
    instantiate them from the listener.
  - `AdminPolicy` + `require_admin_middleware` gate
    `/v1/enroll/*`, `/v1/admin/*`, `/v1/enrolled-users`,
    `/v1/audit/entries`.
  - `ResponseMacKey::from_file` + `sign_response_body_middleware`
    emit
    `X-DDS-Body-MAC = base64(HMAC-SHA256(key, method||0||path||0||body))`
    on every response when a key is configured (H-6 defense-in-depth;
    MSI-provisioned secret lands in step 2).
  - `device_binding` module: JSON-backed TOFU store at
    `<data_dir>/device_bindings.json` (`0o600` on Unix, atomic
    persist via tempfile). `check_device_binding_read` +
    `tofu_device_binding` wired on all 7 Windows/macOS
    `/v1/*/{policies,software,applied,claim-account}` endpoints.
    Admin callers bypass; Anonymous (TCP) still bypasses until the
    listeners in step 2 land so existing deployments stay green.
  - 16 new unit tests (2 config, 5 device_binding, 9 admin/MAC/
    binding plumbing). Commit `730dc6c`.
- **v1 hybrid verify dispatch**: `Token::verify_signature` was
  switching the signed input on `wire_version` but then unconditionally
  calling `crypto::verify`, which after M-2 only routed hybrid /
  triple-hybrid to the v2 domain-separated verifiers. Under the default
  pq build this meant persisted v=1 hybrid tokens (and v=1 hybrid
  tokens admitted via `allow_legacy_v1_tokens`) still failed
  validation. Fixed by adding `crypto::verify_v1` as a sibling
  dispatcher that routes hybrid / triple-hybrid to the pre-M-2 v1
  verifiers; classical schemes share the same backend under both entry
  points. Regression test: a v=1 hybrid signed by `sign_v1` verifies
  end-to-end, and a v=2 hybrid signature placed in a v=1 envelope is
  correctly rejected. Commit `14dbc8f`.
- **Windows admin-SID semantics**: `is_admin` fast-pathed
  `BUILTIN\Administrators` (`S-1-5-32-544`) as always admitted. That's
  a group SID and never appears as a caller's primary SID — the match
  was dead code and the docs misrepresented the policy. Removed;
  only `S-1-5-18` (LocalSystem) is admitted implicitly, and all other
  callers must match `AdminPolicy.admin_sids` as a primary-SID
  allowlist. Doc comments on `CallerIdentity::Pipe`, `AdminPolicy`,
  and `ApiAuthConfig.windows_admin_sids` now describe the actual
  semantics and flag a future `windows_admin_groups` field that the
  pipe listener can populate from `TokenGroups`. Commit `14dbc8f`.

**2026-04-20 follow-up pass — H-6 step-2 (response MAC + MSI secret provisioning):**

- **H-6 step-2**: Closes the challenge-substitution attack vector
  that made the Auth Bridge trust whatever `/v1/session/challenge`
  returned — even from a squatter who bound `127.0.0.1:5551` before
  `dds-node`.
  - **Rust CLI**: new `dds-node gen-hmac-secret --out <FILE>`
    subcommand. Writes 32 random bytes via atomic tempfile rename;
    sets `0o600` on Unix; refuses to overwrite without `--force` so
    reinstalls / repairs cannot rotate the secret and desync the
    Auth Bridge from the node. Exercised by four integration tests
    in `tests/h6_gen_hmac_secret.rs` (size, mode, refuse-overwrite,
    force-rotate, missing-parent-dir).
  - **WiX MSI**: new deferred `CA_GenHmacSecret` custom action
    invokes `dds-node.exe gen-hmac-secret --out
    [CommonAppDataFolder]DDS\node-hmac.key` after `InstallFiles`
    and before the services start; runs as LocalSystem so the
    service accounts that read the file later share the owner.
    Paired registry value `HKLM\SOFTWARE\DDS\AuthBridge\
    HmacSecretPath` under `C_AuthBridge` tells the Auth Bridge
    where to find the file. `config/node.toml` template adds
    `[network.api_auth].node_hmac_secret_path` pointing at the
    same file so `dds-node` and the Auth Bridge always load the
    same 32 bytes.
  - **C++ Auth Bridge**: `CDdsConfiguration` gains
    `HmacSecretPath()` (registry value `HmacSecretPath`).
    `CDdsNodeHttpClient::LoadHmacSecret(path)` reads the file (16-1024
    bytes accepted). `VerifyResponseMac` computes
    `HMAC-SHA256(key, method || 0 || path_without_query || 0 || body)`
    via BCrypt, base64-decodes the `X-DDS-Body-MAC` header via
    `CryptStringToBinary`, and constant-time-compares 32 bytes.
    Wired into both `SendRequestWinHttp` (`WinHttpQueryHeaders`
    with `WINHTTP_QUERY_CUSTOM`) and `SendRequestPipe` (header
    parsed out of the raw response buffer, case-insensitive).
    Mismatched / missing MAC → body cleared + status 0 → caller
    fails closed. On startup, `DdsAuthBridgeMain::Initialize`
    calls `LoadHmacSecret`; configured-but-unreadable aborts
    startup via `SERVICE_START_FAILED`; unconfigured logs a
    warning and runs without verification (transition-only so
    pre-MSI-custom-action installs don't brick). Verification
    in `SendRequestWinHttp` happens before `WinHttpCloseHandle`,
    so the header can still be read when we look for it.
  - **Caveat**: C++ and WiX code is authored on macOS; Windows
    CI must compile and run the end-to-end challenge path
    (real dds-node + Auth Bridge + Credential Provider) before
    this can be considered verified.

**2026-04-24 follow-up pass — Windows host verification + idempotency fix:**

- **H-6 step-2 verified on Windows x64**: Full sweep on a Windows
  11 + BuildTools 14.44 + WiX 5.0.2 host. `cargo test --workspace`
  421/421 green, native `DdsNative.sln` Debug + Release build clean,
  41/41 native unit tests pass, .NET `DdsPolicyAgent.Tests` 149/149
  pass (110 unit + 39 integration on real Win32 APIs), MSI compiles
  and `wix msi validate` passes (33.6 MB), `CA_GenHmacSecret` is
  present in the MSI tables and idempotent end-to-end. Windows E2E
  smoke test 8/8 checks pass, including the `cp_fido_e2e` Rust E2E
  through the assertion + session-issuance path that this
  finding gates.
- **H-6 step-2 idempotency bug fixed**: the original
  `gen-hmac-secret` exited with code 1 if the target file already
  existed, and the WiX `CustomAction Return="check"` would have
  failed every MSI **repair / upgrade**. Added an explicit
  `--keep-existing` flag (exits 0 with a "kept existing secret"
  message when the file is present); the WiX `ExeCommand` now
  passes `--keep-existing`. Direct human callers still get the
  refuse-to-overwrite safety net. Pinned by two new tests in
  `dds-node/tests/h6_gen_hmac_secret.rs`
  (`gen_hmac_secret_keep_existing_is_idempotent`,
  `gen_hmac_secret_keep_existing_writes_when_missing`).
- **H-7 step-2b verified on Windows x64**: `serve_pipe` and the
  C++ Auth Bridge `SendRequestPipe` compile clean under MSVC; the
  C# `DdsNodeHttpFactory` for both Windows and macOS Policy Agents
  compiles and tests pass. The named-pipe transport itself is
  exercised by `cp_fido_e2e` via the Auth Bridge → dds-node round
  trip in the smoke test.
- **Pre-existing Windows-build bugs surfaced and fixed during
  verification** (none of these are security findings, but
  several would have masked CI failures):
  - `dds-cli/src/client.rs` imported `tokio::net::UnixStream` and
    `hyper-util` symbols at module scope without `#[cfg(unix)]`
    guards → broke any Windows build that ran `cargo test
    -p dds-cli`. Now properly gated.
  - `platform/windows/native/Tests/build_tests.bat` invoked
    `vswhere -latest -requires VC.Tools.x86.x64` without
    `-products *`, which excludes the BuildTools SKU. Fixed.
  - `platform/windows/e2e/smoke_test.ps1` hardcoded an ARM64
    dumpbin path and force-rebuilt `cp_fido_e2e` for the host
    triple (which OOM'd a CI runner already holding the
    `x86_64-pc-windows-msvc` workspace cache). Now discovers
    dumpbin via `vswhere` and accepts a `-Target` parameter so
    the existing artifacts get reused.

**2026-04-20 follow-up pass — H-12 (per-peer admission gating):**

- **H-12**: new `request_response` behaviour
  `/dds/admission/1.0.0/<domain_tag>` exchanged immediately after
  Noise completes. `dds_net::admission::AdmissionRequest` /
  `AdmissionResponse { cert_cbor: Option<Vec<u8>> }` — the
  network layer ships the cert as opaque CBOR bytes so
  `dds-net` stays independent of `dds-domain`. `DdsNode` tracks
  a per-connection `admitted_peers: BTreeSet<PeerId>` and:
  - On `SwarmEvent::ConnectionEstablished`, fires an
    `AdmissionRequest` at the peer. No sync is scheduled until
    admission completes — unadmitted peers no longer burn our
    `try_sync_with` budget.
  - On inbound `AdmissionRequest`, responds with our own cert
    (cheap `to_cbor()` per request).
  - On inbound `AdmissionResponse`, runs
    `AdmissionCert::verify(&domain_pubkey, &domain_id, peer_id,
    now)`. Only peers whose cert verifies are inserted into
    `admitted_peers`; verification failure is silently logged and
    the peer stays unadmitted.
  - On `ConnectionClosed`, removes the peer from
    `admitted_peers` so a reconnecting peer must present its
    cert fresh.
  - Gossip ingest in `handle_swarm_event` now checks
    `propagation_source` against `admitted_peers` — messages
    from unadmitted peers are dropped before
    `handle_gossip_message` runs. Sync request/response events
    are gated the same way: unadmitted requesters are refused
    (channel dropped), unadmitted responders' payloads are
    ignored.
  - C-3's publisher-capability filter remains the last line of
    defence even after H-12 lands.
- Two new integration tests in `dds-node/tests/h12_admission.rs`
  pin the behaviour via the production `handle_swarm_event`
  path:
  - `admitted_peers_populated_and_gossip_flows` — two nodes
    with valid certs admit each other and gossip propagates.
  - `unadmitted_peer_gossip_dropped` — a node whose cert was
    issued for the wrong `peer_id` is never admitted and its
    gossip never lands in the receiver's trust graph.
- One test-harness fix in `dds-node/tests/http_binary_e2e.rs`:
  the `Publisher` helper now routes its swarm events through
  `handle_swarm_event` instead of a passthrough
  `select_next_some()`, so the admission handshake actually
  runs on the publisher side. Existing
  `binary_nodes_converge_on_gossip_and_revocation` test
  restored to green.

**2026-04-20 follow-up pass — H-7 step-2b (client transports + Windows pipe listener):**

- **H-7 step-2b (Rust side — Windows named-pipe listener)**:
  `dds-node::http::serve` now recognises `pipe:<name>` alongside the
  existing `unix:<path>`. `serve_pipe` mirrors `serve_unix`: tokio's
  `NamedPipeServer` accepts clients with `first_pipe_instance(true)`
  (fail-fast if another process already owns the pipe), each accept
  spins up a fresh instance so subsequent clients aren't refused,
  and the caller's primary user SID is read via
  `GetNamedPipeClientProcessId` → `OpenProcess` →
  `OpenProcessToken` → `GetTokenInformation(TokenUser)` →
  `ConvertSidToStringSidW`. The SID + PID land in
  `CallerIdentity::Pipe`, which the existing admin gate evaluates.
  Cross-compiled clean under `cargo clippy --target
  x86_64-pc-windows-gnu --all-targets -- -D warnings`; runtime
  verification requires a Windows host.
- **H-7 step-2b (macOS Policy Agent)**: new
  `DdsNodeHttpFactory` dispatches on the `NodeBaseUrl` scheme
  (`unix:/...` / TCP). For UDS it installs a
  `SocketsHttpHandler.ConnectCallback` that opens a
  `UnixDomainSocketEndPoint` per HTTP connection; TCP still uses
  the platform default handler. `HttpClient.BaseAddress` is
  `http://localhost/` under UDS because `HttpClient` requires an
  `http://`-shaped URI. Program.cs pipes the factory through
  `AddHttpClient(...).ConfigurePrimaryHttpMessageHandler(...)`.
  15 xUnit tests including a real UDS echo-responder end-to-end
  confirms the `ConnectCallback` is wired correctly.
- **H-7 step-2b (Windows Policy Agent)**: parallel
  `DdsNodeHttpFactory` with three schemes — `pipe:<name>`
  (primary, opens `NamedPipeClientStream` via
  `ConnectCallback`), `unix:/path` (kept for cross-platform dev
  builds on macOS/Linux), and TCP. 21 xUnit tests including a
  Windows-only named-pipe echo-responder end-to-end path (skipped
  cleanly on non-Windows CI hosts).
- **H-7 step-2b (C++ Auth Bridge)**:
  `CDdsNodeHttpClient::SetBaseUrl` recognises `pipe:<name>`; a new
  `SendRequestPipe` implements HTTP/1.1 over `CreateFileW` +
  `WriteFile` / `ReadFile` with `Connection: close` semantics so
  the server drives end-of-response via `ERROR_BROKEN_PIPE`.
  `WaitNamedPipeW` handles `ERROR_PIPE_BUSY` with a 5 s retry.
  **Authored on macOS; Windows CI must compile + integration-test.**
  The existing WinHTTP path is retained and still kicks in for
  TCP URLs.
- **Still outstanding** after step-2b: TCP listener is still the
  default — flipping `trust_loopback_tcp_admin = false` is safe
  once operators roll the node config + both agents + the Auth
  Bridge to `pipe:` / `unix:` and confirm no legacy clients
  remain. H-6 step-2 (MSI HMAC secret provisioning + Auth Bridge
  response-MAC enforcement + challenge-HMAC binding) is still
  pending and now unblocked by this transport slice.

**2026-04-20 follow-up pass — H-7 step-2a (Rust + CLI):**

- **H-7 step-2a**: `serve` in `dds-node::http` now dispatches on the
  `api_addr` scheme. `unix:/path` routes to a new `serve_unix` that
  hand-rolls a hyper-1 serve loop (axum 0.7's `axum::serve` is
  `TcpListener`-only): accept a `UnixStream`, call `peer_cred()` to
  materialise the caller's `uid`/`gid`/`pid`, inject
  `CallerIdentity::Uds` as a request extension, then delegate to the
  shared axum `Router` via `hyper::service::service_fn`. The admin
  gate and the M-8 device-binding middleware see a concrete
  `CallerIdentity` instead of falling back to `Anonymous`. Socket
  permissions set to `0o660` right after bind; stale socket files
  from a prior crashed run are removed first so `EADDRINUSE` can't
  brick the service.
  - `dds-cli::client` grew a minimal hyper + `UnixStream` client that
    kicks in when the base URL starts with `unix:`. Reqwest stays
    the transport for TCP/HTTPS. `L-6` loopback-only check
    explicitly exempts `unix:` URLs since they are local by
    definition.
  - Four end-to-end integration tests pin the full pipeline:
    service-uid caller admitted, non-matching uid rejected with 403
    even when `trust_loopback_tcp_admin = false`, `0o660` mode
    observed on bind, stale non-socket file replaced cleanly on
    restart.
  - **Still outstanding** (step 2b): Windows named-pipe listener
    (mirror design of `serve_unix` using
    `GetNamedPipeClientProcessId` + `OpenProcessToken`), C# Policy
    Agent `DdsNodeClient` swap of `HttpMessageHandler` to a
    `SocketsHttpHandler` with `ConnectCallback` on Linux/macOS, C++
    Auth Bridge named-pipe HTTP client. `trust_loopback_tcp_admin`
    stays `true` by default until all clients are on the new
    transport.

### Critical

| ID | Status | Notes |
|---|---|---|
| C-1 | ✅ Fixed (pending verify) | `read_cstr`/`write_json`/`write_str` null-check; test `null_input_returns_invalid_input` |
| C-2 | ✅ Fixed (pending verify) | Bootstrap sentinel `<data_dir>/.bootstrap` + refuse-if-roots-non-empty; sentinel consumed atomically |
| C-3 | ✅ Fixed (pending verify) | Publisher-capability filter on `list_applicable_*` (serve time) AND on gossip/sync ingest (`publisher_capability_ok` in `dds-node/src/node.rs`). Unauthorized policy/software attestations are now dropped before they enter the trust graph. Purposes defined in `dds_core::token::purpose`. |

### High

| ID | Status | Notes |
|---|---|---|
| H-1 | ✅ Fixed (pending verify) | Revocations for unknown targets now rejected outright; test `revocation_for_unknown_target_is_rejected` |
| H-2 | ✅ Fixed (pending verify) | `dds-core::envelope::SignedPolicyEnvelope` binds each `/v1/windows/{policies,software}` response to the node's Ed25519 key. Windows agent (BouncyCastle) pins the node pubkey via `AgentConfig.PinnedNodePubkeyB64`, enforces version/kind/device_urn/clock-skew gates, then verifies the signature before dispatching any enforcer. `DdsNodeClient` now fails closed if the pubkey is unconfigured. Cross-language fixture pinned bilaterally: Rust emits, C# verifies the exact same bytes (`envelope::tests::interop_vector_is_stable` ↔ `EnvelopeVerifierTests.InteropVectorAcceptsRustSignature`). **Caveat**: agent pins the node pubkey, not the domain pubkey — a proper domain-signed node-binding chain (closing the TOFU gap at first install) is tracked in the `NodeInfoResponse` doc as follow-up. |
| H-3 | ✅ Fixed (pending verify) | Same envelope design as H-2, applied to `/v1/macos/{policies,software}` and the macOS agent. Mirrored tests cross-verify the Rust-emitted interop vector. |
| H-4 | ✅ Fixed (pending verify) | JTIs suffixed with UUIDv4; `TrustError::DuplicateJti` rejects overlaps |
| H-5 | ✅ Fixed (pending verify) | Named-pipe SDDL tightened to `SY`-only (dropped `IU`); C++ change, compile-test requires Windows CI |
| H-6 | ✅ Fixed (pending verify) | Step-1 plumbing in tree (commit `730dc6c`): `ResponseMacKey::from_file` + `sign_response_body_middleware` emit `X-DDS-Body-MAC` on every response when a key is configured. **Step-2 landed 2026-04-20**: `dds-node gen-hmac-secret` CLI subcommand writes a 32-byte atomic `0o600` secret file (4 integration tests: size, mode, refuse-overwrite, force-rotate). WiX MSI `CA_GenHmacSecret` custom action provisions the file at install time; `HKLM\SOFTWARE\DDS\AuthBridge\HmacSecretPath` points the Auth Bridge at the same file; node.toml template references `[network.api_auth].node_hmac_secret_path` so both sides load the identical bytes. C++ Auth Bridge `CDdsNodeHttpClient::VerifyResponseMac` computes HMAC-SHA256 via BCrypt, base64-decodes the header via CryptStringToBinary, constant-time-compares 32 bytes, and fails closed (body cleared + status 0) on mismatch or missing header — verified on both WinHTTP and pipe transports. `DdsAuthBridgeMain::Initialize` aborts startup when the configured path is unreadable, and logs a warning + runs without verification when the path is empty (transition-only). **Caveat**: C++ + WiX are authored on macOS; Windows CI must compile and run the end-to-end challenge flow. |
| H-7 | ⚠ Partial | Step-1 plumbing in tree (commit `730dc6c`): `ApiAuthConfig` + `CallerIdentity {Anonymous, Uds, Pipe}` extractor + `AdminPolicy` + `require_admin_middleware` gate `/v1/enroll/*`, `/v1/admin/*`, `/v1/enrolled-users`, `/v1/audit/entries`. **Step 2a landed 2026-04-20**: `serve` dispatches on `unix:` scheme; new `serve_unix` accepts UDS connections, extracts peer creds via `stream.peer_cred()`, and injects `CallerIdentity::Uds { uid, gid, pid }` on every request before the admin gate. Socket perms `0o660`; stale-file cleanup on bind. `dds-cli` understands `unix:/path` URLs via a minimal hyper+UnixStream client. **Step 2b landed 2026-04-20**: `serve` now also dispatches on `pipe:<name>`; new `serve_pipe` wraps tokio's `NamedPipeServer` and extracts caller primary-user SID via `GetNamedPipeClientProcessId` + `OpenProcessToken` + `GetTokenInformation(TokenUser)` + `ConvertSidToStringSidW` into `CallerIdentity::Pipe`. Both C# Policy Agents (macOS + Windows) gain a `DdsNodeHttpFactory` that swaps the primary `HttpMessageHandler` to a `SocketsHttpHandler` with a `ConnectCallback` for UDS or `NamedPipeClientStream`. C++ Auth Bridge's `CDdsNodeHttpClient` now dispatches on `pipe:` URLs to `SendRequestPipe` (minimal HTTP/1 over `CreateFileW` + `WriteFile`/`ReadFile` with `Connection: close`). Cross-language tests: Rust 4 UDS e2e on unit tests; C# macOS 15 (incl. live UDS echo-responder); C# Windows 21 (incl. live named-pipe echo-responder, skip-on-non-Windows). C++ Auth Bridge pipe path is authored but requires Windows CI for compile + integration verification. **Still outstanding**: flip `trust_loopback_tcp_admin = false` once operators cut all clients over to the new transports; revisit H-12 after this rolls out. |
| H-8 | ✅ Fixed (pending verify) | `admin_vouch` requires `dds:admin-vouch:<purpose>` for non-bootstrap admins; `bootstrap_admin_urn` persisted to config and rehydrated on startup (survives restart); vouch with `purpose == dds:admin` now promotes the subject into `trusted_roots` and persists. (Generating the second admin's signing key is still a separate operational step — `admin_setup` is the only auto-generation path today.) |
| H-9 | ✅ Fixed (pending verify) | `Zeroizing` wraps passphrase + admin plaintext; buffers wiped on early-return paths |
| H-10 | ✅ Fixed (pending verify) | Bundle v3 carries a mandatory Ed25519 signature over canonical `signing_bytes` (domain_id + domain_pubkey + org_hash + ports + mdns + domain_key_blob), verified on load against the embedded `domain_pubkey`. Fingerprint is now ALSO printed on load so operators can confirm OOB. `save_bundle` requires an unwrapped `DomainKey` and refuses to write if the signer pubkey doesn't match the embedded one. Tests: `bundle_rejects_tampered_signature`, `bundle_fingerprint_diverges_under_key_swap`. |
| H-11 | ✅ Fixed (pending verify) | `SyncResponse` capped at 1000 entries / 5 MB; `complete: false` signals pagination |
| H-12 | ✅ Fixed (pending verify) | New `request_response` behaviour on `/dds/admission/1.0.0/<domain>` runs after Noise; peers exchange admission certs via `AdmissionRequest`/`AdmissionResponse` (opaque CBOR-wrapped cert so `dds-net` stays independent of `dds-domain`). `DdsNode::admitted_peers: BTreeSet<PeerId>` is populated only after `AdmissionCert::verify` succeeds against the domain pubkey + the remote libp2p `peer_id`. Gossip and sync from unadmitted peers are dropped at the behaviour layer: `handle_gossip_message` rejects on `propagation_source`; sync refuses to serve or consume responses from non-admitted peers. Reconnection clears the entry so peers re-verify. C-3's publisher-capability filter remains the last line of defence. Tests: `dds-node/tests/h12_admission.rs` pins positive (valid cert → admitted → gossip flows) and negative (cert for wrong `peer_id` → never admitted → gossip dropped) via `handle_swarm_event`. |

### Medium

| ID | Status | Notes |
|---|---|---|
| M-1 | ✅ Fixed (pending verify) | Canonical-CBOR encoder at `dds-core::cbor_canonical` implements RFC 8949 §4.2.1 (shortest-form ints, definite-length items, sorted text-string keys). Token wire bumped to `v=2`; signed bytes are `"dds-token-v2\x00" \|\| canonical_cbor(payload)`. The v=2 verify path recanonicalises and rejects any wire whose payload bytes aren't byte-identical, closing the key-reorder / length-encoding malleability. Legacy `sign_v1` / v=1 verify kept for pinned vectors + on-disk blobs. New errors: `TokenError::NonCanonicalPayload`, `UnsupportedWireVersion(u8)`. Commit `60050ce`. **See also** the M-1/M-2 downgrade guard in the 2026-04-19 follow-up pass block above — `NetworkConfig.allow_legacy_v1_tokens` (default `false`) refuses fresh v=1 ingest so attackers can't force a downgrade. |
| M-2 | ✅ Fixed (pending verify) | Hybrid and triple-hybrid signatures are now domain-separated per component: Ed25519 signs `"dds-hybrid-v2/ed25519\x00" \|\| msg`, ML-DSA-65 signs `"dds-hybrid-v2/mldsa65\x00" \|\| msg`, triple-hybrid uses the matching `"dds-triple-v2/{ed25519,p256,mldsa65}\x00"` prefixes. Regression test asserts the Ed25519 (and P-256) component of a v2 hybrid signature cannot be lifted out and verified standalone under the base scheme. `sign` / `verify_hybrid` are v2 aliases; `sign_v1` / `verify_*_v1` stay so legacy vectors keep verifying. Commit `60050ce`. Pairs with the M-1/M-2 downgrade guard (see 2026-04-19 block). |
| M-3 | ✅ Fixed (pending verify) | Global token-bucket middleware (60 req/s) returns 429 |
| M-4 | ✅ Fixed (pending verify) | `DdsNode::mdns_accept_peer` gates every mDNS-discovered peer on (a) a sliding-window rate cap of `MDNS_NEW_PEER_ACCEPT_PER_MINUTE = 60` new-peer acceptances per minute and (b) a hard ceiling of `MDNS_PEER_TABLE_MAX = 256` actively-tracked peers. Already-known peers bypass the cap so legitimate re-announcements don't consume budget; expired peers are removed on the mDNS Expired event so the table self-heals. Under a LAN Sybil flood the caps prevent the node from burning CPU on Noise handshakes against ghosts or crowding real peers out of Kademlia. |
| M-5 | ✅ Fixed (pending verify) | `sync_payloads` capped at 10k entries with FIFO eviction in `cache_sync_payload`; `handle_sync_response` now also routes inserts through `cache_sync_payload` so the cap applies on both the gossip and sync paths (previously the raw `insert` in the sync path bypassed the cap). |
| M-6 | ✅ Fixed (pending verify) | `DdsNode::run` re-verifies the admission cert every 600 s against `(domain_pubkey, domain_id, peer_id, now)`. Expiry → clean shutdown. Helper exposed as `verify_admission_still_valid` for tests. |
| M-7 | ✅ Fixed (pending verify) | Config flag `NodeConfig.domain.enforce_device_scope_vouch` (default off). When on, `list_applicable_*` only honors a device's self-attested `tags`/`org_unit` if the device has a `dds:device-scope` vouch from a trusted root (new `purpose::DEVICE_SCOPE` constant). Off by default to preserve behavior on existing deployments. |
| M-8 | ✅ Fixed (pending verify) | Step-1 (commit `730dc6c`): new `device_binding` module — JSON-backed TOFU store at `<data_dir>/device_bindings.json` (`0o600` on Unix, atomic persist). `check_device_binding_read` + `tofu_device_binding` wired on all 7 Windows/macOS `/v1/*/{policies,software,applied,claim-account}` endpoints. Admin callers bypass. Step-2 (2026-04-20): new `ApiAuthConfig.strict_device_binding` (default `false`) + `AdminPolicy.strict_device_binding` flag. When on, both helpers refuse `Anonymous` callers with 403; when off, they fall through so legacy TCP deployments stay working during the H-7 cutover. Operators flip this knob alongside `trust_loopback_tcp_admin = false` after the H-7 step-2 rollout reaches every client. 5 new unit tests pin: lenient read passes, strict read refuses Anonymous with 403, strict write refuses with 403, lenient write passes, admin bypasses strict mode. Full session-token → `device_urn` binding is not needed for the common deployment shape (UDS/pipe already supplies a per-caller principal); it remains a separate design option if a future operator wants TCP + strict in the same deployment. |
| M-9 | ✅ Fixed (pending verify) | Replay window (7 days forward 1h) enforced on BOTH gossip (`ingest_revocation`/`ingest_burn`) and sync (`handle_sync_response` filter) paths via `revocation_within_replay_window`. Revoke/burn tokens with stale `iat` are dropped before reaching `apply_sync_payloads_with_graph`. |
| M-10 | ✅ Fixed (pending verify) | Keyfile schema `v=3` carries Argon2id `(m_cost, t_cost, p_cost)` in the blob so future parameter bumps don't need yet another version. Defaults raised to m=64 MiB, t=3, p=4 (OWASP tier-2; target unlock ~200–500 ms on modern hardware). `load()` accepts v=2 (legacy 19 MiB / t=2 / p=1) and v=3; a v=2 success triggers a transparent rewrap to v=3 on next save, so operators see no disruption post-upgrade. `derive_key` takes `KdfParams`; `save()` always emits v=3. Tests: v=3 schema + params observable in on-disk bytes, v=2 → v=3 lazy rewrap preserves identity URN, M-14 plaintext-downgrade guard unchanged. Commit `1b5f51d`. |
| M-11 | ✅ Fixed (pending verify) | `DefaultBodyLimit::max(256 KiB)` on Axum; gossipsub cap tracked separately |
| M-12 | ✅ Fixed (pending verify) | `AssertionSessionRequest` / `AdminVouchRequest` gained an optional `client_data_json` field. When present, `verify_assertion_common` (i) hashes the supplied JSON and binds it to the authenticator-signed `client_data_hash`, then (ii) parses the JSON and validates `type`, `challenge`, `origin` individually per WebAuthn §7.2 steps 7–9 (plus a `crossOrigin == false` guard). `decode_b64url_any` accepts both base64url-no-pad (spec) and base64url-with-pad (some stacks). When the field is absent the legacy reconstruct-and-hash path still runs so existing clients aren't broken; clients SHOULD start sending the raw bytes. |
| M-13 | ⏸ Deferred | Requires FIDO MDS integration / policy |
| M-14 | ✅ Fixed (pending verify) | `identity_store::save` writes a sticky `<path>.encrypted-marker` after any successful encrypted save. On subsequent saves, if the marker exists and the caller is about to produce a plaintext blob (empty `DDS_NODE_PASSPHRASE`), `save` returns a `Crypto` error and refuses to overwrite. `DDS_NODE_ALLOW_PLAINTEXT_DOWNGRADE=1` is an explicit escape hatch (logged at warn) for dev/testing. Defeats the attack described in the review: an attacker with FS write who clears the passphrase env var and waits for a restart can no longer roll back the key to plaintext silently. Test `test_m14_refuses_plaintext_downgrade` covers both the refusal and the override. |
| M-15 | ⏸ Deferred | Investigated 2026-04-18 and re-deferred. Binding `hmac_salt` to `SHA-256(node_urn)` breaks the provisioning path: `create_bundle` embeds the admin's v3 CBOR blob verbatim into `ProvisionBundle.domain_key_blob`, and the target node's `run_provision` unwraps it with only the authenticator — it has no knowledge of the admin's node URN. A sound fix needs either a bundle-specific re-wrap step in `create_bundle` (strip binding on export) or a separate export format, both larger than the review's one-line suggestion. Impact is also thinner than the review states: `provision` asserts `domain_key.bin` is never persisted on non-admin nodes (`provision.rs:646`), so the "any provisioned node's key file" attack surface is narrower than claimed. |
| M-16 | ✅ Fixed (pending verify) | `.ddsdump` v2 mandatory Ed25519 signature over `DdsDump::signing_bytes`. `dds export` requires unwrapped `DomainKey`. `dds import` verifies against the local `domain.toml` pubkey. **Downgrade-defense**: v1 (unsigned) dumps now REFUSE by default — the importer errors out unless `--allow-unsigned` is passed, because a tampered v2 dump could otherwise be relabelled as v1 and bypass signature verification. Plus L-5 0o600 on the written file. |
| M-17 | ✅ Fixed (pending verify) | `ctap2/cbor.cpp` decoder now enforces a 16-level nesting cap, rejects array/map element counts that exceed remaining wire bytes (closes `resize(2^63)` allocation DoS from a hostile USB-HID device), and rewrites the `m_pos + count` overflow check in `ReadBytes` as `count > Remaining()`. `DecodeValue` threads depth through the recursion rather than storing it on the decoder so repeated `Decode` calls don't accumulate state. |
| M-18 | ⏸ Deferred | WiX / installer change |
| M-19 | ✅ Fixed (pending verify) | Boot-time wall clock captured; `verify_assertion_common` refuses when `now() < boot_wall_time` |
| M-20 | ✅ Fixed (pending verify) | `directory.redb` set to `0o600` on Unix after `Database::create` |
| M-21 | ✅ Fixed (pending verify) | `AuditLogEntry::sign_ed25519`/`verify` added; `ingest_audit` rejects unsigned/forged entries; 4 unit tests |
| M-22 | ✅ Fixed (pending verify) | AES-GCM AAD = `admin_urn`; version byte `0x02`; `0o700`/`0o600` perms; atomic write via tempfile; plaintext zeroized. OS-bound wrap (DPAPI/Keychain/TPM) left as explicit `TODO(security)` |

### Low

| ID | Status | Notes |
|---|---|---|
| L-1 | ✅ Fixed (pending verify) | `Ed25519Only::into_signing_key` consumes the wrapper; `Identity::generate` moves the key out instead of cloning, so only one copy sits on the heap. |
| L-2 | ✅ Fixed (pending verify) | `O_NOFOLLOW` on identity read (Unix) |
| L-3 | ✅ Fixed (pending verify) | `NamedTempFile::persist` for key and admin-key writes |
| L-4 | ✅ Fixed (pending verify) | Parent directory set to `0o700` on Unix after creation |
| L-5 | ✅ Fixed (pending verify) | Dump output file set to `0o600` on Unix |
| L-6 | ✅ Fixed (pending verify) | CLI refuses non-loopback `http://` URLs |
| L-7 | ✅ Fixed (pending verify) | FFI `now_epoch` uses `unwrap_or(0)` |
| L-8 | ✅ Fixed (pending verify) | Caps: 10k rules, 100k tokens |
| L-9 | ✅ Fixed (pending verify) | `ServiceError` mapped to opaque codes (`auth_failed`, `permission_denied`, `invalid_input`, `internal_error`); full detail logged server-side |
| L-10 | ✅ Fixed (pending verify) | Admin blob now prefixed with version byte (rolled into M-22) |
| L-11 | ✅ Audited | Production-callsite audit: `LwwRegister` is only referenced by `dds-loadtest` fixtures and `dds-core/benches/crdt_merge.rs` — no directory CRDT path uses wall-clock LWW semantics. Limitation documented in-module so future callers re-audit before relying on convergence. |
| L-12 | ✅ Fixed (pending verify) | `AuditLogEntry::prev_hash` + `chain_hash()` + `sign_ed25519_chained` constructor. **Append-time enforcement**: both `MemoryBackend` and `RedbBackend` `append_audit_entry` now verify the new entry's `prev_hash` equals the previously-stored entry's `chain_hash` (or is empty for the genesis entry); mismatches return `StoreError::Serde` so the caller can log the forensic event. `DdsNode::emit_local_audit` is the production hook — reads the chain head, stamps, signs, appends. `AuditStore::audit_chain_head` is exposed for callers that need to construct chained entries themselves. |
| L-13 | ✅ Fixed (pending verify) | `credential_ids_eq` in `service.rs` decodes both sides via base64url-no-pad / standard / url-safe / standard-no-pad and compares raw bytes. Falls back to string equality if neither side is base64. |
| L-14 | ✅ Fixed (pending verify) | `helpers.cpp` gains a static `SecureFreePassword(PWSTR)` helper that `SecureZeroMemory`s then `CoTaskMemFree`s. `ProtectAndCopyString` and `ProtectIfNecessaryAndCopyPassword` use it on their internal `SHStrDupW` copies (which previously leaked plaintext into freed heap). Both `CDdsCredential::GetSerializationDds` and `GetSerializationBridge` inline the same zero-before-free on `pwzProtectedPassword` — important because the `CPUS_CREDUI` and already-encrypted branches hand back plaintext through that pointer, not ciphertext. Windows build required to verify. |
| L-15 | ✅ Fixed (pending verify) | `subtle::ConstantTimeEq` on `vch_sum` comparisons via `payload_hash_eq` |
| L-16 | ✅ Fixed (pending verify) | `AppliedStateStore.WriteToDisk` applies the restricted DACL to the `.tmp` file BEFORE `File.Move`. Same-volume `File.Move` is a metadata rename that preserves the source DACL, so the final `applied-state.json` never observably exists with the inherited parent ACL — closes the write-time race. Fail-closed on Windows: if `SetWindowsDacl` throws, the tmp file is deleted and the exception propagates, so the caller (holding `_lock`) sees the write fail. On Windows the DACL grants `FullControl` only to `LocalSystem` and `BUILTIN\Administrators` with inheritance disabled; `OperatingSystem.IsWindows()` short-circuits the helper on non-Windows (the agent never ships there in production). Added `System.IO.FileSystem.AccessControl` to the csproj, guarded by `TargetFramework`. |
| L-17 | ⏸ Deferred | Service mutex refactor; couple with L-18 |
| L-18 | ✅ Fixed (pending verify) | `CredentialStateStore::bump_sign_count(credential, new)` is an atomic check-and-set primitive: the redb backend performs the compare and the write inside a single write transaction, and `StoreError::SignCountReplay { stored, attempted }` distinguishes the replay case from a generic I/O failure. Service layer at `verify_assertion_common` now calls `bump_sign_count` instead of the race-prone `get` + compare + `set` sequence. Today the service-wide mutex (L-17) already serializes these calls, but the backend-level atomicity is correct on its own — if L-17 is ever split out, the sign-count replay invariant stays intact. Tests on both MemoryBackend and RedbBackend assert the accept / equal-reject / less-than-reject behaviour. |

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

### Remaining deferred work after the 2026-04-19 pass

The 2026-04-19 pass landed the Rust-side step-1 plumbing for H-6,
H-7, and M-8 (see the 2026-04-19 follow-up pass block above) and
closed M-1, M-2, and M-10. What's left splits into "step-2 of
previously-partial items," "H-12 architectural," and a small
cleanup cluster.

**Step-2 of previously-partial items** (all cross-language):

- **H-7 step-2 landed 2026-04-20** across both sub-slices.
  Step-2a: Rust UDS listener in `dds-node::http::serve_unix` + CLI
  hyper-over-`UnixStream` client. Step-2b: Rust Windows named-pipe
  listener in `serve_pipe` (extracts caller SID via Win32 token APIs),
  macOS + Windows C# `DdsNodeHttpFactory` for `HttpClient`
  transport-swap, and C++ Auth Bridge pipe HTTP/1 client
  (`SendRequestPipe`). What remains is the operational cutover:
  roll `trust_loopback_tcp_admin = false` in the node config once
  all clients are on UDS/pipe, then remove the TCP bind. M-8 step-2
  (write-side session-token binding) becomes addressable.
  **Verification caveat**: the C++ Auth Bridge changes were
  authored on macOS — Windows CI must confirm the MSVC compile +
  exercise the pipe path end-to-end against the Rust `serve_pipe`.
- **H-6 step-2** — The response-MAC middleware is already emitting
  `X-DDS-Body-MAC` when a key is configured; the remaining work is
  (a) MSI installer provisions a per-install 32-byte random secret
  at `node_hmac_secret_path` (WiX custom action), (b) C++ Auth
  Bridge loads the same secret and verifies the MAC on every
  response, failing closed on mismatch, (c) challenge-HMAC binding
  on `/v1/session/challenge` so an attacker who binds the port
  before `dds-node` can't return an arbitrary challenge. Pairs
  with H-7 step-2.
- **M-8 step-2** — With H-7 step-2 in tree, replace the Anonymous
  bypass on read-side endpoints with a session-token check that
  binds the caller's authenticated identity to `device_urn` before
  any TOFU record is consulted. Tighten `check_device_binding_read`
  to reject unknown `device_urn` instead of logging-and-allowing.

**H-12** (Rust-only, independent):

- Per-peer admission gating in gossip/sync. Requires a new libp2p
  request-response behaviour that the node runs immediately after
  Noise: peers exchange admission certs and the swarm drops
  gossip/sync from unadmitted peers at the behaviour layer. C-3's
  publisher-capability filter remains the last line of defence
  even after H-12 lands. Can run in parallel with H-7/H-6 step-2
  in a separate worktree — no shared files.

**Cleanup cluster** (smaller, independent):

- **M-13** — FIDO MDS integration (attestation-statement verify
  against a policy-configured trust anchor list or offline MDS
  mirror).
- **M-15** — Re-deferred 2026-04-18. Binding the admin-machine
  `domain_key.bin` to its own node identity breaks the provisioning
  path, where `create_bundle` embeds the admin's CBOR v3 blob
  verbatim into `domain_key_blob` and the target node's `provision`
  unwraps it from bytes using only the authenticator. A proper fix
  requires either a bundle-specific re-wrap step (strip binding on
  export) or a separate "export" format; both are larger than the
  review's one-line suggestion. Impact is thinner than the review
  states: `provision` asserts `domain_key.bin` is never persisted
  on non-admin nodes (`provision.rs:646`), so the "any provisioned
  node's key file" attack surface is narrower than claimed.
- **M-18** — Split WiX service accounts: run the HTTP-polling part
  of DdsPolicyAgent and the Auth Bridge under narrower service SIDs;
  have enforcers impersonate up only when they need elevation.
- **L-17** — Service-mutex refactor. Concurrency ceiling of one
  HTTP request at a time on the shared service mutex. L-18's atomic
  `bump_sign_count` already landed, so the sign-count replay
  invariant is safe once the mutex comes off.

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

---

## Addendum — 2026-04-24 code-path pass

An independent re-read of the code on 2026-04-24 (without reopening the
security docs first) surfaced six items not already covered by the
`C-1…H-12 / M-1…M-22 / L-1…L-18` ledger above. Two other items from the
same pass — "loopback TCP is admin by default" and "device APIs allow
anonymous TCP" — are already tracked as H-7 (⚠ Partial) and M-8 step-2
respectively, and are not re-listed.

### A-1 (High). ✅ Fixed (pending HW verify) — FIDO2 packed attestation with `x5c` is accepted without verifying the statement signature or chain
**Location:** [dds-domain/src/fido2.rs](dds-domain/src/fido2.rs)

**What's wrong:** `verify_attestation` accepts `fmt == "none"`
unconditionally ("Nothing to verify cryptographically"), and in the
`packed` path, the moment `x5c` is present the function returns
`Ok(())` without verifying the attestation signature over
`authData || clientDataHash` or walking the certificate chain. The
credential public key parsed from attacker-supplied `authData` is then
stored and used to authenticate future assertions.

**Attack vector:** A local process hitting `POST /v1/enroll/user` can
construct an `attestationObject` with `fmt = "none"` (or `fmt = "packed"`
with any `x5c` value), embed a `COSE_Key` under its own control in
`authData`, and have the node persist that key as an enrolled
credential. Subsequent `POST /v1/session/assert` calls signed by the
matching private key then mint a valid session — no authenticator was
ever involved.

**Relation to M-13:** M-13 (deferred) flags this at the "MDS
integration" level. A-1 records the exploitable delta: the packed
path does not even verify the `sig` field of its own attestation
statement when `x5c` is present, independent of any MDS trust-anchor
decision. A full MDS integration is one fix; a much smaller fix
is to verify the packed `sig` unconditionally (it's self-contained)
and to gate `fmt == "none"` behind an explicit
`allow_unattested_credentials` config knob.

**Resolution status:**

- **Step 1 ✅ landed 2026-04-25** — `verify_attestation` now takes
  an `allow_unattested_credentials: bool`; `fmt = "none"` returns
  `Fido2Error::Unsupported` unless the caller opts in. Wired
  through three enrollment call sites
  (`enroll_user` / `admin_setup` / re-parse on session assert) from
  a new `DomainConfig.allow_unattested_credentials` field that
  defaults to `false`. The re-parse callsite passes `true` so
  already-stored unattested credentials don't regress on the next
  session-assert. Each accepted unattested enrollment is logged
  at WARN so operators can audit usage. Test fixtures across
  `dds-node` (5 in-process tests, 5 HTTP tests, the binary HTTP
  e2e harness, `service_tests.rs`) now use
  `build_packed_self_attestation` over the matching CDH; the
  `dds-fido2-test` HW probe / multinode binaries and the
  `dds-loadtest` harness keep `allow_unattested_credentials =
  true` because they exercise synthetic or HW-driven flows where
  `fmt = "none"` may legitimately appear. New `fido2.rs` tests
  pin: `none` rejected by default (Ed25519 + P-256), `none`
  accepted under `allow = true`, packed unaffected by the flag.
  `cargo test --workspace` ⇒ 439/439 ok;
  `cargo clippy -p dds-domain -p dds-node -p dds-loadtest
  --all-targets -- -D warnings` ⇒ clean.
- **Step 2 ✅ landed 2026-04-25** — `verify_packed` no longer
  returns `Ok(())` when `x5c` is present. New
  `leaf_public_key_from_der` helper parses `x5c[0]` via
  `x509-parser`, extracts the SubjectPublicKey from its SPKI,
  enforces that the SPKI's algorithm OID matches the `attStmt.alg`
  field (defending against an alg-downgrade where the attacker
  ships an EC cert under EdDSA framing), and returns the pubkey as
  an internal `AttestationPublicKey` enum. New
  `verify_attestation_sig` then verifies the `sig` field over
  `authData || clientDataHash` under that pubkey using the same
  Ed25519 / P-256 paths the self-attestation branch already used
  (with low-S normalisation on P-256). Both packed sub-modes
  (self-attestation and full-attestation-with-x5c) now go through
  the same signature check. Chain validation against a
  trust-anchor list stays deferred to M-13 — A-1 step-2 is
  strictly stronger than the pre-A-1 "trust on sight" posture
  because the attacker now has to forge a sig matching the leaf
  pubkey on a CDH the server controls. New `fido2.rs` tests:
  positive (synthetic packed-with-x5c using a `rcgen`-generated
  self-signed leaf, sig verified end-to-end), negative — garbage
  cert rejected with `Format`, negative — sig under the wrong
  attestation key rejected with `BadSignature`, negative —
  alg/SPKI mismatch rejected with `Unsupported`. New direct dep
  `x509-parser = "0.18"` on `dds-domain` (already a transitive in
  the workspace lock); `rcgen = "0.13"` and
  `p256` `pkcs8` feature added as dev-deps for the synthetic
  cert. `cargo test --workspace` ⇒ 443/443 ok; clippy clean on
  the touched crates. **Verification caveat**: real-HW path
  (Crayonic KeyVault via `dds-multinode-fido2-test`) was not
  re-run as part of this commit — the user should re-run the
  multinode HW E2E next time a key is connected. The synthetic
  test mirrors the WebAuthn shape closely (separate attestation
  key in the leaf cert vs credential pubkey in `authData`, sig
  over `authData || cdh`) so spec-conforming authenticators
  should pass without changes.
- **Step 3 ✅ landed 2026-04-25** — `EnrollUserRequest` (and
  `AdminSetupRequest`, which is a type alias) gain an optional
  `client_data_json: Option<Vec<u8>>` field. New
  `verify_enrollment_client_data` helper mirrors M-12's
  assertion-side logic: bind the supplied JSON to the signed
  `client_data_hash` via SHA-256, parse, then enforce
  `type == "webauthn.create"`,
  `origin == "https://<rp_id>"`, and `crossOrigin != true` per
  WebAuthn §7.1 steps 8–11. Both `enroll_user` and `admin_setup`
  call the helper before `verify_attestation`. The helper returns
  `Ok(())` when `cdj_bytes` is `None`, so existing clients that
  don't populate the field stay on the legacy
  `client_data_hash` ↔ `authData.rp_id_hash` check (pure backward
  compat). HTTP wire layer gains
  `EnrollUserRequestJson::client_data_json_b64: Option<String>`
  (`#[serde(default)]`) on the same backward-compat policy.
  **Known gap**: today's enrollment flow has no server-issued
  challenge endpoint, so `cdj.challenge` is *not* validated
  against a server value (assertion-side does, via
  `consume_challenge`). Closing that requires introducing
  `/v1/enroll/challenge` and is tracked separately. The `type`
  and `origin` checks land here in step-3 because they're
  independent of the challenge plumbing and the type check alone
  blocks the practical attack of replaying an assertion-time
  clientDataJSON to the enrollment endpoint. New unit tests in
  `service::a1_step3_client_data_tests` (8 tests): legacy
  no-cdj passthrough, well-formed accepted, cdh mismatch rejected,
  wrong type rejected, wrong origin rejected, crossOrigin true
  rejected, crossOrigin false/missing accepted, malformed JSON
  rejected. `cargo test --workspace` ⇒ 451/451 ok (up from 443);
  clippy clean.

**A-1 overall**: Step-1 closed the `fmt=none` gap, Step-2 closed
the `x5c` skipped-signature gap, Step-3 added field-level
clientDataJSON validation at enrollment. The original A-1
finding is fully addressed pending real-HW reverification of the
multinode FIDO2 test (`dds-multinode-fido2-test` against a
Crayonic / YubiKey).

---

### A-2 (High). Windows Auth Bridge config path cannot select the pipe transport
**Location:** [platform/windows/native/DdsAuthBridge/Configuration.cpp:26-28](platform/windows/native/DdsAuthBridge/Configuration.cpp#L26-L28), [platform/windows/native/DdsAuthBridge/Configuration.h:20](platform/windows/native/DdsAuthBridge/Configuration.h#L20), [platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp:362](platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp#L362)

**What's wrong:** H-7 step-2b added `SetBaseUrl` to
`CDdsNodeHttpClient` and taught it to parse `pipe:<name>` URLs.
However, the Windows service's Configuration class only reads a
`DdsNodePort` DWORD from the registry; there is no `ApiAddr` / URL
field. `DdsAuthBridgeMain::Initialize` wires the HTTP client via
`m_httpClient.SetPort(m_config.DdsNodePort())`, not `SetBaseUrl`.
Net effect: even on a Windows machine where the Rust `dds-node` is
configured for `pipe:<name>`, the Auth Bridge will still dial
`http://127.0.0.1:<port>`, and — because the Rust side no longer
serves on TCP in that configuration — the bridge simply fails to
connect. Operators who keep the TCP listener enabled to work around
this stay on the unauthenticated loopback transport.

**Attack vector:** Any operator who follows the H-7 step-2 cutover
path for Windows ends up with a bridge that can't reach the node and
has to keep `api_addr = tcp` + `trust_loopback_tcp_admin = true`.
The H-7 defense-in-depth benefit is therefore unreachable on Windows
until the config wiring closes.

**Fix:**
- Add `ApiAddr` (REG_SZ) alongside `DdsNodePort` in
  `CDdsConfiguration`; when set, pass it to `SetBaseUrl`, else fall
  back to port.
- Update the WiX MSI to write `ApiAddr = pipe:<install-specific name>`
  by default, matching the Rust `node.toml` template generated by
  the same install.
- Flip `trust_loopback_tcp_admin = false` in the shipped config once
  this lands.

---

### A-3 (Medium). Response MAC verification is fail-open when no secret is configured
**Location:** [platform/windows/native/DdsAuthBridge/DdsNodeHttpClient.cpp:242-248](platform/windows/native/DdsAuthBridge/DdsNodeHttpClient.cpp#L242-L248), [dds-node/src/config.rs:215-228](dds-node/src/config.rs#L215-L228)

**What's wrong:** `CDdsNodeHttpClient::VerifyResponseMac` returns
`true` when `m_hmacKey.empty()`. The Rust node default for
`api_auth.node_hmac_secret_path` is `None`. `DdsAuthBridgeMain` does
log a warning and (good) fails closed on a configured-but-unreadable
path, but a bridge that boots without an `HmacSecretPath` registry
value accepts unsigned responses with no further indication.

The H-6 remediation acknowledges this as "transition-only" (see the
2026-04-21 highlights block), but it still means the default
posture of a hand-installed dev/test deployment has the MAC check
disabled on both sides, despite the middleware being present in the
Rust binary.

**Attack vector:** An attacker who binds `127.0.0.1:<port>` before
`dds-node` starts (the H-6 threat model) can still return arbitrary
challenges on any deployment that did not run the MSI's
`CA_GenHmacSecret` custom action or did not set the
`node_hmac_secret_path` in `node.toml`.

**Fix:**
- Treat the MAC as a mandatory protocol feature on the Auth Bridge
  ↔ node channel: if `m_hmacKey.empty()`, refuse to start the bridge
  on production builds (or refuse to make HTTP calls). Keep the
  current behaviour behind a build-time `DDS_DEV_ALLOW_NO_MAC` flag.
- On the Rust side, emit the MAC unconditionally in the transport
  envelope so clients that ignore the header today remain
  unaffected but clients that check it cannot be tricked into
  missing-header = accept.

---

### A-4 (Medium). Auth Bridge logs emit first 4 bytes of HMAC-derived material and password length; log directory has no explicit DACL
**Location:** [platform/windows/native/DdsAuthBridge/CredentialVault.cpp:226-229](platform/windows/native/DdsAuthBridge/CredentialVault.cpp#L226-L229), [platform/windows/native/DdsAuthBridge/CredentialVault.cpp:304-309](platform/windows/native/DdsAuthBridge/CredentialVault.cpp#L304-L309), [platform/windows/native/DdsAuthBridge/FileLog.cpp:27-37](platform/windows/native/DdsAuthBridge/FileLog.cpp#L27-L37)

**What's wrong:** `EncryptPassword` and `DecryptPassword` write the
first four bytes of the HMAC-derived encryption key plus the caller
password length into the file log, via `FileLog::Writef`. The log
file is created under `%ProgramData%\DDS\authbridge.log` by
`FileLog::Init`, which calls `CreateDirectoryW` but sets no explicit
DACL — the directory and file inherit the default `%ProgramData%`
ACL, which grants Read to `BUILTIN\Users` on most Windows SKUs.

The comment in `EncryptPassword` asserts "safe — not the actual
password", which is true, but the four bytes are derived from
(`hmac_salt_output`) output of a FIDO2 `hmac-secret` extension call.
That output is both the AES-GCM key *and* (via its derivation) a
long-lived proof-of-possession for the authenticator + credential on
that host. Leaking any prefix of it into a user-readable log is a
weaker-by-degrees disclosure that's worth removing outright given
the trivial fix.

**Attack vector:** Any user account on the box can read
`%ProgramData%\DDS\authbridge.log` and correlate username +
password-length per logon to a four-byte HMAC-key prefix, degrading
the offline-attack posture of the vault.

**Fix:**
- Strip the `hmacKey[0..3]` debug printf from both paths — they were
  for development diagnostics and are no longer needed.
- Optionally replace with a SHA-256 prefix of the ciphertext as a
  stable non-secret identifier if debugging still needs per-entry
  correlation.
- Set an explicit DACL on `%ProgramData%\DDS` at `FileLog::Init`:
  `LocalSystem` + `BUILTIN\Administrators` = `FullControl`,
  everyone else denied. Mirror the `AppliedStateStore` DACL helper
  used for L-16.

---

### A-5 (Medium). ✅ Fixed (pending verify) — P2P identity store lacks the hardening applied to the main identity store
**Location:** [dds-node/src/p2p_identity.rs](dds-node/src/p2p_identity.rs)

**What's wrong:** `p2p_identity::save` wrote the keypair with a
plain `std::fs::write` and only called `set_owner_only_permissions`
*after* the write completed. There was no `O_NOFOLLOW` protection on
load. Argon2 parameters were fixed at `Params::new(19 * 1024, 2, 1,
…)` (m=19 MiB, t=2, p=1 — the old OWASP tier-1 values).

The main identity store got L-2 (`O_NOFOLLOW` on read), L-3
(`NamedTempFile::persist` for atomic writes), and M-10 (Argon2id
bumped to m=64 MiB, t=3, p=4 with a `v=3` schema and lazy rewrap).
None of those changes were ported to `p2p_identity.rs`, even though
the P2P key determines the node's libp2p `PeerId` (and therefore its
admission-cert identity under H-12).

**Attack vector:**
- Pre-seeding a symlink at the write path redirects the fresh
  keypair into an attacker-writable location.
- The non-atomic write leaves a window in which a crash produces a
  truncated/partially-permissioned file.
- The lower Argon2 parameters reduce the cost of an offline attack
  on the passphrase-wrapped form by ~3× relative to the main
  identity file.

**Resolution (2026-04-25):** ported all three patterns from
`identity_store.rs` verbatim:
- L-3 — `tempfile::NamedTempFile::new_in(parent)` +
  `set_owner_only_permissions(tmp.path())` *before*
  `tmp.persist(path)`, plus L-4 (parent dir `0o700`) on Unix.
- L-2 — new `read_no_follow` helper using
  `OpenOptions::custom_flags(libc::O_NOFOLLOW)` on Unix.
- M-10 — new `VERSION_ENCRYPTED_V3` blob with `(m_cost, t_cost,
  p_cost)` fields embedded in CBOR; defaults bumped to m=64 MiB,
  t=3, p=4. Loads of pre-existing v=2 blobs decrypt under the
  legacy tier-1 params and trigger a transparent rewrap to v=3 on
  the same path so the upgrade is invisible to operators. PeerId is
  preserved across the rewrap.

Tests added (in `dds-node/src/p2p_identity.rs`):
- `save_writes_v3_with_embedded_params` — pins the on-disk schema:
  v=3 plus the three KDF fields with the expected values.
- `lazy_rewrap_v2_to_v3_preserves_peer_id` — hand-builds a v=2 blob,
  loads it (PeerId stable), and asserts the on-disk version flipped
  to v=3 afterwards.
- `load_refuses_symlink_unix` — symlinks the key path at a real
  blob and asserts the load fails with `Io` (O_NOFOLLOW).

The two pre-existing tests (`plain_roundtrip_stable_peer_id`,
`encrypted_roundtrip`) still pass against the new code, which means
the format is forward-compatible for callers that only see the
public `load_or_create` entry point. `cargo test -p dds-node` ⇒
138/138 ok; `cargo clippy -p dds-node --all-targets -- -D warnings`
⇒ clean.

---

### A-6 (Medium). ✅ Fixed (Windows-CI for the Windows half) — Agent software downloaders stream untrusted content to disk before hash validation, with no byte cap
**Location:** [platform/windows/DdsPolicyAgent/Enforcers/WindowsSoftwareOperations.cs](platform/windows/DdsPolicyAgent/Enforcers/WindowsSoftwareOperations.cs), [platform/macos/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs](platform/macos/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs)

**What's wrong:** Both the Windows and macOS Policy Agent software
enforcers downloaded a package with `response.Content.CopyToAsync(fs,
ct)` and only computed SHA-256 after the full file was on disk. There
was no `Content-Length` check, no byte cap, and no streaming hash.

**Attack vector:** A compromised or MITM'd publisher URL can return
an attacker-chosen body of arbitrary size. Even though the SHA-256
check later rejects it, the agent has already written the full
response to `%TEMP%\dds-software\…` (Windows) or the package cache
(macOS). On a resource-constrained host this is a cheap DoS
(disk-fill, or triggering a low-space cascade in other services).

**Impact:** Local availability on managed endpoints; no change in
integrity posture (the hash check still runs).

**Resolution (2026-04-25):**

- New `AgentConfig.MaxPackageBytes` knob on both Windows and macOS
  (default 1 GiB).
- **Windows** (`WindowsSoftwareOperations.DownloadAndVerifyAsync`)
  now: (1) pre-flights `Content-Length` against the cap and refuses
  the download outright when it's larger; (2) streams in 64 KiB
  chunks via a new `CopyAndHashWithCapAsync` helper that maintains a
  running byte counter and an `IncrementalHash` SHA-256, aborts the
  moment the counter crosses the cap, and returns the finalized
  digest in the same pass — no second read over the file. Partial
  files are deleted on any abort path. Constructor gains a second
  parameter `long maxPackageBytes`; `Program.cs` wires it from the
  configured value.
- **macOS** (`SoftwareInstaller.DownloadPackageAsync`) gets the
  same `Content-Length` pre-flight + streaming size cap via a new
  `CopyWithCapAsync` helper. Partial files deleted on overrun.
  SHA-256 hashing stays at the call site so the file:// path
  (which doesn't go through the downloader) keeps the same
  comparison shape.
- 3 new macOS unit tests in `EnforcerTests` exercise the path
  through `SoftwareInstaller.ApplyAsync` with a synthetic
  `FakeBytesHandler` HTTP message handler:
  `SoftwareInstaller_a6_refuses_download_when_content_length_exceeds_cap`,
  `SoftwareInstaller_a6_refuses_download_when_stream_exceeds_cap`
  (no Content-Length declared), and
  `SoftwareInstaller_a6_under_cap_proceeds_to_hash_check`.
- macOS test totals: 69/69 (up from 66). Rust: 451/451 unchanged.
  Windows project compiles clean (`dotnet build`); Windows test
  run pending Windows CI.
