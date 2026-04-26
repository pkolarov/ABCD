# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](docs/DDS-Design-Document.md).
> Last updated: 2026-04-26 follow-up #6 (FFI signing-key leak —
> closes `Claude_sec_review.md` informational item I-9). The
> classical `dds_identity_create` FFI export was the last DDS API
> surface that emitted secret key material (`signing_key_hex` in the
> response JSON); the hybrid variant has always been clean. Per I-9
> in the security review, plaintext key bytes flowing through Python
> ctypes / C# P/Invoke / Swift / Kotlin land in GC'd strings that
> cannot be reliably zeroized after use. Fix lives at the source
> (`dds-ffi/src/ffi_core.rs`) rather than in each binding: the
> response JSON now carries `{ urn, scheme, pubkey_len }` and the
> freshly-generated `Identity` is dropped immediately, so the secret
> never crosses the FFI boundary. Callers that need to sign should
> use the higher-level `dds_token_create_attest` entry point — it
> already keeps the signing key confined to Rust and returns only
> the signed token CBOR. The C and Swift headers
> (`bindings/c/dds.h`, `bindings/swift/Sources/CDDS/include/dds.h`)
> document the new contract. Two regression tests pin the absence:
> `dds-ffi::tests::test_identity_create` (Rust) and
> `bindings/python/test_dds.py::TestIdentity::test_create_classical`
> (Python) both assert that neither `signing_key_hex` nor
> `signing_key` appears in the response. Workspace test count: 528
> (no test count change — converted positive `is_empty` assertion
> into negative `is_none` assertions, no new tests added); cargo
> fmt clean; cargo clippy clean (workspace, all-targets, `-D
> warnings`); Python binding tests still 13/13 against the rebuilt
> `target/release/libdds_ffi.dylib`. No remaining open Critical,
> High, or Medium items in the security review; only I-1, I-6, I-9
> (now closed) and I-11 remain in the Informational tier.
>
> Previous: 2026-04-26 follow-up #5 (node identity rotation —
> partially closes `docs/threat-model-review.md` §2 recommendation #3
> / §8 open item #9). New `dds-node rotate-identity --data-dir <DIR>
> [--no-backup]` subcommand rotates the libp2p keypair in place: it
> reads the existing `<data_dir>/p2p_key.bin` (refusing to proceed
> if the blob is encrypted but `DDS_NODE_PASSPHRASE` is not set —
> the operator needs the *old* PeerId to issue a revocation, so
> silently overwriting an unreadable key would be worse than
> aborting), backs up the previous file as
> `p2p_key.bin.rotated.<unix_seconds>` unless `--no-backup`,
> generates a fresh Ed25519 keypair, and writes it back through the
> same `p2p_identity::save` path the running node uses (preserving
> the v=3 ChaCha20-Poly1305 + Argon2id schema when a passphrase is
> configured, plain v=1 otherwise). Stdout reports both the old and
> new PeerIds, the backup path, and the explicit `dds-node admit`
> + `dds-node revoke-admission` commands the admin must run before
> the operator can restart the node — the existing admission cert
> is bound to the old PeerId and becomes invalid the moment the
> rotation lands, so this is a refuse-to-start situation rather
> than a soft warning. The "automatic admission cert renewal" half
> of the original recommendation is intentionally left manual:
> admission certs stay an admin ceremony so a compromised node
> cannot self-renew its own admission. On error during the new
> save, the helper attempts to roll the backup back into place so a
> botched rotation does not strand the operator without a usable
> key. Tests: six new CLI integration tests in
> `dds-node/tests/rotate_identity_cli.rs` cover (a) the happy path
> (new PeerId differs, backup is byte-identical to pre-rotation,
> backup still loads to the OLD PeerId, follow-up commands name
> both PeerIds), (b) `--no-backup` (no `p2p_key.bin.rotated.*`
> sibling created), (c) missing data_dir, (d) missing
> `p2p_key.bin` (must redirect to `gen-node-key`), (e) the
> encrypted-blob refuse-without-passphrase guard (file must be
> byte-identical after refusal), and (f) missing `--data-dir` flag.
> Docs: `README.md` CLI block gains the new subcommand;
> `docs/threat-model-review.md` §2 risk row + recommendation #3 +
> §8 item #9 marked partially closed. Workspace test count: 528
> (up from 522); cargo fmt clean; cargo clippy clean (workspace,
> all-targets, `-D warnings`).
>
> Previous: 2026-04-26 follow-up #4 (FIDO2 parser hardening —
> closes Claude_sec_review.md informational items I-8 + I-10). Two
> small source-validated parser fixes in `dds-domain/src/fido2.rs`:
> (a) `parse_auth_data` now caps `cred_id_len` at the new public
> `MAX_CREDENTIAL_ID_LEN = 1023` constant (CTAP2.1 §6.1
> `MAX_CREDENTIAL_ID_LENGTH`; WebAuthn §4 also recommends RPs ignore
> credential IDs ≥1024 bytes), so a peer-supplied authData declaring
> a 64 KiB credential id is rejected with a `Format` error before the
> `to_vec` allocation; (b) `cose_to_credential_public_key` now
> requires the COSE_Key `alg` parameter (label 3) per RFC 9052 §3.1
> instead of falling back to inferring the algorithm from `kty`
> alone — both the OKP/Ed25519 and EC2/P-256 paths share one upfront
> required-`alg` check and the kty/alg mismatch arms (`kty=OKP +
> alg=ES256` etc.) are still handled by the unchanged catch-all
> `_ => Err(Unsupported)`. Tests: four new regression tests in
> `dds-domain/src/fido2.rs::tests` —
> `i8_parse_auth_data_rejects_oversized_credential_id`,
> `i8_parse_auth_data_accepts_max_credential_id_length` (boundary at
> 1023 still parses past the cap, fails later in COSE),
> `i10_cose_to_credential_public_key_rejects_missing_alg`, and
> `i10_cose_to_credential_public_key_rejects_missing_alg_p256`.
> Workspace test count: 522 (up from 518); cargo fmt clean; cargo
> clippy clean (workspace, all-targets, `-D warnings`). No remaining
> open Critical, High, or Medium items in the security review.
> Closures recorded in `Claude_sec_review.md` §Informational.
>
> Previous: 2026-04-26 follow-up #3 (Windows data-directory DACL
> at install time — closes threat-model §3 / §8 open item #8).
> The MSI now applies the same restricted DACL the C++ Auth Bridge
> self-heals on every start (`FileLog::Init`) and the .NET Policy
> Agent applies to its staging cache (B-6) — but it does so
> *before* anything else writes inside `%ProgramData%\DDS`,
> closing the install-time race where `node-hmac.key` (created by
> `CA_GenHmacSecret`) inherited the wide-open
> `%ProgramData%` parent ACL on first install. New
> `dds-node restrict-data-dir-acl --data-dir <DIR>` subcommand
> applies SDDL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` via
> `ConvertStringSecurityDescriptorToSecurityDescriptorW` +
> `SetNamedSecurityInfoW` (`SE_FILE_OBJECT` +
> `PROTECTED_DACL_SECURITY_INFORMATION`), mirroring the existing
> SDDL used by `FileLog::Init` and `AppliedStateStore.SetWindowsDacl`.
> Cross-platform: no-op on macOS / Linux (Unix path security stays
> on per-file `0o600` / per-dir `0o700` modes set in
> `identity_store` / `domain_store` / `redb_backend` —
> L-2/L-3/L-4/M-20). New `CA_RestrictDataDirAcl` MSI custom action
> in `installer/DdsBundle.wxs` runs after `InstallFiles` and before
> `CA_GenHmacSecret`. Tests: 5 new CLI integration tests in
> `dds-node/tests/restrict_data_dir_acl.rs` cover the success path,
> missing-dir failure, non-directory rejection, missing-flag failure,
> and idempotent re-application. The Windows `SetNamedSecurityInfoW`
> call requires Windows host CI to exercise end-to-end. Workspace
> test count: 518 (up from 513); cargo fmt clean; cargo clippy clean
> on both `aarch64-apple-darwin` and `x86_64-pc-windows-gnu`.
>
> Previous: 2026-04-26 follow-up #2 (admission revocation
> operator visibility — `dds-node list-revocations` subcommand).
> Closes a documented operator-ergonomics gap in the revocation flow:
> after `dds-node import-revocation` (or after H-12 piggy-back
> propagation in the morning's same-day follow-up) there was no way
> to inspect what was actually on disk under
> `<data_dir>/admission_revocations.cbor` — operators only saw the
> `total entries: N` summary from `import-revocation`. The new
> `dds-node list-revocations --data-dir <DIR> [--json]` subcommand
> reads the store under the same domain-pubkey verification gate as
> the runtime path (`admission_revocation_store::load_or_empty`), so
> the listed entries always reflect what the running node would
> actually enforce — corrupt or foreign-domain entries are dropped
> before they appear. Default output is human-readable
> (data_dir / file / domain / count + numbered entries with peer_id,
> revoked_at, optional reason); `--json` emits one
> hand-rolled-escaped JSON object per entry on stdout for `jq` /
> monitoring pipelines (no serde_json dep added for one read-only
> command). Tests: four new CLI integration tests in
> `dds-node/tests/admission_revocation_cli.rs` cover the
> empty-store path, the round-trip with two entries (human + JSON),
> the JSON-escape path for reasons containing `"` / `\` / newline,
> and the no-`dds.toml` failure mode. Docs refreshed:
> [docs/DDS-Admin-Guide.md](docs/DDS-Admin-Guide.md) gains a new
> "Revoking a Node's Admission" section (TOC entry #4) covering the
> full issue → distribute → verify flow; [README.md](README.md)'s
> dds-node command list now shows all three revocation commands;
> `docs/threat-model-review.md` §1 mitigation row updated to mention
> the inspection path. Workspace test count: 513 (up from 509);
> clippy clean; cargo fmt clean.
>
> Previous: 2026-04-26 follow-up (admission revocation
> gossip-piggyback — closes the "future increment" caveat that the
> morning revocation-list pass left open in
> `docs/threat-model-review.md` §1 recommendation #2). Wire format:
> `dds_net::admission::AdmissionResponse` now carries a
> `#[serde(default)] revocations: Vec<Vec<u8>>` field with backward-
> compatible decoding (legacy v1 senders that omit the field
> deserialize cleanly; legacy readers ignore the unknown v2 field —
> both pinned by new wire-format unit tests). Sender side
> (`DdsNode::handle_admission_event`) attaches up to
> `MAX_REVOCATIONS_PER_RESPONSE = 1024` opaque CBOR-encoded
> `AdmissionRevocation` blobs from the local store on every H-12
> handshake response. Receiver side (`verify_peer_admission` →
> `merge_piggybacked_revocations`) drops the entire vector if the
> sender over-shoots the cap (DoS guard), then routes survivors
> through `AdmissionRevocationStore::merge` — which verifies each
> entry's signature against the domain pubkey before insertion —
> and atomically rewrites
> `<data_dir>/admission_revocations.cbor` if any new entries
> landed. Net effect: an admin issues `dds-node revoke-admission`
> against any one node and the revocation now propagates
> domain-wide on the order of a handshake round trip; the
> manual-file-copy flow remains as an emergency-rollout fallback.
> Six new tests: 4 unit tests in `dds-net::admission::tests` (cap
> constant pinned, with-revocations roundtrip, v1→v2 forward decode,
> v2→v1 backward decode), 2 integration tests in
> `dds-node/tests/h12_revocation_piggyback.rs` (happy-path
> propagation + persistence; foreign-domain rejection at the merge
> boundary). Workspace test count: 509 (up from 503); clippy clean;
> cargo fmt clean.
>
> Previous: 2026-04-26 morning (admission cert revocation list — closed the
> last remaining High item from `docs/threat-model-review.md` §1 / §8
> open item #4. New `dds_domain::AdmissionRevocation` type (domain-signed
> CBOR, mirrors `AdmissionCert`); new `dds_node::admission_revocation_store`
> with atomic save + foreign-domain rejection on import; revocation
> lookup wired into both halves of H-12 (peer admission handshake refuses
> revoked peer ids; `DdsNode::init` refuses to start if the local node's
> own PeerId is on the list); two new CLI subcommands —
> `dds-node revoke-admission` issues a revocation,
> `dds-node import-revocation` adds it to a node's data dir.
> 23 new tests across `dds-domain` (6 unit), `dds-node`
> (11 unit + 4 integration + 2 CLI integration). Workspace test count:
> 503 (up from 480); clippy clean; cargo fmt clean.
>
> Previous: 2026-04-25 (Windows host verification pass — H-6 step-2 +
> H-7 step-2b now verified end-to-end on Windows x64; several pre-existing
> build/CI bugs surfaced and fixed: dds-cli unix-only imports,
> build_tests.bat BuildTools support, gen-hmac-secret idempotency for
> MSI repair/upgrade, smoke_test.ps1 -Target plumbing. A 2026-04-24 addendum code-path pass added 6 new findings — 2 High, 4 Medium — tracked as A-1…A-6 in [Claude_sec_review.md](Claude_sec_review.md). 2026-04-25 follow-up: B-5 closed — `http::issue_challenge` now sweeps expired rows on every put, enforces a `MAX_OUTSTANDING_CHALLENGES = 4096` global cap (503 when full), and `consume_challenge` deletes expired/malformed rows in the same write txn; `count_challenges` added to `ChallengeStore`. 2026-04-25 follow-up #2: B-3 closed — Policy Agent `AppliedStateStore.HasChanged` now requires a successful prior status (`"ok"`/`"skipped"`) to short-circuit, and the Windows worker threads the real `EnforcementStatus` through a new `ApplyBundleResult` aggregate into `RecordApplied` / `ReportAsync` instead of hardcoding `"ok"` (matches macOS pattern); 6 regression tests added across both AppliedStateStore test suites. Also published [docs/AD-drop-in-replacement-roadmap.md](docs/AD-drop-in-replacement-roadmap.md) — claim-ladder gap map for any future "AD DS replacement" framing. 2026-04-25 follow-up #3: A-2 / A-3 / A-4 source-side fixes landed (Windows-CI verification still pending) — see the per-finding entries below. Also fixed a pre-existing flaky-test bug in the macOS .NET suite: `BackendOperationTests` and `EnforcerTests` both mutate the process-wide `DDS_POLICYAGENT_ASSUME_ROOT` env var, and xUnit's parallel runner was interleaving one class's `Dispose` with another class's still-running tests. Both classes now share an `[Collection("PolicyAgentEnvSerial")]` non-parallel collection; macOS suite is 72/72 deterministic across 5 reruns. 2026-04-25 follow-up #4: B-1 closed — `dds-net::sync::apply_sync_payloads_with_graph` now feeds the `TrustGraph` BEFORE the store, so a duplicate-JTI / unauthorized-revoke / burned-issuer payload can no longer poison persistent state; `store.put_token` uses put-if-absent semantics and `store.revoke` / `store.burn` only fire on graph acceptance. The graphless `apply_sync_payloads` got the same put-if-absent guard. Three new regression tests in `dds-net/src/sync.rs`. **2026-04-25 follow-up #5: B-2 / B-4 / B-6 closed** — closes the remaining open findings from the 2026-04-25 independent review pass:
> - **B-2 (High)**: `Token::create_with_version` and `Token::validate` now share one structural validator (`Token::validate_shape`), so a foreign signer that emits a CBOR-correct, signature-valid `Vouch` without `vch_iss`/`vch_sum` (or `Revoke` without `revokes`, or `Revoke`/`Burn` carrying `exp`) is rejected at graph ingest the same way it would be at construction. `TrustGraph::has_purpose` / `purposes_for` / `walk_chain` now require an *active* target attestation for every purpose grant — revoked, expired, or burned-issuer attestations no longer satisfy a vouch's `vch_iss` lookup, and `vch_sum` matches an attestation by exact payload-hash rather than falling back to "first attestation for issuer". Four new regression tests in `dds-core::trust` cover (a) grant drops on target-attestation revoke, (b) grant drops on subject burn, (c) construction-time shape rejection of malformed Vouch, and (d) shape rejection of legacy vouches missing `vch_sum`.
> - **B-4 (Medium)**: `LocalService::list_applicable_*` now collapses duplicate `policy_id` (Windows + macOS) and `package_id` (software) at serve time. Winner: highest `version`, ties broken by latest `iat`, final tiebreak lex-smallest `jti`; software falls back to `iat` since `version` is a free-form string. Result is sorted by logical ID for stable agent ordering across polls. Four new regression tests in `dds-node/src/service.rs::platform_applier_tests` cover version supersession, iat tiebreak on version equality, software supersession by iat, and that distinct IDs are not collapsed.
> - **B-6 (Medium)**: Windows software installer now stages downloads under `%ProgramData%\DDS\software-cache` with an explicit, non-inherited DACL granting only LocalSystem and BUILTIN\Administrators (mirrors L-16's `AppliedStateStore` helper). `DownloadAndVerifyAsync` pins the post-verify `(size, last-write UTC)` of every staged file; `InstallMsi` / `InstallExe` re-check both immediately before `Process.Start` and refuse with `InvalidOperationException` on any mismatch. The path-prefix check fails closed if the staged file moves outside the cache. Direct callers that supply their own path (integration tests pointing at a pre-built MSI) get the existence check only. Four new tests in `DdsPolicyAgent.Tests/B6SoftwareStagingTests.cs` exercise size-tamper, mtime-only-tamper, external-path acceptance, and cache-location pinning. The cross-platform unit tests use a per-test sandbox via the new `cacheDir` constructor parameter; production paths route to the protected default.)
>
> **2026-04-25 follow-up #7: threat-model §8 item 13 closed — real-time expiry in `evaluate_policy`.** The threat-model review listed "expiry sweep race" as a Low-priority open item, recommending an inline expiry check in `evaluate_policy` because a token that just expired could be evaluated as valid until the next 60-s sweep. The trust graph hot paths (`has_purpose`, `purposes_for`, `walk_chain`, `active_attestation_for_iss`) already filter via `is_expired()` against `SystemTime::now()` on every call — the periodic sweep exists only to reclaim store space, not to gate evaluation. Three regression tests in `dds-core::trust::tests` now pin that contract so a future refactor cannot silently reintroduce the sweep-only window: `realtime_expiry_drops_grant_in_has_purpose_and_purposes_for` (expired vouch dropped from `has_purpose` and `purposes_for` without calling `sweep_expired`), `realtime_expiry_in_target_attestation_drops_grant` (grant drops when the target attestation is expired even though the vouch itself is fresh), and `realtime_expiry_breaks_chain_at_intermediate_vouch` (an expired intermediate vouch breaks a depth-2 chain). `docs/threat-model-review.md` §5 / §8 updated. Workspace test count: 480 (up from 477); clippy clean; cargo fmt clean.
>
> **2026-04-25 follow-up #6: A-1 follow-up closed — server-issued enrollment challenge.** The 2026-04-24 A-1 step-3 pass landed `type` / `origin` / `crossOrigin` validation at enrollment but explicitly deferred the §7.1 step-9 challenge binding because no `/v1/enroll/challenge` endpoint existed. That endpoint now ships: `GET /v1/enroll/challenge` (admin-gated, sits on the same enrollment sub-router) issues a 32-byte random nonce with the same `chall-enroll-` prefix and 5-min TTL the session/admin variants use, going through the shared B-5 sweep+cap pipeline (`MAX_OUTSTANDING_CHALLENGES = 4096`). `EnrollUserRequest` (and `AdminSetupRequest` via the type alias) gains an optional `challenge_id` field; when supplied, `enroll_user`/`admin_setup` consume the challenge atomically (single-use, mirrors assertion side) and forward the bytes to `verify_enrollment_client_data`, which now decodes the cdj `challenge` field with the same lenient base64url decoder as M-12 and refuses any mismatch. Backward compatible: legacy callers that omit `challenge_id` keep working unchanged (only `type` / `origin` / `crossOrigin` get checked). Nine new tests added: 5 unit tests in `service::a1_step3_client_data_tests` (matching challenge accepted, mismatched challenge rejected, padded base64url accepted, challenge supplied without cdj rejected, missing challenge field rejected when expected); 4 HTTP integration tests in `http::tests` (unique nonces, full round-trip with single-use enforcement, mismatched challenge rejected, legacy no-challenge_id path still passes). Workspace test count: 477 (up from 468); clippy clean; cargo fmt clean (this pass also normalized pre-existing fmt drift across `dds-core` / `dds-cli` / `dds-domain` / `dds-store` / `dds-fido2-test` / `dds-node` so the `fmt --check` CI gate is green again — no behavior changes in those files). Three pre-existing clippy-on-test errors in `dds-fido2-test/src/bin/multinode.rs` (field_reassign_with_default, collapsible_if, clone_on_copy) also fixed in the same pass.

## Security Remediation Status

Full, source-validated independent review: [Claude_sec_review.md](Claude_sec_review.md)
(latest full pass 2026-04-21; addendum pass 2026-04-24 adds A-1…A-6 —
see the "Addendum — 2026-04-24 code-path pass" section of that file).
Prior pre-review gaps file: [security-gaps.md](security-gaps.md) — now
marked superseded.

| Severity | Fixed | Deferred | Addendum (open) | Rationale for deferral |
|---|---|---|---|---|
| **Critical** | 3/3 | — | — | — |
| **High** | 12/12 | — | A-1 + A-2 landed pending Windows-host reverify | H-6 + H-7 step-2b verified on Windows x64 host 2026-04-24 — see "Windows host verification (2026-04-24)" below. A-2 source side landed 2026-04-25 (`ApiAddr` registry field + `SetBaseUrl` wiring + WiX/MSI defaults); Windows CI rerun pending. |
| **Medium** | 21/22 | 3 | A-3 / A-4 / A-5 / A-6 source side landed; Windows CI half pending for A-3/A-4/A-6 | M-13 (FIDO MDS integration — external design), M-15 (node-bound FIDO2 `hmac_salt`; blocked on bundle re-wrap design), M-18 (WiX service-account split — multi-day Windows refactor). |
| **Low** | 17/18 | 1 | — | L-17 (service-mutex refactor — 29 HTTP handler lock sites; L-18's atomic `bump_sign_count` already closed the replay race so the remaining gain is throughput not security). |

The "Fixed" column count for Medium tracks A-5 alongside the
M-1…M-22 ledger; the addendum table below is the per-finding view.

**Addendum pass 2026-04-24** (5 open + 1 landed):

- **A-1 (High) ✅ steps 1+2+3 landed 2026-04-25, pending HW reverify**:
  Step-1 — `fmt = "none"` is rejected by default; opt-in via
  `DomainConfig.allow_unattested_credentials` (default `false`),
  with WARN logging on accepted unattested paths.
  Step-2 — `verify_packed` now verifies `attStmt.sig` even when
  `x5c` is present: `x509-parser` extracts the leaf cert's SPKI,
  the alg OID is double-checked against `attStmt.alg`, and the
  signature is verified over `authData || clientDataHash` under
  that pubkey. Chain validation against trust anchors stays in
  M-13 (FIDO MDS integration). Four new unit tests cover the
  positive path (synthetic rcgen leaf), garbage cert, sig under
  wrong key, and alg/SPKI mismatch.
  Step-3 — `EnrollUserRequest` / `AdminSetupRequest` gain optional
  `client_data_json` (mirroring M-12 at the assertion side); new
  `verify_enrollment_client_data` helper enforces
  `type == "webauthn.create"`, `origin == "https://<rp_id>"`, and
  `crossOrigin != true` after binding the JSON to the signed CDH
  via SHA-256. Backward-compatible — when the field is absent the
  legacy rp-id-hash-only path runs. 8 new unit tests cover the
  helper.
  **Real-HW (`dds-multinode-fido2-test`) verification pending** —
  re-run next time a Crayonic / YubiKey is connected.
  Server-issued enrollment challenge (closes the cdj.challenge
  gap) is tracked separately as a follow-up.
- **A-2 (High) ✅ source-side landed 2026-04-25, pending Windows CI**:
  `CDdsConfiguration` now reads an `ApiAddr` (REG_SZ) value next to
  `DdsNodePort`; when non-empty, `DdsAuthBridgeMain::Initialize`
  threads it through `m_httpClient.SetBaseUrl(...)` (the H-7 step-2b
  path that recognises the `pipe:<name>` scheme). The shipped
  `installer/DdsBundle.wxs` writes `ApiAddr = "pipe:dds-api"` to
  `HKLM\SOFTWARE\DDS\AuthBridge` by default, the Rust template
  `installer/config/node.toml` defaults `api_addr = 'pipe:dds-api'`,
  and `installer/config/appsettings.json` defaults
  `DdsPolicyAgent.NodeBaseUrl = "pipe:dds-api"` — all three sides of
  the H-7 step-2b transport now agree out of the box. C++ compile +
  test of the bridge is pending Windows CI.
- **A-3 (Medium) ✅ source-side landed 2026-04-25, pending Windows CI**:
  `CDdsAuthBridgeMain::Initialize` is now fail-closed when
  `HmacSecretPath` is empty (logs an EventLog error + returns FALSE
  rather than continuing with MAC disabled). The legacy permissive
  behaviour is gated behind a build-time `DDS_DEV_ALLOW_NO_MAC` macro
  the production MSI does not define. Defense-in-depth: the same
  flag also gates the `m_hmacKey.empty() → accept` short-circuit in
  `CDdsNodeHttpClient::VerifyResponseMac`. Dev/test rigs (and the
  C++ test binaries, which run without the MSI) still work.
- **A-4 (Medium) ✅ source-side landed 2026-04-25, pending Windows CI**:
  `CCredentialVault::EncryptPassword` / `DecryptPassword` no longer
  log the four-byte hmac-secret key prefix or the cleartext password
  length. `FileLog::Init` now applies an explicit, non-inherited
  DACL to `%ProgramData%\DDS` via
  `ConvertStringSecurityDescriptorToSecurityDescriptorW` +
  `SetNamedSecurityInfoW` with SDDL
  `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` — full control to
  LocalSystem and BUILTIN\Administrators, OICI inheritance for
  current and future child files, mirroring the L-16 helper in
  `AppliedStateStore.cs`. Upgrade-safe: a stale wide-open ACL from
  a pre-A-4 build is corrected on first start of the new bits.
- **A-5 (Medium)** ✅ landed 2026-04-25: `dds-node/src/p2p_identity.rs`
  ported L-2 (`O_NOFOLLOW`), L-3 (atomic persist via `NamedTempFile` +
  perm-before-rename + L-4 parent dir `0o700`), and M-10 (Argon2id v=3
  with embedded params, m=64 MiB, t=3, p=4) — matching `identity_store`
  exactly. Lazy v=2 → v=3 rewrap on first successful load preserves
  PeerId. Three new tests pin the schema, the rewrap, and the symlink
  refusal; all 138 dds-node tests still pass.
- **A-6 (Medium) ✅ landed 2026-04-25 (Windows-CI for the Windows half)**:
  Both Policy Agent software enforcers gained an `AgentConfig.MaxPackageBytes`
  knob (default 1 GiB), `Content-Length` pre-flight, and a streaming
  64 KiB copy loop that aborts the moment the running byte total
  crosses the cap. Windows additionally hashes incrementally via
  `IncrementalHash` in the same pass so the SHA-256 digest is
  finalized without a second read over the file. Partial files are
  deleted on any overrun / cancellation path. 3 new macOS unit tests
  (`SoftwareInstaller_a6_*` in `EnforcerTests`) cover the
  Content-Length-declared overrun, streaming overrun without
  Content-Length, and the under-cap path. macOS suite: 69/69 ok (up
  from 66). Windows test run pending Windows CI.

**Highlights shipped in the 2026-04-17 → 2026-04-21 sweep:**

- **Transport auth (H-6, H-7)**: `dds-node::http::serve` now dispatches
  on `api_addr` scheme. `unix:/path` binds a Unix domain socket and
  extracts peer credentials on every connection via `peer_cred()`;
  `pipe:<name>` binds a Windows named pipe and pulls the caller's
  primary SID via `GetNamedPipeClientProcessId` →
  `OpenProcessToken` → `GetTokenInformation(TokenUser)`. The
  `CallerIdentity { Anonymous, Uds, Pipe }` extractor injects the
  result into every request, and the admin-gate middleware admits
  based on uid/sid allowlists. Three clients gained matching
  transport-swap factories: `dds-cli` (hyper + `UnixStream`), the
  macOS Policy Agent (`DdsNodeHttpFactory` + `ConnectCallback` to
  `UnixDomainSocketEndPoint`), the Windows Policy Agent (same,
  plus `NamedPipeClientStream`), and the C++ Auth Bridge
  (`SendRequestPipe` with `CreateFileW` +
  `WriteFile`/`ReadFile`). The MSI provisions a per-install 32-byte
  HMAC secret via a new `CA_GenHmacSecret` custom action; the C++
  Auth Bridge verifies `X-DDS-Body-MAC` on every response via
  BCrypt (H-6 step-2 defense-in-depth).
- **Per-peer admission (H-12)**: new libp2p request-response
  behaviour on `/dds/admission/1.0.0/<domain>` runs after Noise;
  `DdsNode::admitted_peers` is populated only after the peer's
  admission cert verifies against the domain pubkey. Gossip and
  sync from unadmitted peers are dropped at the behaviour layer.
- **Crypto hygiene (M-1, M-2, M-10)**: canonical-CBOR token
  envelope (`v=2`, `dds-token-v2\0 || canonical_cbor(payload)`);
  hybrid + triple-hybrid signatures now domain-separated per
  component; Argon2id keyfile schema `v=3` carries
  `(m_cost, t_cost, p_cost)` with defaults bumped to m=64 MiB,
  t=3, p=4 (OWASP tier-2, lazy v=2 → v=3 rewrap on load).
- **Publisher capabilities (C-3)**: `publisher_capability_ok`
  filter on gossip/sync ingest drops unauthorised
  policy/software attestations before they enter the trust graph;
  a symmetric filter on the serve side is kept as defense in
  depth.
- **CLI**: new `dds-node gen-hmac-secret --out <FILE>` subcommand
  writes the per-install HMAC secret (used by the MSI custom
  action). New `dds-macos-e2e gen-publisher-seed --out <FILE>`
  subcommand produces a deterministic publisher identity for the
  e2e harness (needed after C-3's ingest filter).
- **Doc-refresh pass 2026-04-21**: STATUS, Admin Guide,
  threat-model review, Design Document, Developer Guide,
  Implementation Whitepaper, README, and security-gaps.md all
  updated to reflect the current posture.

## Build Health

| Metric | Value |
|---|---|
| **Rust version** | 1.94.1 (stable) |
| **Edition** | 2024 |
| **Workspace crates** | 9 (dds-core, dds-domain, dds-store, dds-net, dds-node, dds-ffi, dds-cli, dds-loadtest, dds-fido2-test) |
| **Rust LOC** | 8,400+ |
| **Rust tests** | 480 (up from 305 after B-1, B-2, B-3, B-5 regressions, the A-1 follow-up enrollment-challenge plumbing, and the threat-model §8 item-13 real-time-expiry regression triple; macOS dev host) |
| **.NET tests** | 132 (Windows: 89 unit + 43 integration; up from 117 after B-3, B-6 regressions) + 72 (macOS; up from 17 after B-3 regressions and macOS Tests parity) |
| **C++ native tests** | 47 (Windows) |
| **Python tests** | 13 |
| **Total tests** | 735 ✅ all passing on the macOS dev host (Rust + macOS .NET + Python). Windows-side .NET / native counts are CI-verified (last run 2026-04-24). |
| **Shared library** | libdds\_ffi.dylib (739 KB) |

Verification note (2026-04-13, Windows 11 ARM64):
- `cargo test --workspace` — **298/298 pass** on Windows 11 ARM64 (aarch64-pc-windows-msvc)
- `cargo test -p dds-node --test cp_fido_e2e` — **3/3 CP+FIDO2 E2E tests pass** (Ed25519, P-256, enrollment+assertion)
- `dotnet build ABCD.sln` — **0 errors** across DdsPolicyAgent (net8.0+net9.0), DdsPolicyAgent.Tests, DdsCredentialProvider (.NET stub)
- `dotnet test` for `platform/windows/DdsPolicyAgent.Tests` — **99/99 pass** (60 unit + 39 integration, net8.0+net9.0)
- Native C++ solution (`DdsNative.sln`) — **6/6 projects build**: Helpers.lib, DdsBridgeIPC.lib, DdsCredentialProvider.dll (ARM64), DdsAuthBridge.exe (x64), DdsTrayAgent.exe (x64), test suites
- `dds-node/tests/multinode.rs` — **4/4 pass** on Windows ARM64 (dag_converges_after_partition, rejoined_node_catches_up_via_sync_protocol now green)
- Windows E2E smoke test (`platform/windows/e2e/smoke_test.ps1`) — **8/8 checks pass** including CP DLL COM export verification
- **Security hardening merged (2026-04-13 → 2026-04-21):** initial
  6-commit pre-review batch (removed unauthenticated session
  endpoint, RP-ID binding in assertion, credential_id plumbing,
  vault lookup fix, HTTP contract alignment, CP test coverage);
  then the full Claude-sec-review remediation sweep covering all
  3 Critical, all 12 High, 19 of 22 Medium, 17 of 18 Low findings
  — see the [Security Remediation Status](#security-remediation-status)
  section above and [Claude_sec_review.md](Claude_sec_review.md)
  for the per-finding ledger. On the Rust workspace every
  security test added in the sweep is now in-tree and green on
  the native host + cross-compiled clean for
  `x86_64-pc-windows-gnu`. The C++ Auth Bridge / MSI pieces of
  H-6 and H-7 step-2b still need Windows CI to run.
- **FIDO2 passwordless Windows login re-verified after merge (2026-04-13):** Clean wipe + fresh enrollment: admin setup (auto-persisted trusted_roots) → user enrollment (2 touches) → admin vouch → lock screen → touch key → Windows session. Real YubiKey on Win11 ARM64 QEMU/UTM VM.
- `test_components.exe` — **11/11 pass**: AES-GCM roundtrip, wrong-key rejection, password encoding, vault serialization, URN-to-SID extraction, IPC struct layout, IPC password transfer, KERB packing, full pipeline, SID resolution, LsaLogonUser with real credentials
- `test_full_flow.exe` — **PASS**: Full enrollment→login with real FIDO2 authenticator (MakeCredential + 2× GetAssertion + vault save/load + LsaLogonUser)
- `test_hmac_roundtrip.exe` — **PASS**: hmac-secret determinism + encrypt/decrypt roundtrip with real authenticator
- **Policy Applier Phases D–F verified (2026-04-13, Windows 11 ARM64):** All 4 enforcers now have production Win32 implementations + real e2e integration tests. `WindowsAccountOperations` (netapi32 P/Invoke: create/delete/disable/enable users, group membership, domain-join check), `WindowsPasswordPolicyOperations` (NetUserModalsGet/Set + secedit for complexity), `WindowsSoftwareOperations` (HTTP download + SHA-256 verify + msiexec install/uninstall + registry-based detection), `WindowsRegistryOperations` (idempotent DWORD/String/QWORD/MultiString/Binary/ExpandString with int↔uint comparison fix). 39 integration tests exercise real Win32 APIs on ARM64. Test MSI (32 KB WiX package) installs/uninstalls cleanly.
- **Phase G+H (installer + CI) verified (2026-04-13, Windows 11 ARM64):** WiX v4 MSI builds clean (30.9 MB ARM64 package, 0 warnings). Includes 5 components: `dds-node.exe` (Windows Service), `DdsAuthBridge.exe` (Windows Service, depends on DdsNode), `DdsCredentialProvider.dll` (COM DLL in System32), `DdsPolicyAgent.exe` (Windows Service, depends on DdsNode), `DdsTrayAgent.exe` (optional). Configuration templates (`node.toml`, `appsettings.json`) installed to `C:\Program Files\DDS\config\`. `C:\ProgramData\DDS\` created for vault/logs/state. CI workflows: `msi.yml` builds x64 MSI + validates + generates SHA-256 checksums + Authenticode signing scaffolding (conditional on certificate secret); `ci.yml` `windows-native` job enhanced with .NET 8.0+9.0 dual testing, Release MSI compile verification, and E2E smoke test execution.

Windows host verification (2026-04-24, Windows 11 x64 + BuildTools 14.44 + WiX 5.0.2):

- `cargo test --workspace --target x86_64-pc-windows-msvc` — **421/421 pass across 25 binaries** (`CARGO_PROFILE_TEST_DEBUG=line-tables-only` to keep PDBs from blowing the runner's disk).
- C++ native solution (`platform\windows\native\DdsNative.sln`, x64 Debug + Release) — **6/6 projects build clean**: Helpers, DdsBridgeIPC, DdsCommon, DdsCredentialProvider, DdsAuthBridge, DdsTrayAgent.
- Native test suite (`Tests\build_tests.bat` + `run_all_tests.bat`) — **41/41 tests pass**: IPC layout, message types, struct field offsets, IPC serialization, dds-node URL parsing, JSON helpers, base64url decoding, vault-by-credential-id matching, subject-URN extraction.
- `dotnet test platform\windows\DdsPolicyAgent.Tests --framework net8.0` — **149/149 pass** (110 unit + 39 integration on real Win32 APIs). net9.0 framework runtime not installed locally on this host; CI continues to cover both via `setup-dotnet`.
- WiX MSI compiles clean: `wix build DdsBundle.wxs` → **33.64 MB MSI**, `wix msi validate` passes. `CA_GenHmacSecret` custom action present in MSI tables, idempotent end-to-end (verified by re-invoking the staged `dds-node.exe gen-hmac-secret --keep-existing --out X` and hash-comparing the file).
- Windows E2E smoke test (`platform\windows\e2e\smoke_test.ps1 -Target x86_64-pc-windows-msvc`) — **8/8 checks pass** including `cp_fido_e2e` Rust E2E (3/3) and CP DLL COM-export verification.
- **Pre-existing build/CI bugs surfaced and fixed during this pass:**
  - `dds-cli/src/client.rs` imported `tokio::net::UnixStream` and `hyper-util` symbols at module scope without `#[cfg(unix)]` guards → broke any Windows build that ran `cargo test -p dds-cli`. Now properly gated; on Windows the UDS branch compiles to a `fail()` stub.
  - `dds-node gen-hmac-secret`: refused to overwrite an existing key file with exit 1 → combined with the WiX `CustomAction Return="check"`, this would have failed every MSI **repair / upgrade** install (the secret already exists from the original install). Added `--keep-existing` flag (exits 0 with message when the file is present); the WiX `ExeCommand` now passes `--keep-existing`. Two new tests in `h6_gen_hmac_secret.rs` pin the behavior.
  - `platform\windows\native\Tests\build_tests.bat` invoked `vswhere -latest -requires VC.Tools.x86.x64` without `-products *` → matched only Community/Pro/Enterprise IDEs, not the BuildTools SKU. Now passes `-products *` so a clean BuildTools-only host (and the GitHub Actions runner) can build the native test binary.
  - `platform\windows\e2e\smoke_test.ps1`: hardcoded the ARM64 dumpbin path under `bin\Hostarm64\arm64`; on x64 runners this silently skipped the COM-export check. Now discovers dumpbin via `vswhere` for any host arch. The script also unconditionally ran `cargo test -p dds-node --test cp_fido_e2e` against the host triple — on a CI runner that already built the workspace under `--target x86_64-pc-windows-msvc` this kicked off a second full link cycle and OOM'd the runner's disk. Added `-Target` parameter so callers can reuse the existing artifacts.
  - `.github/workflows/ci.yml`: dropped the brittle "copy binaries into target/debug" pre-step in favor of passing the new `-NodeBinary`/`-CliBinary`/`-Target` parameters directly, with `CARGO_INCREMENTAL=0` set on the smoke-test step to keep its incremental cache from doubling target size on the runner.

Multinode FIDO2 E2E with real hardware (2026-04-24, Windows 11 x64 + Crayonic KeyVault):

- New interactive binary [`dds-multinode-fido2-test`](dds-fido2-test/README.md)
  spawns three in-process `DdsNode` instances in a star mesh on
  loopback, each with its own HTTP API. Walks a real authenticator
  through enrollment on node A, cross-node session issuance on node B,
  partition-while-revoke + sync catch-up on C, and a final assertion
  on C that must fail because the vouch was revoked.
- Verified end-to-end on the Crayonic KeyVault: 3 touches, all checks
  passed:
  ```
  ✓ user visible on B and C
  ✓ vouch propagated — purposes_for(user) contains dds:user on all 3 nodes
  ✓ session issued by node B
  ✓ node C also grants dds:user → cross-node consistency confirmed
  ✓ revoke visible on A and B (C is partitioned)
  ✓ revoke arrived on C via sync protocol
  ✓ node C correctly refused session issuance after revoke
  === ALL CHECKS PASSED ===
  ```
- Bugs surfaced and fixed during the bring-up (full detail in
  [`dds-fido2-test/README.md`](dds-fido2-test/README.md)):
  - `dds-fido2-test`'s assertion path passed the pre-hashed cdh to
    `ctap-hid-fido2`'s `GetAssertionArgsBuilder`, which hashes its
    `challenge` arg internally before wiring it to the CTAP2
    command — so the device signed over `SHA-256(cdh)` while the
    server verified over `cdh`. ctap-hid-fido2's local verifier
    hashes the same way and agreed with itself, masking the
    mismatch. Fix: pass `clientDataJSON` bytes; the lib hashes
    once. Same bug also fixed in the single-node `src/main.rs`.
  - `dds_domain::fido2::verify_assertion` didn't `normalize_s()` the
    P-256 signature before verify. Defensive — the actual root cause
    was the double-hash above — but the RustCrypto p256 verifier
    enforces low-S to defend against malleability, and authenticators
    aren't required to emit normalized sigs. Replay is already gated
    upstream by the single-use server challenge.
- **Follow-up landed**: `dds-node::ingest_revocation` and
  `ingest_burn` now seed the sync-payload cache with a deterministic
  synthetic op (`op-<jti>`) so a node that learned a revoke / burn
  via gossip can relay it to a future reconnecting peer via the
  request_response sync protocol — not just the originating
  publisher. New regression test
  `relay_revocation_propagates_via_sync_after_originator_drops` in
  `dds-node/tests/multinode.rs` pins the contract: A publishes
  revoke → B ingests via gossip → A drops → C joins fresh and
  connects only to B → C must learn the revoke via sync.
  All 5 multinode tests (including the 4 pre-existing) pass.

Previous verification note (2026-04-13, macOS ARM64):

- `dotnet test` for `platform/macos/DdsPolicyAgent.Tests` — **17/17 pass** (state store, worker, enforcers, real plutil, launchd, profile, software)
- `platform/macos/e2e/smoke-test.sh` — **6/6 pass** (single-machine e2e: domain init → node start → device enroll → gossip publish → agent poll → preference enforcement validated)
- `make pkg` in `platform/macos/packaging/` — **builds clean**, `DDS-Platform-macOS-0.1.0-arm64.pkg` (Rust + .NET + LaunchDaemons + scripts)
- Real-host validation: `plutil` plist round-trip, `dscl` user lookup, `id -Gn` admin check, `pwpolicy` auth status, `launchctl` availability, `profiles` command — all confirmed working
- Focused verification after enterprise account/SSO schema addition: `~/.cargo/bin/cargo test -p dds-domain` — **53/53 pass** (33 unit + 20 integration)

## Crate Status

| Crate | Design Ref | Status | Tests | Summary |
|---|---|---|---|---|
| **dds-core** | §3–§9 | 🟢 Done | 114 | Crypto, identity, tokens (extensible body), CRDTs, trust graph, policy engine |
| **dds-domain** | §14 | 🟢 Done | 33+20 integ | 9 typed domain documents + Stage 1 domain identity + FIDO2 attestation+assertion (Ed25519 + P-256) + macOS account/SSO bindings |
| **dds-store** | §6 | 🟢 Done | 21 | Storage traits, MemoryBackend, RedbBackend (ACID), audit log retention |
| **dds-net** | §5 | 🟢 Done | 19 | libp2p transport, gossipsub, Kademlia, mDNS, delta-sync |
| **dds-node** | §12 | 🟢 Done | 56+15 integ | Config, P2P event loop, local authority service, HTTP API (incl. audit query), encrypted persistent identity, CP+FIDO2 E2E |
| **dds-domain** (fido2) | §14 | 🟢 Done | (incl. above) | WebAuthn attestation + assertion parser/verifier (Ed25519 + P-256) |
| **dds-ffi** | §14.2–14.3 | 🟢 Done | 12 | C ABI (cdylib): identity, token, policy, version |
| **dds-cli** | §12 | 🟢 Done | 16 | Full HTTP-surface coverage + air-gapped `export`/`import` (one-file CBOR .ddsdump) |

## Module Detail — dds-core

| Module | §Ref | Tests | Key Types |
|---|---|---|---|
| `crypto::classical` | §13.1 | 5 | `Ed25519Only`, `verify_ed25519()` |
| `crypto::hybrid` | §13.1+ | 7 | `HybridEdMldsa`, `verify_hybrid()` |
| `crypto::traits` | — | — | `SchemeId`, `PublicKeyBundle`, `SignatureBundle`, `verify()` |
| `identity` | §3 | 12 | `VouchsafeId`, `Identity` |
| `token` | §4 | 15 | `Token`, `TokenPayload` (with extensible `body_type`+`body_cbor`), `TokenKind` |
| `crdt::lww_register` | §5.1 | 11 | `LwwRegister<T>` |
| `crdt::twop_set` | §5.2 | 13 | `TwoPSet<T>` |
| `crdt::causal_dag` | §5.3 | 17 | `CausalDag`, `Operation` |
| `trust` | §6 | 14 | `TrustGraph`, `validate_chain()`, `purposes_for()` |
| `policy` | §7 | 12 | `PolicyEngine`, `PolicyRule`, `PolicyDecision` |
| integration tests | — | 5 | Full trust lifecycle, policy E2E, store roundtrip, two-node sync, hybrid PQ |

## Module Detail — dds-domain

| Document | `body_type` | Tests | Purpose |
|---|---|---|---|
| `UserAuthAttestation` | `dds:user-auth-attestation` | 2 | FIDO2/passkey user enrollment |
| `DeviceJoinDocument` | `dds:device-join` | 2 | Device enrollment + TPM attestation |
| `WindowsPolicyDocument` | `dds:windows-policy` | 1 | GPO-equivalent policy (scope, settings, enforcement) |
| `MacOsPolicyDocument` | `dds:macos-policy` | 2 | macOS managed-device policy (preferences, accounts, launchd, profiles) |
| `MacAccountBindingDocument` | `dds:macos-account-binding` | 2 | Bind DDS subject + device to the macOS local account that hosts the session |
| `SsoIdentityLinkDocument` | `dds:sso-identity-link` | 2 | Link enterprise IdP identity to a DDS subject without replacing DDS authorization |
| `SoftwareAssignment` | `dds:software-assignment` | 1 | App/package deployment manifests |
| `ServicePrincipalDocument` | `dds:service-principal` | 1 | Machine/service identity registration |
| `SessionDocument` | `dds:session` | 2 | Short-lived auth session (< 1 ms local check) |
| Cross-type safety | — | 2 | Wrong type → None, no body → None |

All documents implement `DomainDocument` trait: `embed()` / `extract()` from `TokenPayload`.

## Module Detail — dds-store

| Module | Tests | Key Types |
|---|---|---|
| `traits` | — | `TokenStore`, `RevocationStore`, `OperationStore`, `AuditStore`, `DirectoryStore` |
| `memory_backend` | 10 | `MemoryBackend` (in-process, for tests and embedded) |
| `redb_backend` | 11 | `RedbBackend` (ACID persistent, zero-copy) |

## Module Detail — dds-net

| Module | Tests | Key Types |
|---|---|---|
| `transport` | 3 | `DdsBehaviour`, `SwarmConfig` (per-domain protocols), `build_swarm()` |
| `gossip` | 8 | `DdsTopic`, `DdsTopicSet`, `GossipMessage` (per-domain topics) |
| `discovery` | 3 | `add_bootstrap_peer()`, `parse_peer_multiaddr()` |
| `sync` | 9 | `StateSummary`, `SyncMessage`, `apply_sync_payloads()` |

## Module Detail — dds-node

| Module | Tests | Key Types |
|---|---|---|
| `config` | 9 | `NodeConfig`, `NetworkConfig`, `DomainConfig` (TOML, domain section required, delegation depth + audit retention) |
| `node` | 0 | `DdsNode` — swarm event loop, gossip/sync ingestion, admission cert verification at startup |
| `service` | 6 | `LocalService` — enrollment (with FIDO2 verification), sessions (assertion-based with RP-ID binding), enrolled-user enumeration, admin setup (auto-persists trusted\_roots to TOML config), admin vouch (server-side Ed25519 signing), policy resolution, status |
| `http` | 9 | `axum` router exposing `LocalService` over `/v1/*` JSON endpoints (incl. `/v1/session/assert`, `/v1/enrolled-users`, `/v1/admin/setup`, `/v1/admin/vouch`); unauthenticated `/v1/session` removed |
| `identity_store` | 3 | Encrypted-at-rest persistent node identity (Argon2id + ChaCha20Poly1305) |
| `p2p_identity` | 2 | Persistent libp2p keypair so `PeerId` is stable across restarts |
| `domain_store` | 5 | TOML public domain file + CBOR domain key + CBOR admission cert load/save |
| `cp_fido_e2e` (integration) | 3 | Full CP+FIDO2 lifecycle: enroll device/user, list users, Ed25519+P-256 assertion, session token, negative cases |
| `http_binary_e2e` (integration) | 2 | Real dds-node binary: HTTP API, gossip convergence, revocation propagation |
| `multinode` (integration) | 4 | 3-node cluster: attestation/revocation propagation, DAG convergence, sync-on-rejoin |
| `service_tests` (integration) | 6 | Enrollment, sessions, policy, node status |

## Module Detail — dds-ffi (C ABI)

| Export | Purpose | Signature |
|---|---|---|
| `dds_identity_create` | Classical Ed25519 identity | `(label, out) → i32` |
| `dds_identity_create_hybrid` | Hybrid Ed25519+ML-DSA-65 | `(label, out) → i32` |
| `dds_identity_parse_urn` | Parse/validate URN | `(urn, out) → i32` |
| `dds_token_create_attest` | Sign attestation token | `(json, out) → i32` |
| `dds_token_validate` | Validate token from CBOR hex | `(hex, out) → i32` |
| `dds_policy_evaluate` | Policy decision with trust graph | `(json, out) → i32` |
| `dds_version` | Library version | `(out) → i32` |
| `dds_free_string` | Free returned strings | `(ptr) → void` |

## Module Detail — dds-cli

Global flags: `--data-dir <dir>` (local store), `--node-url <url>` (dds-node HTTP API, default `http://127.0.0.1:5551`).

| Subcommand | Tests | What It Does |
|---|---|---|
| `identity create [--hybrid]` | 2 | Generate classical or hybrid PQ identity |
| `identity show <urn>` | 2 | Parse and display URN components |
| `group vouch` | 2 | Create vouch token, persist to store |
| `group revoke` | 1 | Revoke a vouch by JTI |
| `policy check [--remote]` | 1 | Offline policy evaluation (or `/v1/policy/evaluate`) |
| `status [--remote]` | 1 | Local store stats (or `/v1/status`) |
| `enroll user` / `enroll device` | help | `POST /v1/enroll/user`, `POST /v1/enroll/device` |
| `admin setup` / `admin vouch` | help | `POST /v1/admin/setup`, `POST /v1/admin/vouch` |
| `audit list [--action] [--limit]` | help+fail | `GET /v1/audit/entries` |
| `platform windows policies\|software\|applied\|claim-account` | help | Wraps all four `/v1/windows/*` endpoints |
| `platform macos policies\|software\|applied` | help | Wraps `/v1/macos/*` endpoints |
| `cp enrolled-users` / `cp session-assert` | — | `GET /v1/enrolled-users`, `POST /v1/session/assert` |
| `debug ping` / `debug stats` | help+fail | Reachability check / full `NodeStatus` dump |
| `debug config <file>` | 2 | Parse/validate a dds-node `config.toml` offline |
| `export --out <file>` | 1 | Package local store (tokens + CRDT ops + revocations) as one CBOR `.ddsdump` file for air-gapped sync |
| `import --in <file> [--dry-run]` | 2 | Idempotent merge of a `.ddsdump` into the local store; domain-id guarded |

## Platform Integrations

| Platform | Language | Mechanism | Wrapper | Tests | Verified |
|---|---|---|---|---|---|
| **Any** | C | Header | `bindings/c/dds.h` | — | ✅ |
| **Linux/macOS** | Python | ctypes | `bindings/python/dds.py` | 13 pytest | ✅ Runs against .dylib |
| **Windows** | C# | P/Invoke | `bindings/csharp/DDS.cs` | 11 NUnit | Written |
| **Android** | Kotlin | JNA | `bindings/kotlin/.../DDS.kt` | 10 JUnit5 | Written |
| **iOS/macOS** | Swift | C module | `bindings/swift/.../DDS.swift` | 10 XCTest | Written |

### Managed Platform Agents

| Platform | Path | Status | Verified | Notes |
|---|---|---|---|---|
| **Windows** | `platform/windows/` | 🟢 **Login verified** | ✅ 298 Rust + 56 .NET + 47 C++ + 3 E2E | Native CP DLL + Auth Bridge + Tray Agent + Policy Agent all build + test on Win11 ARM64; **FIDO2 passwordless lock screen login re-verified after security hardening merge (2026-04-13)**; security fixes: credential_id-based vault lookup, RP-ID binding, removed unauth session endpoint; WebAuthn hmac-secret two-phase challenge/response verified with real authenticator |
| **macOS** | `platform/macos/` | 🟢 **Smoke verified** | ✅ .NET build + 17 tests + smoke e2e | `DdsPolicyAgent.MacOS` worker with 5 host-backed enforcers, `.pkg` installer, single-command smoke test passing (6/6 checks), preference + launchd + account backends validated on real macOS ARM64 hardware; enterprise account/SSO coexistence is now modeled in `dds-domain`, while login-window/FileVault integration remains future `DdsLoginBridge` work |
| **Linux** | `platform/linux/` | ⚪ Planned | n/a | Design-only at this point; no agent code in tree yet |

## Cryptography

| Algorithm | Purpose | Crate | Key | Sig |
|---|---|---|---|---|
| Ed25519 | Classical signatures | ed25519-dalek 2.2 | 32 B | 64 B |
| ECDSA-P256 | FIDO2 hardware compatibility | p256 0.13 | 64 B | 64 B |
| ML-DSA-65 (FIPS 204) | Post-quantum signatures | pqcrypto-mldsa 0.1.2 | 1,952 B | 3,309 B |
| Hybrid Ed25519+ML-DSA-65 | Composite quantum-safe | both | 1,984 B | 3,373 B |
| Triple-Hybrid | Ed25519+ECDSA-P256+ML-DSA-65 | multiple | 2,048 B | 3,437 B |
| SHA-256 | ID hashing | sha2 0.10 | — | 32 B |

Feature-flagged: `pq` on by default. Hybrid signs with both; verification requires both to pass.
Classical-only available for embedded/`no_std` targets.

## FIDO2 / WebAuthn

- FIDO2 leaf identities use `Ed25519` (hardware limitation — no PQ authenticators ship yet)
- Trust roots and admins use `HybridEdMldsa65` (quantum-safe)
- Trust chain: PQ root → PQ admin → classical FIDO2 leaf
- Quantum resistance flows from the vouch chain, not the leaf authenticator
- `UserAuthAttestation` document type carries FIDO2 attestation objects inside signed tokens

## Cross-Platform Build Status

| Target | Status | Notes |
|---|---|---|
| macOS ARM64 (aarch64-apple-darwin) | ✅ Builds + tests | Dev host, 229+ Rust tests + 17 .NET |
| Linux x86\_64 | ✅ Expected to build | Standard Rust target |
| **Windows ARM64 (aarch64-pc-windows-msvc)** | ✅ **298 Rust + 56 .NET + 47 C++ tests pass** | **Win11 ARM64, MSVC 14.44 + LLVM 22.1.3, full workspace verified 2026-04-13 (post security merge)** |
| Windows x86\_64 | ✅ Expected to build (cross) | CI cross-compile gate |
| Android ARM64 (aarch64-linux-android) | 🔲 Untested | Needs cargo-ndk |
| iOS ARM64 (aarch64-apple-ios) | 🔲 Untested | Needs Xcode toolchain |
| Embedded (thumbv7em-none-eabihf) | 🔲 Untested | `no_std` core only |

## Performance Budgets (§10)

Latest results from `cargo run -p dds-loadtest --release -- --smoke`
(60 s, 3 in-process nodes, macOS aarch64 dev host).

| KPI | Target | Smoke result | Status |
|---|---|---|---|
| Local auth decision (p99) | ≤ 1 ms | 0.043 ms (max of `evaluate_policy` / `session_validate` p99) | ✅ |
| Ed25519 verify throughput | ≥ 50K ops/sec | ~46K ops/sec (p50 21.7 µs, batched 4096/sample) | ⚠️ within 10% on a busy host; criterion bench is the authority |
| CRDT merge (p99) | ≤ 0.05 ms | < 0.001 ms (`LwwRegister::merge`) | ✅ |
| Peak heap per 1K entries | ≤ 5 MB | RSS-based proxy dominated by libp2p baseline; see loadtest README | ⚠️ measurement caveat, not a regression |
| Idle gossip bandwidth | ≤ 2 KB/sec | RSS-delta proxy; libp2p does not expose per-direction byte counters | ⚠️ measurement caveat |
| Enrollment latency (informational) | n/a | enroll_user p99 0.12 ms, enroll_device p99 0.09 ms | ✅ |
| Gossip propagation (informational) | n/a | p50 ~12 ms, p99 ~102 ms across 3-node mesh | ✅ |
| dds-core binary (Cortex-M) | ≤ 512 KB | needs cross-compile | 🔲 |

Hard verdicts on the ≥ 50K ops/sec throughput KPI come from the
dedicated criterion bench (`dds-core/benches/crypto_verify.rs`); the
soak harness reports it for trend tracking and warns within 20% of the
target.

## Load Testing

`dds-loadtest` is a long-running multinode harness that drives a mixed
realistic workload (enroll/issue/evaluate/revoke) across N in-process
`DdsNode`s wired into a libp2p full-mesh and emits per-op latency
histograms plus a KPI verdict table. See [`dds-loadtest/README.md`](dds-loadtest/README.md).

```bash
# 60s smoke (CI gate, also enforces error rate ≤ 1% per op type)
cargo run -p dds-loadtest --release -- --smoke --output-dir /tmp/dds-smoke

# 24h soak
cargo run --release -p dds-loadtest -- --duration 24h --output-dir results/$(date +%Y%m%d)
```

The CI smoke job lives in `.github/workflows/loadtest-smoke.yml`.

## What's Next

All 7 crates are functionally complete. The following work is ordered by impact and dependency:

### Phase 1 — Production Hardening (high priority)

1. 🟢 **HTTP/JSON-RPC API on dds-node** — `dds-node/src/http.rs` exposes `LocalService` over a localhost axum server. Endpoints: `POST /v1/enroll/user`, `POST /v1/enroll/device`, `POST /v1/session/assert` (assertion-based session; unauthenticated `/v1/session` removed), `GET /v1/enrolled-users` (CP tile enumeration), `POST /v1/admin/setup`, `POST /v1/admin/vouch`, `POST /v1/policy/evaluate`, `GET /v1/status`, `GET /v1/windows/policies`, `GET /v1/windows/software`, `POST /v1/windows/applied`, `POST /v1/windows/claim-account` (resolve first-account claim from a freshly issued local session token), `GET /v1/macos/policies`, `GET /v1/macos/software`, `POST /v1/macos/applied`, `GET /v1/audit/entries?action=&limit=` (audit log query). JSON request/response types with serde, base64-encoded binary fields. reqwest integration tests cover both Windows and macOS applier endpoints against an in-process server.

2. 🟢 **FIDO2 attestation + assertion verification** — `dds-domain/src/fido2.rs` parses WebAuthn attestation objects with `ciborium`, supports `none` and `packed` (Ed25519 self-attestation) formats, extracts the COSE_Key credential public key, and verifies the attestation signature. Now also verifies getAssertion responses (Ed25519 + ECDSA P-256) via `verify_assertion()`, with `cose_to_credential_public_key()` for multi-algorithm key parsing. `LocalService::enroll_user` rejects enrollment whose attestation fails to verify; `issue_session_from_assertion()` verifies assertion signatures against enrolled keys. 12 unit tests cover attestation round-trips, assertion verification (both algorithms), bad signatures, COSE key parsing.

3. 🟢 **Persistent node identity** — `dds-node/src/identity_store.rs` loads or generates the node Ed25519 signing key on startup and persists it to `<data_dir>/node_key.bin` (or the new `identity_path` config field). When `DDS_NODE_PASSPHRASE` is set, the file is encrypted with ChaCha20-Poly1305 using a 32-byte key derived from the passphrase via Argon2id (19 MiB, 2 iters); otherwise the key is stored unencrypted with a warning log. Versioned CBOR on-disk format. 3 tests cover plain roundtrip, encrypted roundtrip with wrong-passphrase rejection, and load-or-create idempotency.

4. 🟢 **CI pipeline** — `.github/workflows/ci.yml` runs `cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, and the python binding pytest suite. Cross-compile jobs check `x86_64-pc-windows-gnu` (mingw-w64), `aarch64-linux-android` (cargo-ndk + setup-ndk), and `thumbv7em-none-eabihf` (`dds-core --no-default-features` smoke).

9\. 🟢 **Domain identity (Stage 1 — software domain key)** — `dds-domain/src/domain.rs` introduces `Domain`, `DomainId` (`dds-dom:<base32(sha256(pubkey))>`), `DomainKey` (Ed25519), `AdmissionCert` (domain key signs `(domain_id, peer_id, issued_at, expires_at)`), and a `DomainSigner` trait that Stage 2 will reimplement against a FIDO2 authenticator without touching call sites. `dds-net` bakes the domain tag into libp2p protocol strings (`/dds/kad/1.0.0/<tag>`, `/dds/id/1.0.0/<tag>`) and into gossipsub topics (`/dds/v1/dom/<tag>/org/<org>/...`), so nodes from different domains cannot complete a libp2p handshake. `dds-node`'s `NodeConfig` requires a `[domain]` section and refuses to start without a valid admission cert at `<data_dir>/admission.cbor` matching its libp2p `PeerId`. Persistent libp2p keypair (`p2p_key.bin`) is now loaded/generated by `dds-node/src/p2p_identity.rs` (encrypted at rest via `DDS_NODE_PASSPHRASE`) so the peer id is stable across restarts. New CLI subcommands: `init-domain`, `gen-node-key`, `admit`, `run` (no clap dep — hand-rolled flag parsing). Domain key on disk is encrypted with `DDS_DOMAIN_PASSPHRASE` (Argon2id + ChaCha20-Poly1305). 14+ new unit tests covering id roundtrip, cert sign/verify/tamper/expiry, domain/key TOML+CBOR roundtrips, protocol-string isolation, and stable peer id across restart.

### Phase 2 — Operational Readiness

5. 🟢 **Performance benchmarks** — criterion benches for Ed25519 verify, hybrid verify, CRDT merge (causal_dag insert + lww_register merge), policy evaluation, and SessionDocument issue+validate. Benches live under `dds-core/benches/` (`crypto_verify.rs`, `crdt_merge.rs`, `policy_eval.rs`) and `dds-node/benches/` (`session_lifecycle.rs`). CI runs `cargo bench --workspace --no-run` as a compile-check job; numbers are not yet wired as regression gates and dhat heap profiling is deferred.

6. 🟢 **Multi-node integration tests** — `dds-node/tests/multinode.rs` spins up 3 in-process `DdsNode` instances on ephemeral TCP ports, dials them into a star topology, lets the gossipsub mesh form, and verifies (a) attestation operation propagation, (b) revocation propagation, (c) DAG convergence after a node is dropped and a fresh node rejoins. Uses a multi-thread tokio runtime and `select_all` to drive every swarm concurrently.

7. 🟢 **Windows Credential Provider (native C++)** — Production-grade Credential Provider forked from the Crayonic CP codebase and integrated with DDS. See [Crayonic CP Integration Plan](docs/crayonic-cp-integration-plan.md). Replaces the .NET stub with native C++ COM DLL + Auth Bridge service.

    **Rust side (completed):**
    - `dds-domain/src/fido2.rs`: Added `verify_assertion()` supporting both Ed25519 and ECDSA P-256 assertions, `cose_to_credential_public_key()` parser, and `build_assertion_auth_data()` test helper. 7 new tests (12 total).
    - `dds-node/src/service.rs`: Added `issue_session_from_assertion()` that looks up credential public key from trust graph, verifies the assertion, and issues a `SessionDocument`. Added `list_enrolled_users()` for CP tile enumeration.
    - `dds-node/src/http.rs`: Added `POST /v1/session/assert` (assertion-based session issuance) and `GET /v1/enrolled-users?device_urn=...` (CP user enumeration) endpoints.
    - All 225+ existing tests pass; 7 new FIDO2 assertion tests added.
    - `dds-node/src/service.rs`: `admin_setup()` now auto-persists admin URN to `trusted_roots` in the TOML config file via `toml_edit`, eliminating manual config editing. `admin_vouch()` signs vouch tokens with server-side Ed25519 keys.

    **C++ side (login verified on Windows 11 ARM64, 2026-04-13):**
    - `platform/windows/native/DdsCredentialProvider/` — COM DLL (ARM64), CLSID `{a7f3b2c1-...}`, BLE/PIV stripped, DDS auth path via Auth Bridge IPC, WebAuthn hmac-secret assertion on secure desktop
    - `platform/windows/native/DdsAuthBridge/` — Windows Service (x64) with WinHTTP client, credential vault (DPAPI + AES-256-GCM), vault password decryption via hmac-secret, first-account claim via `/v1/windows/claim-account`, local account create/reset + group application, SID resolution via `LookupAccountSid`
    - `platform/windows/native/DdsTrayAgent/` — System tray enrollment tool (x64): user enrollment (MakeCredential + hmac-secret encrypt), admin setup, admin vouch approval, WebAuthn API wrappers
    - `platform/windows/native/DdsBridgeIPC/` — Named-pipe IPC library with DDS messages (0x0060-0x007F range), TLV protocol, pack(1) structs
    - `platform/windows/native/Helpers/` — LSA packaging (KERB_INTERACTIVE_UNLOCK_LOGON), COM factory
    - `platform/windows/native/Tests/` — 3 test executables: `test_components.exe` (11 non-interactive unit tests), `test_full_flow.exe` (end-to-end with real authenticator + LsaLogonUser), `test_hmac_roundtrip.exe` (hmac-secret determinism)
    - `platform/windows/installer/DdsBundle.wxs` — WiX v4 MSI bundle for all components
    - Visual Studio 2022 solution: `DdsNative.sln` with 6 projects, all build clean

    **Build fixes applied (2026-04-12):**
    - Fixed `const wchar_t[]` to `LPWSTR`/`PWSTR` conversion errors in `common.h` and `CDdsCredential.cpp` (MSVC strict C++17)
    - Fixed include paths from renamed `CrayonicBridgeIPC` to `DdsBridgeIPC` in `DdsAuthBridgeMain.h`
    - Fixed IPC type mismatches: `IPC_RESP_AUTH_RESULT` → `IPC_RESP_DDS_AUTH_COMPLETE`, added `AUTH_CANCELLED` error code
    - Added missing linker dependencies: Secur32.lib, credui.lib, netapi32.lib, shlwapi.lib
    - Created `.cargo/config.toml` with explicit ARM64 MSVC linker path (prevents Git Bash `/usr/bin/link` shadowing)
    - Disabled pqcrypto-mldsa `neon` feature to avoid GAS-syntax `.S` assembly files incompatible with MSVC/clang-cl on Windows ARM64

    **E2E smoke test (`platform/windows/e2e/smoke_test.ps1`):**
    - 3 Rust CP+FIDO2 tests (Ed25519 full lifecycle, P-256 assertion, enrollment+assertion)
    - Native artifact verification (CP DLL COM exports, Auth Bridge launch, IPC lib, Helpers)
    - .NET Policy Agent build verification
    - All 8 checks passing

8\. 🟢 **Token expiry enforcement** — `dds-node/src/expiry.rs` provides `sweep_once()` and an async `expiry_loop()` task. `NodeConfig::expiry_scan_interval_secs` (default 60) controls the cadence. Expired tokens are removed from the trust graph via a new `TrustGraph::remove_token()` method and marked revoked in the store. Unit-tested with `tokio::time::pause()` and direct sweep calls.

### Phase 3 — Enterprise Features

9. **WindowsPolicyDocument distribution** — End-to-end flow: admin creates a policy document, signs it, gossip propagates to target devices, dds-node on each device evaluates scope + applies settings (registry keys, security policy). **Plan landed 2026-04-09 — see [Windows Policy Applier Plan](#windows-policy-applier-plan-phase-3-items-910) below. Phases A–F + I (reconciliation) complete; G–H remaining.**

10. **SoftwareAssignment workflow** — Admin publishes a software assignment, devices poll/receive via gossip, local agent downloads package, verifies SHA-256, installs silently. **Enforcement implemented (Phase F, 2026-04-13):** `SoftwareInstaller` + `WindowsSoftwareOperations` with HTTP download, SHA-256 verify, msiexec install/uninstall, registry-based detection. 7 integration tests including real MSI install/uninstall on ARM64.

11\. 🟢 **Audit log** — Append-only signed log of all trust graph mutations (attest, vouch, revoke, burn) for compliance. Each entry signed by the node that performed the action. Syncable via gossip. Opt-in feature enabled via `domain.toml` or `DomainConfig` during domain creation to minimize network overhead. **Retention**: configurable `audit_log_max_entries` (count cap) and `audit_log_retention_days` (age cap); pruning runs on the expiry sweep timer. Query endpoint: `GET /v1/audit/entries?action=&limit=`.

12\. 🟢 **ECDSA-P256 support** — Some FIDO2 authenticators only support P-256. Added as a third `SchemeId` variant with triple-hybrid option `Ed25519+ECDSA-P256+ML-DSA-65`.

13. **macOS managed-device platform** — First working slice landed on 2026-04-10. `dds-domain` now has `MacOsPolicyDocument`; `dds-node` exposes `/v1/macos/policies`, `/v1/macos/software`, and `/v1/macos/applied`; `platform/macos/DdsPolicyAgent` now builds and tests. Remaining work is listed in the macOS status section below.

14\. 🟢 **FIDO2-backed domain key** — Domain secret key can be protected by a FIDO2 hardware authenticator instead of a passphrase (`dds-node init-domain --fido2`). The key is encrypted with the authenticator's hmac-secret output; touch the key to decrypt. Feature-gated behind `--features fido2` (ctap-hid-fido2 crate). Version 3 on-disk format stores credential_id + hmac_salt alongside the encrypted key.

15\. 🟢 **Single-file node provisioning** — `dds-node provision <bundle.dds>`: one file on USB + admin's FIDO2 key + one command + one touch = node admitted, configured, started, and enrolled. The `.dds` bundle contains domain config + encrypted domain key. The provisioning command decrypts the domain key in memory (FIDO2 touch), signs an admission cert, writes config, starts the node, enrolls the device. Domain key is zeroed after use — never written to disk on new machines. `dds-node create-provision-bundle` creates the bundle from an existing domain directory.

16\. 🟢 **macOS installer package** — `platform/macos/packaging/Makefile` produces a `.pkg` installer (Rust binaries + self-contained .NET agent + LaunchDaemons + config templates). Bootstrap scripts: `dds-bootstrap-domain` (creates domain, starts node, enrolls device), `dds-enroll-admin` (enrolls FIDO2 admin user), `dds-admit-node` (issues admission certs). All scripts support FIDO2 domain key protection.

17\. 🟢 **dds-fido2-test** — Interactive FIDO2 enrollment + authentication test tool. Tests the full hardware flow: USB key → makeCredential → dds-node enroll → getAssertion → dds-node session. Works on macOS and Windows with any FIDO2 USB key.

18. **macOS enterprise login / Platform SSO roadmap** — DDS should not try to replace `loginwindow` directly. The supported path is to evolve from the current post-login coexistence model into an Apple-approved Platform SSO integration: first coexist with directory / IdP-owned login, then implement Platform SSO password mode, then add Secure Enclave backed passwordless flows where Apple allows them. Detailed tasks are tracked in the macOS roadmap section below.

### Windows Policy Applier Plan (Phase 3 items 9–10)

Items 9 and 10 above split into *distribution* (already solved by gossip + the
existing trust graph) plus *enforcement* (not solved — `dds-node` is a pure
directory service and never calls Win32). Enforcement is delivered as a new
Windows Service running alongside `dds-node` on the managed device.

#### Architecture

A new **`DdsPolicyAgent`** Windows Service (.NET 8 worker, `LocalSystem`)
polls `dds-node`'s loopback HTTP API once a minute for `WindowsPolicyDocument`
and `SoftwareAssignment` documents scoped to *this* device, then applies them
via four pluggable enforcers: **Registry / Account / PasswordPolicy /
SoftwareInstall**. State is persisted under `%ProgramData%\DDS\applied-state.json`
for idempotency, and outcomes are reported back to `dds-node` for audit. The
agent ships in the same WiX MSI bundle as `dds-node.exe` and the existing
`DdsCredentialProvider`, so installing one binary brings up the full Windows
integration.

`dds-node` itself stays a pure directory service — only the agent is
Windows-specific. The same `dds-node` binary continues to run unchanged on
macOS/Linux/embedded.

#### v1 scope decisions (locked 2026-04-09)

| Decision | Choice | Reason |
| --- | --- | --- |
| Service identity | `LocalSystem` | Required for HKLM writes + local account creation |
| Domain-joined machines | Out of scope v1 — refuse + log | AD-replacement is a Phase 4 conversation |
| Packaging | Single WiX MSI bundle (node + agent + credprov) | One install resolves B1 atomically |
| Pre/post install scripts | Trust on document signature | Authenticode-script PKI deferred |
| `WindowsSettings` typed bundle | **Alongside** existing `Vec<PolicySetting>` | Don't break existing tests; free-form list is the escape hatch |
| OS floor | Windows 10 1809+ | Pilot target |
| Secrets / passwords | DPAPI-local random; `SecretReleaseDocument` deferred to v2 | No on-the-wire plaintext |
| Propagation cadence | Poll `/v1/windows/*` every 60 s | GPO-class change cadence; SSE deferred |

#### Component layout

```text
platform/windows/
├── DdsCredentialProvider/        # exists — logon, untouched
├── DdsPolicyAgent/               # worker service (Phases A–F ✅)
│   ├── Worker.cs                 # poll loop, dispatch
│   ├── Client/DdsNodeClient.cs   # GET /v1/windows/* + POST /v1/windows/applied
│   ├── State/AppliedStateStore.cs# %ProgramData%\DDS\applied-state.json
│   └── Enforcers/
│       ├── RegistryEnforcer.cs       # ✅ Microsoft.Win32.Registry, allowlisted hives
│       ├── AccountEnforcer.cs        # ✅ netapi32 P/Invoke, refuse on domain-joined
│       ├── PasswordPolicyEnforcer.cs # ✅ NetUserModalsGet/Set + secedit
│       ├── SoftwareInstaller.cs      # ✅ msiexec + HTTP download + SHA-256
│       ├── WindowsRegistryOperations.cs      # Win32 impl
│       ├── WindowsAccountOperations.cs       # netapi32 impl
│       ├── WindowsPasswordPolicyOperations.cs# netapi32+secedit impl
│       └── WindowsSoftwareOperations.cs      # msiexec+HttpClient impl
└── installer/                    # NEW — WiX v4 MSI bundle (signed)
```

Rust side (smaller surface):

```text
dds-domain/src/types.rs            # add WindowsSettings typed bundle
dds-node/src/service.rs            # list_applicable_windows_policies(device_urn)
dds-node/src/http.rs               # GET /v1/windows/policies, /v1/windows/software,
                                   #     POST /v1/windows/applied
```

#### Domain-type extension

`WindowsPolicyDocument` gains an optional `windows: Option<WindowsSettings>`
field. The existing `settings: Vec<PolicySetting>` stays as the forward-compat
escape hatch. `WindowsSettings` carries:

- `registry: Vec<RegistryDirective>`  — hive, key, name, kind, value, action
- `local_accounts: Vec<AccountDirective>` — name, action, full_name, groups
- `password_policy: Option<PasswordPolicy>` — min_len, complexity, lockout
- `services: Vec<ServiceDirective>` — name, start_type, action

`SoftwareAssignment` is already typed enough — kept as-is for v1.

#### `dds-node` API additions

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/windows/policies?device_urn=...` | List `WindowsPolicyDocument` tokens whose `scope` matches the given device URN |
| `GET` | `/v1/windows/software?device_urn=...` | Same for `SoftwareAssignment` |
| `POST` | `/v1/windows/applied` | Agent reports per-directive outcome → audit log |

The agent trusts dds-node's pre-filtered list — both run as different
identities on the same loopback, and dds-node already verifies signatures
against `trusted_roots` on ingest. This avoids embedding `dds-ffi` in the
agent.

#### Phasing

| Phase | Scope | Exit criteria | Status |
| --- | --- | --- | --- |
| **A** | Extend `WindowsPolicyDocument` with `WindowsSettings` typed bundle | `cargo test -p dds-domain` green; existing tests untouched | ✅ |
| **B** | Three new `dds-node` HTTP endpoints + `LocalService::list_applicable_*` | reqwest tests in `dds-node/src/http.rs` cover scope matching + audit POST | ✅ |
| **C** | `DdsPolicyAgent` skeleton: Worker host, config, `DdsNodeClient`, `AppliedStateStore`, log-only | `dotnet test` green for state-store + client | ✅ |
| **D** | `RegistryEnforcer` + first end-to-end on Windows | 15 integration tests (HKCU + HKLM) on ARM64 | ✅ |
| **E** | `AccountEnforcer` (refuse on domain-joined) + `PasswordPolicyEnforcer` | 11 account + 6 password policy integration tests on ARM64 | ✅ |
| **F** | `SoftwareInstaller` for MSI → EXE; SHA-256 verify; uninstall lookup | 7 integration tests: install/uninstall test MSI, HTTP download + SHA-256 | ✅ |
| **G** | WiX bundle, Authenticode signing scaffolding, service registration. **Resolves B1.** | MSI builds in CI; manual install brings up both services | ✅ |
| **H** | `windows-latest` CI job runs the full integration suite. **Resolves B2 for Windows.** | CI green end-to-end | ✅ |
| **I** | Reconciliation & drift detection: managed-items tracking in state store, stale-item cleanup (registry delete, account disable, group removal, software uninstall), audit-mode support. 18 new unit tests. | `dotnet test` green; stale items cleaned up within one poll cycle | ✅ |

A–I complete (2026-04-13). G+H landed 2026-04-13: WiX v4 MSI installer verified on ARM64 (30.9 MB, all 5 components + service registration + COM registration + config templates), Authenticode signing scaffolding in CI (conditional on `SIGN_CERT_BASE64` secret), MSI validation + SHA-256 checksums in release workflow, CI `windows-native` job enhanced with .NET 8.0+9.0 dual testing, MSI compile verification, and E2E smoke test.

### macOS Managed Device Status (2026-04-13)

Completed:

- `dds-domain` gained `MacOsPolicyDocument` (`dds:macos-policy`) plus typed `MacOsSettings` directives for preferences, local accounts, launchd jobs, and configuration profiles.
- `dds-node/src/service.rs` now exposes `list_applicable_macos_policies()` using the same scope semantics as Windows policy distribution.
- `dds-node/src/http.rs` now exposes `GET /v1/macos/policies`, `GET /v1/macos/software`, and `POST /v1/macos/applied`.
- Rust tests were added for macOS document round-trip, service scope matching, typed-bundle round-trip, and HTTP endpoint coverage.
- `platform/macos/DdsPolicyAgent/` landed as a .NET worker with config binding, `dds-node` HTTP client, applied-state persistence, worker poll loop, and a launchd plist template.
- `Program.cs` now registers host-backed macOS backends by default through a shared command runner instead of the previous in-memory DI registrations.
- Managed preferences now persist real plist state through `plutil`; launchd now persists label-to-plist bindings and drives `launchctl`; profiles now use `profiles`; software install/update now uses hash-checked package staging with `pkgutil` + `installer`; local account operations now target `dscl` / `pwpolicy` / `dseditgroup` / `sysadminctl`.
- `platform/macos/README.md` and `platform/macos/appsettings.e2e.sample.json` now document a staged macOS end-to-end path with temp-rooted preferences/launchd/package cache directories.
- `dds-node/src/bin/dds-macos-e2e.rs` now provides a real two-machine macOS harness: live policy/software publish into the DDS mesh, local summary collection, and merged result comparison.
- `platform/macos/e2e/` now contains runbook and wrapper scripts for machine init, node config generation, package staging, device enrollment, agent startup, result collection, result comparison, and cleanup.
- `platform/macos/DdsPolicyAgent.Tests/` now has 17 passing .NET tests covering state-store behavior, worker startup guardrails, in-memory enforcers, real plist round-trips, and command-backed launchd/profile/software flows.
- `ABCD.sln` now includes the macOS policy-agent projects.

Verified on real hardware (2026-04-13, macOS ARM64):

- **Single-machine smoke test added and passing** (`platform/macos/e2e/smoke-test.sh`): one-command harness that inits a domain, starts a `dds-node`, enrolls a device, publishes a macOS policy fixture via gossip, runs the .NET policy agent for one poll cycle, and validates 6 enforcement checks (applied state, preference write, launchd binding, software recording, node health). 6/6 checks pass.
- **Preference backend validated on real host**: `plutil` round-trip of binary plist values (string, int, bool, array) works correctly. The smoke test confirms `FleetMessage = "smoke-test-pass"` is written to a managed preference plist and read back.
- **Launchd backend validated on real host**: plist label extraction via `plutil -extract Label raw` works. Launchd state bindings are persisted to JSON. `launchctl` version `7.0.0` confirmed available. Real `bootstrap`/`bootout`/`kickstart` operations require root (tested in unit tests with `RecordingCommandRunner`).
- **Account backend (read-only) validated on real host**: `dscl . -read /Users/<user>` user lookup works, `id -Gn` admin group membership check works, `pwpolicy -u <user> -authentication-allowed` returns correct status, `dscl localhost -list /` directory-binding detection works (correctly reports not bound). Write operations (`CreateUser`, `DeleteUser`, `DisableUser`) require root and a disposable machine.
- **Profile backend validated on real host**: `/usr/bin/profiles` command available; system profile listing requires root. Profile install/remove tested via `RecordingCommandRunner` in unit tests.
- **macOS .pkg installer builds successfully**: `make pkg` in `platform/macos/packaging/` produces `DDS-Platform-macOS-0.1.0-arm64.pkg` (53 MB debug). Payload verified: Rust binaries + self-contained .NET agent + LaunchDaemon plists + bootstrap scripts + config template. Pre/post install scripts handle service stop/start and directory creation.

Still TODO:

- Run the two-machine macOS harness on two real Macs and capture the first comparison artifact as a baseline.
- Run the smoke test with `--sudo` on a disposable macOS machine to validate full enforcement (launchd bootstrap/kickstart, real package install/uninstall, account creation).
- Decide how to model safe package uninstall/remove recipes. Generic `.pkg` uninstall remains intentionally unsupported.
- Implement `DdsLoginBridge` / Authorization Services integration for post-login privileged workflows. Full loginwindow / FileVault replacement is still explicitly out of scope.
- Sign and notarize the `.pkg` with an Apple Developer ID; validate install/upgrade/uninstall flows on a fresh Mac.
- Decide whether Linux should share a common policy-agent core library with macOS/Windows or remain as three mostly separate worker implementations.
- ~~Investigate and stabilize the unrelated `dds-node` multinode failures~~ — **Resolved 2026-04-13**: `dag_converges_after_partition` and `rejoined_node_catches_up_via_sync_protocol` now pass on Windows ARM64 (see verification note above).

### macOS Enterprise Login Roadmap (Phase 3 item 18)

Goal: make DDS work on macOS the way Entra works today, but through the
Apple-supported identity path rather than by trying to replace the macOS login
stack directly.

Guardrails:

- DDS remains the trust graph and local authorization source.
- macOS still has a real local account underneath login, home folder ownership,
  Secure Token, and FileVault.
- The implementation path is `coexistence -> Platform SSO password mode ->
  Secure Enclave / passwordless mode`, not "raw FIDO2 key unlocks the desktop".
- Full custom replacement of `loginwindow` or FileVault pre-boot auth remains
  out of scope unless Apple exposes a safe, supported API surface for it.

#### Milestone M18.1 — v1.5 Coexistence On Enterprise Macs

Target outcome: DDS works cleanly on Macs where AD / Open Directory / LDAP /
Entra Platform SSO / Okta already owns login.

- [ ] Add macOS host classification in the platform agent / future login bridge:
  `Standalone`, `DirectoryBound`, `PlatformSsoManaged`, `Unknown`
- [ ] Use that classification consistently to refuse DDS-owned `local_accounts`
  mutation on non-standalone Macs
- [ ] Add node/API support to publish and query `MacAccountBindingDocument`
  and `SsoIdentityLinkDocument`
- [ ] Define the admin issuance flow for those documents: subject mapping,
  device scoping, conflict detection, revocation/update semantics
- [ ] Add local reporting so a managed Mac can tell `dds-node` which macOS
  account signed in and which external identity source owns it
- [ ] Document operator guidance for:
  - standalone DDS-managed Macs
  - directory-bound Macs
  - Platform SSO-managed Macs
- [ ] Add tests covering:
  - directory-bound host classification
  - Platform SSO-managed host classification
  - skipped account mutation on externally managed Macs
  - binding/link document round-trip through HTTP

Exit criteria:

- DDS-managed local account mutation is impossible on externally managed Macs.
- Operators can bind DDS subjects to enterprise-managed macOS accounts without
  promising DDS desktop login yet.

#### Milestone M18.2 — v2 DDS Platform SSO Password Mode

Target outcome: DDS can participate in macOS desktop sign-in through an
Apple-approved Platform SSO extension using password-based login semantics.

- [ ] Create `platform/macos/DdsPlatformSsoExtension/` as the new identity
  integration component
- [ ] Stand up the required macOS app / extension packaging structure so the
  Platform SSO extension can be deployed by MDM
- [ ] Implement DDS-backed identity lookup:
  - external principal -> `SsoIdentityLinkDocument`
  - linked DDS subject -> policy / group / purpose resolution
  - device -> `MacAccountBindingDocument`
- [ ] Implement account binding behavior for first login:
  - create local account if policy allows
  - or attach to an existing local account
  - persist the resulting binding document
- [ ] Implement session bootstrap after successful Platform SSO sign-in:
  - extension obtains DDS proof
  - `dds-node` issues `SessionDocument`
  - local apps / follow-on authorization can use DDS session state
- [ ] Add MDM deployment artifacts and configuration profile templates for the
  Platform SSO extension
- [ ] Add a test harness for:
  - principal mapping
  - first-login account creation/binding logic
  - password sync / password change event handling
  - session issuance after sign-in
- [ ] Validate on a real MDM-managed macOS host

Exit criteria:

- A user can sign in to macOS through DDS-backed Platform SSO password mode.
- The Mac still has a normal local account underneath, but DDS now participates
  in the supported desktop login path.

#### Milestone M18.3 — v3 Secure Enclave / Passwordless Mode

Target outcome: DDS offers the best macOS sign-in UX Apple allows, using Secure
Enclave / platform credential style flows instead of direct password entry.

- [ ] Extend the Platform SSO implementation to support Secure Enclave-backed
  credential mode where the platform permits it
- [ ] Define how DDS proof material binds to:
  - local Secure Enclave state
  - DDS subject identity
  - device identity
- [ ] Decide whether DDS FIDO2 enrollment and macOS platform credentials should
  share one identity link or remain separate linked authenticators
- [ ] Implement recovery / rebind flows for:
  - motherboard replacement / Secure Enclave reset
  - lost hardware key
  - account re-association on reprovisioned Macs
- [ ] Test reboot, unlock, password change, account recovery, and FileVault
  interaction behavior on real hardware
- [ ] Document the exact limits clearly: what is true desktop passwordless,
  what still falls back to local password, and what remains Apple-controlled

Exit criteria:

- DDS supports the strongest Apple-supported passwordless macOS login path
  available.
- Recovery and operational failure modes are understood well enough for pilot
  deployment.

#### Milestone M18.4 — Deferred / Explicit Non-Goals

- [ ] Do not attempt unsupported replacement of `loginwindow`
- [ ] Do not attempt custom FileVault pre-boot authentication replacement
- [ ] Do not promise plain FIDO2 security-key desktop login unless Apple exposes
  a supportable path for it
- [ ] Do not couple DDS authorization semantics to any one IdP vendor; DDS
  remains the authorization system even when Entra/Okta/etc. provides login UX

## Path to Production

Overall: **~98% ready for a scoped pilot.** All 8 crates are functionally
complete, security-critical hardening (Phase 1) is done, the three
algorithmic / sync blockers the chaos soak found (B5, B5b, B6) are fixed
and validated, and the two platform blockers (B1, B2) are now resolved
with full Windows ARM64 FIDO2 passwordless login verified end-to-end on real hardware (2026-04-13).
All four Windows policy enforcers (Registry, Account, PasswordPolicy, Software)
are now production-implemented with 39 Win32 integration tests passing on ARM64 (2026-04-13).
WiX installer packaging and Windows service registration are now complete.
Remaining gaps are *Authenticode code signing* (scaffolding in CI, needs certificate)
and *operational instrumentation*.

### Production Blockers

#### Open 🔴

None. All production blockers resolved.

#### Resolved ✅

| # | Gap | Resolution |
| --- | --- | --- |
| **B1** | **Windows Credential Provider stubbed** | Resolved 2026-04-13: **FIDO2 passwordless Windows login verified end-to-end on real hardware.** Full flow: admin setup (FIDO2 key → trusted root, auto-persisted to config) → user enrollment (MakeCredential + hmac-secret encrypt password → DPAPI vault) → admin vouch → lock screen tile → touch key → hmac-secret decrypt → KERB_INTERACTIVE_LOGON → Windows session. The current tree also adds a first-account-claim path for policy-bound local accounts: after `/v1/session/assert`, the native Auth Bridge can call `/v1/windows/claim-account`, generate a random local password, create/reset the Windows account, and seed the vault without putting a password in policy. Tested on Win11 ARM64 VM with real YubiKey. Re-verified after merging 6 security hardening commits (credential_id-based vault lookup, RP-ID binding enforcement, removed unauthenticated session endpoint, HTTP API contract alignment). Clean wipe + fresh enrollment confirms the merged code works end-to-end. C++ test suite validates AES-GCM, vault serialization, KERB packing, IPC struct layout, LsaLogonUser, and full pipeline with real authenticator (13 tests across 3 executables). Critical fix: WebAuthn `GetAssertion` options must match exactly between enrollment (tray agent, x64) and login (credential provider, ARM64) for hmac-secret determinism. Remaining for production: WiX installer, Windows service registration, code signing. |
| **B2** | **Cross-platform builds untested** | Resolved 2026-04-12 for Windows: `cargo build --workspace` + `cargo test --workspace` — 309/309 Rust tests pass on Windows 11 ARM64 (aarch64-pc-windows-msvc). `dotnet build` + `dotnet test` — 78/78 .NET unit tests pass (117 total with integration). Native C++ solution — 4/4 projects build. Android, iOS, embedded remain 🔲 but are not in pilot scope. |
| B3 | **24h soak result missing** | Resolved by the 2026-04-09 30-min chaos validation soak (`b6-validation-20260409-210025`): 0 errors / 466K ops, all 5 hard §10 KPIs PASS, 14/14 chaos rejoins succeeded. A 24h endurance run is still nice-to-have for long-tail evidence but is no longer load-bearing for §10 sign-off. |
| B4 | **Ed25519 throughput unverified** | Resolved: 53,975 ops/sec measured in the validation soak (above the 50K target). Heap/bandwidth caveats remain (R5 below) but they are *measurement* gaps, not perf gaps. |
| **B5** | **Trust graph queries O(V) in vouch count** — `purposes_for` and `walk_chain` linearly scanned every vouch on every call. Broken soak measured `evaluate_policy` p99 climbing 0.5 → 10.8 ms as the graph grew to 14K tokens. | Fixed in [dds-core/src/trust.rs](dds-core/src/trust.rs): added `vouches_by_subject` and `attestations_by_iss` secondary indices, routed all hot paths through them. Unit test `test_purposes_for_scales_to_10k_vouches` measured 3.2 µs worst-case at 10K vouches (vs 10.8 ms broken — **3,400× speedup**). Validation soak: flat 5 µs across 4K tokens / 30 min. |
| **B5b** | **Trust graph rebuilt from store on every query** — `LocalService::trust_graph_snapshot` re-read every store token + re-verified every signature on every `evaluate_policy` and `issue_session` call. Hidden by B5 in the broken soak; surfaced once B5 was fixed. | Fixed by making `DdsNode::trust_graph` and `LocalService::trust_graph` a shared `Arc<RwLock<TrustGraph>>`, dropping the per-query rebuild, and rehydrating from the store once at `LocalService::new`. Resolved a multi-writer regression in the http_binary_e2e test. |
| **B6** | **No anti-entropy / catch-up sync wired into the swarm** — gossipsub delivers only live messages, so a node offline for any window permanently lost every op published during that window. Broken soak: 16 of 29 chaos rejoins timed out at 5 min. | Fixed in [dds-net/src/transport.rs](dds-net/src/transport.rs) and [dds-node/src/node.rs](dds-node/src/node.rs): added a libp2p `request_response::cbor::Behaviour<SyncRequest, SyncResponse>` over a domain-namespaced `/dds/sync/1.0.0/<tag>` protocol. Triggered on `ConnectionEstablished` (catches fresh rejoins) plus a 60-second periodic anti-entropy timer (catches steady-state drift). Regression test `rejoined_node_catches_up_via_sync_protocol` proves a fresh node converges to existing peers' state with **no further publishes after join**. Validation soak: **14/14 chaos rejoins succeeded, 0 timeouts.** |

### Soak Findings (2026-04-09, 2h 38m run, aborted)

Run dir: `loadtest-results/soak-20260409-140730/` — chaos enabled (5 nodes,
1 of 5 paused every ~5 min for ~60s, max 1 offline at a time). 1.24M ops,
16 errors. Aborted early because two production blockers became visible
within the first hour.

| Metric | Smoke (90s) | Soak (158m) | Verdict |
| --- | --- | --- | --- |
| `evaluate_policy` p99 | 0.300 ms | **10.805 ms** | ❌ FAIL §10 ≤ 1 ms |
| `issue_session` p99 | 0.377 ms | **10.846 ms** | ❌ FAIL §10 ≤ 1 ms |
| `session_validate` p99 | 0.033 ms | 0.048 ms | ✅ |
| `ed25519_verify` ops/s | 54,972 | 54,972 | ✅ resolves B4 throughput |
| `gossip_propagation` p99 | 104 ms | **577 sec** (9.6 min) | ❌ |
| `rejoin_convergence` | 3/3 ok | **13/29 ok, 16 timeouts** | ❌ |
| Trust graph tokens | 82 | **14,407** (still growing linearly) | ⚠️ unbounded in harness |
| Per-node trust spread | uniform | **[4411, 4386, 3269, 1617, 724]** | ❌ mesh divergent |
| Op rate | n/a | 280 → 138 ops/s (halved by graph growth) | ⚠️ symptom of B5 |
| RSS | 41 MB | 109 MB | ⚠️ symptom of B5 + harness |
| Errors | 0 | 16 / 1.24M | ✅ |

The two blocker findings (B5 and B6) are independent. B5 breaks any deployment
larger than ~1K tokens regardless of network conditions. B6 breaks any
deployment with any node churn regardless of size. Both must land before
the next soak.

The soak also surfaced two harness bugs (not production code):

- **Vouch tokens issued by the harness have a 365-day expiry**, so the trust
  graph grows monotonically and the expiry sweeper never reclaims anything.
  Need to drop vouch expiry to ~1 hour to exercise steady-state behavior.
- **`Notify::notify_waiters` only wakes current waiters**, so a SIGINT racing
  with the select-loop tick can be lost. Should switch to
  `tokio_util::sync::CancellationToken` or `AtomicBool::load(Acquire)`.

### Validation Soak (2026-04-09, 30 min, all KPIs ✅)

Run dir: `loadtest-results/b6-validation-20260409-210025/` — same chaos
settings as the broken soak (5 nodes, 1 of 5 paused every ~2 min for 45s,
max 1 offline). Wrapped in `caffeinate -dimsu` so macOS could not suspend
mid-run. **0 errors / 466K ops, all five hard §10 KPIs PASS.**

| KPI | §10 target | Validation soak | Verdict |
| --- | --- | --- | --- |
| Local auth decision (p99) | ≤ 1 ms | **0.050 ms** | ✅ 20× under budget |
| `evaluate_policy` (p99) | ≤ 1 ms | **0.005 ms** | ✅ 200× under |
| `session_validate` (p99) | ≤ 1 ms | **0.050 ms** | ✅ |
| `issue_session` (p99) | informational | **0.102 ms** | ✅ flat |
| Ed25519 verify throughput | ≥ 50,000 ops/s | **53,975 ops/s** | ✅ |
| CRDT merge (p99) | ≤ 0.05 ms | **< 1 µs** | ✅ |
| `gossip_propagation` (p99) | informational | 105 ms | ✅ |
| **`rejoin_convergence`** | no timeouts | **14 ok / 0 timeouts** | ✅ |
| Errors | — | **0 / 466K ops** | ✅ |
| Trust graph tokens (peak) | — | 4,123 (steady-state) | — |
| RSS (peak) | — | 74 MB | ⚠️ R5 |
| Heap / 1K entries | ≤ 5 MB | 17.94 MB | ⚠️ R5 (RSS-proxy) |
| Idle gossip bandwidth | ≤ 2 KB/s | 11.5 KB/s | ⚠️ R5 (RSS-delta proxy) |

Comparison to the broken soak at the same wall-clock point (15 min in,
~2K tokens):

| Signal | Broken | Validation | Result |
| --- | --- | --- | --- |
| `evaluate_policy` p99 | climbed 0.5 → 2.5 ms | **flat 5 µs** | **509× faster** |
| `gossip_propagation` p99 | 577 sec | 105 ms | **5,500× faster** |
| `rejoin_convergence` | 13 ok / 16 timeouts | 14 ok / 0 timeouts | ✅ |
| Op rate | 285/s declining | 318/s climbing | ✅ |
| Errors | 16 | **0** | ✅ |

### Production Risks ⚠️ (not blockers, but must be acknowledged)

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | FIDO2 attestation only supports `none` + `packed` self-attestation; TPM and full x5c chains deferred | ✅ Documented in [`fido2-attestation-allowlist.md`](docs/fido2-attestation-allowlist.md) with upgrade path |
| R2 | ~~No delegation depth limit on vouch chains~~ | ✅ **Resolved**: `max_delegation_depth` config (default 5) wired to `TrustGraph` at node init |
| R3 | No sharded Kademlia | Only matters > 10K nodes; out of scope for pilot |
| R4 | `DdsNode::node` module has 0 unit tests (event loop covered only by multinode integration test) | Multinode test is the load-bearing coverage; acceptable if soak passes |
| R5 | Heap and idle-bandwidth KPIs use whole-process RSS proxies, not real allocator / per-direction byte counters. Validation soak measured 17.94 MB / 1K entries vs the §10 ≤ 5 MB target — but the number is dominated by the libp2p / tokio runtime baseline and is *not* a real-allocations regression. | Acceptable for pilot. If a hard verdict is needed pre-GA: wire `dhat` for heap and a custom `Transport` wrapper for byte counters. |

### Plan to Production

#### Milestone P0 — Fix the blockers the chaos soak surfaced ✅ COMPLETE

All four sub-milestones landed and validated by the 2026-04-09 30-min
chaos soak (`b6-validation-20260409-210025`): 0 errors / 466K ops, all
five hard §10 KPIs PASS, 14/14 chaos rejoins succeeded.

##### P0.a — Fix B5 (algorithmic): trust graph queries must be sublinear ✅

- [x] Add `vouches_by_subject: BTreeMap<String, BTreeSet<String>>` and `attestations_by_iss` indices to `TrustGraph`
- [x] Maintain the indices in `add_token`, `remove_token`, `sweep_expired`, and the `Burn` revocation cascade
- [x] Route `purposes_for`, `walk_chain`, and `has_purpose` through the index instead of iterating `vouches.values()`
- [x] Unit test `test_purposes_for_scales_to_10k_vouches`: 10K-vouch graph, asserts `purposes_for` worst-case < 500 µs. **Measured 3.2 µs.**
- [x] Smoke + 30-min chaos soak: `evaluate_policy` p99 stays flat at 5 µs from 1 → 4,123 tokens

##### P0.b — Fix harness issues that contaminated the first soak ✅

- [x] Drop harness vouch expiry from 365 days to 1 hour and cap user pool to 300 — landed in `dds-loadtest/src/harness.rs`
- [x] Replace `Notify::notify_waiters` with `tokio::sync::watch` so SIGINT can't race with the select loop — landed in `dds-loadtest/src/main.rs`
- [x] Wrap soak runs in `caffeinate -dimsu` so macOS suspend can't contaminate the timer

##### P0.b2 — Fix B5b (per-query rebuild) — surfaced after P0.a ✅

- [x] Drop the per-query `trust_graph_snapshot()` rebuild from `LocalService::issue_session`, `evaluate_policy`, `status`
- [x] Add `LocalService::rehydrate_from_store()`, called once at construction (preserves the http_binary_e2e seed_store path)
- [x] Make `DdsNode::trust_graph` and `LocalService::trust_graph` a shared `Arc<RwLock<TrustGraph>>` so gossip-received tokens are visible to HTTP API queries instantly (fixes a multi-writer regression in `binary_nodes_converge_on_gossip_and_revocation`)
- [x] Update all 10+ in-tree access sites to take read/write locks
- [x] Validation smoke: `evaluate_policy` p99 dropped from 299 µs → 5 µs (60× faster)

##### P0.c — Fix B6 (sync): wire `dds-net::sync` into the swarm event loop ✅

- [x] Add `libp2p` `request-response` + `cbor` features to the workspace
- [x] Add `request_response::cbor::Behaviour<SyncRequest, SyncResponse>` to `DdsBehaviour` with a domain-namespaced `/dds/sync/1.0.0/<tag>` protocol
- [x] Define `SyncRequest { known_op_ids, heads }` and `SyncResponse { payloads, complete }` in `dds-net::sync`
- [x] Add `apply_sync_payloads_with_graph` that also feeds the trust graph (post-B5b: in-memory graph is the source of truth)
- [x] Maintain a `sync_payloads` cache on `DdsNode` populated at gossip ingest, so the responder can serve diffs without round-tripping through the store
- [x] On `ConnectionEstablished` → call `try_sync_with(peer)` (catches fresh rejoins)
- [x] On `ConnectionClosed` → drop the per-peer cooldown so the next reconnect re-syncs immediately
- [x] Periodic 60s anti-entropy timer in `run()` → sync against every connected peer (catches steady-state drift)
- [x] Per-peer 15s cooldown to avoid sync storms during reconnect flap
- [x] Regression test `rejoined_node_catches_up_via_sync_protocol`: A and B publish ops, C joins fresh with no shared past, **C converges via sync protocol with no further publishes**. Passes in 11 s.
- [x] Validation soak: **14 of 14 chaos rejoins succeeded with 0 timeouts** (vs 13/29 timeouts in the broken soak)

##### P0.d — Run a clean validation soak ✅

- [x] 30-min chaos soak after P0.a + P0.b: `validation-20260409-193017` — eval p99 flat at 5 µs, 0 errors. (Note: original 30-min run was contaminated by macOS sleep at 22 min; rerun with `caffeinate` → clean.)
- [x] 30-min chaos soak after P0.c: `b6-validation-20260409-210025` — all five §10 KPIs PASS, 14/14 rejoins succeed, 0 errors / 466K ops
- [ ] **Optional**: 24-hour endurance run for long-tail evidence. Not load-bearing for §10 sign-off; defer to pilot pre-flight.
- [ ] **Optional**: Wire `dhat` heap profiling and a custom transport-byte-counter to convert R5's RSS-proxy KPIs to hard verdicts. Defer to pre-GA if pilot sign-off needs them.

#### Milestone P1 — Pilot scoping decision ✅ COMPLETE

- [x] Decide pilot platform scope: **Windows logon included.** Full FIDO2 passwordless flow verified end-to-end on Windows 11 ARM64 with real YubiKey: admin setup → admin enrollment → user enrollment → admin vouch → lock screen → touch key → Windows session. Remaining work is packaging (WiX/MSI), service registration, and Authenticode signing.

#### Milestone P2 — Platform breadth (resolves B2)

- [ ] Wire `x86_64-pc-windows-msvc` build + run C# NUnit suite against the real `dds_ffi.dll` in CI
- [ ] Wire `aarch64-linux-android` via cargo-ndk + run Kotlin JUnit suite on an emulator in CI
- [ ] Wire `aarch64-apple-ios` via Xcode toolchain + run Swift XCTest suite on a simulator in CI
- [ ] Cross-compile `dds-core --no-default-features` for `thumbv7em-none-eabihf` and record binary size vs the 512 KB §10 budget

#### Milestone P3 — Operational readiness ✅

- [x] Add delegation depth cap to `DomainConfig` (R2) — `max_delegation_depth` field (default 5), wired to `TrustGraph::set_max_chain_depth()` at node init, 4 config tests
- [x] Add audit-log retention/rotation — `AuditLogEntry.timestamp` field, `prune_audit_entries_before()` / `prune_audit_entries_to_max()` in both backends, config fields (`audit_log_max_entries`, `audit_log_retention_days`), pruning wired into expiry sweep loop, `GET /v1/audit/entries?action=&limit=` HTTP endpoint, 6 new store tests (21 total)
- [x] Document FIDO2 attestation allow-list and TPM/x5c upgrade path (R1) — see [`docs/fido2-attestation-allowlist.md`](docs/fido2-attestation-allowlist.md)
- [x] Threat model review of admission cert flow + encrypted identity store — see [`docs/threat-model-review.md`](docs/threat-model-review.md)

#### Milestone P4 — Pilot deploy

- [ ] Deploy 3-node mesh in a staging environment matching the pilot topology
- [ ] Enroll a representative cohort end-to-end (user passkey → device join → session → policy evaluate)
- [ ] Run for 7 days, watch the audit log, gossip propagation p99, and error rates from the loadtest harness running in parallel
- [ ] Pilot sign-off → general availability decision

#### Out of scope for first production cut

Deferred to post-GA:

- Phase 4 items 13–15 (sharded Kad, offline enrollment)
- Open items from threat model review (admission cert revocation list, key rotation — see `docs/threat-model-review.md` §6)

Note: Phase 3 items 9–10 (WindowsPolicyDocument distribution + SoftwareAssignment) are fully implemented through all phases A–I including G+H — all 4 Windows enforcers have production Win32 implementations with full reconciliation/drift-detection, 117 passing .NET tests, WiX MSI installer verified, CI integration complete with MSI compile verification and E2E smoke test.

### Phase 4 — Scale

13. **Sharded Kademlia** — For deployments > 10K nodes, shard the DHT by org-unit to reduce gossip fan-out and Kademlia routing table size.

14. **Delegation depth limits** — Add configurable max vouch chain depth (e.g. root → admin → user = depth 2) to bound trust graph traversal and prevent unbounded delegation.

15. **Offline enrollment** — Generate enrollment tokens that can be carried on USB/QR to air-gapped devices. Device presents token to local node, node verifies signature and creates attestation without network.
