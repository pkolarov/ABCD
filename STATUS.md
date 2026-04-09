# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](DDS-Design-Document.md).
> Last updated: 2026-04-09 (post-chaos-soak findings)

## Build Health

| Metric | Value |
|---|---|
| **Rust version** | 1.94.1 (stable) |
| **Edition** | 2024 |
| **Workspace crates** | 7 |
| **Rust LOC** | 8,400 |
| **Rust tests** | 212 |
| **Python tests** | 13 |
| **Total tests** | 225 ✅ all passing |
| **Shared library** | libdds\_ffi.dylib (739 KB) |

## Crate Status

| Crate | Design Ref | Status | Tests | Summary |
|---|---|---|---|---|
| **dds-core** | §3–§9 | 🟢 Done | 114 | Crypto, identity, tokens (extensible body), CRDTs, trust graph, policy engine |
| **dds-domain** | §14 | 🟢 Done | 22 | 6 typed domain documents + Stage 1 domain identity (`Domain`, `DomainKey`, `AdmissionCert`, `DomainSigner` trait) |
| **dds-store** | §6 | 🟢 Done | 15 | Storage traits, MemoryBackend, RedbBackend (ACID) |
| **dds-net** | §5 | 🟢 Done | 19 | libp2p transport, gossipsub, Kademlia, mDNS, delta-sync |
| **dds-node** | §12 | 🟢 Done | 18 | Config, P2P event loop, local authority service, HTTP API, encrypted persistent identity |
| **dds-domain** (fido2) | §14 | 🟢 Done | (incl. above) | WebAuthn attestation parser/verifier (none + packed/Ed25519) |
| **dds-ffi** | §14.2–14.3 | 🟢 Done | 12 | C ABI (cdylib): identity, token, policy, version |
| **dds-cli** | §12 | 🟢 Done | 9 | Identity, group, policy, status subcommands |

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
| `SoftwareAssignment` | `dds:software-assignment` | 1 | App/package deployment manifests |
| `ServicePrincipalDocument` | `dds:service-principal` | 1 | Machine/service identity registration |
| `SessionDocument` | `dds:session` | 2 | Short-lived auth session (< 1 ms local check) |
| Cross-type safety | — | 2 | Wrong type → None, no body → None |

All documents implement `DomainDocument` trait: `embed()` / `extract()` from `TokenPayload`.

## Module Detail — dds-store

| Module | Tests | Key Types |
|---|---|---|
| `traits` | — | `TokenStore`, `RevocationStore`, `OperationStore`, `DirectoryStore` |
| `memory_backend` | 7 | `MemoryBackend` (in-process, for tests and embedded) |
| `redb_backend` | 8 | `RedbBackend` (ACID persistent, zero-copy) |

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
| `config` | 5 | `NodeConfig`, `NetworkConfig`, `DomainConfig` (TOML, domain section required) |
| `node` | 0 | `DdsNode` — swarm event loop, gossip/sync ingestion, admission cert verification at startup |
| `service` | 6 | `LocalService` — enrollment (with FIDO2 verification), sessions, policy resolution, status |
| `http` | 5 | `axum` router exposing `LocalService` over `/v1/*` JSON endpoints |
| `identity_store` | 3 | Encrypted-at-rest persistent node identity (Argon2id + ChaCha20Poly1305) |
| `p2p_identity` | 2 | Persistent libp2p keypair so `PeerId` is stable across restarts |
| `domain_store` | 5 | TOML public domain file + CBOR domain key + CBOR admission cert load/save |

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

| Subcommand | Tests | What It Does |
|---|---|---|
| `identity create [--hybrid]` | 2 | Generate classical or hybrid PQ identity |
| `identity show <urn>` | 2 | Parse and display URN components |
| `group vouch` | 2 | Create vouch token, persist to store |
| `group revoke` | 1 | Revoke a vouch by JTI |
| `policy check` | 1 | Offline policy evaluation |
| `status` | 1 | Store diagnostics (tokens, revocations, burns) |

## Platform Integrations

| Platform | Language | Mechanism | Wrapper | Tests | Verified |
|---|---|---|---|---|---|
| **Any** | C | Header | `bindings/c/dds.h` | — | ✅ |
| **Linux/macOS** | Python | ctypes | `bindings/python/dds.py` | 13 pytest | ✅ Runs against .dylib |
| **Windows** | C# | P/Invoke | `bindings/csharp/DDS.cs` | 11 NUnit | Written |
| **Android** | Kotlin | JNA | `bindings/kotlin/.../DDS.kt` | 10 JUnit5 | Written |
| **iOS/macOS** | Swift | C module | `bindings/swift/.../DDS.swift` | 10 XCTest | Written |

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
| macOS ARM64 (aarch64-apple-darwin) | ✅ Builds + tests | Current dev host |
| Linux x86\_64 | ✅ Expected to build | Standard Rust target |
| Windows x86\_64 | 🔲 Untested | Needs CI |
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

1. 🟢 **HTTP/JSON-RPC API on dds-node** — `dds-node/src/http.rs` exposes `LocalService` over a localhost axum server. Endpoints: `POST /v1/enroll/user`, `POST /v1/enroll/device`, `POST /v1/session`, `POST /v1/policy/evaluate`, `GET /v1/status`. JSON request/response types with serde, base64-encoded binary fields. 5 integration tests via reqwest against an in-process server.

2. 🟢 **FIDO2 attestation verification** — `dds-domain/src/fido2.rs` parses WebAuthn attestation objects with `ciborium`, supports `none` and `packed` (Ed25519 self-attestation) formats, extracts the COSE_Key credential public key, and verifies the attestation signature. `LocalService::enroll_user` rejects enrollment whose attestation fails to verify (`ServiceError::Fido2`). Built without webauthn-rs to keep the dependency footprint small; full attestation chains (TPM, x5c) are deliberately deferred. 5 unit tests cover round-trips, bad signature, garbage input, unsupported format.

3. 🟢 **Persistent node identity** — `dds-node/src/identity_store.rs` loads or generates the node Ed25519 signing key on startup and persists it to `<data_dir>/node_key.bin` (or the new `identity_path` config field). When `DDS_NODE_PASSPHRASE` is set, the file is encrypted with ChaCha20-Poly1305 using a 32-byte key derived from the passphrase via Argon2id (19 MiB, 2 iters); otherwise the key is stored unencrypted with a warning log. Versioned CBOR on-disk format. 3 tests cover plain roundtrip, encrypted roundtrip with wrong-passphrase rejection, and load-or-create idempotency.

4. 🟢 **CI pipeline** — `.github/workflows/ci.yml` runs `cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, and the python binding pytest suite. Cross-compile jobs check `x86_64-pc-windows-gnu` (mingw-w64), `aarch64-linux-android` (cargo-ndk + setup-ndk), and `thumbv7em-none-eabihf` (`dds-core --no-default-features` smoke).

9\. 🟢 **Domain identity (Stage 1 — software domain key)** — `dds-domain/src/domain.rs` introduces `Domain`, `DomainId` (`dds-dom:<base32(sha256(pubkey))>`), `DomainKey` (Ed25519), `AdmissionCert` (domain key signs `(domain_id, peer_id, issued_at, expires_at)`), and a `DomainSigner` trait that Stage 2 will reimplement against a FIDO2 authenticator without touching call sites. `dds-net` bakes the domain tag into libp2p protocol strings (`/dds/kad/1.0.0/<tag>`, `/dds/id/1.0.0/<tag>`) and into gossipsub topics (`/dds/v1/dom/<tag>/org/<org>/...`), so nodes from different domains cannot complete a libp2p handshake. `dds-node`'s `NodeConfig` requires a `[domain]` section and refuses to start without a valid admission cert at `<data_dir>/admission.cbor` matching its libp2p `PeerId`. Persistent libp2p keypair (`p2p_key.bin`) is now loaded/generated by `dds-node/src/p2p_identity.rs` (encrypted at rest via `DDS_NODE_PASSPHRASE`) so the peer id is stable across restarts. New CLI subcommands: `init-domain`, `gen-node-key`, `admit`, `run` (no clap dep — hand-rolled flag parsing). Domain key on disk is encrypted with `DDS_DOMAIN_PASSPHRASE` (Argon2id + ChaCha20-Poly1305). 14+ new unit tests covering id roundtrip, cert sign/verify/tamper/expiry, domain/key TOML+CBOR roundtrips, protocol-string isolation, and stable peer id across restart.

### Phase 2 — Operational Readiness

5. 🟢 **Performance benchmarks** — criterion benches for Ed25519 verify, hybrid verify, CRDT merge (causal_dag insert + lww_register merge), policy evaluation, and SessionDocument issue+validate. Benches live under `dds-core/benches/` (`crypto_verify.rs`, `crdt_merge.rs`, `policy_eval.rs`) and `dds-node/benches/` (`session_lifecycle.rs`). CI runs `cargo bench --workspace --no-run` as a compile-check job; numbers are not yet wired as regression gates and dhat heap profiling is deferred.

6. 🟢 **Multi-node integration tests** — `dds-node/tests/multinode.rs` spins up 3 in-process `DdsNode` instances on ephemeral TCP ports, dials them into a star topology, lets the gossipsub mesh form, and verifies (a) attestation operation propagation, (b) revocation propagation, (c) DAG convergence after a node is dropped and a fresh node rejoins. Uses a multi-thread tokio runtime and `select_all` to drive every swarm concurrently.

7. **Windows Credential Provider** — `platform/windows/DdsCredentialProvider/` ships a `net8.0` class library with the COM-visible `DdsCredentialProvider` class (stable CLSID `8C0DBE9A-…`), an `ICredentialProvider` managed shape, and an `HttpClient` that POSTs to dds-node's `/v1/session` with a passkey-derived Vouchsafe-shaped subject URN. Full COM interop, comhost packaging, LSA hand-off, and the installer are stubbed — see the folder README for what is required to actually appear on the Windows logon screen.

8\. 🟢 **Token expiry enforcement** — `dds-node/src/expiry.rs` provides `sweep_once()` and an async `expiry_loop()` task. `NodeConfig::expiry_scan_interval_secs` (default 60) controls the cadence. Expired tokens are removed from the trust graph via a new `TrustGraph::remove_token()` method and marked revoked in the store. Unit-tested with `tokio::time::pause()` and direct sweep calls.

### Phase 3 — Enterprise Features

9. **WindowsPolicyDocument distribution** — End-to-end flow: admin creates a policy document, signs it, gossip propagates to target devices, dds-node on each device evaluates scope + applies settings (registry keys, security policy).

10. **SoftwareAssignment workflow** — Admin publishes a software assignment, devices poll/receive via gossip, local agent downloads package, verifies SHA-256, installs silently. Needs a local agent service on managed devices.

11. 🟢 **Audit log** — Append-only signed log of all trust graph mutations (attest, vouch, revoke, burn) for compliance. Each entry signed by the node that performed the action. Syncable via gossip. Opt-in feature enabled via `domain.toml` or `DomainConfig` during domain creation to minimize network overhead.

12. 🟢 **ECDSA-P256 support** — Some FIDO2 authenticators only support P-256. Added as a third `SchemeId` variant with triple-hybrid option `Ed25519+ECDSA-P256+ML-DSA-65`.

## Path to Production

Overall: **~70–80% ready for a scoped pilot, not yet for general production.**
All 7 crates are functionally complete and the security-critical hardening
work (Phase 1) is done. The remaining gaps are in *operational proof* and
*platform breadth*, not core functionality.

### Production Blockers 🔴

| # | Gap | Where | Impact |
| --- | --- | --- | --- |
| B1 | **Windows Credential Provider stubbed** — COM interop, LSA hand-off, comhost packaging, installer all incomplete | `platform/windows/DdsCredentialProvider/` | Hard blocker if Windows logon is in scope |
| B2 | **Cross-platform builds untested** — Windows, Android, iOS, embedded all 🔲 in the build matrix | see [Cross-Platform Build Status](#cross-platform-build-status) | Bindings written but never run against a real artifact on-device |
| B3 | **24h soak aborted at 2h 38m** — chaos-enabled soak surfaced two new blockers (B5, B6) before completing. Need a clean steady-state soak after fixes land. | `dds-loadtest` | No evidence of stability under sustained load |
| B4 | **Two KPIs unverified** — Ed25519 throughput verified PASS in soak (54,972 ops/s); heap + idle bandwidth still RSS-proxy measurements with measurement caveats | [Performance Budgets](#performance-budgets-10) | Bandwidth/heap need real instrumentation for hard verdict |
| **B5** | **Trust graph queries are O(V) in vouch count** — `TrustGraph::purposes_for` and `walk_chain` linearly scan every vouch on every call. Soak measured `evaluate_policy` p99 climbing from 0.5 ms (500 tokens) → 10.8 ms (14K tokens). Blows the §10 ≤ 1 ms KPI for any non-toy deployment. | `dds-core/src/trust.rs` (`purposes_for`, `walk_chain`) | **Hard production blocker** at any scale > ~1K tokens |
| **B6** | **No anti-entropy / catch-up sync wired into the swarm** — gossipsub delivers only live messages. A node offline for 60s misses every op published in that window, permanently. Soak measured: 16 of 29 chaos rejoin attempts timed out at 5 min, with as little as 19% of missing tokens recovered. The protocol exists fully implemented in `dds-net/src/sync.rs` (8 passing tests) but is never invoked from `dds-node/src/node.rs`. | `dds-node/src/node.rs` (event loop) ↔ `dds-net/src/sync.rs` (unused) | **Hard production blocker** for any deployment with normal node churn |

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

### Production Risks ⚠️ (not blockers, but must be acknowledged)

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | FIDO2 attestation only supports `none` + `packed/Ed25519`; TPM and full x5c chains deferred | Acceptable for pilot with known authenticator models; document allow-list |
| R2 | No delegation depth limit on vouch chains | Bound at config layer before opening enrollment to untrusted admins |
| R3 | No sharded Kademlia | Only matters > 10K nodes; out of scope for pilot |
| R4 | `DdsNode::node` module has 0 unit tests (event loop covered only by multinode integration test) | Multinode test is the load-bearing coverage; acceptable if soak passes |

### Plan to Production

#### Milestone P0 — Fix the two blockers the soak surfaced (CRITICAL PATH)

These must land in order. Each step is gated on the next soak passing.

##### P0.a — Fix B5 (algorithmic): trust graph queries must be sublinear

- [x] Add a `vouches_by_subject: BTreeMap<String, BTreeSet<String>>` index to `TrustGraph` (subject URN → JTIs of vouches whose `vch_iss == subject`)
- [x] Maintain the index in `add_token`, `remove_token`, `sweep_expired`, and the `Burn` revocation cascade
- [x] Route `purposes_for` and `walk_chain` through the index instead of iterating `vouches.values()`
- [ ] Add a unit test that builds a 10K-vouch graph and asserts `purposes_for` p99 < 0.1 ms — this is the regression gate for B5
- [ ] Re-run smoke and confirm `evaluate_policy` p99 stays flat as the graph grows

##### P0.b — Fix harness issues that contaminated the first soak

- [x] Drop harness vouch expiry from 365 days to 1 hour so the trust graph reaches steady state instead of growing monotonically (separate from B5: even with the index, monotonic growth is unrealistic) — landed in `dds-loadtest/src/harness.rs`
- [x] Replace `Notify::notify_waiters` with `tokio::sync::watch` so SIGINT can't race with the select loop and lose the shutdown signal — landed in `dds-loadtest/src/main.rs`

##### P0.c — Fix B6 (sync): wire `dds-net::sync` into the swarm event loop

- [ ] Add a libp2p `request_response` behaviour to `DdsBehaviour` carrying `SyncMessage` (the protocol is already implemented in `dds-net/src/sync.rs` with 8 passing tests — never invoked)
- [ ] On `ConnectionEstablished`, send the local `StateSummary` to the new peer
- [ ] On `Summary` received, compare op counts/heads; if behind, request the peer's full op-id set
- [ ] On `OperationIds` received, call `compute_missing_ops` and request the missing ops via `RequestOps`
- [ ] On `RequestOps` received, fetch ops + their backing tokens from the local store and reply with `SendOps`
- [ ] On `SendOps` received, call `apply_sync_payloads` to merge into local state
- [ ] Multinode integration test: pause node A, publish 100 ops on B/C/D, resume A, assert A converges to peers within 30 s (regression gate for B6)

##### P0.d — Run a clean validation soak

- [ ] 30-min chaos soak after P0.a + P0.b: confirms B5 fix holds end-to-end with monotonic growth removed
- [ ] 30-min chaos soak after P0.c: confirms rejoin convergence works
- [ ] 24-hour chaos soak after both: this is the soak that resolves B3
- [ ] If the heap/bandwidth caveats are still soft after the 24h run, decide: accept for pilot, or invest in dhat/jemalloc instrumentation → resolves B4 (memory/bw)

#### Milestone P1 — Pilot scoping decision

- [ ] Decide pilot platform scope: Linux/macOS daemons only, *or* Windows logon included
  - If Linux/macOS only → B1 drops out, jump to P2
  - If Windows included → B1 becomes the critical path (multi-week effort: COM, LSA, MSI, signing)

#### Milestone P2 — Platform breadth (resolves B2)

- [ ] Wire `x86_64-pc-windows-msvc` build + run C# NUnit suite against the real `dds_ffi.dll` in CI
- [ ] Wire `aarch64-linux-android` via cargo-ndk + run Kotlin JUnit suite on an emulator in CI
- [ ] Wire `aarch64-apple-ios` via Xcode toolchain + run Swift XCTest suite on a simulator in CI
- [ ] Cross-compile `dds-core --no-default-features` for `thumbv7em-none-eabihf` and record binary size vs the 512 KB §10 budget

#### Milestone P3 — Operational readiness

- [ ] Add audit-log retention/rotation policy and document operator runbook
- [ ] Add delegation depth cap to `PolicyEngine` config (R2)
- [ ] Document the FIDO2 attestation allow-list and the upgrade path to TPM/x5c (R1)
- [ ] Threat model review of the domain admission cert flow + the encrypted-at-rest identity store (independent eyes on f225e57)

#### Milestone P4 — Pilot deploy

- [ ] Deploy 3-node mesh in a staging environment matching the pilot topology
- [ ] Enroll a representative cohort end-to-end (user passkey → device join → session → policy evaluate)
- [ ] Run for 7 days, watch the audit log, gossip propagation p99, and error rates from the loadtest harness running in parallel
- [ ] Pilot sign-off → general availability decision

#### Out of scope for first production cut

Deferred to post-GA:

- Phase 3 items 9–10 (WindowsPolicyDocument distribution, SoftwareAssignment workflow + local agent)
- Phase 4 items 13–15 (sharded Kad, delegation depth limits as a hard feature, offline enrollment)

### Phase 4 — Scale

13. **Sharded Kademlia** — For deployments > 10K nodes, shard the DHT by org-unit to reduce gossip fan-out and Kademlia routing table size.

14. **Delegation depth limits** — Add configurable max vouch chain depth (e.g. root → admin → user = depth 2) to bound trust graph traversal and prevent unbounded delegation.

15. **Offline enrollment** — Generate enrollment tokens that can be carried on USB/QR to air-gapped devices. Device presents token to local node, node verifies signature and creates attestation without network.
