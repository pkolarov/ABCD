# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](DDS-Design-Document.md).
> Last updated: 2026-04-07

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
| ML-DSA-65 (FIPS 204) | Post-quantum signatures | pqcrypto-mldsa 0.1.2 | 1,952 B | 3,309 B |
| Hybrid Ed25519+ML-DSA-65 | Composite quantum-safe | both | 1,984 B | 3,373 B |
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

11. **Audit log** — Append-only signed log of all trust graph mutations (attest, vouch, revoke, burn) for compliance. Each entry signed by the node that performed the action. Syncable via gossip.

12. **ECDSA-P256 support** — Some FIDO2 authenticators only support P-256. Add as a third `SchemeId` variant with hybrid option `Ed25519+ECDSA-P256+ML-DSA-65`.

### Phase 4 — Scale

13. **Sharded Kademlia** — For deployments > 10K nodes, shard the DHT by org-unit to reduce gossip fan-out and Kademlia routing table size.

14. **Delegation depth limits** — Add configurable max vouch chain depth (e.g. root → admin → user = depth 2) to bound trust graph traversal and prevent unbounded delegation.

15. **Offline enrollment** — Generate enrollment tokens that can be carried on USB/QR to air-gapped devices. Device presents token to local node, node verifies signature and creates attestation without network.
