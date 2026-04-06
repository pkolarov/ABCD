# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](DDS-Design-Document.md).
> Last updated: 2026-04-06

## Build Health

| Metric | Value |
|---|---|
| **Rust version** | 1.94.1 (stable) |
| **Edition** | 2024 |
| **Workspace crates** | 7 |
| **Rust LOC** | 7,618 |
| **Rust tests** | 189 |
| **Python tests** | 13 |
| **Total tests** | 202 ✅ all passing |
| **Shared library** | libdds\_ffi.dylib (739 KB) |

## Crate Status

| Crate | Design Ref | Status | Tests | Summary |
|---|---|---|---|---|
| **dds-core** | §3–§9 | 🟢 Done | 114 | Crypto, identity, tokens (extensible body), CRDTs, trust graph, policy engine |
| **dds-domain** | §14 | 🟢 Done | 11 | 6 typed domain documents embedded in token body |
| **dds-store** | §6 | 🟢 Done | 15 | Storage traits, MemoryBackend, RedbBackend (ACID) |
| **dds-net** | §5 | 🟢 Done | 19 | libp2p transport, gossipsub, Kademlia, mDNS, delta-sync |
| **dds-node** | §12 | 🟢 Done | 9 | Config, P2P event loop, local authority service |
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
| `transport` | 0 | `DdsBehaviour`, `SwarmConfig`, `build_swarm()` |
| `gossip` | 7 | `DdsTopic`, `DdsTopicSet`, `GossipMessage` |
| `discovery` | 3 | `add_bootstrap_peer()`, `parse_peer_multiaddr()` |
| `sync` | 9 | `StateSummary`, `SyncMessage`, `apply_sync_payloads()` |

## Module Detail — dds-node

| Module | Tests | Key Types |
|---|---|---|
| `config` | 4 | `NodeConfig`, `NetworkConfig` (TOML) |
| `node` | 0 | `DdsNode` — swarm event loop, gossip/sync ingestion |
| `service` | 5 | `LocalService` — enrollment, sessions, policy resolution, status |

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

| KPI | Target | Status |
|---|---|---|
| Local auth decision | ≤ 1 ms | 🔲 Needs criterion benchmark |
| Ed25519 verify throughput | ≥ 50K ops/sec | 🔲 Needs criterion benchmark |
| CRDT merge (single op) | ≤ 0.05 ms p99 | 🔲 Needs criterion benchmark |
| Peak heap (1K entries) | ≤ 5 MB | 🔲 Needs dhat profiling |
| dds-core binary (Cortex-M) | ≤ 512 KB | 🔲 Needs cross-compile |
| Idle gossip bandwidth | ≤ 2 KB/sec | 🔲 Needs network test |

## What's Next

All 7 crates are functionally complete. The following work is ordered by impact and dependency:

### Phase 1 — Production Hardening (high priority)

1. **HTTP/JSON-RPC API on dds-node** — Expose `LocalService` (enrollment, session issuance, policy check, status) over a localhost HTTP endpoint so platform clients (C#, Swift, Kotlin, Python) can call the node without embedding libp2p. This is the critical integration point for real deployments.

2. **FIDO2 attestation verification** — Currently `UserAuthAttestation` stores raw attestation bytes but does not parse/verify them. Add a `fido2` module (or crate) that validates WebAuthn attestation objects (packed, TPM, none formats), extracts the credential public key, and verifies the attestation signature chain.

3. **Persistent node identity** — The node generates a new identity on each start. Store the node signing key encrypted-at-rest (using OS keyring or a passphrase-derived key) so the node maintains a stable identity across restarts.

4. **CI pipeline** — GitHub Actions workflow: `cargo test --workspace`, `cargo clippy`, `cargo fmt --check`, Python binding tests. Add cross-compile jobs for Windows, Android (cargo-ndk), and `thumbv7em-none-eabihf` (no\_std smoke).

### Phase 2 — Operational Readiness

5. **Performance benchmarks** — criterion benches for Ed25519 verify, hybrid verify, CRDT merge, policy evaluation, SessionDocument issue+validate. dhat heap profiler for memory budgets. Wire results into CI as regression gates.

6. **Multi-node integration tests** — Spin up 3+ in-process nodes, verify gossip propagation, revocation propagation, network partition recovery, and DAG convergence. Test with simulated clock for expiry behavior.

7. **Windows Credential Provider** — C# credential provider DLL that calls dds-node's HTTP API during Windows logon. This is the §14.2 "replaces AD" proof point: user authenticates with passkey, node issues a SessionDocument, credential provider grants logon.

8. **Token expiry enforcement** — Add a background task in dds-node that periodically scans for expired tokens/sessions and removes them from the trust graph. Currently tokens have `exp` but nothing enforces it at runtime.

### Phase 3 — Enterprise Features

9. **WindowsPolicyDocument distribution** — End-to-end flow: admin creates a policy document, signs it, gossip propagates to target devices, dds-node on each device evaluates scope + applies settings (registry keys, security policy).

10. **SoftwareAssignment workflow** — Admin publishes a software assignment, devices poll/receive via gossip, local agent downloads package, verifies SHA-256, installs silently. Needs a local agent service on managed devices.

11. **Audit log** — Append-only signed log of all trust graph mutations (attest, vouch, revoke, burn) for compliance. Each entry signed by the node that performed the action. Syncable via gossip.

12. **ECDSA-P256 support** — Some FIDO2 authenticators only support P-256. Add as a third `SchemeId` variant with hybrid option `Ed25519+ECDSA-P256+ML-DSA-65`.

### Phase 4 — Scale

13. **Sharded Kademlia** — For deployments > 10K nodes, shard the DHT by org-unit to reduce gossip fan-out and Kademlia routing table size.

14. **Delegation depth limits** — Add configurable max vouch chain depth (e.g. root → admin → user = depth 2) to bound trust graph traversal and prevent unbounded delegation.

15. **Offline enrollment** — Generate enrollment tokens that can be carried on USB/QR to air-gapped devices. Device presents token to local node, node verifies signature and creates attestation without network.
