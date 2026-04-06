# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](DDS-Design-Document.md).
> Last updated: 2026-04-06

## Build Health

| Metric | Value |
|---|---|
| **Rust version** | 1.94.1 (stable) |
| **Workspace crates** | 6 |
| **Total tests** | 186 (173 Rust + 13 Python) |
| **Tests passing** | 186 ✅ |
| **Tests failing** | 0 |

## Crate Status

| Crate | Design Ref | Status | Tests | Notes |
|---|---|---|---|---|
| **dds-core** | §12 | 🟢 Complete | 114 | Identity, tokens, CRDTs, trust, policy, crypto (hybrid PQ), integration tests |
| **dds-store** | §12 | 🟢 Complete | 15 | Traits + MemoryBackend + RedbBackend |
| **dds-net** | §12 | 🟢 Complete | 19 | Transport, gossip, discovery, sync protocol |
| **dds-node** | §12 | � Complete | 4 | Config, event loop, swarm lifecycle, gossip/sync ingestion |
| **dds-ffi** | §12, §14.2–14.3 | � Complete | 12 | C ABI: identity, token, policy, version + 12 Rust tests |
| **dds-cli** | §12 | � Complete | 9 | Smoke tests (help, create, hybrid, show, invalid URN, policy, status, vouch+status, vouch+revoke) |

## Module Detail — dds-core

| Module | Design Ref | Status | Tests | Key Types |
|---|---|---|---|---|
| `crypto::classical` | §13.1 | ✅ Done | 5 | `Ed25519Only`, `verify_ed25519()` |
| `crypto::hybrid` | §13.1 (extended) | ✅ Done | 7 | `HybridEdMldsa`, `verify_hybrid()` |
| `crypto::traits` | — | ✅ Done | — | `SchemeId`, `PublicKeyBundle`, `SignatureBundle`, `verify()` |
| `identity` | §3, §4.1 | ✅ Done | 12 | `VouchsafeId`, `Identity` |
| `token` | §4.1–4.4 | ✅ Done | 15 | `Token`, `TokenPayload`, `TokenKind` |
| `crdt::lww_register` | §5.1 | ✅ Done | 11 | `LwwRegister<T>` |
| `crdt::twop_set` | §5.2 | ✅ Done | 13 | `TwoPSet<T>` |
| `crdt::causal_dag` | §5.3 | ✅ Done | 17 | `CausalDag`, `Operation` |
| `trust` | §4.3, §6 | ✅ Done | 14 | `TrustGraph` |
| `policy` | §7 | ✅ Done | 12 | `PolicyEngine`, `PolicyRule`, `PolicyDecision` |

## Module Detail — dds-store

| Module | Design Ref | Status | Tests | Key Types |
|---|---|---|---|---|
| `traits` | §12 | ✅ Done | — | `TokenStore`, `RevocationStore`, `OperationStore`, `DirectoryStore` |
| `memory_backend` | §12, §14.4 | ✅ Done | 7 | `MemoryBackend` |
| `redb_backend` | §13.2 | ✅ Done | 8 | `RedbBackend` |

## Module Detail — dds-net

| Module | Design Ref | Status | Tests | Key Types |
|---|---|---|---|---|
| `transport` | §13.3, §14.1 | ✅ Done | 0 | `DdsBehaviour`, `SwarmConfig`, `build_swarm()` |
| `gossip` | §8 | ✅ Done | 7 | `DdsTopic`, `DdsTopicSet`, `GossipMessage` |
| `discovery` | §8 | ✅ Done | 3 | `add_bootstrap_peer()`, `parse_peer_multiaddr()` |
| `sync` | §8.2, §10.6 | ✅ Done | 9 | `StateSummary`, `SyncMessage`, `apply_sync_payloads()` |

## Module Detail — dds-node

| Module | Design Ref | Status | Tests | Key Types |
|---|---|---|---|---|
| `config` | §12 | ✅ Done | 4 | `NodeConfig`, `NetworkConfig`, `ConfigError` |
| `node` | §12 | ✅ Done | 0 | `DdsNode`, event loop, gossip/sync ingestion |

## Module Detail — dds-cli

| Subcommand | Design Ref | Status | Key Operations |
|---|---|---|---|
| `identity create` | §3 | ✅ Done | Classical + hybrid identity generation |
| `identity show` | §3 | ✅ Done | URN parse and display |
| `group vouch` | §4.2 | ✅ Done | Create vouch token, store |
| `group revoke` | §4.3 | ✅ Done | Create revoke token, mark revoked |
| `policy check` | §7 | ✅ Done | Offline policy evaluation |
| `status` | — | ✅ Done | Store diagnostics (token/revocation/burn counts) |

## Module Detail — dds-ffi

| Export | Purpose | Signature |
|---|---|---|
| `dds_identity_create` | Classical identity | `(label, out) -> i32` |
| `dds_identity_create_hybrid` | Hybrid PQ identity | `(label, out) -> i32` (feature-gated) |
| `dds_identity_parse_urn` | URN validation | `(urn, out) -> i32` |
| `dds_token_create_attest` | Create attestation token | `(config_json, out) -> i32` |
| `dds_token_validate` | Validate token from CBOR hex | `(token_hex, out) -> i32` |
| `dds_policy_evaluate` | Evaluate policy decision | `(config_json, out) -> i32` |
| `dds_version` | Library version | `(out) -> i32` |
| `dds_free_string` | Free returned strings | `(ptr)` |

## Platform Integrations

| Platform | Language | Binding Type | Wrapper | Tests | Status |
|---|---|---|---|---|---|
| **Any** | C | Header (`dds.h`) | `bindings/c/dds.h` | — | ✅ Complete |
| **Linux/macOS** | Python | ctypes | `bindings/python/dds.py` | 13 (pytest) | ✅ Tested |
| **Windows** | C# | P/Invoke | `bindings/csharp/DDS.cs` | 11 (NUnit) | ✅ Written |
| **Android** | Kotlin | JNA | `bindings/kotlin/.../DDS.kt` | 10 (JUnit5) | ✅ Written |
| **iOS/macOS** | Swift | C module | `bindings/swift/.../DDS.swift` | 10 (XCTest) | ✅ Written |

## Integration Tests

| Test | Crates Exercised | What It Validates |
|---|---|---|
| `test_full_trust_chain_lifecycle` | core (identity, token, trust) | root→admin→user chain, vouch, revoke breaks chain, admin survives |
| `test_policy_evaluation_end_to_end` | core (identity, token, trust, policy) | Policy allow/deny with trust graph, outsider denied, wrong resource/action denied |
| `test_token_store_roundtrip` | core + store | CBOR serialize→store→retrieve→deserialize→validate signature |
| `test_two_node_sync` | core + store + net (sync) | Two DAGs exchange summaries, compute missing ops, apply payloads, merge |
| `test_hybrid_identity_full_lifecycle` | core (crypto, identity, token, trust) | Hybrid PQ root vouches classical user, mixed-scheme trust chain |

## Cryptography Status

| Algorithm | Purpose | Status | Crate | Key Size | Sig Size |
|---|---|---|---|---|---|
| **Ed25519** | Classical signatures | ✅ Integrated | ed25519-dalek 2.2 | 32 B | 64 B |
| **ML-DSA-65** (FIPS 204) | Post-quantum signatures | ✅ Integrated | pqcrypto-mldsa 0.1.2 | 1,952 B | 3,309 B |
| **Hybrid Ed25519+ML-DSA-65** | Composite quantum-safe | ✅ Integrated | Both above | 1,984 B | 3,373 B |
| **SHA-256** | ID derivation, hashing | ✅ Integrated | sha2 0.10 | — | 32 B |

**Crypto architecture**: Feature-flagged (`pq` feature, on by default). Hybrid signs with both schemes; verification requires both to pass. Classical-only mode available for embedded/no_std targets without `pq` feature.

## Performance Budgets (Design §10)

| KPI | Target | Status |
|---|---|---|
| Local auth decision (Tier 3) | ≤ 1 ms | 🔲 Not yet benchmarked |
| Ed25519 verify throughput | ≥ 50K ops/sec | 🔲 Not yet benchmarked |
| CRDT merge (single op) | ≤ 0.05 ms p99 | 🔲 Not yet benchmarked |
| Peak heap 1K entries | ≤ 5 MB | 🔲 Not yet benchmarked |
| `dds-core` binary (thumbv7em) | ≤ 512 KB | 🔲 Not yet benchmarked |
| Idle gossip bandwidth | ≤ 2 KB/sec | 🔲 Not yet benchmarked |

## Cross-Platform (Design §14)

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | ✅ Compiles & tests | Primary dev platform |
| macOS ARM64 | ✅ Compiles & tests | Current build host |
| Windows x86_64 | 🔲 Not tested | |
| Android ARM64 | 🔲 Not tested | Needs cargo-ndk |
| iOS ARM64 | 🔲 Not tested | |
| Embedded (Cortex-M) | 🔲 Not tested | Needs no_std validation |

## FIDO2 / WebAuthn Compatibility

FIDO2 hardware authenticators (YubiKey, passkeys, TPMs) only produce Ed25519 or ECDSA-P256 signatures — no PQ support yet (IANA registered ML-DSA COSE IDs in April 2025, but no hardware ships it). Our design accommodates this:

- **FIDO2 leaf identities** use `SchemeId::Ed25519` (classical only)
- **Trust roots and admins** use `SchemeId::HybridEdMldsa65` (quantum-safe)
- **Trust chain**: PQ-hybrid root → PQ-hybrid admin → classical FIDO2 leaf
- Quantum resistance flows from the vouch chain, not the leaf authenticator
- When FIDO2 hardware adds ML-DSA, leaf identities upgrade seamlessly

## Next Steps

All 6 crates are 🟢 Complete. Remaining hardening work:

1. **CI benchmarks** (§10.9) — criterion + dhat for perf budgets
2. **Integration tests** — Multi-node sync, revocation propagation, network partition
3. **Cross-platform CI** — Windows, Android (cargo-ndk), iOS, embedded (thumbv7em)
4. **Persistent identity storage** — Encrypt-at-rest for node keys
5. **Local API server** — JSON-RPC/REST endpoint on dds-node for client apps
6. **FIDO2 integration** — WebAuthn attestation flow for leaf identities
