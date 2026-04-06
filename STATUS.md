# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](DDS-Design-Document.md).
> Last updated: 2026-04-06

## Build Health

| Metric | Value |
|---|---|
| **Rust version** | 1.94.1 (stable) |
| **Workspace crates** | 6 |
| **Total tests** | 143 |
| **Tests passing** | 143 ✅ |
| **Tests failing** | 0 |

## Crate Status

| Crate | Design Ref | Status | Tests | Notes |
|---|---|---|---|---|
| **dds-core** | §12 | 🟢 Core complete | 109 | Identity, tokens, CRDTs, trust, policy, crypto (hybrid PQ) |
| **dds-store** | §12 | 🟢 Core complete | 15 | Traits + MemoryBackend + RedbBackend |
| **dds-net** | §12 | 🟢 Core complete | 19 | Transport, gossip, discovery, sync protocol |
| **dds-node** | §12 | 🔴 Stub only | 0 | Entry point placeholder |
| **dds-ffi** | §12, §14.2–14.3 | 🔴 Stub only | 0 | UniFFI definitions not yet written |
| **dds-cli** | §12 | 🔴 Stub only | 0 | CLI placeholder |

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

1. **CI benchmarks** (§10.9) — criterion + dhat
2. **dds-node** — Main binary with config, local API, swarm event loop
3. **dds-cli** — Identity creation, group management, diagnostics
4. **dds-ffi** — UniFFI definitions for C#/Swift/Kotlin bindings
5. **Integration tests** — Multi-node sync, revocation propagation
