# DDS — Decentralized Directory Service

A peer-to-peer identity and access management system built in Rust. DDS enables offline-capable authentication and authorization using cryptographically signed tokens, CRDTs for conflict-free replication, and libp2p for peer-to-peer networking.

**Quantum-resistant by default** — all signatures use hybrid Ed25519 + ML-DSA-65 (FIPS 204).

## Quick Start

```bash
# Build
cargo build --workspace

# Run all tests (140 tests)
cargo test --workspace

# Run a specific crate's tests
cargo test -p dds-core
cargo test -p dds-store
cargo test -p dds-net
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  dds-node / dds-cli              │
│              (binaries — user-facing)            │
├──────────────┬──────────────┬────────────────────┤
│   dds-net    │  dds-store   │     dds-ffi        │
│  (libp2p)   │   (redb)     │    (UniFFI)        │
├──────────────┴──────────────┴────────────────────┤
│                   dds-core                       │
│  crypto · identity · token · crdt · trust · policy│
│              (no_std compatible)                 │
└──────────────────────────────────────────────────┘
```

## Interfaces

### For Humans — CLI (`dds-cli`)

```bash
# Generate a new identity
dds identity create --label alice

# List local identities
dds identity list

# Create a group and vouch a member
dds group create backend-devs
dds group vouch backend-devs --user urn:vouchsafe:bob.<hash>

# Revoke a membership
dds group revoke backend-devs --user urn:vouchsafe:bob.<hash>

# Check access (offline-capable)
dds policy check --user urn:vouchsafe:bob.<hash> \
                 --resource repo:main-service \
                 --action read

# Start the P2P node
dds node start --listen /ip4/0.0.0.0/tcp/4001 \
               --bootstrap /ip4/10.0.1.1/tcp/4001/p2p/<peer-id>

# Node status and diagnostics
dds node status
dds node peers
dds sync status
```

### For Machines — Rust API (`dds-core`)

```rust
use dds_core::crypto::{HybridEdMldsa, verify, SchemeId};
use dds_core::identity::{Identity, VouchsafeId};
use dds_core::token::{Token, TokenPayload, TokenKind};
use dds_core::trust::TrustGraph;
use dds_core::policy::{PolicyEngine, PolicyRule, Effect};

// Generate a quantum-safe identity
let key = HybridEdMldsa::generate(&mut rng);
let pk = key.public_key_bundle(); // Ed25519 + ML-DSA-65

// Sign and verify with hybrid crypto
let sig = key.sign(b"message");
assert!(verify(&pk, b"message", &sig).is_ok());

// Create a Vouchsafe identity
let identity = Identity::generate("alice", &mut rng);

// Evaluate policy locally (offline-capable, < 1ms)
let engine = PolicyEngine::new();
let decision = engine.evaluate(
    &user_urn, "repo:main-service", "read",
    &trust_graph, &trusted_roots,
);
```

### For Machines — FFI (`dds-ffi`)

The Rust core is exposed via UniFFI for native platform integration:

| Platform | Language | Binding |
|---|---|---|
| Windows | C# | uniffi-bindgen-cs (NordSecurity) |
| Android | Kotlin | UniFFI (Mozilla) |
| iOS | Swift | UniFFI (Mozilla) |
| Linux/macOS | Python | UniFFI (Mozilla) |

### For Machines — P2P Protocol (`dds-net`)

Nodes communicate over libp2p with these protocols:

| Protocol | Transport | Purpose |
|---|---|---|
| Gossipsub | TCP/QUIC + Noise | Directory operation broadcast |
| Kademlia DHT | TCP/QUIC + Noise | Peer discovery and routing |
| mDNS | UDP multicast | Local network zero-config discovery |
| DDS Sync | libp2p streams | Delta-sync for state convergence |

Topic structure: `/dds/v1/org/<org-hash>/{ops,revocations,burns}`

## Cryptography

| Scheme | Algorithm | Standard | Key Size | Sig Size |
|---|---|---|---|---|
| Classical | Ed25519 | RFC 8032 | 32 B | 64 B |
| Post-Quantum | ML-DSA-65 | FIPS 204 | 1,952 B | 3,309 B |
| **Hybrid (default)** | Ed25519 + ML-DSA-65 | IETF composite | **1,984 B** | **3,373 B** |

Both signatures are always produced and both must verify. The Ed25519 component remains independently verifiable for backward compatibility.

Disable PQ for embedded/constrained targets: `cargo build --no-default-features --features std`

## Project Status

See [STATUS.md](STATUS.md) for detailed implementation progress.
See [DDS-Design-Document.md](DDS-Design-Document.md) for full design specification.

## License

MIT OR Apache-2.0
