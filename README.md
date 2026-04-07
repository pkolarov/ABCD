# DDS — Decentralized Directory Service

A peer-to-peer identity and access management system built in Rust. DDS enables offline-capable authentication and authorization using cryptographically signed tokens, CRDTs for conflict-free replication, and libp2p for peer-to-peer networking.

**Quantum-resistant by default** — all signatures use hybrid Ed25519 + ML-DSA-65 (FIPS 204).

**202 tests** (189 Rust + 13 Python) · 7 crates · 7,618 lines of Rust · 5 platform bindings

## Quick Start

```bash
# Build everything
cargo build --workspace

# Run all 189 Rust tests
cargo test --workspace

# Build the shared library for platform bindings
cargo build -p dds-ffi --release

# Run Python binding tests (requires shared lib)
python3 -m pytest bindings/python/test_dds.py -v

# Run the CLI
cargo run -p dds-cli -- identity create alice
cargo run -p dds-cli -- identity create quantum-bob --hybrid
cargo run -p dds-cli -- status
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│               dds-node  /  dds-cli              │
│          (binaries — node + CLI)                │
├─────────────┬──────────────┬────────────────────┤
│  dds-domain │   dds-net    │     dds-ffi        │
│ (typed docs)│  (libp2p)    │  (C ABI cdylib)    │
├─────────────┼──────────────┼────────────────────┤
│             │  dds-store   │                    │
│             │ (redb/memory)│                    │
├─────────────┴──────────────┴────────────────────┤
│                   dds-core                      │
│  crypto · identity · token · crdt · trust · policy │
│              (no_std compatible)                │
└─────────────────────────────────────────────────┘
```

## Crates

| Crate | Type | Tests | Purpose |
|---|---|---|---|
| `dds-core` | lib (`no_std`) | 114 | Crypto, identity, tokens (extensible body), CRDTs, trust graph, policy engine |
| `dds-domain` | lib | 11 | 6 typed domain documents: auth, device, policy, software, service, session |
| `dds-store` | lib | 15 | Storage traits + MemoryBackend + RedbBackend (ACID) |
| `dds-net` | lib | 19 | libp2p transport, gossipsub, Kademlia, mDNS, delta-sync |
| `dds-node` | lib + bin | 9 | P2P daemon + local authority service (enrollment, sessions, policy, status) |
| `dds-ffi` | cdylib | 12 | C ABI for Python/C#/Swift/Kotlin bindings |
| `dds-cli` | bin | 9 | CLI: identity, group, policy, status |

## Interfaces

### CLI (`dds-cli`)

```bash
# Generate identities
dds identity create alice                # Ed25519
dds identity create quantum-bob --hybrid # Ed25519 + ML-DSA-65

# Inspect a URN
dds identity show urn:vouchsafe:alice.<hash>

# Vouch and revoke group membership
dds group vouch --as-label admin --user urn:vouchsafe:bob.<hash> --purpose group:backend
dds group revoke --as-label admin --jti vouch-admin-bob-<uuid>

# Offline policy check
dds policy check --user urn:vouchsafe:bob.<hash> --resource repo:main --action read

# Store diagnostics
dds status
```

### Rust API (`dds-core` + `dds-domain`)

```rust
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenPayload, TokenKind};
use dds_core::policy::{PolicyEngine, PolicyRule, Effect};
use dds_domain::{SessionDocument, DomainDocument};

// Generate a quantum-safe identity
let identity = Identity::generate_hybrid("alice", &mut rng);

// Create a token with a domain document body
let mut payload = TokenPayload { /* ... */ body_type: None, body_cbor: None };
let session = SessionDocument { session_id: "sess-1".into(), /* ... */ };
session.embed(&mut payload)?;
let token = Token::sign(payload, &identity.signing_key)?;

// Evaluate policy locally (offline, < 1ms target)
let decision = engine.evaluate(&user_urn, "repo:main", "read", &trust_graph, &roots);
```

### FFI (`dds-ffi`) — C ABI for all platforms

```c
#include "dds.h"
char *out;
int rc = dds_identity_create("alice", &out);     // JSON result
rc = dds_token_create_attest("{\"label\":\"alice\"}", &out);
rc = dds_token_validate(cbor_hex, &out);
rc = dds_policy_evaluate(config_json, &out);
dds_free_string(out);
```

| Platform | Language | Wrapper | Tests |
|---|---|---|---|
| Any | C | `bindings/c/dds.h` | — |
| Linux/macOS | Python (ctypes) | `bindings/python/dds.py` | 13 ✅ |
| Windows | C# (P/Invoke) | `bindings/csharp/DDS.cs` | 11 |
| Android | Kotlin (JNA) | `bindings/kotlin/.../DDS.kt` | 10 |
| iOS/macOS | Swift (C module) | `bindings/swift/.../DDS.swift` | 10 |

### P2P Network (`dds-net`)

| Protocol | Transport | Purpose |
|---|---|---|
| Gossipsub | TCP/QUIC + Noise | Directory operation broadcast |
| Kademlia DHT | TCP/QUIC + Noise | Peer discovery and routing |
| mDNS | UDP multicast | Local network zero-config discovery |
| DDS Sync | libp2p streams | Delta-sync for state convergence |

Protocol strings and topics are namespaced per **domain** (see below):
- `/dds/kad/1.0.0/<domain-tag>` — Kademlia
- `/dds/id/1.0.0/<domain-tag>` — Identify
- `/dds/v1/dom/<domain-tag>/org/<org-hash>/{ops,revocations,burns}` — gossipsub topics

Nodes from different DDS domains cannot complete a libp2p handshake at all.

### Domains (`dds-domain`)

A **domain** is a cryptographic realm that DDS nodes belong to (e.g.
`acme.com`). Two mechanisms keep domains separate and admission-controlled:

1. **Protocol isolation** — the domain id is baked into the libp2p protocol
   strings (above), so nodes from `acme.com` and `globex.com` running on the
   same network never form a connection.
2. **Admission certificates** — within a domain, only nodes holding an
   `AdmissionCert` signed by the **domain key** are valid. The cert binds
   a libp2p `PeerId` to a `DomainId` and is verified at node startup.

The domain key is an Ed25519 keypair created on the first node ("genesis")
and used to sign admission certs for sibling nodes. **Stage 1** (current)
holds the secret in software, encrypted at rest with `DDS_DOMAIN_PASSPHRASE`
(Argon2id + ChaCha20-Poly1305). **Stage 2** will move the secret onto a
FIDO2 authenticator via the `DomainSigner` trait, with no other code changes
required.

#### Bootstrapping a domain

```bash
# 1. Genesis ceremony — admin creates the domain on their machine.
DDS_DOMAIN_PASSPHRASE=… dds-node init-domain --name acme.com --dir ./acme
# Writes acme/domain.toml (public, share with siblings)
# Writes acme/domain_key.bin (secret, keep safe)

# 2. On a sibling node machine — generate its libp2p identity, print PeerId.
dds-node gen-node-key --data-dir ~/.dds
# → peer_id: 12D3KooW…

# 3. Admin signs an admission cert for that PeerId.
DDS_DOMAIN_PASSPHRASE=… dds-node admit \
    --domain-key ./acme/domain_key.bin \
    --domain     ./acme/domain.toml \
    --peer-id    12D3KooW… \
    --out        admission.cbor \
    --ttl-days   365

# 4. Ship admission.cbor to the sibling, place at ~/.dds/admission.cbor,
#    write a dds.toml that references the public domain info, then run.
dds-node run dds.toml
```

A node refuses to start without a valid admission certificate matching its
own peer id and the configured domain pubkey.

Topics: `/dds/v1/dom/<domain-tag>/org/<org-hash>/{ops,revocations,burns}`

### Local Authority Service (`dds-node`)

`dds-node` runs as a local service providing:

- **User enrollment** — FIDO2/passkey attestation → signed `UserAuthAttestation` token
- **Device enrollment** — Hardware ID/TPM → signed `DeviceJoinDocument` token
- **Session issuance** — Resolves trust graph → short-lived `SessionDocument` (< 1ms check)
- **Policy resolution** — Evaluates access against trust graph + policy rules
- **Status reporting** — Peer count, DAG operations, trust stats

### Domain Documents (`dds-domain`)

Typed payloads embedded inside signed tokens via `body_type` + `body_cbor`:

| Document | Use Case |
|---|---|
| `UserAuthAttestation` | FIDO2/passkey user enrollment |
| `DeviceJoinDocument` | Device enrollment + TPM attestation |
| `WindowsPolicyDocument` | GPO-equivalent policy distribution |
| `SoftwareAssignment` | App/package deployment manifest |
| `ServicePrincipalDocument` | Machine/service identity |
| `SessionDocument` | Short-lived auth session |

## Cryptography

| Scheme | Algorithm | Standard | Key Size | Sig Size |
|---|---|---|---|---|
| Classical | Ed25519 | RFC 8032 | 32 B | 64 B |
| Classical | ECDSA-P256 | FIPS 186-4 | 65 B | 64 B |
| Post-Quantum | ML-DSA-65 | FIPS 204 | 1,952 B | 3,309 B |
| **Hybrid (default)** | Ed25519 + ML-DSA-65 | IETF composite | **1,984 B** | **3,373 B** |
| **Triple-Hybrid** | Ed25519 + ECDSA-P256 + ML-DSA-65 | Max compat | **2,049 B** | **3,437 B** |

Both signatures are always produced and both must verify. Feature-flagged (`pq`, on by default). Disable for embedded: `cargo build --no-default-features --features std`

FIDO2 leaf identities use classical Ed25519 or ECDSA-P256 (hardware limitation). Trust roots use hybrid. Quantum resistance flows from the vouch chain.

## `no_std`

`dds-core` compiles without the Rust standard library (`#![no_std]` + `alloc`), enabling deployment on bare-metal embedded targets (Cortex-M), UEFI firmware, WebAssembly, and TPM co-processors. Higher-level crates (`dds-store`, `dds-net`, `dds-node`) use `std`.

## Project Status

See [STATUS.md](STATUS.md) for detailed progress, module tables, and proposed next steps.

See [DDS-Design-Document.md](DDS-Design-Document.md) for the full design specification.

## License

MIT OR Apache-2.0
