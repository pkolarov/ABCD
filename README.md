# DDS — Decentralized Directory Service

A peer-to-peer identity and access management system built in Rust. DDS provides offline-capable authentication and authorization using cryptographically signed tokens, CRDTs for conflict-free replication, and libp2p for peer-to-peer networking.

**Quantum-resistant token signatures** — hybrid Ed25519 + ML-DSA-65 (FIPS 204) on every token.

> ⚠ **Scope of the PQ claim.** The hybrid signature applies to the
> token / attestation layer only. The libp2p **transport handshake**
> (Noise XX over X25519, QUIC over rustls/ECDHE) is currently
> classical — see Z-1 in
> [Claude_sec_review.md](Claude_sec_review.md) and
> [docs/threat-model-review.md](docs/threat-model-review.md) §4 for the
> Harvest-Now-Decrypt-Later exposure and the planned remediation. Do
> not market DDS as end-to-end post-quantum until Z-1 closes.

**9 crates · 22,000 lines of Rust · 5 platform bindings**

## Quick Start

```bash
# Build everything
cargo build --workspace

# Run all Rust tests
cargo test --workspace

# Build the shared library for platform bindings
cargo build -p dds-ffi --release

# Run Python binding tests (requires shared lib)
python3 -m pytest bindings/python/test_dds.py -v
```

### Windows MSI Installer

```powershell
# Build the all-in-one MSI (installs node, credential provider, auth bridge, policy agent)
cd platform\windows\installer
.\Build-Msi.ps1 -Platform x64   # or arm64
```

See [DDS Admin Guide — Windows Deployment](docs/DDS-Admin-Guide.md#windows-deployment) for details.

## Documentation

| Document | Audience | Description |
|---|---|---|
| **[DDS Admin Guide](docs/DDS-Admin-Guide.md)** | Administrators | Domain setup, node deployment, user enrollment, policy, monitoring |
| **[DDS Developer Guide](docs/DDS-Developer-Guide.md)** | Developers | End-to-end walkthrough of how DDS works under the hood |
| **[Design Document](docs/DDS-Design-Document.md)** | Architects | Formal specification (§1–§14): identity, CRDTs, P2P, tokens, policy, trust |
| **[Implementation Whitepaper](docs/DDS-Implementation-Whitepaper.md)** | Engineers | Technical deep-dive on implementation choices and performance budgets |
| **[AD Drop-in Replacement Roadmap](docs/AD-drop-in-replacement-roadmap.md)** | Architects / Product | Gap map and claim-gated roadmap for DDS to become a credible AD DS replacement |
| **[Observability Plan](docs/observability-plan.md)** | Operators / Engineers | Audit emission, Prometheus `/metrics`, Alertmanager rules, SIEM export, CLI ops surface — closes Z-3 and the AD-roadmap §4.9 Monitoring/SIEM row |
| **[Supply-Chain Integrity & Self-Update Plan](docs/supply-chain-plan.md)** | Operators / Architects | Code-signing of DDS releases, two-signature gate on managed software, SLSA provenance / SBOM / `cargo-vet`, multi-sig fleet self-update — closes Z-6 / Z-7 / Z-8 |
| **[Hardware-Bound Admission Plan](docs/hardware-bound-admission-plan.md)** | Architects | Phased plan to bind libp2p admission identity to TPM / Secure Enclave — closes Z-2 |
| **[STATUS.md](STATUS.md)** | Contributors | Module-by-module implementation tracker with test counts |
| **[Claude_sec_review.md](Claude_sec_review.md)** | Security reviewers | Source-validated security review with per-finding remediation status (latest pass 2026-04-21 — all Critical + High findings closed; 2026-04-26 zero-trust audit added Z-1..Z-5 open items) |
| **[Threat Model Review](docs/threat-model-review.md)** | Architects | Narrative threat model with resolved / open items per subsystem |

### Platform-Specific

| Document | Description |
|---|---|
| [Windows Credential Provider](docs/crayonic-cp-integration-plan.md) | C++ CP integration plan (Crayonic fork) |
| [Windows E2E](platform/windows/e2e/README.md) | Windows smoke test: node + CP + policy agent |
| [macOS Platform](platform/macos/README.md) | macOS policy agent and installer |
| [macOS E2E](platform/macos/e2e/README.md) | Two-machine macOS mesh validation |
| [Second Node](platform/macos/packaging/SECOND-NODE.md) | Adding nodes to an existing domain |
| [Load Test](dds-loadtest/README.md) | Soak/smoke harness and KPI verdicts |

## Architecture

```
┌─────────────────────────────────────────────────┐
│               dds-node  /  dds-cli              │
│          (binaries — node daemon + CLI)          │
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

| Crate | Type | Purpose |
|---|---|---|
| `dds-core` | lib (`no_std`) | Crypto, identity, tokens (extensible body), CRDTs, trust graph, policy engine |
| `dds-domain` | lib | Typed domain documents: auth, device, policy, software, service, session |
| `dds-store` | lib | Storage traits + MemoryBackend + RedbBackend (ACID) |
| `dds-net` | lib | libp2p transport, gossipsub, Kademlia, mDNS, delta-sync |
| `dds-node` | lib + bin | P2P daemon + local authority HTTP API |
| `dds-ffi` | cdylib | C ABI for Python/C#/Swift/Kotlin bindings |
| `dds-cli` | bin | CLI: identity, group, policy, status, enroll, admin, audit, platform, cp, debug, export/import |
| `dds-loadtest` | bin | Multi-node load/soak test harness |
| `dds-fido2-test` | bin | WebAuthn testing utility |

## Interfaces

### Node Daemon (`dds-node`)

```bash
# Genesis ceremony — create a new DDS domain
dds-node init-domain --name acme.com --dir ./acme [--fido2]

# Generate node identity and print PeerId
dds-node gen-node-key --data-dir ~/.dds

# Rotate the node's libp2p identity in place (threat-model §2 rec #3 /
# §8 open item #9). Backs up the old key, generates a fresh keypair,
# and prints the admin / operator follow-up commands needed to issue
# a new admission cert + revoke the old peer id before restart.
dds-node rotate-identity --data-dir ~/.dds [--no-backup]

# Issue admission cert for a sibling node
dds-node admit --domain-key ./acme/domain_key.bin --domain ./acme/domain.toml \
    --peer-id 12D3KooW… [--out admission.cbor] [--ttl-days 365]

# Revoke / inspect / import an admission revocation
# (revocations propagate domain-wide via H-12 piggy-back gossip;
#  the manual import path stays as a force-immediate fallback)
dds-node revoke-admission --domain-key ./acme/domain_key.bin --domain ./acme/domain.toml \
    --peer-id 12D3KooW… [--reason "key compromise"] [--out admission_revocation.cbor]
dds-node import-revocation --data-dir ~/.dds --in admission_revocation.cbor
dds-node list-revocations --data-dir ~/.dds [--json]

# Tighten the data-directory DACL (Windows MSI custom action target;
# no-op on macOS/Linux where Unix file modes are authoritative)
dds-node restrict-data-dir-acl --data-dir 'C:\ProgramData\DDS'

# Create a single-file provisioning bundle
dds-node create-provision-bundle --dir ./acme --org acme [--out provision.dds]

# Provision a new node from bundle (one command, one touch)
dds-node provision bundle.dds [--data-dir ~/.dds] [--no-start]

# Start the node
dds-node run [config.toml]
```

### CLI (`dds-cli`)

The `dds` CLI wraps every `dds-node` HTTP endpoint and also exposes
offline local-store operations. Remote subcommands share the global
`--node-url` flag (default `http://127.0.0.1:5551`). Offline subcommands
share `--data-dir` (default `.dds`).

```bash
# ---- Offline / local store ----
dds identity create alice                # Ed25519
dds identity create quantum-bob --hybrid # Ed25519 + ML-DSA-65
dds identity show urn:vouchsafe:alice.<hash>

dds group vouch  --as-label admin --user urn:vouchsafe:bob.<hash> --purpose group:backend
dds group revoke --as-label admin --jti vouch-admin-bob-<uuid>

dds policy check --user urn:vouchsafe:bob.<hash> --resource repo:main --action read
dds status                               # local store counters

# ---- Remote (requires a running dds-node) ----
dds status --remote                      # GET  /v1/status
dds policy check --user ... --resource ... --action ... --remote
                                         # POST /v1/policy/evaluate

# Enrollment
dds enroll user   --label alice --credential-id <b64url> \
    --attestation-object <b64> --client-data-hash <b64> \
    --rp-id example.com --display-name "Alice"
dds enroll device --label laptop --device-id <uuid> --hostname lap01 \
    --os windows --os-version 11

# Admin bootstrap (first admin / subsequent vouches)
dds admin setup --label root-admin --credential-id <b64url> \
    --attestation-object <b64> --client-data-hash <b64> \
    --rp-id example.com --display-name "Root"
dds admin vouch --subject-urn urn:vouchsafe:bob.<hash> \
    --credential-id <b64url> --authenticator-data <b64> \
    --client-data-hash <b64> --signature <b64> --purpose group:admins

# Audit log
dds audit list                           # newest first
dds audit list --action vouch --limit 50

# Platform applier queries (agent-facing, but useful for debugging)
dds platform windows policies  --device-urn urn:vouchsafe:laptop.<hash>
dds platform windows software  --device-urn urn:vouchsafe:laptop.<hash>
dds platform windows applied   --from-file report.json
dds platform windows claim-account --device-urn ... --session-token-b64 <b64>
dds platform macos   policies  --device-urn ...

# Credential Provider helpers
dds cp enrolled-users [--device-urn ...]
dds cp session-assert --credential-id ... --authenticator-data ... \
    --client-data-hash ... --signature ...

# Debugging
dds debug ping                           # reachability check
dds debug stats                          # pretty-printed NodeStatus
dds debug config ./config.toml           # offline TOML validation

# Air-gapped sync (USB stick / courier)
dds --data-dir ./node-a export --out sync.ddsdump   # package tokens + CRDT ops + revocations
dds --data-dir ./node-b import --in  sync.ddsdump   # idempotent merge into sibling node
dds --data-dir ./node-b import --in  sync.ddsdump --dry-run   # preview only
```

### HTTP API (`dds-node`)

`api_addr` is scheme-dispatched — production deployments should pick
**UDS or named pipe** so peer credentials gate the admin endpoints
and the device-binding helper pins callers to `device_urn` on
reads:

| `api_addr` | Transport | Peer auth |
|---|---|---|
| `127.0.0.1:5551` | loopback TCP (Linux/macOS dev default) | none |
| `unix:/var/run/dds/api.sock` | Unix domain socket | `SO_PEERCRED` / `getpeereid` |
| `pipe:dds-api` | Windows named pipe (`\\.\pipe\dds-api`); **Windows MSI default since A-2 (2026-04-25)** | primary user SID |

When `network.api_auth.node_hmac_secret_path` is set, every response
body also carries `X-DDS-Body-MAC` (HMAC-SHA256) so Windows Auth
Bridge clients can verify response integrity. The MSI provisions
this secret; locally, run
`dds-node gen-hmac-secret --out <FILE>`.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/v1/enroll/user` | FIDO2/passkey user enrollment |
| `POST` | `/v1/enroll/device` | Device enrollment + hardware attestation |
| `GET` | `/v1/session/challenge` | Fresh single-use session challenge |
| `POST` | `/v1/session/assert` | Issue session from FIDO2 assertion |
| `GET` | `/v1/enrolled-users` | List enrolled users |
| `POST` | `/v1/policy/evaluate` | Offline policy evaluation |
| `GET` | `/v1/status` | Node diagnostics (peers, DAG, trust) |
| `GET` | `/v1/node/info` | Node pubkey + peer id (for agent pinning) |
| `GET` | `/v1/windows/policies` | Windows policy for this device |
| `GET` | `/v1/macos/policies` | macOS policy for this device |
| `GET` | `/v1/audit/entries` | Signed audit-log slice |

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

### FFI — C ABI for all platforms (`dds-ffi`)

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
| Linux/macOS | Python (ctypes) | `bindings/python/dds.py` | 13 |
| Windows | C# (P/Invoke) | `bindings/csharp/DDS.cs` | 11 |
| Android | Kotlin (JNA) | `bindings/kotlin/.../DDS.kt` | 10 |
| iOS/macOS | Swift (C module) | `bindings/swift/.../DDS.swift` | 10 |

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

## License

MIT OR Apache-2.0
