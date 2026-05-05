# Decentralized Directory Service (DDS) — Design Document

**Version:** 0.2 (Draft)
**Date:** 2026-04-10  (security sections §8.4–§8.7 revised 2026-04-21)

---

## 1. Problem Statement

Active Directory (AD) provides identity, group membership, policy enforcement, and trust delegation for organizations. However, AD depends on centralized domain controllers, LDAP connectivity, and real-time network access. When the network is unavailable — in disaster zones, edge deployments, contested environments, or disconnected field operations — AD-based authorization collapses entirely.

**Goal:** Design a Decentralized Directory Service (DDS) that provides AD-equivalent capabilities (identity, groups, policies, delegation, revocation) without centralized servers, functioning fully offline and converging when connectivity returns.

---

## 2. Design Principles

1. **Zero infrastructure** — No central servers, registries, blockchains, or certificate authorities required for trust verification
2. **Offline-first** — All identity verification, authorization, and policy evaluation happen locally
3. **Every node is a full node** — Inspired by Minima: each device carries the full directory state relevant to it
4. **Convergent** — When peers reconnect, directory state converges deterministically via CRDTs
5. **Cryptographically verifiable** — All assertions are signed, content-addressed, and self-verifying
6. **Minimal footprint** — Designed to run on constrained devices (phones, IoT, field laptops)

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    DDS Node                              │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │  Identity     │  │  Directory   │  │  Policy       │  │
│  │  Layer        │  │  CRDT Store  │  │  Engine       │  │
│  │  (Vouchsafe)  │  │              │  │               │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬────────┘  │
│         │                 │                  │           │
│  ┌──────┴─────────────────┴──────────────────┴────────┐  │
│  │              Token Processing Pipeline              │  │
│  │          (JWT validation, trust graph eval)          │  │
│  └──────────────────────┬──────────────────────────────┘  │
│                         │                                │
│  ┌──────────────────────┴──────────────────────────────┐  │
│  │              P2P Sync Layer (libp2p)                 │  │
│  │     Gossipsub · Kademlia DHT · mDNS · Maxima        │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐  │
│  │         Storage (MMR-inspired compact store)         │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Identity Layer — Vouchsafe Integration

### 4.1 Self-Verifying Identities

Every principal (user, device, service) in DDS has a **Vouchsafe ID**:

```
urn:vouchsafe:<label>.<base32-sha256-of-public-key>
```

Identity properties:
- **Cryptographically bound** — The ID is derived from the public key via SHA-256 + Base32. Change the key, the ID changes. No spoofing possible.
- **No registry needed** — Anyone can verify the binding using only the ID and the public key (included in every token).
- **Offline verifiable** — Verification is a local SHA-256 computation, no network call.
- **Human-readable label** — The label prefix (e.g., `alice`, `fileserver-01`) aids usability while the hash suffix provides cryptographic binding.

### 4.2 FIDO2 Bridge

Users authenticate to their local DDS node via **FIDO2/WebAuthn** (hardware keys, biometrics). The FIDO2 ceremony produces a signature proof that is then wrapped into a Vouchsafe attestation token:

```json
{
  "iss": "urn:vouchsafe:alice.4z2vjf6zjk3j3xkwcu58ftwks61uyd4a",
  "iss_key": "BASE64_ED25519_PUBLIC_KEY",
  "jti": "uuid-v4",
  "sub": "uuid-v4",
  "kind": "vch:attest",
  "purpose": "fido2-auth",
  "fido2_credential_id": "base64url-credential-id",
  "fido2_authenticator_aaguid": "device-aaguid",
  "iat": 1714605000,
  "exp": 1714691400
}
```

This bridges the passwordless FIDO2 world with Vouchsafe's portable trust model. The attestation can then be vouched for by organizational authorities to grant directory access.

### 4.3 Token Types for Directory Operations

DDS maps Vouchsafe token types to directory operations:

| Directory Operation | Vouchsafe Token Type | Example |
|---|---|---|
| Create user/device identity | Attestation (`vch:attest`) | Self-issued identity declaration |
| Add member to group | Vouch (`vch:vouch`) | Admin vouches for user's group membership token |
| Delegate admin rights | Vouch chain | Admin vouches for sub-admin's delegation token |
| Remove from group | Revocation (`vch:revoke`) | Admin revokes group membership vouch |
| Decommission identity | Burn (`vch:burn`) | Identity owner permanently retires key |
| Policy assignment | Attestation with `purpose` | Policy scoped by purpose filtering |

### 4.4 Trust Graph as Directory

The Vouchsafe trust graph naturally forms a directory structure:

- **Organizational root** = A well-known Vouchsafe identity whose public key is pre-shared
- **Organizational Units** = Purpose-scoped delegation chains (e.g., `purpose: "ou:engineering"`)
- **Group membership** = A vouch from a group-admin identity for a user identity, with `purpose: "group:devops"`
- **Nested groups** = Chained vouches with intersectional purpose filtering (scope can only narrow, never expand)
- **Trust boundaries** = Separate root identities for different organizations; cross-org trust via explicit vouches

```
OrgRoot (vch:attest)
├── vouch → Admin-A (purpose: "admin ou:engineering")
│   ├── vouch → User-1 (purpose: "group:backend")
│   ├── vouch → User-2 (purpose: "group:backend group:oncall")
│   └── vouch → SubAdmin-B (purpose: "admin group:frontend")
│       └── vouch → User-3 (purpose: "group:frontend")
└── vouch → Admin-C (purpose: "admin ou:operations")
    └── vouch → ServiceAcct-1 (purpose: "group:monitoring")
```

---

## 5. Data Model — CRDTs for Directory State

### 5.1 Why CRDTs

In a decentralized system without coordination, concurrent edits (e.g., two admins modifying group membership simultaneously while offline) must converge deterministically. **Conflict-Free Replicated Data Types (CRDTs)** guarantee eventual consistency without consensus protocols.

### 5.2 Directory Primitives as CRDTs

| AD Concept | CRDT Type | Semantics |
|---|---|---|
| User/Device entries | LWW-Register (Last-Writer-Wins) | Mutable attributes (display name, email) with timestamp ordering |
| Group membership | 2P-Set with remove-wins | Members can be added and removed; removal takes precedence over concurrent add |
| Security policies | Policy-CRDT (custom) | Remove-wins semantics for security-critical revocations |
| OU hierarchy | Causal DAG | Operations form a directed acyclic graph with causal dependencies |
| Trust delegations | Append-only log per identity | Vouches and revocations form an immutable, ordered log |

### 5.3 Remove-Wins for Security

Following the p2panda convergent access control model, DDS uses **remove-wins** conflict resolution for security-sensitive operations:

- If one admin adds a user to a group and another concurrently removes them, the **removal wins**
- This ensures the principle of least privilege under concurrent modifications
- Rationale: It is safer to deny access that should have been granted (correctable) than to grant access that should have been denied (potential breach)

### 5.4 Operation Ordering via DAG

Each directory mutation is an **operation** linked to its causal predecessors, forming a DAG:

```json
{
  "op_id": "uuid-v7",
  "author": "urn:vouchsafe:admin-a.hash...",
  "op_type": "group_add",
  "target_group": "group:backend",
  "target_member": "urn:vouchsafe:user-1.hash...",
  "deps": ["uuid-of-predecessor-op"],
  "vouchsafe_vouch_jti": "jti-of-backing-vouch-token",
  "timestamp": 1714605000
}
```

- **`deps`** links to predecessor operations, establishing causal order
- When two operations are concurrent (neither depends on the other), conflict resolution rules apply (remove-wins for memberships)
- The DAG structure allows efficient delta-sync: nodes exchange only operations the peer hasn't seen

### 5.5 Compact State via MMR (Minima-Inspired)

Inspired by Minima's Merkle Mountain Range approach:

- Each node stores only the **current directory state** plus proofs for entries relevant to it
- Historical operations can be pruned once their effects are reflected in the current state
- A **root hash** of the MMR tree summarizes the entire directory state, enabling efficient integrity checks
- Storage target: **< 50MB** for a typical organizational directory (thousands of entries)

### 5.6 Cryptographic Audit Log

DDS includes an append-only cryptographic audit log to record all trust graph mutations (attest, vouch, revoke, burn) for compliance and forensic tracing. Each entry is signed by the node that performed the action and synced via gossipsub.
To minimize network overhead and storage growth, the audit log is an **opt-in** feature. It must be explicitly enabled in the domain configuration (`domain.toml` or `DomainConfig`) during domain creation. If disabled, nodes converge on the final directory state without retaining the full historical sequence of operations.

---

## 6. P2P Network Layer

### 6.1 Transport — libp2p

DDS uses **libp2p** as the networking substrate:

- **Gossipsub** — Mesh-based pub/sub for propagating directory operations. Nodes subscribe to topics mapped to organizational units or groups.
- **Kademlia DHT** — Peer discovery and routing across the wider network
- **mDNS** — Local network peer discovery for zero-config LAN operation
- **Noise protocol** — Transport encryption for all peer connections

> ⚠ **Partial: post-quantum gap in the transport handshake (Z-1, High).**
> The Noise XX handshake still uses X25519 DH and the QUIC keyshare
> still uses classical ECDHE (rustls). Token signatures are hybrid PQ
> (Ed25519+ML-DSA-65), and as of **Z-1 Phase A (2026-04-28)** the
> `AdmissionCert` and `AdmissionRevocation` are also hybrid PQ — a
> v2-hybrid domain (`Domain.pq_pubkey` populated) rejects any cert or
> revocation that lacks the ML-DSA-65 component.
> **Z-1 Phase B (complete 2026-05-01)** closed the application-layer
> Harvest-Now-Decrypt-Later gap: gossipsub messages and sync payloads
> are now AEAD-encrypted under a per-publisher ML-KEM-768 epoch key on
> `enc-v3` domains, so plaintext is not recoverable even from recorded
> ciphertext. The transport channel itself is **still not** post-quantum
> (Noise XX uses classical DH); full transport PQ awaits hybrid-Noise
> upstream (rust-libp2p tracking issue rs/9595) or Phase C.
> Tracked in [Claude_sec_review.md](../Claude_sec_review.md) Z-1 and
> [docs/threat-model-review.md](threat-model-review.md) §4.

### 6.2 Domain Isolation & Topic Structure

DDS nodes belong to a **domain** — a cryptographic realm identified by
`DomainId = sha256(domain_pubkey)`, displayed as `dds-dom:<base32>`. Nodes
from different domains cannot peer at all: the domain tag is baked into
the libp2p protocol strings, so handshakes between mismatched domains fail
during protocol negotiation.

```
/dds/kad/1.0.0/<domain-tag>               — Kademlia
/dds/id/1.0.0/<domain-tag>                — Identify
```

Within a domain, only nodes holding an **admission certificate** signed by
the domain key may join. The cert binds the node's libp2p `PeerId` to the
`DomainId` and is verified at startup. The domain key is created on the
first node ("genesis"); in Stage 1 it is held in software (encrypted at
rest with `DDS_DOMAIN_PASSPHRASE`), and in Stage 2 it will move onto a
FIDO2 authenticator via the `DomainSigner` trait.

Directory operations are published to Gossipsub topics organized by
(domain, org) scope:

```
/dds/v1/dom/<domain-tag>/org/<org-root-hash>/ops          — All operations for an org
/dds/v1/dom/<domain-tag>/org/<org-root-hash>/revocations  — Dedicated revocation channel
/dds/v1/dom/<domain-tag>/org/<org-root-hash>/burns        — Identity burns (high priority)
```

- Revocations and burns are propagated on **separate high-priority topics** to ensure rapid dissemination
- Nodes subscribe only to topics relevant to their scope (e.g., a device in OU:Engineering subscribes to that OU's topic, plus the revocation/burn topics)

### 6.3 Sync Protocol

When two nodes connect (or reconnect after being offline):

1. **Exchange state summaries** — Each node sends its MMR root hash
2. **If hashes differ** — Begin DAG-based delta sync:
   - Exchange the set of operation IDs each node has
   - Transfer missing operations
   - Each received operation is validated (Vouchsafe signature check, CRDT merge)
3. **Converge** — Both nodes arrive at identical directory state

This is similar to Minima's approach where nodes exchange block headers first, then request missing data.

### 6.4 Offline Operation

When a node is offline:
- It continues to evaluate authorization using its local directory state
- New operations (e.g., local group changes by an authorized admin) are queued
- Upon reconnection, queued operations are disseminated via Gossipsub
- CRDT merge guarantees convergence regardless of the order or timing of sync

---

## 7. JWT/Token Format — DDS Directory Tokens

### 7.1 Directory Entry Token

A directory entry is represented as a Vouchsafe attestation:

```json
{
  "iss": "urn:vouchsafe:user-1.abc123hash",
  "iss_key": "BASE64_ED25519_PUBKEY",
  "jti": "entry-uuid",
  "sub": "entry-uuid",
  "kind": "vch:attest",
  "purpose": "dds:directory-entry",
  "dds_display_name": "Alice Johnson",
  "dds_email": "alice@example.org",
  "dds_device_type": "laptop",
  "dds_ou": "engineering",
  "iat": 1714605000,
  "exp": 1746141000
}
```

### 7.2 Group Membership Token

An admin vouches for a user's membership in a group:

```json
{
  "iss": "urn:vouchsafe:admin-a.def456hash",
  "iss_key": "BASE64_ED25519_PUBKEY",
  "jti": "membership-uuid",
  "sub": "entry-uuid-of-user-1",
  "vch_iss": "urn:vouchsafe:user-1.abc123hash",
  "vch_sum": "sha256-of-user-1-entry-token",
  "kind": "vch:vouch",
  "purpose": "dds:group:backend-devs",
  "iat": 1714606000,
  "exp": 1746142000
}
```

### 7.3 Policy Token

A policy (e.g., "members of group:backend-devs can access resource X") is an attestation:

```json
{
  "iss": "urn:vouchsafe:org-root.xyz789hash",
  "iss_key": "BASE64_ED25519_PUBKEY",
  "jti": "policy-uuid",
  "sub": "policy-uuid",
  "kind": "vch:attest",
  "purpose": "dds:policy",
  "dds_policy_rule": {
    "effect": "allow",
    "principal_purpose": "dds:group:backend-devs",
    "resource": "repo:main-service",
    "actions": ["read", "write", "deploy"]
  },
  "iat": 1714607000,
  "exp": 1746143000
}
```

### 7.4 Revocation Flow

To remove a user from a group, the admin issues a revocation token targeting the membership vouch:

```json
{
  "iss": "urn:vouchsafe:admin-a.def456hash",
  "iss_key": "BASE64_ED25519_PUBKEY",
  "jti": "revocation-uuid",
  "sub": "entry-uuid-of-user-1",
  "revokes": "membership-uuid",
  "vch_iss": "urn:vouchsafe:user-1.abc123hash",
  "vch_sum": "sha256-of-user-1-entry-token",
  "kind": "vch:revoke",
  "iat": 1714608000
}
```

Note: Per Vouchsafe spec, revocation tokens **MUST NOT** include `exp` — they are permanent and take effect immediately.

---

## 8. Security & Trust Model

### 8.1 Threat Model

| Threat | Mitigation |
|---|---|
| Forged identity | Impossible — identity is cryptographically bound to key via SHA-256 hash |
| Forged group membership | Requires a valid vouch from an authorized admin; signature verification prevents forgery |
| Stale permissions (user removed but node hasn't synced) | Remove-wins CRDT ensures removal propagates; high-priority revocation topic accelerates dissemination |
| Replay of revoked tokens | Nodes maintain a revocation set; `vch_sum` content-addressing prevents substitution |
| Partition attack (isolate a node to prevent revocation receipt) | Nodes should require periodic sync or reduce trust in stale state; configurable staleness threshold |
| Key compromise | Burn token permanently retires compromised identity; new identity must be re-vouched |
| Sybil attack | Organizational root must vouch for all legitimate identities; un-vouched identities have no directory standing |

### 8.2 Revocation Propagation Guarantees

- Revocations propagate on a **dedicated Gossipsub topic** with higher mesh redundancy
- Burn tokens receive **highest priority** in sync — always exchanged first
- Nodes track a **staleness timer** — if no sync has occurred within a configurable window (e.g., 24 hours), the node can optionally degrade to read-only or restricted mode
- Anti-entropy background sync ensures revocations are eventually received even if gossip messages are lost

### 8.3 Trust Chain Depth Limits

To prevent resource exhaustion in trust graph evaluation:
- Maximum delegation chain depth: **configurable, default 5**
- Cycle detection: Impossible by design (Vouchsafe's `vch_sum` content-addressing means vouch chains are strictly acyclic)
- Verification is bounded deterministic computation

### 8.4 Per-Peer Admission (H-12)

A DDS node binds to its domain by holding an `AdmissionCert` — a
domain-key signature over `(domain_id, peer_id, issued_at,
expires_at)`. The signature is Ed25519 on legacy v1 domains; on
v2-hybrid domains (Z-1 Phase A, `Domain.pq_pubkey` populated) the
cert additionally carries an ML-DSA-65 (FIPS 204) signature with the
`dds-admission-v2/mldsa65\0` domain separator, and the verifier
rejects any cert lacking the PQ component. Self-verification at
startup is necessary but not sufficient: without a peer-facing
exchange, any libp2p peer that completes Noise can publish into
gossip/sync without being admitted.

Design:

- A dedicated `request_response::cbor::Behaviour` on
  `/dds/admission/1.0.0/<domain_tag>` runs immediately after Noise.
  Each side sends an `AdmissionRequest` and the peer answers with
  its admission cert (carried as opaque CBOR bytes so the network
  layer stays independent of the domain layer).
- `DdsNode::admitted_peers: BTreeSet<PeerId>` is populated only
  after `AdmissionCert::verify_with_domain(&domain,
  &peer_id.to_string(), now)` succeeds — the v2-aware entry point
  that re-verifies the body invariants and the Ed25519 signature, and
  on a v2-hybrid `Domain` also requires the ML-DSA-65 `pq_signature`
  to verify (Z-1 Phase A). Failure is silently logged; the peer stays
  unadmitted.
- Gossipsub `Event::Message { propagation_source, .. }` is gated on
  `propagation_source ∈ admitted_peers` before the message reaches
  `handle_gossip_message`. Sync request/response events are gated
  the same way — unadmitted requesters have their channel dropped;
  unadmitted responders' payloads are ignored.
- `ConnectionClosed` removes the peer from the set, so a
  reconnecting peer must re-verify.
- C-3's publisher-capability filter (§8.5) remains as the last line
  of defence even after H-12.

### 8.5 Publisher Capabilities (C-3)

Policy and software attestations are only admitted into the trust
graph when the issuer chains back to a trusted root with the
matching publisher-capability vouch: `dds:policy-publisher-windows`,
`dds:policy-publisher-macos`, or `dds:software-publisher`. The
filter (`publisher_capability_ok` in `dds-node/src/node.rs`) runs
both on gossip ingest and again on the serve side of
`list_applicable_*`. Unauthorised attestations never land in the
graph and never reach the Policy Agents.

### 8.6 HTTP API Transport Auth (H-6 / H-7)

The local HTTP API's `api_addr` dispatches on scheme:

| Scheme | Transport | Peer cred |
|---|---|---|
| `127.0.0.1:<port>` | loopback TCP (legacy; Linux/macOS dev default) | none — `CallerIdentity::Anonymous` |
| `unix:/path` | Unix domain socket | `SO_PEERCRED` / `getpeereid` → `CallerIdentity::Uds { uid, gid, pid }` |
| `pipe:<name>` | Windows named pipe (Windows MSI default since A-2) | `GetNamedPipeClientProcessId` + `OpenProcessToken` + `GetTokenInformation(TokenUser)` → `CallerIdentity::Pipe { sid, pid }` |

Admin endpoints (`/v1/enroll/*`, `/v1/admin/*`, `/v1/enrolled-users`,
`/v1/audit/entries`) run through `require_admin_middleware`, which
evaluates the caller against `AdmissionPolicy.{admin_uids,
admin_sids, service_uid}`. Device-scoped endpoints
(`/v1/{windows,macos}/{policies,software,applied}`) run through
`check_device_binding_read` / `tofu_device_binding`, which TOFU-bind
the first caller to a device URN and refuse mismatched follow-ups.

The Windows Auth Bridge picks its transport via
`HKLM\SOFTWARE\DDS\AuthBridge\ApiAddr` (REG_SZ) — added in **A-2
(2026-04-25)** — which is forwarded verbatim to
`CDdsNodeHttpClient::SetBaseUrl`. Empty falls back to the legacy
`DdsNodePort` DWORD (TCP loopback). The MSI provisions
`ApiAddr = pipe:dds-api`, matching the shipped `node.toml` template
(`api_addr = 'pipe:dds-api'` + `trust_loopback_tcp_admin = false`)
and the Policy Agent's `appsettings.json`
(`NodeBaseUrl = "pipe:dds-api"`). Stock MSI installs reach the
named-pipe transport without operator changes.

Response-body MAC (H-6): when configured, every response carries
`X-DDS-Body-MAC: base64(HMAC-SHA256(key, method || 0 || path || 0
|| body))`. The Windows Auth Bridge verifies the MAC before
processing the response, defeating the
challenge-substitution-via-port-squat attack. The MSI provisions
the 32-byte per-install secret; `dds-node gen-hmac-secret --out
<FILE>` is the operator tool.

### 8.7 Keyfile Format v=3 (M-10)

Encrypted identity keyfiles now carry the Argon2id parameters in
the blob so future parameter bumps don't require yet another
schema version:

```
{ v: 3,
  salt: bytes(16),
  nonce: bytes(12),
  key: encrypted_bytes,
  m_cost: uint,   // KiB
  t_cost: uint,   // iterations
  p_cost: uint }  // parallelism
```

v=3 defaults are **m=64 MiB, t=3, p=4** (OWASP tier-2 — target
unlock 200–500 ms on modern hardware). Legacy v=2 blobs (19 MiB,
t=2, p=1) load successfully and are transparently rewrapped to
v=3 on first save. Plaintext downgrade is refused when an
`<path>.encrypted-marker` is present (M-14); operators can opt
into a plaintext rewrite with
`DDS_NODE_ALLOW_PLAINTEXT_DOWNGRADE=1` for disposable dev
environments.

---

## 9. AD Feature Mapping

| Active Directory Feature | DDS Equivalent |
|---|---|
| Domain Controller | Every node is a full node (Minima pattern) |
| LDAP directory | CRDT-based directory store with Vouchsafe tokens |
| Kerberos authentication | FIDO2 + Vouchsafe attestation tokens |
| Group Policy Objects (GPO) | `WindowsPolicyDocument` with typed `WindowsSettings` bundle (§14.5.1) |
| GPO enforcement (registry, security policy) | `DdsPolicyAgent` Windows Service with pluggable enforcers (§14.5.4) |
| Software deployment (SCCM/Intune) | `SoftwareAssignment` document + `SoftwareInstaller` enforcer (§14.5.1) |
| Linux fleet policy / config management | `LinuxPolicyDocument` + `DdsPolicyAgent.Linux` + systemd/PAM bridges (§14.6) |
| macOS device configuration / profile management | `MacOsPolicyDocument` + `DdsPolicyAgent.MacOS` (§14.7) |
| Standalone local account management | `AccountDirective` / `MacAccountDirective` via platform appliers, with external-directory guard (§14.5.5, §14.7.4) |
| macOS enterprise account / SSO coexistence | `MacAccountBindingDocument` + `SsoIdentityLinkDocument` layered on top of directory or Platform SSO-owned login flows (§14.7.1, §14.7.5) |
| Password policy (Fine-Grained) | `PasswordPolicyEnforcer` via `PasswordPolicy` directive (§14.5.1) |
| Organizational Units | Purpose-filtered delegation chains |
| Group membership | Vouch tokens from authorized admins |
| Trust relationships (cross-domain) | Cross-org vouches between root identities |
| Replication | Gossipsub + DAG-based delta sync |
| Sites and subnets | Gossipsub topic partitioning + mDNS for local discovery |
| FSMO roles | No equivalent needed — no single-master operations; all ops are CRDT-mergeable |
| DNS integration | Kademlia DHT for name resolution |
| Schema | Token format defined by `kind` and `purpose` conventions + typed domain documents |
| Windows logon (Credential Provider) | Native `DdsCredentialProvider` + `DdsAuthBridge` — passkey → `/v1/session/assert` → optional first-account claim (§14.5) |

---

## 10. Performance Requirements & Resource Budgets

### 10.1 Deployment Tiers

DDS targets three deployment tiers. All requirements below are **hard constraints** that must be validated during implementation with automated benchmarks in CI.

| Property | Tier 1: Embedded/RTOS | Tier 2: Mobile | Tier 3: Desktop/Server |
|---|---|---|---|
| **Example devices** | Cortex-M4/M7 @ 168 MHz, field radios, IoT gateways | Android/iOS phones, tablets | Linux servers, Windows workstations, macOS laptops |
| **Directory scale** | ≤ 500 entries | ≤ 5,000 entries | ≤ 100,000 entries |
| **Crates used** | `dds-core` only | `dds-core` + `dds-store` + `dds-net` | Full stack |

### 10.2 Data Sizes — Token & Directory Primitives

| Data Item | JSON (bytes) | CBOR (bytes) | Notes |
|---|---|---|---|
| Ed25519 public key (raw) | — | 32 | Fixed |
| Ed25519 signature (raw) | — | 64 | Fixed |
| Single directory entry token | ~400–500 | ~200–250 | User/device attestation |
| Group membership vouch | ~450–550 | ~225–275 | Vouch from admin to user |
| Policy token | ~500–700 | ~275–350 | Includes policy rule object |
| Revocation token | ~350–450 | ~175–225 | References revoked JTI |
| CRDT operation envelope | ~200–300 | ~100–150 | DAG deps + op metadata |

**Derived directory sizes (CBOR, on-disk with redb overhead):**

| Directory Scale | Entries | Est. Tokens | Raw CBOR | redb On-Disk | In-Memory (CRDT state) |
|---|---|---|---|---|---|
| **Patrol team** | 20 | ~100 | ~25 KB | ~100 KB | ~50 KB |
| **Company** | 200 | ~1,000 | ~250 KB | ~1 MB | ~500 KB |
| **Battalion** | 1,000 | ~5,000 | ~1.25 MB | ~5 MB | ~2.5 MB |
| **Brigade** | 5,000 | ~25,000 | ~6.25 MB | ~25 MB | ~12.5 MB |
| **Enterprise** | 50,000 | ~250,000 | ~62.5 MB | ~250 MB | ~125 MB |
| **Large enterprise** | 100,000 | ~500,000 | ~125 MB | ~500 MB | ~250 MB |

*Assumption: ~5 tokens per entry (1 identity + 3 group memberships + 1 policy reference average).*

### 10.3 RAM Budgets

| Resource | Tier 1: Embedded | Tier 2: Mobile | Tier 3: Desktop/Server |
|---|---|---|---|
| **Minimum RAM** | 64 KB | 16 MB | 128 MB |
| **Target working set** | ≤ 256 KB | ≤ 50 MB | ≤ 512 MB |
| **Hard ceiling** | 512 KB | 200 MB | 2 GB |
| **Directory state** | ≤ 50 KB (500 entries) | ≤ 12.5 MB (5K entries) | ≤ 250 MB (100K entries) |
| **CRDT metadata overhead** | ~20% of directory state | ~20% | ~20% |
| **libp2p connection state** | N/A | ~2 MB (8 peers) | ~5 MB (20 peers) |
| **Revocation set** | ≤ 10 KB | ≤ 500 KB | ≤ 5 MB |
| **Operation queue (offline)** | ≤ 50 KB | ≤ 2 MB | ≤ 20 MB |

### 10.4 Storage (ROM / Flash / HDD)

| Resource | Tier 1: Embedded | Tier 2: Mobile | Tier 3: Desktop/Server |
|---|---|---|---|
| **Binary size (stripped)** | ≤ 512 KB (`dds-core` only) | ≤ 8 MB (full stack) | ≤ 15 MB (full stack + CLI) |
| **Database on disk** | N/A (in-memory) | ≤ 50 MB | ≤ 1 GB |
| **Operation log (before prune)** | ≤ 100 KB | ≤ 10 MB | ≤ 100 MB |
| **Log retention** | Last 100 ops | Last 10K ops | Last 100K ops or 30 days |

### 10.5 CPU / MCU Performance Targets

#### Cryptographic Operations

| Operation | Tier 1: Cortex-M4 @ 168 MHz | Tier 2: ARM Cortex-A78 | Tier 3: x86_64 (modern) |
|---|---|---|---|
| **Ed25519 sign** | ~5 ms (~200/sec) | ~0.05 ms (~20K/sec) | ~0.02 ms (~50K/sec) |
| **Ed25519 verify** | ~7 ms (~143/sec) | ~0.07 ms (~14K/sec) | ~0.015 ms (~67K/sec) |
| **SHA-256 (256 bytes)** | ~0.1 ms | ~0.001 ms | ~0.0005 ms |
| **Trust chain (depth 3)** | ~21 ms (~48/sec) | ~0.21 ms (~4.8K/sec) | ~0.045 ms (~22K/sec) |

#### Directory Operations

| Operation | Tier 1 | Tier 2 | Tier 3 | Notes |
|---|---|---|---|---|
| **Local policy evaluation** (no crypto) | ≤ 0.1 ms | ≤ 0.01 ms | ≤ 0.005 ms | Pure computation, no I/O |
| **Full auth check** (parse + verify + chain + policy) | ≤ 50 ms | ≤ 1 ms | ≤ 0.3 ms | End-to-end local decision |
| **CRDT merge** (single operation) | ≤ 1 ms | ≤ 0.05 ms | ≤ 0.01 ms | — |
| **Bulk sync merge** (1,000 ops) | ≤ 2 sec | ≤ 100 ms | ≤ 20 ms | After reconnection |
| **Directory lookup by ID** | ≤ 5 ms | ≤ 0.1 ms | ≤ 0.05 ms | redb B-tree lookup |

### 10.6 Network I/O Budgets

| Metric | Target | Notes |
|---|---|---|
| **Idle gossip overhead** | ≤ 2 KB/sec | Heartbeats across ~8 mesh peers |
| **Single operation broadcast** | ~300–500 bytes | One CBOR-encoded CRDT op + signature |
| **Revocation broadcast** | ~200–300 bytes | High-priority, separate topic |
| **Delta sync (10 new ops)** | ~3–5 KB | Typical reconnection after short offline |
| **Delta sync (1,000 ops)** | ~300–500 KB | Reconnection after extended offline |
| **Full directory sync (1K entries)** | ~1.5–2.5 MB | Cold start or new node bootstrap |
| **Full directory sync (10K entries)** | ~15–25 MB | — |
| **Sync negotiation overhead** | ~1–2 KB | MMR root hash exchange + Bloom filter |
| **Max sustained throughput** | ≤ 50 KB/sec per peer | Avoid saturating constrained links |

### 10.7 Latency KPIs

| KPI | Target | Measurement |
|---|---|---|
| **Local auth decision** | **≤ 1 ms** (Tier 3), ≤ 50 ms (Tier 1) | From request to allow/deny, fully offline |
| **Revocation propagation (connected mesh)** | **≤ 5 seconds** to 95% of nodes | Gossipsub fanout |
| **Sync convergence (2 peers reconnect)** | **≤ 3 seconds** for ≤ 100 pending ops | Delta sync protocol |
| **Cold start to operational** | **≤ 2 seconds** (Tier 3), ≤ 5 sec (Tier 2) | Load DB + join mesh |
| **Bootstrap (new node, full sync)** | **≤ 30 seconds** for 10K-entry directory | Over 10 Mbps link |

### 10.8 Staleness & Consistency KPIs

| KPI | Default | Configurable Range |
|---|---|---|
| **Max acceptable directory staleness** | 24 hours | 1 hour – 7 days |
| **Staleness action** | Degrade to read-only | read-only, deny-all, warn-only |
| **Revocation set max age** | 4 hours | 30 min – 24 hours |
| **Anti-entropy sync interval** | 60 seconds (when connected) | 10 sec – 10 min |
| **Gossip mesh target peers** | 8 | 4 – 20 |

### 10.9 CI Benchmark Requirements

All performance targets above must be enforced via automated benchmarks:

```toml
# Cargo.toml — benchmark configuration
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
dhat = "0.3"               # Heap profiling for memory budget validation

[[bench]]
name = "crypto_ops"         # Ed25519 sign/verify, SHA-256, trust chains
harness = false

[[bench]]
name = "crdt_merge"         # Single op merge, bulk merge (100, 1K, 10K ops)
harness = false

[[bench]]
name = "policy_eval"        # Policy evaluation at various directory scales
harness = false

[[bench]]
name = "sync_protocol"      # Delta sync negotiation + transfer at various scales
harness = false

[[bench]]
name = "memory_budget"      # Validate RAM usage stays within tier budgets
harness = false
```

**CI gates (fail the build if violated):**
- Ed25519 verify on x86_64: ≥ 50,000 ops/sec
- Full auth check on x86_64: ≤ 0.5 ms p99
- CRDT merge (single op): ≤ 0.05 ms p99
- Peak heap for 1K-entry directory: ≤ 5 MB
- Peak heap for 10K-entry directory: ≤ 50 MB
- `dds-core` binary size (thumbv7em, stripped): ≤ 512 KB

---

## 11. Open Questions & Future Work

1. **Key rotation** — How does a user rotate their Ed25519 key while maintaining directory continuity? Potential approach: self-vouch from old key to new key before burning old identity.

2. **Large-scale performance** — How does Gossipsub perform with 10K+ nodes and frequent directory changes? Need benchmarking.

3. **Selective sync** — Can nodes subscribe to only the directory subset they need, while still verifying trust chains that span other parts of the directory?

4. **Regulatory compliance** — How to handle "right to be forgotten" in an append-only operation log? MMR pruning may help.

5. **Recovery from mass key compromise** — If the org root key is compromised, what is the recovery path? Multi-sig root identities?

6. **Integration with existing AD** — Hybrid mode where DDS syncs with AD when connected and operates independently when disconnected.

7. **Audit trail** — The DAG of operations naturally forms an audit log, but how to make it queryable and exportable?

8. **Bandwidth optimization** — Bloom filters or similar probabilistic structures for efficient sync negotiation.

---

## 12. Technical Architecture — Crate Structure

The DDS implementation is a **Rust workspace** organized into layered crates with strict dependency boundaries. The innermost crate (`dds-core`) is `no_std`-compatible, enabling deployment from embedded RTOS devices to full desktop environments.

```
dds/
├── Cargo.toml                    (workspace root)
├── dds-core/                     (no_std + alloc — portable everywhere)
│   ├── src/
│   │   ├── identity.rs           Vouchsafe ID generation, key handling
│   │   ├── token.rs              Token parsing, validation, signature checks
│   │   ├── crdt/
│   │   │   ├── lww_register.rs   Last-Writer-Wins register
│   │   │   ├── twop_set.rs       2P-Set with remove-wins
│   │   │   ├── causal_dag.rs     DAG operation ordering
│   │   │   └── mod.rs
│   │   ├── policy.rs             Policy evaluation engine
│   │   ├── trust.rs              Trust graph traversal, chain validation
│   │   └── lib.rs
│   └── Cargo.toml                [no_std, alloc]
│
├── dds-store/                    (std — storage abstraction)
│   ├── src/
│   │   ├── traits.rs             Storage trait definitions
│   │   ├── redb_backend.rs       redb implementation
│   │   ├── memory_backend.rs     In-memory (for tests + embedded)
│   │   └── lib.rs
│   └── Cargo.toml
│
├── dds-net/                      (std + tokio — P2P networking)
│   ├── src/
│   │   ├── transport.rs          libp2p swarm setup, Noise encryption
│   │   ├── gossip.rs             Gossipsub topic management
│   │   ├── discovery.rs          Kademlia DHT + mDNS
│   │   ├── sync.rs               Delta-sync protocol (DAG exchange)
│   │   └── lib.rs
│   └── Cargo.toml
│
├── dds-node/                     (Full node binary — all layers combined)
│   ├── src/
│   │   ├── main.rs               Entry point, config loading
│   │   ├── api.rs                Local REST/gRPC API for client apps
│   │   └── metrics.rs            Observability
│   └── Cargo.toml
│
├── dds-ffi/                      (UniFFI interface definitions)
│   ├── src/lib.rs                UniFFI exported functions
│   ├── dds.udl                   UniFFI Definition Language file
│   └── Cargo.toml
│
├── dds-cli/                      (CLI tooling)
│   ├── src/main.rs               Identity management, group ops, diagnostics
│   └── Cargo.toml
│
└── platform/
    ├── windows/
    │   ├── DdsCredentialProvider/    C# COM credential provider for Windows logon
    │   ├── DdsPolicyAgent/           .NET 8 worker service — policy enforcement
    │   │   ├── Client/               HTTP client for dds-node /v1/windows/* API
    │   │   ├── Config/               Agent configuration model
    │   │   ├── State/                Applied-state persistence (idempotency)
    │   │   └── Enforcers/            Registry, Account, PasswordPolicy, Software, Service
    │   ├── DdsPolicyAgent.Tests/     xUnit tests (cross-platform via InMemory* doubles)
    │   └── installer/                WiX v4 MSI bundle (Build-Msi.ps1 + DdsBundle.wxs)
    ├── linux/
    │   ├── DdsPolicyAgent/           .NET 8 worker service — Linux policy enforcement
    │   │   ├── Client/               HTTP client for dds-node /v1/linux/* API
    │   │   ├── State/                Applied-state persistence in /var/lib/dds
    │   │   └── Enforcers/            Users, Sudoers, Files, Systemd, Packages, Sysctl, Sshd
    │   ├── DdsPolicyAgent.Tests/     xUnit tests (cross-platform via InMemory* doubles)
    │   ├── pam_dds/                  Rust crate: pam_dds.so cdylib + dds-pam-helper binary
    │   └── packaging/                .deb / .rpm / systemd unit assets
    ├── macos/
    │   ├── DdsPolicyAgent/           .NET 8 launchd daemon — macOS policy enforcement
    │   │   ├── Client/               HTTP client for dds-node /v1/macos/* API
    │   │   ├── State/                Applied-state persistence in /Library/Application Support/DDS
    │   │   └── Enforcers/            Preferences, Accounts, launchd, Profiles, Software
    │   ├── DdsPolicyAgent.Tests/     xUnit tests (cross-platform via InMemory* doubles)
    │   ├── DdsLoginBridge/           Authorization Services / session bootstrap bridge (v2, planned)
    │   └── packaging/                pkgbuild/productbuild/notarization assets
    ├── android/                  Kotlin wrapper via UniFFI
    ├── ios/                      Swift wrapper via UniFFI
    └── embedded/                 no_std integration examples (Embassy)
```

### Dependency Flow

```
dds-core  ←──  dds-store  ←──  dds-node
(no_std)       (std)           (std + tokio)
    ↑              ↑               ↑
    │              │               │
    └──────────────┴───── dds-net (std + tokio)
                                   │
dds-core  ←──  dds-ffi            │
                   ↑               │
                   └───────────────┘
```

**Rule:** `dds-core` MUST NOT depend on `std`, `tokio`, or any platform-specific crate. All crypto, token validation, CRDT logic, and policy evaluation live here. This is the crate that runs everywhere — including bare-metal RTOS.

---

## 13. Technology Stack — Library Selection

All libraries below are open source, mature (1.0+ or production-deployed), and actively maintained.

### 13.1 Core Libraries (used in `dds-core`, `no_std`-compatible)

| Library | Version | Purpose | Downloads | License | `no_std` |
|---|---|---|---|---|---|
| **ed25519-dalek** | 2.2.x | Ed25519 signing & verification | 112M+ | BSD-3 | ✅ |
| **p256** | 0.13.x | ECDSA-P256 for FIDO2 compatibility | 30M+ | MIT/Apache-2.0 | ✅ |
| **sha2** | 0.10.x | SHA-256 for Vouchsafe ID derivation | 150M+ | MIT/Apache-2.0 | ✅ |
| **base32** | 0.5.x | Base32 encoding for Vouchsafe URNs | 15M+ | MIT/Apache-2.0 | ✅ |
| **serde** | 1.x | Serialization framework | 400M+ | MIT/Apache-2.0 | ✅ |
| **ciborium** | 0.2.x | CBOR encoding (compact wire format) | 18M+ | Apache-2.0 | ✅ |
| **uuid** | 1.x | UUIDv4/v7 for operation IDs | 200M+ | MIT/Apache-2.0 | ✅ (with feature flag) |
| **heapless** | 0.8.x | Fixed-capacity collections for `no_std` | 55M+ | MIT/Apache-2.0 | ✅ |

### 13.2 Storage Layer (`dds-store`)

| Library | Version | Purpose | Notes | License |
|---|---|---|---|---|
| **redb** | 2.x | Embedded key-value database | ACID, stable file format, pure Rust, zero-copy reads. Chosen over sled (pre-1.0, unstable format). | MIT/Apache-2.0 |

### 13.3 Networking Layer (`dds-net`)

| Library | Version | Purpose | Notes | License |
|---|---|---|---|---|
| **rust-libp2p** | 0.55.x | P2P networking framework | Gossipsub, Kademlia DHT, mDNS, Noise protocol, QUIC transport. 6M+ downloads. Production-used by IPFS, Polkadot, Filecoin. | MIT |
| **tokio** | 1.x | Async runtime | 300M+ downloads. Required by rust-libp2p. | MIT |

### 13.4 Authentication (`dds-node`)

| Library | Version | Purpose | Notes | License |
|---|---|---|---|---|
| **webauthn-rs** | 0.5.x | FIDO2/WebAuthn relying party | 2.6M+ downloads. From the Kanidm project. Covers passkeys, security keys, attestation. | MPL-2.0 |

### 13.5 FFI & Cross-Language Bindings (`dds-ffi`)

| Library | Version | Purpose | Notes | License |
|---|---|---|---|---|
| **UniFFI** (Mozilla) | 0.29.x | Multi-language binding generator | Generates Swift, Kotlin, Python, Ruby bindings from `.udl` definitions. Battle-tested in Firefox. | MPL-2.0 |
| **uniffi-bindgen-cs** (NordSecurity) | 0.9.x | C# binding generator for UniFFI | Extends UniFFI to generate C# P/Invoke bindings. Used in production by NordVPN. | MPL-2.0 |

### 13.6 Serialization & Wire Format

| Format | Library | When Used |
|---|---|---|
| **CBOR** | ciborium | Over-the-wire: gossip messages, sync payloads (50-70% smaller than JSON) |
| **JSON** | serde_json | Token display, REST API responses, human-readable debug output |
| **Postcard** | postcard | On-disk storage serialization in redb (compact, `no_std`-friendly) |

---

## 14. Cross-Platform Strategy

### 14.1 Platform Matrix

| Platform | Runtime | Networking | Storage | Auth | Build Tooling |
|---|---|---|---|---|---|
| **Linux x86_64/ARM** | tokio | rust-libp2p (TCP+QUIC) | redb | webauthn-rs + PAM/SSH bridge | `cargo build` + `dotnet publish` |
| **macOS x86_64/ARM** | tokio | rust-libp2p (TCP+QUIC) | redb | webauthn-rs + LocalAuthentication / Authorization bridge | `cargo build` + `dotnet publish` |
| **Windows x86_64** | tokio | rust-libp2p (TCP+QUIC) | redb | webauthn-rs + Credential Provider bridge | `cargo build --target x86_64-pc-windows-msvc` + `dotnet publish` |
| **Android (ARM64)** | tokio | rust-libp2p (TCP+QUIC) | redb | Platform FIDO2 | `cargo ndk -t arm64-v8a` |
| **iOS (ARM64)** | tokio | rust-libp2p (TCP+QUIC) | redb | Platform FIDO2 | `cargo build --target aarch64-apple-ios` |
| **Embedded RTOS** | Embassy | Custom transport | In-memory | N/A (pre-provisioned) | `cargo build --target thumbv7em-none-eabihf` |

For the three managed desktop/server platforms, DDS uses the same core pattern:

- `dds-node` stays a portable Rust daemon with trust graph, sync, and localhost API;
- an OS-specific privileged agent polls localhost for applicable policy/software;
- optional login/auth bridges integrate DDS sessions into the platform's local auth stack.

### 14.2 Rust Core + Native Shell Pattern

```
┌──────────────────────────────────────────────────────┐
│  Platform-Native UI                                  │
│  ┌────────┐ ┌──────────┐ ┌───────┐ ┌──────────────┐ │
│  │ C#/WPF │ │ Swift UI │ │Kotlin │ │ GTK/Terminal │ │
│  │(Windows)│ │  (iOS)   ││(Droid)│ │   (Linux)    │ │
│  └────┬───┘ └────┬─────┘ └──┬───┘ └──────┬───────┘ │
│       │          │           │             │         │
│  ┌────┴──────────┴───────────┴─────────────┴───────┐ │
│  │           UniFFI Generated Bindings              │ │
│  │   (C# via uniffi-bindgen-cs, Swift, Kotlin)      │ │
│  └──────────────────────┬───────────────────────────┘ │
│                         │ C ABI                       │
│  ┌──────────────────────┴───────────────────────────┐ │
│  │              dds-ffi (Rust cdylib)                │ │
│  │    ┌─────────┐ ┌──────────┐ ┌─────────────────┐  │ │
│  │    │dds-core │ │ dds-net  │ │   dds-store     │  │ │
│  │    │(no_std) │ │ (libp2p) │ │   (redb)        │  │ │
│  │    └─────────┘ └──────────┘ └─────────────────┘  │ │
│  └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

### 14.3 Windows C# Client Details

The Windows client uses C# for the UI layer with DDS Rust core exposed via UniFFI:

```csharp
// Auto-generated by uniffi-bindgen-cs from dds.udl
using DdsCore;

var node = DdsNode.Start(new DdsConfig {
    StoragePath = @"C:\Users\alice\AppData\Local\DDS\store",
    ListenAddresses = new[] { "/ip4/0.0.0.0/tcp/4001" },
    BootstrapPeers = new[] { "/ip4/10.0.1.1/tcp/4001/p2p/QmPeerIdHere" }
});

// Verify a user's group membership locally (offline-capable)
var isMember = node.EvaluateGroupMembership(
    userId: "urn:vouchsafe:alice.4z2vjf6zjk3j3xkwcu58ftwks61uyd4a",
    group: "group:backend-devs"
);

// Issue a vouch (admin operation)
var vouch = node.CreateGroupVouch(
    targetUser: "urn:vouchsafe:bob.9x7abcd...",
    group: "group:backend-devs",
    signingKey: adminKeyHandle
);
```

### 14.4 Embedded / RTOS Considerations

For constrained devices (e.g., field radios, IoT gateways, military hardware):

- **Only `dds-core` is required** — Token validation, policy evaluation, trust chain verification all work in `no_std` + `alloc`
- **Async runtime:** Embassy (Rust async framework for embedded) replaces tokio
- **Networking:** Transport-agnostic — `dds-core` accepts serialized operations from any transport (BLE, LoRa, serial, mesh radio). A thin platform adapter feeds operations into the CRDT engine.
- **Storage:** In-memory backend with optional persistence to flash via platform HAL
- **Pre-provisioned trust:** Embedded devices are provisioned with the organizational root public key and their own identity token at manufacturing/deployment time. No FIDO2 ceremony needed — identity is baked in.
- **Memory budget:** `dds-core` targets **< 256KB RAM** for a typical directory cache (hundreds of entries) using `heapless` fixed-capacity collections

```rust
// Embedded example — no_std, no networking, just policy evaluation
#![no_std]
extern crate alloc;

use dds_core::{DirectoryState, PolicyEngine, VouchsafeToken};

fn check_access(state: &DirectoryState, requester_token: &[u8], resource: &str) -> bool {
    let token = VouchsafeToken::parse(requester_token).unwrap();
    let engine = PolicyEngine::new(state);
    engine.evaluate(&token, resource, "read")
}
```

### 14.5 Windows Platform — Policy Enforcement Architecture

DDS replaces Active Directory Group Policy with a decentralized, gossip-propagated
policy model. The enforcement architecture separates concerns across three components
that run on each managed Windows device:

```
┌──────────────────────────────────────────────────────────────┐
│  Managed Windows Device                                      │
│                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────┐  │
│  │      dds-node            │  │  DdsCredentialProvider   │  │
│  │  (Rust, LocalSystem)     │  │  (C++ COM, LogonUI)      │  │
│  │                          │  │                          │  │
│  │  • Trust graph           │  │  Logon tile              │  │
│  │  • Policy evaluation     │  │  KERB packing            │  │
│  │  • Gossip + sync         │  └──────────┬───────────────┘  │
│  │  • HTTP API on 127.0.0.1 │             │ named pipe       │
│  └──────────┬───────────────┘    ┌────────┴───────────────┐  │
│             │ loopback HTTP      │    DdsAuthBridge       │  │
│  ┌──────────┴───────────────┐    │  (C++ Windows Service) │  │
│  │    DdsPolicyAgent        │    │                        │  │
│  │  (.NET 8, LocalSystem)   │    │  • WebAuthn getAssertion│ │
│  │                          │    │  • hmac-secret vault    │ │
│  │  Poll /v1/windows/*      │    │  • /v1/session/assert   │ │
│  │  every 60s               │    │  • /v1/windows/claim-account │
│  │                          │    └─────────────────────────┘  │
│  │  ┌──────────────────┐    │                                │
│  │  │ Registry Enforcer│    │                                │
│  │  │ Account Enforcer │    │                                │
│  │  │ Password Policy  │    │                                │
│  │  │ Software Install │    │                                │
│  │  └──────────────────┘    │                                │
│  │                          │                                │
│  │  State: %ProgramData%    │                                │
│  │         \DDS\applied-    │                                │
│  │         state.json       │                                │
│  └──────────────────────────┘                                │
└──────────────────────────────────────────────────────────────┘
```

**Separation of concerns:**

| Component | Language | Runs as | Responsibility |
| --- | --- | --- | --- |
| `dds-node` | Rust | Windows Service (LocalSystem) | Directory service: trust graph, gossip, sync, policy evaluation, HTTP API |
| `DdsAuthBridge` | C++ | Windows Service (LocalSystem) | WebAuthn + hmac-secret broker: `/v1/session/assert`, `/v1/windows/claim-account`, local vault |
| `DdsPolicyAgent` | .NET 8 | Windows Service (LocalSystem) | Post-boot enforcement: poll dds-node, dispatch to enforcers, report outcomes |
| `DdsCredentialProvider` | C++ | COM in-proc (LogonUI) | Windows logon tile: talk to Auth Bridge and pack `KERB_INTERACTIVE_UNLOCK_LOGON` |

`dds-node` never calls Win32 APIs — it is the same binary on all platforms.
Windows-specific code lives in the native Auth Bridge / Credential Provider
pair and in `DdsPolicyAgent`. This separation keeps the directory layer
portable while still allowing pre-logon Windows integration.

#### 14.5.1 Domain Document Types for Enforcement

Two domain document types (defined in `dds-domain/src/types.rs`) carry the
enforcement payload through the trust graph:

**WindowsPolicyDocument** (`body_type: "dds:windows-policy"`):

```
WindowsPolicyDocument
├── policy_id: String          # e.g. "security/password-policy"
├── display_name: String
├── version: u64               # monotonically increasing
├── scope: PolicyScope         # who this targets
│   ├── device_tags: [String]  # e.g. ["workstation", "developer"]
│   ├── org_units: [String]    # e.g. ["engineering"]
│   └── identity_urns: [String]# direct device URN targeting
├── settings: [PolicySetting]  # free-form key/value (escape hatch)
├── enforcement: Enforcement   # Audit | Enforce | Disabled
└── windows: Option<WindowsSettings>   # strongly-typed bundle
    ├── registry: [RegistryDirective]
    │   ├── hive: RegistryHive         # LocalMachine | CurrentUser | Users | ClassesRoot
    │   ├── key: String                # e.g. "SOFTWARE\Policies\Microsoft\Windows\System"
    │   ├── name: Option<String>       # value name, None = (Default)
    │   ├── value: Option<RegistryValue># String | ExpandString | Dword | Qword | MultiString | Binary
    │   └── action: RegistryAction     # Set | Delete
    ├── local_accounts: [AccountDirective]
    │   ├── username: String
    │   ├── action: AccountAction      # Create | Delete | Disable | Enable
    │   ├── claim_subject_urn: Option<String>  # subject allowed to first-claim this local account
    │   ├── full_name: Option<String>
    │   ├── description: Option<String>
    │   ├── groups: [String]           # additive membership
    │   └── password_never_expires: Option<bool>
    ├── password_policy: Option<PasswordPolicy>
    │   ├── min_length: Option<u32>
    │   ├── max_age_days: Option<u32>
    │   ├── min_age_days: Option<u32>
    │   ├── history_size: Option<u32>
    │   ├── complexity_required: Option<bool>
    │   ├── lockout_threshold: Option<u32>
    │   └── lockout_duration_minutes: Option<u32>
    └── services: [ServiceDirective]
        ├── name: String               # e.g. "RemoteRegistry"
        ├── display_name: Option<String>
        ├── start_type: Option<ServiceStartType>  # Boot | System | Automatic | Manual | Disabled
        └── action: ServiceAction      # Configure | Start | Stop
```

**SoftwareAssignment** (`body_type: "dds:software-assignment"`):

```
SoftwareAssignment
├── package_id: String         # e.g. "com.example.editor"
├── display_name: String
├── version: String
├── source: String             # download URL or content hash
├── sha256: String             # package integrity verification
├── action: InstallAction      # Install | Uninstall | Update
├── scope: PolicyScope         # same scope model as WindowsPolicyDocument
├── silent: bool
├── pre_install_script: Option<String>
└── post_install_script: Option<String>
```

Both types are signed Vouchsafe attestation tokens. The trust graph validates
signatures against `trusted_roots` on ingest — the agent never needs to
re-verify. `WindowsPolicyDocument::windows` is `Option` with `serde(default)`
so tokens signed against the pre-Phase-A schema (no `windows` field)
deserialize correctly as `windows: None`.

#### 14.5.2 Scope Matching

The scope model determines which devices receive which policies:

| Scope Configuration | Matches |
| --- | --- |
| Empty scope (all three fields empty) | Every device (global policy) |
| `device_tags: ["workstation"]` | Any device whose `DeviceJoinDocument.tags` contains `"workstation"` |
| `org_units: ["engineering"]` | Any device whose `DeviceJoinDocument.org_unit` is `"engineering"` |
| `identity_urns: ["urn:vouchsafe:device.xxx"]` | That specific device only |
| Multiple fields populated | **Any-of** — matches if any one criterion is satisfied |

The scope filter runs server-side in `dds-node` (via `LocalService::list_applicable_windows_policies`),
not in the agent. This keeps the trust/scope logic in one Rust codebase and means the
.NET agent never needs to embed `dds-ffi`.

#### 14.5.3 dds-node HTTP API — Applier Endpoints

Three new endpoints on the existing localhost HTTP server (`127.0.0.1:5551`):

| Method | Path | Request | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/windows/policies?device_urn=...` | Query string | `{ "policies": [{ "jti", "issuer", "iat", "document": WindowsPolicyDocument }] }` |
| `GET` | `/v1/windows/software?device_urn=...` | Query string | `{ "software": [{ "jti", "issuer", "iat", "document": SoftwareAssignment }] }` |
| `POST` | `/v1/windows/applied` | `AppliedReport` JSON body | `202 Accepted` |

The `AppliedReport` structure:

```json
{
  "device_urn": "urn:vouchsafe:device.xxx",
  "target_id": "security/baseline",
  "version": "7",
  "status": "ok",
  "directives": ["Set LocalMachine\\SOFTWARE\\Policies\\...\\Enabled = 1"],
  "error": null,
  "applied_at": 1712640000
}
```

#### 14.5.4 DdsPolicyAgent — Enforcer Architecture

The agent is a .NET 8 `BackgroundService` (runs as a Windows Service via
`Microsoft.Extensions.Hosting.WindowsServices`). Its poll loop:

1. `GET /v1/windows/policies?device_urn=$self` — fetch all policies scoped to this device
2. For each policy, compute `SHA-256(document_json)` — compare to `applied-state.json`
3. If unchanged → skip (idempotent)
4. If new or changed → dispatch `WindowsSettings` bundle to enforcers
5. `POST /v1/windows/applied` — report outcome per directive
6. Repeat for `/v1/windows/software`
7. Sleep 60 seconds, repeat

**Enforcer interface:**

```csharp
public interface IEnforcer
{
    string Name { get; }
    Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive,
        EnforcementMode mode,  // Audit | Enforce
        CancellationToken ct = default);
}

public sealed record EnforcementOutcome(
    EnforcementStatus Status,  // Ok | Failed | Skipped
    string? Error = null,
    IReadOnlyList<string>? Changes = null);
```

Each enforcer is backed by a testable interface that abstracts the Win32 surface:

| Enforcer | Interface | Win32 Implementation | Test Double |
| --- | --- | --- | --- |
| `RegistryEnforcer` | `IRegistryOperations` | `Microsoft.Win32.Registry` | `InMemoryRegistryOperations` |
| `AccountEnforcer` | `IAccountOperations` | `netapi32` P/Invoke / `DirectoryServices.AccountManagement` | `InMemoryAccountOperations` |
| `PasswordPolicyEnforcer` | `IPasswordPolicyOperations` | `secedit` / `NetUserModalsSet` | `InMemoryPasswordPolicyOperations` |
| `SoftwareInstaller` | `ISoftwareOperations` | `WindowsSoftwareOperations` (`msiexec` / process exec) | `InMemorySoftwareOperations` |
| `ServiceEnforcer` | `IServiceOperations` | `WindowsServiceOperations` (SCM P/Invoke) | `InMemoryServiceOperations` |

All Win32 implementations carry `[SupportedOSPlatform("windows")]`. The DI
container selects the real or in-memory implementation based on the platform,
so the full enforcer logic (idempotency, audit mode, error handling) is
testable on macOS/Linux via `dotnet test`.

#### 14.5.5 Security Controls

**Registry allowlist:** The `RegistryEnforcer` restricts writes to three
HKLM subkey prefixes:

- `SOFTWARE\Policies\*` — standard GPO location
- `SOFTWARE\DDS\*` — DDS-specific configuration
- `SYSTEM\CurrentControlSet\Services\*` — service configuration

Writes to any other path (including non-HKLM hives) are refused with
`EnforcementStatus.Failed`. This limits blast radius if a compromised
`dds-node` pushes a malicious policy.

**Domain-join guard:** The `AccountEnforcer` refuses all local-account
operations when `IJoinStateProbe.Detect()` returns `AdJoined`,
`HybridJoined`, or `Unknown`. This prevents conflicts with AD-managed
accounts on domain-joined machines (v1 scope decision — see
`docs/windows-ad-coexistence-spec.md`). The other policy surfaces
(registry, password policy, software, service) are forced to audit-only
on AD/Hybrid hosts via the `Worker.EffectiveMode` helper (AD-04/05).
The native Windows Auth Bridge applies the same guard before allowing
first-account claim at the logon screen.

**Account name validation:** The `AccountEnforcer` validates both
`username` and group names before any Win32 call. Usernames use an
allowlist: 1–20 characters, only ASCII letters, digits, `.`, `_`,
and `-`; must not end with `.`. This is intentionally stricter than
the raw SAM spec to align with the operations layer and prevent
control-character injection into Win32 APIs. Group names are validated
with the SAM-forbidden character denylist (`" / \ [ ] : ; | = , + *
? < > @`) plus control characters (< 0x20), max 256 characters; spaces
within the name are permitted (e.g. "Remote Desktop Users"), but names
may not end with `.` or space. Strings outside these constraints are
rejected with `EnforcementStatus.Failed` without touching the Win32 layer.

**Service display name length:** The `ServiceEnforcer` caps `display_name`
at 256 characters (Windows SCM registry limit). Names exceeding this
are rejected with `EnforcementStatus.Failed` before the registry write.

**Password handling:** Passwords are never carried in `WindowsPolicyDocument`
or `SoftwareAssignment`. Two Windows flows exist today:

1. For already-known local accounts, enrollment captures the current
   Windows password once and stores it in the local vault encrypted under
   a key derived from FIDO2 `hmac-secret`.
2. For claim-bound accounts (`claim_subject_urn`), the native
   `DdsAuthBridge` generates a random password locally on the first
   successful DDS logon, applies it to the local Windows account, then
   wraps it into the same vault with `hmac-secret`.

The pre-logon claim path is authorized by `dds-node` through
`POST /v1/windows/claim-account`, which accepts a freshly issued local
`dds:session` token from `/v1/session/assert` and resolves the one
policy-authorized local account for that subject and device. A future
`SecretReleaseDocument` or equivalent encrypted release channel remains a
v2 extension, but the current design avoids central plaintext password
distribution for first-account claim.

**Script trust:** Pre/post install scripts in `SoftwareAssignment` are
trusted based on the document's Vouchsafe signature (the admin who signed
the token is the trust anchor). Authenticode-signed-script requirements are
deferred until a code-signing PKI is available.

#### 14.5.6 Idempotency & Applied State

The agent persists `%ProgramData%\DDS\applied-state.json`:

```json
{
  "policies": {
    "security/password-policy": {
      "version": "7",
      "content_hash": "sha256:...",
      "applied_at": 1712640000,
      "status": "ok"
    }
  },
  "software": {
    "com.example.editor": {
      "version": "1.4.2",
      "content_hash": "sha256:...",
      "applied_at": 1712640123,
      "status": "ok"
    }
  },
  "managed_items": {
    "registry": {
      "LocalMachine\\SOFTWARE\\Policies\\DDS\\Feature\\Enabled": {
        "last_outcome": "applied", "host_state_at_apply": "Workgroup",
        "audit_frozen": false, "updated_at": 1712640123
      }
    },
    "accounts": {
      "dds-kiosk": { "last_outcome": "applied", "host_state_at_apply": "Workgroup",
        "audit_frozen": false, "updated_at": 1712640123 }
    },
    "account_groups": {
      "dds-kiosk:Users": { "last_outcome": "applied", "host_state_at_apply": "Workgroup",
        "audit_frozen": false, "updated_at": 1712640123 }
    },
    "software_managed": {
      "com.example.editor": { "last_outcome": "applied", "host_state_at_apply": "Workgroup",
        "audit_frozen": false, "updated_at": 1712640123 }
    }
  }
}
```

The `managed_items` section tracks which items DDS currently owns on the
endpoint, enabling reconciliation of stale items (see §14.5.9).

On each poll cycle, the agent computes `SHA-256(document_json)` and compares
to the stored `content_hash`. If unchanged, the policy is skipped entirely.
This ensures:

- **Restart safety** — the agent picks up where it left off
- **No re-application churn** — unchanged policies are not re-applied
- **Version tracking** — the agent knows which version it last applied

The state file is written atomically (write to `.tmp`, then rename).
ACL: `LocalSystem` write, `Administrators` read, `Users` no access.

#### 14.5.7 Packaging & Deployment

A single **WiX v4 MSI bundle** ships all Windows components:

| Component | Install Path | Registered As |
| --- | --- | --- |
| `dds-node.exe` | `C:\Program Files\DDS\` | Windows Service `DdsNode` |
| `DdsPolicyAgent.exe` | `C:\Program Files\DDS\` | Windows Service `DdsPolicyAgent` |
| `DdsAuthBridge.exe` | `C:\Program Files\DDS\` | Windows Service `DdsAuthBridge` |
| `DdsTrayAgent.exe` | `C:\Program Files\DDS\` | Startup item (HKCU Run key) |
| `DdsCredentialProvider.dll` | `C:\Program Files\DDS\` | COM CLSID `{8C0DBE9A-5E27-4DDA-9A4B-3B5C8A6E2A11}` |
| `DdsConsole.ps1` | `C:\Program Files\DDS\` | Desktop / Start Menu shortcut |
| `Bootstrap-DdsDomain.ps1` | `C:\Program Files\DDS\` | Provisioning helper script |
| `appsettings.json` | `C:\Program Files\DDS\` | Policy Agent configuration |
| `node.toml` | `C:\Program Files\DDS\config\` | DDS Node configuration |
| State directory | `%ProgramData%\DDS\` | ACL: LocalSystem write, Admins read |

The MSI bundle resolved production blockers **B1** (Windows Credential
Provider) and **B2** (cross-platform builds / Windows CI). Both blockers are
fully resolved: the Credential Provider ships code-complete in the MSI; a
`windows-latest` CI job runs the full Windows integration suite end-to-end.

#### 14.5.8 Enforcement Modes

| Mode | Behavior |
| --- | --- |
| `Enforce` | Read current state → compute delta → apply via Win32 → report outcome |
| `Audit` | Read current state → compute delta → log what *would* change → report as `[AUDIT]` |
| `Disabled` | Filtered out server-side by `dds-node` — never reaches the agent |

Audit mode is the recommended rollout strategy: publish policies in `Audit`
first, review the agent logs, then flip to `Enforce` by publishing a new
version of the same `policy_id` with `enforcement: Enforce`.

#### 14.5.9 Reconciliation & Drift Detection

Idempotent per-directive enforcement (§14.5.6) ensures the *desired* state is
applied, but it does not address two critical scenarios:

1. **Stale items** — an item was in a previous policy but has been removed from
   the current policy. Without reconciliation, the old setting/account/package
   persists on the endpoint indefinitely.
2. **Drift** — an admin or script manually changes a DDS-managed value. Without
   reconciliation, the drift is not corrected until the policy document itself
   changes (triggering a hash difference).

**Managed-items tracking.** The applied-state file includes a
`managed_items` map, keyed by enforcer category. Each value is itself a map
from managed-item key to a `ManagedItemRecord`:

```json
{
  "policies": { ... },
  "software": { ... },
  "managed_items": {
    "registry": {
      "LocalMachine\\SOFTWARE\\Policies\\DDS\\Feature\\Enabled": {
        "last_outcome": "applied", "last_reason": null,
        "host_state_at_apply": "Workgroup",
        "audit_frozen": false, "updated_at": 1712640123
      }
    },
    "accounts": { "dds-kiosk": { ... }, "dds-audit": { ... } },
    "account_groups": { "dds-kiosk:Users": { ... } },
    "software_managed": { "com.example.editor": { ... } },
    "services": { "MySvc": { ... } }
  }
}
```

`host_state_at_apply` records the `JoinState` when the item was last written
(enables audit-re-pass on transition). `audit_frozen` is set when
reconciliation would remove an item on an AD/Hybrid/Unknown host; the freeze
clears on the next workgroup-mode reconcile that lists the item.

**Reconciliation algorithm.** On every poll cycle, after all policies and
software assignments have been applied, the Worker executes a reconciliation
pass:

1. **Extract desired set** — scan all current policy documents and build the
   full set of managed-item keys per category (registry paths, usernames,
   group memberships, package IDs, service names, systemd drop-in keys,
   sudoers filenames, sysctl keys).
2. **Compute stale set** — `stale = previously_managed − desired`. Items in
   this set were managed by DDS in a prior cycle but are absent from the
   current policy.
3. **Clean up stale items** — dispatch to the appropriate enforcer:
   - **Registry:** delete the stale value or key (within allowlist).
   - **Accounts:** disable (not delete) stale users to avoid data loss.
   - **Group memberships:** remove the user from the stale group.
   - **Software:** silently uninstall stale packages via `msiexec /x`.
   - **Services:** logged only — no auto-revert. Reversing a prior Stop or
     Configure is ambiguous, so stale service directives are surfaced in the
     reconciliation report for operators to review manually.
4. **Update managed set** — replace the stored managed-items with the
   current desired set.

**Drift correction** is handled by the existing idempotent enforcers: on every
poll cycle, each Set/Create directive re-reads actual state and overwrites if it
differs from desired. Because this happens every 60 seconds, manual drift is
corrected within one poll interval — even when the policy document hash has not
changed.

**Audit mode** applies to reconciliation: when any policy in the cycle specifies
`enforcement: Audit`, the reconciliation pass logs what *would* be removed but
does not actually delete/disable anything.

**Safety guarantees:**

- The reconciliation pass only touches items DDS previously created or set
  (tracked in `managed_items`). Pre-existing system state is never modified.
- Registry cleanup respects the same allowlist as forward enforcement
  (§14.5.5).
- Account cleanup disables rather than deletes, preserving user profiles and
  data for forensic or recovery purposes.
- Software uninstall uses the same `msiexec /x` path as explicit Uninstall
  directives, so it honours MSI rollback on failure.

**Platform scope:** Reconciliation is implemented for Windows, Linux, and macOS
in v1. For Linux: stale users are disabled (not deleted, to preserve home
directories), stale managed files are deleted, stale packages are uninstalled
via the host package manager, stale `sysctl` keys are removed from the managed
drop-in, stale `sudoers` drop-ins are deleted from `/etc/sudoers.d/`, stale
`systemd` drop-in files are deleted from `/etc/systemd/system/<unit>.d/` (with
`daemon-reload`), and the `sshd` drop-in is removed when no current policy
declares an `ssh` field with at least one recognized valid directive (absent field,
`null`, empty object, and all-invalid-value objects are all treated equivalently). Unit-state directives (Enable/Disable/Start/Stop/Restart/Mask/Unmask)
are applied on the forward pass only — reversing them is ambiguous. For macOS:
the same algorithm runs with platform-appropriate backends (dscl, launchctl,
profiles, etc.); generic package uninstall is not supported so stale software
entries are flagged for manual removal.

### 14.6 Linux Platform — Managed Device Architecture

Linux support follows the same high-level split as Windows:

- `dds-node` is the portable Rust daemon;
- `DdsPolicyAgent.Linux` is the privileged applier;
- optional PAM/SSH bridges connect DDS sessions to local authentication paths.

The important design decision is that DDS does **not** try to encode every Linux
distribution quirk into `dds-node`.
All distro-specific behavior stays in the Linux agent and its enforcers.

```
┌──────────────────────────────────────────────────────────────┐
│  Managed Linux Device                                        │
│                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────┐  │
│  │      dds-node            │  │       pam_dds           │  │
│  │   (Rust, systemd)        │  │   (PAM / sshd hook)     │  │
│  │                          │  │                         │  │
│  │  • Trust graph           │  │  login / sudo / ssh     │  │
│  │  • Policy evaluation     │  │  → /v1/session/assert   │  │
│  │  • Gossip + sync         │  └──────────┬──────────────┘  │
│  │  • HTTP API on 127.0.0.1 │             │                 │
│  └──────────┬───────────────┘             │                 │
│             │ loopback HTTP               │                 │
│  ┌──────────┴───────────────┐             │                 │
│  │  DdsPolicyAgent.Linux    │             │                 │
│  │ (.NET 8, root/systemd)   │             │                 │
│  │                          ├─────────────┘                 │
│  │  Poll /v1/linux/*        │                               │
│  │  every 60s               │                               │
│  │                          │                               │
│  │  ┌──────────────────┐    │                               │
│  │  │ SysctlEnforcer   │    │                               │
│  │  │ FileEnforcer     │    │                               │
│  │  │ UserEnforcer     │    │                               │
│  │  │ SudoersEnforcer  │    │                               │
│  │  │ SystemdEnforcer  │    │                               │
│  │  │ SshdEnforcer     │    │                               │
│  │  │ PackageEnforcer  │    │                               │
│  │  └──────────────────┘    │                               │
│  │                          │                               │
│  │  State: /var/lib/dds     │                               │
│  └──────────────────────────┘                               │
└──────────────────────────────────────────────────────────────┘
```

#### 14.6.1 Linux Domain Document Types

Linux policy uses the same envelope conventions as Windows:

- signed Vouchsafe attestation token;
- `PolicyScope` for targeting;
- `Enforcement` for audit/enforce/disabled;
- optional strongly-typed OS bundle plus free-form `settings` escape hatch.

**LinuxPolicyDocument** (`body_type: "dds:linux-policy"`):

```
LinuxPolicyDocument
├── policy_id: String
├── display_name: String
├── version: u64
├── scope: PolicyScope
├── settings: [PolicySetting]
├── enforcement: Enforcement
└── linux: Option<LinuxSettings>
    ├── local_users: [LinuxUserDirective]
    │   ├── username: String
    │   ├── uid: Option<u32>
    │   ├── shell: Option<String>
    │   ├── groups: [String]          # supplementary groups (additive)
    │   ├── full_name: Option<String> # GECOS / full name
    │   └── action: LinuxUserAction   # Create | Delete | Disable | Enable | Modify
    ├── sudoers: [LinuxSudoersDirective]
    │   ├── filename: String          # drop-in name under /etc/sudoers.d/ (no slashes)
    │   ├── content: String           # sudoers rule text
    │   └── content_sha256: Option<String>
    ├── files: [LinuxFileDirective]
    │   ├── path: String              # allowlisted paths only
    │   ├── owner: Option<String>     # "user" or "user:group" (POSIX names only, ≤32 chars each)
    │   ├── mode: Option<String>      # 3–4 octal digits, e.g. "0644" or "644"
    │   ├── content_b64: Option<String>
    │   ├── content_sha256: Option<String>
    │   └── action: LinuxFileAction   # Set | Delete | EnsureDir
    ├── systemd: [LinuxSystemdDirective]
    │   ├── unit: String              # unit name, e.g. "sshd.service"
    │   ├── action: SystemdAction     # Enable | Disable | Start | Stop | Restart | Mask | Unmask | ConfigureDropin | RemoveDropin
    │   ├── dropin_name: Option<String>   # stem for ConfigureDropin / RemoveDropin (no slashes or dots)
    │   └── dropin_content: Option<String> # INI fragment; required for ConfigureDropin
    ├── packages: [LinuxPackageDirective]
    │   ├── name: String              # package name
    │   ├── action: PackageAction     # Install | Remove
    │   └── version: Option<String>
    ├── sysctl: [SysctlDirective]
    │   ├── key: String               # e.g. "net.ipv4.ip_forward"
    │   ├── value: Option<String>     # ignored for Delete
    │   └── action: SysctlAction      # Set | Delete
    └── ssh: Option<SshdPolicy>
        ├── password_authentication: Option<bool>
        ├── permit_root_login: Option<String>   # "yes"|"no"|"prohibit-password"|"forced-commands-only"
        ├── pubkey_authentication: Option<bool>
        ├── allow_users: [String]
        └── allow_groups: [String]
```

`SoftwareAssignment` remains shared across platforms.
On Linux, the agent resolves `SoftwareAssignment.source` into one of:

- distro package repo operation (`apt`, `dnf`, `zypper`);
- direct signed package artifact (`.deb`, `.rpm`);
- pinned tarball / binary drop into an allowlisted install root.

#### 14.6.2 dds-node HTTP API — Linux Endpoints

The Linux agent mirrors the Windows polling pattern with Linux-namespaced endpoints:

| Method | Path | Request | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/linux/policies?device_urn=...` | Query string | `{ "policies": [{ "jti", "issuer", "iat", "document": LinuxPolicyDocument }] }` |
| `GET` | `/v1/linux/software?device_urn=...` | Query string | `{ "software": [{ "jti", "issuer", "iat", "document": SoftwareAssignment }] }` |
| `POST` | `/v1/linux/applied` | `AppliedReport` JSON body | `202 Accepted` |

Server-side scope matching stays in Rust.
The Linux agent never embeds the trust graph or vouch validation logic.

#### 14.6.3 DdsPolicyAgent.Linux — Enforcer Model

`DdsPolicyAgent.Linux` is a .NET 8 worker running as `root` under `systemd`.
The cross-platform agent core is shared with Windows/macOS where practical:

- same poll loop;
- same applied-state hashing and idempotency model;
- same audit/enforce/disabled semantics;
- different enforcer implementations selected by OS.

Linux-specific enforcers:

| Enforcer | Backend | Notes |
| --- | --- | --- |
| `UserEnforcer` | `useradd`, `usermod`, `groupadd`, `passwd -l/-u` | Local accounts only |
| `SudoersEnforcer` | drop-in files under `/etc/sudoers.d/` + `visudo -c` | Safe filename allowlist guards path traversal |
| `FileEnforcer` | atomic temp-write + rename + `chmod`/`chown` | Only allowlisted paths |
| `SystemdEnforcer` | `systemctl` + drop-in files under `/etc/systemd/system/` | Enable/Disable/Start/Stop/Restart/Mask/Unmask units; `ConfigureDropin` drop-ins tracked in state store and reconciled; `RemoveDropin` removes them |
| `PackageEnforcer` | distro package manager abstraction | Backend chosen from host capability |
| `SysctlEnforcer` | `/etc/sysctl.d/*.conf` + `sysctl --system` | Avoids ephemeral-only writes to `/proc/sys` |
| `SshdEnforcer` | managed drop-in under `/etc/ssh/sshd_config.d/` + reload | No direct in-place edits to vendor file |

Persisted state lives at `/var/lib/dds/applied-state.json`.
Config lives under `/etc/dds/`.
Logs go to `journald`.

#### 14.6.4 Linux Security Controls

**Filesystem allowlist:** `FileEnforcer` only writes under:

- `/etc/dds/`
- `/etc/ssh/sshd_config.d/`
- `/etc/sysctl.d/`
- `/etc/systemd/system/`
- `/usr/local/lib/dds/`

This allowlist is enforced inside `FileEnforcer.IsSafePath` (`AllowedPrefixes`), which
is checked before every `Set`, `Delete`, and `EnsureDir` operation — including the
reconciliation stale-delete path.

Writes to `/etc/passwd`, `/etc/shadow`, `/boot`, `/usr/bin`, or arbitrary user
home directories are forbidden.

**Account-source guard:** If the host is joined to an external directory source
through SSSD, `realmd`, LDAP, or AD integration, local-account directives are
rejected by default unless the agent is explicitly configured with
`allowLocalAccountMutationWhenDomainJoined=true`.

**Package trust:** Direct package/file installs require:

- a pinned `sha256` in `SoftwareAssignment`;
- an allowlisted source URL or repository;
- optional GPG signature verification when the backend supports it.

**Privilege minimization:** `pam_dds` talks only to localhost `dds-node` and
never parses trust-graph data itself.
The policy agent runs as `root`, but enforcers are narrowly scoped and path-restricted.

#### 14.6.5 Linux Login And SSH Integration

Linux gives DDS more than one auth surface:

- console / display-manager login via PAM;
- `sudo` elevation via PAM;
- SSH via PAM and optional `AuthorizedKeysCommand` integration.

The v1 design is conservative:

- DDS authenticates and authorizes **existing local accounts**;
- it does not synthesize NSS users on the fly;
- a policy document can map a DDS identity URN to one or more local POSIX accounts.

`pam_dds.so` flow:

1. User selects or enters a local username.
2. PAM module asks local `dds-node` for a DDS session based on WebAuthn/FIDO2 evidence.
3. `dds-node` evaluates trust + policy locally.
4. If allowed, PAM returns success and emits the DDS session metadata for downstream auditing.

This gives Linux near-parity with the Windows Credential Provider idea without
requiring the DDS core to know anything about PAM internals.

#### 14.6.6 Packaging And Deployment

Linux packaging targets:

- `.deb` for Debian/Ubuntu family;
- `.rpm` for RHEL/Fedora/SUSE family;
- systemd units for `dds-node.service` and `dds-policy-agent.service`;
- optional `pam_dds.so` installed under the platform PAM module directory.

State paths:

- config: `/etc/dds/`
- database: `/var/lib/dds/store.redb`
- agent state: `/var/lib/dds/applied-state.json`
- logs: `journald`

### 14.7 macOS Platform — Managed Device Architecture

macOS follows the same control-plane split as Windows and Linux, but the actual
enforcement surface is different:

- `dds-node` remains the portable Rust daemon;
- `DdsPolicyAgent.MacOS` runs as a privileged `launchd` daemon;
- login integration uses macOS security frameworks rather than a Windows-style credential provider.

```
┌──────────────────────────────────────────────────────────────┐
│  Managed macOS Device                                        │
│                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────┐  │
│  │      dds-node            │  │    DdsLoginBridge       │  │
│  │ (Rust, LaunchDaemon)     │  │ (Authorization bridge)  │  │
│  │                          │  │                         │  │
│  │  • Trust graph           │  │  login / unlock /       │  │
│  │  • Policy evaluation     │  │  privileged action      │  │
│  │  • Gossip + sync         │  │  → /v1/session/assert   │  │
│  │  • HTTP API on 127.0.0.1 │  └──────────┬──────────────┘  │
│  └──────────┬───────────────┘             │                 │
│             │ loopback HTTP               │                 │
│  ┌──────────┴───────────────┐             │                 │
│  │  DdsPolicyAgent.MacOS    │             │                 │
│  │(.NET 8, root/launchd)    │             │                 │
│  │                          ├─────────────┘                 │
│  │  Poll /v1/macos/*        │                               │
│  │  every 60s               │                               │
│  │                          │                               │
│  │  ┌──────────────────┐    │                               │
│  │  │ Preferences      │    │                               │
│  │  │ Accounts         │    │                               │
│  │  │ launchd          │    │                               │
│  │  │ Profiles         │    │                               │
│  │  │ Software Install │    │                               │
│  │  └──────────────────┘    │                               │
│  │                          │                               │
│  │  State: /Library/        │                               │
│  │  Application Support/DDS │                               │
│  └──────────────────────────┘                               │
└──────────────────────────────────────────────────────────────┘
```

#### 14.7.1 macOS Domain Document Types

macOS needs DDS to model three separate identities that are often collapsed on
Windows:

1. the **DDS subject** in the trust graph;
2. the **local macOS account** that owns the home folder, Secure Token, and
   FileVault relationship;
3. the **enterprise SSO identity** (AD, Entra, Okta, OpenID Connect, and so on)
   that may own the login window experience.

The document model reflects that split instead of pretending the three layers
are the same object.

**MacOsPolicyDocument** (`body_type: "dds:macos-policy"`):

```
MacOsPolicyDocument
├── policy_id: String
├── display_name: String
├── version: u64
├── scope: PolicyScope
├── settings: [PolicySetting]
├── enforcement: Enforcement
└── macos: Option<MacOsSettings>
    ├── preferences: [PreferenceDirective]
    │   ├── domain: String            # e.g. "com.apple.screensaver"
    │   ├── key: String
    │   ├── value: JsonValue
    │   ├── scope: PreferenceScope    # System | UserTemplate
    │   └── action: PreferenceAction  # Set | Delete
    ├── local_accounts: [MacAccountDirective]
    │   ├── username: String
    │   ├── full_name: Option<String>
    │   ├── shell: Option<String>
    │   ├── admin: Option<bool>
    │   ├── hidden: Option<bool>
    │   └── action: MacAccountAction  # Create | Delete | Disable | Enable | Modify
    ├── launchd: [LaunchdDirective]
    │   ├── label: String
    │   ├── plist_path: String
    │   ├── enabled: Option<bool>
    │   └── action: LaunchdAction     # Load | Unload | Kickstart | Configure
    └── profiles: [ProfileDirective]
        ├── identifier: String
        ├── display_name: String
        ├── payload_sha256: String
        ├── mobileconfig_b64: String
        └── action: ProfileAction     # Install | Remove
```

`MacAccountDirective` is only authoritative on **standalone** Macs where DDS is
allowed to own local account lifecycle. On directory-bound or Platform SSO
managed Macs, the account lifecycle remains external and these directives are
skipped by policy.

**MacAccountBindingDocument** (`body_type: "dds:macos-account-binding"`):

```
MacAccountBindingDocument
├── binding_id: String
├── subject_urn: String
├── device_urn: String
├── local_short_name: String
├── local_display_name: Option<String>
├── join_state: MacJoinState          # Standalone | DirectoryBound | PlatformSsoManaged | Unknown
├── authority: MacAccountAuthority    # DdsLocal | LocalOnly | ExternalDirectory | PlatformSso
├── admin_groups: [String]
├── sso_link_id: Option<String>
└── created_at: u64
```

This records which local macOS account a DDS subject actually uses on a
specific Mac and who owns that account lifecycle.

**SsoIdentityLinkDocument** (`body_type: "dds:sso-identity-link"`):

```
SsoIdentityLinkDocument
├── link_id: String
├── subject_urn: String
├── provider: String                  # e.g. "entra", "okta", "ad", "openidc"
├── provider_subject: String          # immutable IdP object / subject identifier
├── issuer: Option<String>            # tenant, realm, issuer URL
├── principal_name: Option<String>    # UPN / login name / email-style principal
├── email: Option<String>
├── display_name: Option<String>
└── created_at: u64
```

This binds the enterprise IdP identity to the DDS subject without turning the
IdP into the authorization source. Group membership and privilege still come
from DDS vouches and policy evaluation.

`SoftwareAssignment` is also reused on macOS.
Supported install forms:

- signed `.pkg` installer;
- `softwareupdate` item;
- pinned application bundle artifact copied into an allowlisted install root.

Homebrew support is explicitly **out of the core design path** for v1 because it
adds a user-space package manager dependency that is not standard on enterprise
macOS fleets.

#### 14.7.2 dds-node HTTP API — macOS Endpoints

| Method | Path | Request | Response |
| --- | --- | --- | --- |
| `GET` | `/v1/macos/policies?device_urn=...` | Query string | `{ "policies": [{ "jti", "issuer", "iat", "document": MacOsPolicyDocument }] }` |
| `GET` | `/v1/macos/software?device_urn=...` | Query string | `{ "software": [{ "jti", "issuer", "iat", "document": SoftwareAssignment }] }` |
| `POST` | `/v1/macos/applied` | `AppliedReport` JSON body | `202 Accepted` |

The same server-side scope matching and token validation model is reused.

#### 14.7.3 DdsPolicyAgent.MacOS — Enforcer Model

`DdsPolicyAgent.MacOS` is a self-contained .NET 8 worker registered as a
`LaunchDaemon`.
It reuses the same hash-based idempotency logic as Windows/Linux, but its
enforcers call macOS-native surfaces:

| Enforcer | Backend | Notes |
| --- | --- | --- |
| `PreferenceEnforcer` | plist / CFPreferences / `defaults` | Writes system or user-template managed preferences |
| `MacAccountEnforcer` | `sysadminctl`, `dscl`, `dseditgroup` | Local account lifecycle only on standalone Macs |
| `LaunchdEnforcer` | `launchctl` + managed plist files | Service and agent configuration |
| `ProfileEnforcer` | `profiles` / managed payload install | Only payload classes installable by a local privileged agent |
| `SoftwareInstaller` | `/usr/sbin/installer`, `softwareupdate` | Requires signature/hash verification |

Persisted state lives at:

- `/Library/Application Support/DDS/applied-state.json`
- `/Library/Application Support/DDS/store.redb`

Daemon configuration is installed under `/Library/Application Support/DDS/config/`
with launchd plists in `/Library/LaunchDaemons/`.

#### 14.7.4 macOS Security Controls

**SIP / TCC boundary:** DDS does not attempt to disable System Integrity Protection,
edit the TCC database directly, or bypass user-consent requirements.
Any setting that requires MDM-only entitlement or explicit user approval remains
out of scope for v1.

**Filesystem allowlist:** The macOS agent may only manage:

- `/Library/Application Support/DDS/`
- `/Library/Managed Preferences/`
- `/Library/LaunchDaemons/`
- `/Library/LaunchAgents/`
- `/usr/local/lib/dds/`

It does not rewrite arbitrary application bundles or protected system locations.

**External account-source guard:** If the host is bound to Active Directory,
Open Directory, LDAP, or another external account source, local account mutation
is disabled by default. The same architectural rule applies to Platform SSO
managed Macs: DDS may layer trust, session issuance, and policy on top, but it
does not become the authority for the login window or FileVault account
lifecycle.

**Package trust:** `.pkg` installs require:

- a pinned `sha256`;
- Developer ID signature verification when available;
- an allowlisted source.

Unsigned DMG scripting and arbitrary shell bootstrap installers are out of scope.

#### 14.7.5 macOS Login Integration

macOS is not Windows.
There is no direct analog to the Windows Credential Provider that can replace the
entire login path without running into FileVault, Secure Token, and platform
security constraints.

So the design is phased:

- **v1:** macOS management parity only — policy enforcement, software deployment,
  local account management, and DDS session bootstrap **after** OS login.
- **v2:** `DdsLoginBridge` can integrate DDS-issued sessions into Authorization
  Services for privileged actions, screen unlock, or app-specific SSO where the
  platform allows it.
- **Deferred:** replacing FileVault pre-boot authentication or the full loginwindow
  path is explicitly out of scope until a safe, supportable Apple-approved path exists.

This keeps the platform story honest. macOS can be managed similarly to Windows
in policy/software/device terms, but interactive login replacement should not
be promised casually.

The host-account model is therefore explicit:

- **Standalone:** DDS may create and mutate local accounts, publish
  `MacAccountBindingDocument`, and bootstrap DDS sessions after the user logs in
  with the local macOS account.
- **DirectoryBound:** AD / Open Directory / LDAP owns the login window and local
  account lifecycle. DDS records the relationship using
  `MacAccountBindingDocument` and `SsoIdentityLinkDocument`, but skips
  local-account mutation.
- **PlatformSsoManaged:** MDM + Platform SSO owns login, local-account creation,
  password sync, and FileVault-adjacent policy. DDS treats the IdP identity as
  an input into trust and session issuance, not as something DDS replaces.
- **Unknown:** DDS fails closed for account mutation and limits itself to
  non-destructive policy / session work until ownership is known.

In other words, DDS owns the trust graph and local authorization decision. On
managed enterprise Macs, it does not claim to own the login window.

#### 14.7.6 Packaging And Deployment

macOS packaging targets:

- notarized `.pkg` containing `dds-node`, `DdsPolicyAgent.MacOS`, and launchd plists;
- `pkgbuild` + `productbuild` pipeline;
- code signing with Developer ID Application + Developer ID Installer identities.

State paths:

- config: `/Library/Application Support/DDS/config/`
- database: `/Library/Application Support/DDS/store.redb`
- agent state: `/Library/Application Support/DDS/applied-state.json`
- daemon plists: `/Library/LaunchDaemons/`

Operationally, the macOS rollout model is:

1. install signed package;
2. register launch daemons;
3. enroll device with DDS;
4. apply policies in `Audit` mode first;
5. move selected policies to `Enforce`.

On externally managed Macs, omit `local_accounts` directives and let the
directory / IdP own login-window account lifecycle.

---

## 15. References

- **Vouchsafe Token Format Specification v2.0.1** — Jay Kuri, Ionzero (2025). [github.com/ionzero/vouchsafe](https://github.com/ionzero/vouchsafe)
- **Vouchsafe: A Zero-Infrastructure Capability Graph Model for Offline Identity and Trust** — Jay Kuri (2026). arXiv:2601.02254
- **Minima Blockchain** — [minima.global](https://minima.global). Cascading Chain, MMR database, every-node-is-a-full-node architecture
- **p2panda: Convergent Access Control with CRDTs** — [p2panda.org](https://p2panda.org/2025/08/27/notes-convergent-access-control-crdt.html). Remove-wins policy CRDT, DAG-based operation ordering
- **libp2p** — [libp2p.io](https://libp2p.io). Gossipsub, Kademlia DHT, mDNS, Noise protocol
- **FIDO2/WebAuthn** — W3C Web Authentication specification
- **CRDTs** — Shapiro et al., "A comprehensive study of Convergent and Commutative Replicated Data Types" (2011)
- **rust-libp2p** — [github.com/libp2p/rust-libp2p](https://github.com/libp2p/rust-libp2p). MIT. Production P2P networking.
- **ed25519-dalek** — [github.com/dalek-cryptography/curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek). BSD-3. `no_std` Ed25519.
- **redb** — [github.com/cberner/redb](https://github.com/cberner/redb). MIT/Apache-2.0. Embedded ACID key-value store, pure Rust, stable file format.
- **UniFFI** — [github.com/mozilla/uniffi-rs](https://github.com/mozilla/uniffi-rs). MPL-2.0. Mozilla's multi-language binding generator.
- **uniffi-bindgen-cs** — [github.com/NordSecurity/uniffi-bindgen-cs](https://github.com/nicksecurity/uniffi-bindgen-cs). MPL-2.0. C# binding generator for UniFFI.
- **webauthn-rs** — [github.com/kanidm/webauthn-rs](https://github.com/kanidm/webauthn-rs). MPL-2.0. FIDO2/WebAuthn for Rust.
- **Embassy** — [embassy.dev](https://embassy.dev). Async framework for embedded Rust. MIT/Apache-2.0.
