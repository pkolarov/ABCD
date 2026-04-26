# DDS Implementation Whitepaper

Implementation-grounded, educational guide to the `ABCD` project

Date: 2026-04-09  
Basis: repository code snapshot in `/Users/peter/ABCD`

## Abstract

This document explains the project as it exists in code, not just as an idea.
It is written for two audiences at once:

- people who are new to peer-to-peer systems, distributed directories, DHTs, CRDTs, and "blockchain-like" thinking;
- engineers who want a precise mental model of what the crates actually do, what data moves across the wire, what is persisted, and where the current implementation stops.

The short version is:

- DDS is a decentralized directory service, not a blockchain.
- It models trust as signed assertions and signed delegations.
- It uses libp2p for peer connectivity and message dissemination.
- It uses a trust graph and local policy evaluation so nodes can make decisions offline.
- It includes CRDT building blocks, but the live node is still more "signed-token and graph" than "full CRDT directory object store."
- Some parts are production-shaped and tested; some parts are prototypes or partially wired.

If you remember only one sentence, remember this one:

> DDS is best understood as a signed, replicated, offline-capable directory and trust system, not as a consensus chain.

## Reading Guide

This whitepaper is intentionally educational rather than academic.

- If you are new to the topic, read Sections 1 through 5 first.
- If you want the implementation details, Sections 6 through 19 are the core.
- If you want to experiment on small devices, jump to Section 22.
- If you want to compare DDS with adjacent open-source and commercial systems, see Section 23.
- If you want the standards, papers, and related project references behind the ideas, see Section 25.

Where the code and the older design prose differ, this document treats the code as the source of truth.

## 1. What DDS Is Trying To Be

At a high level, DDS is trying to provide some of the jobs people usually expect from systems like Active Directory, IAM directories, device enrollment services, and local policy agents:

- identify users, devices, and services;
- describe who trusts whom;
- describe what a person or device is allowed to do;
- keep enough state locally that decisions still work when the network is poor or absent;
- synchronize when peers come back into contact.

The important difference is architectural:

- there is no central LDAP server in the middle;
- there is no blockchain ordering every event;
- there is no global consensus protocol in the current code;
- there are just nodes, signed statements, local verification, and eventual dissemination.

That makes DDS especially interesting for:

- disaster recovery networks;
- edge deployments;
- intermittently connected fleets;
- lab experiments in decentralized identity;
- educational prototypes on SBCs, phones, or eventually microcontrollers.

## 2. What DDS Is Not

This matters because many readers hear words like "replication", "gossip", "DHT", and "audit log" and immediately think "blockchain."

DDS is **not** a blockchain in the current codebase.

It does **not** have:

- global block production;
- consensus on one total history;
- leader election;
- proof-of-work or proof-of-stake;
- chain reorg logic;
- token economics or fees.

Instead, DDS uses:

- signed tokens to represent claims;
- a trust graph to decide whether claims are meaningful;
- explicit revocation and burn semantics;
- local policy rules;
- peer-to-peer dissemination with libp2p;
- DAG-style operation tracking for convergence experiments.

If you come from the blockchain world, the closest mental model is:

- take away consensus;
- keep signed objects;
- keep gossip;
- keep local verification;
- use explicit conflict rules instead of global ordering.

If you come from the CRDT world, the closest mental model is:

- the repo contains genuine CRDT building blocks;
- but the deployed node path is still centered on signed tokens and trust-chain evaluation more than on a rich replicated object graph.

## 3. Repository Snapshot

At the time of writing, the repository contains:

- 57 Rust source files
- about 15,399 lines of Rust
- about 1,640 lines of Markdown
- additional bindings in C, Python, C#, Swift, and Kotlin

The Rust workspace is split into 8 crates:

| Crate | Rust files | Approx. Rust LOC | Role |
|---|---:|---:|---|
| `dds-core` | 20 | 4,688 | core identity, crypto, tokens, trust, policy, CRDTs |
| `dds-domain` | 5 | 1,466 | typed documents, domain identity, FIDO2 bridge |
| `dds-store` | 4 | 961 | storage traits plus memory and redb backends |
| `dds-net` | 5 | 1,054 | libp2p transport, discovery, gossip, sync module |
| `dds-node` | 14 | 4,184 | full node, local service, HTTP API, bootstrap commands |
| `dds-cli` | 2 | 501 | lightweight CLI and smoke tests |
| `dds-ffi` | 2 | 557 | C ABI for language bindings |
| `dds-loadtest` | 5 | 1,988 | multinode soak and KPI harness |

This layering is real and visible in code:

```text
dds-core
  ^
  |-- dds-domain
  |-- dds-store
  |-- dds-net
        ^
        |-- dds-node
        |-- dds-loadtest
  ^
  |-- dds-ffi
  |-- dds-cli
```

The most important implementation fact is that `dds-core` is marked `no_std`-compatible with `alloc`, which makes it the natural place to start if you want to experiment on constrained targets.

## 4. The Core Mental Model

Before diving into structs and functions, it helps to explain DDS in plain language.

Imagine an organization where:

- every user or device has a cryptographic identity;
- identities can make signed statements about themselves;
- trusted authorities can sign statements about others;
- those statements can later be revoked;
- every node carries enough verified state to answer local questions like "may Alice read repo X?" without asking a central server;
- peers spread new signed statements when they reconnect.

That gives DDS five central objects:

1. **Identity**: who someone or something is.
2. **Token**: a signed statement.
3. **Trust graph**: how signed statements connect to trusted roots.
4. **Policy**: the local rules that turn trust into an allow or deny decision.
5. **Replication layer**: how peers discover each other and exchange updates.

Everything else in the repo is support machinery around those five ideas.

## 5. Key Terms For Non-Experts

### 5.1 P2P

Peer-to-peer means nodes talk directly to other nodes instead of always going through a single server.

### 5.2 DHT

A distributed hash table is a way to locate data or peers across many machines without a central index. DDS includes a Kademlia-based discovery component, but, importantly, the current code does **not** yet use the DHT as the storage layer for directory state.

### 5.3 Gossip

Gossip is a message spreading technique: one node tells some peers, they tell others, and information diffuses through the network. DDS uses Gossipsub for this.

### 5.4 CRDT

A Conflict-Free Replicated Data Type is a data structure designed so that multiple replicas can be changed independently and still converge when merged later. DDS implements several CRDT primitives, but only part of the design is currently wired into the live node path.

### 5.5 Trust Root

A trust root is a preconfigured identity you are willing to treat as authoritative. In DDS, trust always starts from one or more root URNs configured in the node.

### 5.6 Vouch

A vouch is a signed statement saying, in effect, "I, who may already be trusted, assert something about this other identity."

### 5.7 Revoke

A revocation invalidates a previously issued token.

### 5.8 Burn

A burn permanently retires an identity. In the current trust graph logic, burning an identity also revokes vouches issued by that identity.

### 5.9 Abbreviation Dictionary

This table is intentionally practical.
It explains abbreviations as they are used in this project, not as a complete
standards glossary.

| Abbreviation | Expansion | Basic meaning | How it relates to DDS |
|---|---|---|---|
| ABI | Application Binary Interface | The low-level calling convention between compiled code | `dds-ffi` exposes a C ABI so other languages can call DDS primitives |
| ACL | Access Control List | A list saying who may do what | DDS does not model access only as ACLs, but policies may answer ACL-like questions |
| AD | Active Directory | Microsoft's centralized enterprise directory | DDS is partly interesting as a decentralized/offline contrast to AD-style directory services |
| API | Application Programming Interface | A callable interface for software | `dds-node` exposes an HTTP API, and `dds-ffi` exposes a native API |
| BC | Blockchain | A globally replicated chain of blocks with consensus | DDS is explicitly not a blockchain; it borrows signed objects and gossip, not global consensus |
| CBOR | Concise Binary Object Representation | A compact binary data encoding format | DDS serializes token payloads and domain documents using CBOR |
| CLI | Command-Line Interface | A program operated from a terminal | `dds-cli` provides identity, vouch, revoke, policy, and status commands |
| COSE | CBOR Object Signing and Encryption | Cryptographic message formats built around CBOR | Relevant to WebAuthn and signature algorithm identifiers |
| CRDT | Conflict-Free Replicated Data Type | A data type that can merge concurrent edits predictably | `dds-core` includes LWW registers, two-phase sets, and a causal DAG |
| DAG | Directed Acyclic Graph | A graph with arrows and no cycles | DDS uses DAG thinking for operation ordering and trust-chain reasoning |
| DHT | Distributed Hash Table | A decentralized lookup system for finding peers or records | DDS uses Kademlia DHT behavior for discovery/routing, not as the live directory database today |
| DID | Decentralized Identifier | A W3C-style identifier for decentralized identity systems | DDS identities are not DIDs; DDS uses `urn:vouchsafe:...` self-verifying URNs |
| EdDSA | Edwards-Curve Digital Signature Algorithm | A modern digital-signature family | Ed25519 is the main EdDSA scheme used in DDS |
| ECDSA | Elliptic Curve Digital Signature Algorithm | A common older elliptic-curve signature family | DDS has P-256 ECDSA support in the crypto abstraction |
| FFI | Foreign Function Interface | A bridge for calling code across programming languages | `dds-ffi` lets Python, C#, Swift, Kotlin, C, and other runtimes use DDS primitives |
| FIDO2 | Fast IDentity Online 2 | A passwordless authentication standard family | DDS has a FIDO2/WebAuthn bridge for enrollment evidence |
| HTTP | Hypertext Transfer Protocol | The normal request/response protocol used by web APIs | `dds-node` exposes local service endpoints over HTTP |
| IAM | Identity and Access Management | Systems for identity, login, authorization, and policy | DDS is best understood as an experimental decentralized IAM/directory substrate |
| JSON | JavaScript Object Notation | A human-readable data interchange format | DDS HTTP and FFI surfaces use JSON for integration convenience |
| KDF | Key Derivation Function | A function that derives encryption keys from secrets | Node key storage uses passphrase-based encryption machinery |
| LAN | Local Area Network | A local network, such as an office or home network | mDNS discovery helps DDS nodes find each other on a LAN |
| LDAP | Lightweight Directory Access Protocol | A common protocol for centralized directory lookup | DDS is not LDAP, but it targets some directory-service problems LDAP systems usually handle |
| LOC | Lines of Code | A rough code-size measurement | The repository snapshot uses LOC to show implementation size |
| LWW | Last-Writer-Wins | A conflict rule where the newest write wins | DDS includes an LWW register CRDT |
| MCU | Microcontroller Unit | A very small embedded computer, often with tight RAM and flash limits | The `no_std`-leaning `dds-core` crate is the natural starting point for MCU experiments |
| mDNS | Multicast DNS | Local-network peer discovery without a central DNS server | DDS can use mDNS to discover peers on the same LAN |
| ML-DSA | Module-Lattice-Based Digital Signature Algorithm | NIST's post-quantum digital-signature standard family | DDS includes hybrid signature support involving ML-DSA-65 |
| NAT | Network Address Translation | Router behavior that hides private addresses behind public ones | P2P systems often need NAT-aware connectivity, though DDS currently relies on libp2p transport behavior |
| P2P | Peer-to-Peer | Nodes communicate directly with each other | DDS uses libp2p to build a peer-to-peer dissemination network |
| PKI | Public Key Infrastructure | A system for managing public keys, certificates, and trust anchors | DDS uses public keys and trust roots, but not a traditional CA-only PKI model |
| PQ | Post-Quantum | Cryptography intended to resist quantum-computer attacks | DDS experiments with hybrid post-quantum signatures |
| QUIC | Quick UDP Internet Connections | A modern encrypted transport protocol over UDP | DDS transport setup includes QUIC support through libp2p |
| RBAC | Role-Based Access Control | Authorization based on user roles or groups | DDS vouches and purposes can express role-like trust relationships |
| RP | Relying Party | The service that asks a user to authenticate with WebAuthn | DDS FIDO2 verification checks RP-related WebAuthn evidence |
| SBC | Single-Board Computer | A small Linux-capable board such as a Raspberry Pi | A realistic DDS edge node target is an SBC running `dds-node` for nearby smaller devices |
| SSB | Secure Scuttlebutt | A decentralized signed-log and gossip protocol | SSB is useful prior art for signed feeds, gossip, and offline-friendly replication |
| TCP | Transmission Control Protocol | A common reliable network transport | DDS transport setup includes TCP support through libp2p |
| TPM | Trusted Platform Module | Hardware used for device identity and attestation evidence | DDS stores TPM-related device metadata but does not yet do full TPM remote attestation |
| URI | Uniform Resource Identifier | A generic identifier string format | URNs are a kind of URI |
| URN | Uniform Resource Name | A stable name-style URI | DDS identities use `urn:vouchsafe:...` identifiers |
| UUID | Universally Unique Identifier | A common unique identifier format | DDS uses UUID-like identifiers in several operation/document contexts |
| WebAuthn | Web Authentication | Browser/platform API for passkeys and security keys | DDS parses selected WebAuthn evidence during user enrollment |

### 5.10 Basic Concept Translations

Some terms sound similar but mean different things in this project.
These distinctions are important when reading the code.

**Identity versus peer ID**

An identity in `dds-core` is a DDS-level actor such as a user, device, service,
or authority.
It is represented by a self-verifying `urn:vouchsafe:...` identifier.

A libp2p peer ID is a network-level identifier for a running node's transport key.
It tells DDS how to recognize a network peer, but it is not the same thing as a
DDS user or device identity.

In the current codebase, `dds-node` has both:

- a persistent libp2p keypair for stable network identity;
- a DDS identity key for signing directory tokens and service artifacts.

**Token versus session**

A token is the general signed statement format.
It can mean "this user exists", "this device joined", "this vouch delegates a
purpose", "this old token is revoked", or "this identity is burned."

A session is a more specific domain document.
It represents a temporary authorization result that can be handed to another
system or checked locally.

In short:

- all sessions are represented through signed token machinery;
- not all tokens are sessions.

**Gossip versus DHT**

Gossip is for spreading messages.
If Alice learns a new revocation, she can gossip it so Bob and Carol eventually
hear about it.

A DHT is for lookup and routing.
It helps a node find peers or records in a decentralized address space.

In this DDS repo today:

- Gossipsub carries directory operations, revocations, burns, and audit messages.
- Kademlia helps discovery/routing.
- The DHT is not yet used as the authoritative directory data store.

**CRDT versus blockchain**

A CRDT is about merging concurrent changes without a central coordinator.
Different replicas can receive changes in different orders and still converge if
the merge rules are well designed.

A blockchain is about agreeing on one globally ordered history.
That usually requires consensus.

DDS is closer to the CRDT/local-verification family than the blockchain family.
It wants useful convergence and verifiable claims, not a global block order.

**Trust root versus certificate authority**

A certificate authority, or CA, is a traditional PKI actor that issues
certificates under a hierarchy.

A DDS trust root is simpler and more local.
It is an identity that a node is configured to trust as a starting point for
validating chains of attestations and vouches.

DDS could interoperate with CA-style systems in the future, but the current trust
graph is not just X.509 certificate validation.

**Attestation versus vouch**

An attestation is a signed statement about something.
For example, a token can attest that a user or device exists with certain metadata.

A vouch is a delegation-style statement.
It says that one identity is willing to extend trust or purpose to another
identity.

In DDS terms:

- attestations describe facts or claims;
- vouches connect identities into a trust graph.

**Revocation versus burn**

A revocation invalidates a specific token.
Use it when one statement should no longer be trusted.

A burn retires an identity itself.
Use it when the identity is compromised, obsolete, or no longer allowed to act.

The difference is scale:

- revocation is token-level;
- burn is identity-level.

## 6. Identities: The Foundation Layer

Relevant code:

- `dds-core/src/identity.rs`
- `dds-core/src/crypto/traits.rs`
- `dds-core/src/crypto/classical.rs`
- `dds-core/src/crypto/hybrid.rs`
- `dds-core/src/crypto/ecdsa.rs`
- `dds-core/src/crypto/triple_hybrid.rs`

### 6.1 Vouchsafe IDs

DDS identities are represented as URNs:

```text
urn:vouchsafe:<label>.<base32-sha256-of-public-key-bundle>
```

Examples:

- `urn:vouchsafe:alice.<hash>`
- `urn:vouchsafe:laptop-01.<hash>`

The label is human-friendly. The hash is the security anchor.

This is important because it means the identifier is **self-verifying**:

- if the public key changes, the hash changes;
- if the URN and public key do not match, verification fails locally;
- no registry lookup is needed to verify the binding.

### 6.2 What Exactly Is Hashed

The hash is not just over a bare Ed25519 key.
It is over `PublicKeyBundle.bytes`, which means the identity scheme is part of the practical identity material.

That allows DDS to support:

- classical Ed25519 identities;
- hybrid Ed25519 + ML-DSA-65 identities;
- experimental multi-scheme bundles.

This is a subtle but important design choice: the identity namespace is attached to the whole public-key bundle, not just one algorithm.

### 6.3 Supported Signature Schemes

The code defines four scheme IDs:

- `Ed25519`
- `EcdsaP256`
- `HybridEdMldsa65`
- `TripleHybridEdEcdsaMldsa65`

In practical terms:

| Scheme | Public key bytes | Signature bytes | Status in repo |
|---|---:|---:|---|
| Ed25519 | 32 | 64 | standard path |
| ECDSA P-256 | 65 | 64 | auxiliary / compatibility path |
| Ed25519 + ML-DSA-65 | 1,984 | 3,373 | major hybrid path |
| Ed25519 + ECDSA P-256 + ML-DSA-65 | 2,049 | 3,437 | implemented but not central to node flow |

The hybrid and triple-hybrid sizes follow the constants in the crypto modules.

### 6.4 Why Hybrid Signatures Exist Here

The repo is opinionated about post-quantum transition.
The hybrid path signs the same message with:

- Ed25519, and
- ML-DSA-65

and verification requires **both** to pass.

That gives the project two useful properties:

- backward familiarity and compact classical verification;
- a built-in post-quantum transition story for the **token layer**.

> ⚠ **Scope.** The hybrid signature applies to tokens only. The libp2p
> **transport handshake** is classical (Noise XX / X25519, QUIC /
> rustls / ECDHE). A Harvest-Now-Decrypt-Later adversary recording P2P
> traffic today recovers plaintext gossipsub / sync / admission flows
> on a future quantum break — token signatures still hold, but channel
> confidentiality and forward-secrecy of the recorded traffic do not.
> Tracked as Z-1 (Critical) in
> [../Claude_sec_review.md](../Claude_sec_review.md). Until Z-1 closes,
> do not describe DDS as end-to-end post-quantum.

The relevant standards behind those choices are:

- Ed25519 / EdDSA: RFC 8032 [R1]
- ECDSA / DSS family: FIPS 186-5 [R2]
- ML-DSA: FIPS 204 [R3]

### 6.5 What This Means For Embedded Work

This is one of the first "MCU reality" moments.

If you want to experiment on a microcontroller:

- Ed25519 is the obvious starting point;
- hybrid signatures are much larger and more expensive;
- the `dds-core` structure supports running without `std`, but you would still need to budget for `alloc` and tree-based data structures.

## 7. Tokens: The Signed Statement Format

Relevant code:

- `dds-core/src/token.rs`
- `dds-domain/src/lib.rs`
- `dds-domain/src/types.rs`

Tokens are the central unit of meaning in DDS.
If identities are "who", tokens are "what was said."

### 7.1 Token Kinds

The code defines four token kinds:

- `Attest`
- `Vouch`
- `Revoke`
- `Burn`

These map naturally to directory operations:

- self-assertion or enrollment evidence;
- delegation or group membership;
- revocation;
- permanent retirement.

### 7.2 Token Payload Fields

The important payload fields are:

- `iss`: issuer URN
- `iss_key`: issuer public key bundle
- `jti`: unique token ID
- `sub`: subject
- `kind`: token type
- `purpose`: scope string such as group or resource name
- `vch_iss`: for vouches, the identity being vouched for
- `vch_sum`: SHA-256 hash of the vouched token's payload bytes
- `revokes`: target JTI for revocations
- `iat`, `exp`: issued-at and expiry
- `body_type`, `body_cbor`: optional typed extension payload

In practice, `purpose` is one of the most important fields.
It is how the trust graph later answers questions like:

- is this user in `group:backend`?
- does this subject have `repo:main` as a granted purpose?

### 7.3 Wire Format

Tokens are serialized as CBOR.
The signed bytes are the CBOR-encoded payload.
The outer wire object then stores:

- `payload`: raw payload bytes
- `signature`: CBOR-encoded signature bundle

This is a compact, binary-first format, which is a good fit for:

- offline storage;
- P2P transmission;
- embedded experiments.

### 7.4 Validation Rules

The token code enforces several shape rules before or during validation:

- revoke and burn tokens must not carry `exp`;
- vouch tokens must include `vch_iss` and `vch_sum`;
- revoke tokens must include `revokes`;
- signature must verify against `iss_key`;
- issuer URN must match the embedded public key bundle;
- if `exp` exists, expired tokens fail validation in `std` builds.

This is a strong pattern in DDS: the payload says what the token means, but the token is only useful if the format, signature, and key binding all line up.

### 7.5 A Good Way To Think About `vch_sum`

`vch_sum` is how DDS avoids a vague vouch like "I trust Alice" from floating loose in space.
Instead, a vouch can bind to the hash of the specific attestation payload it refers to.

That means the chain is not merely:

- "Admin trusts Alice"

but closer to:

- "Admin trusts this specific self-assertion made by Alice."

That is a more precise and safer building block.

## 8. The Trust Graph: DDS As A Directory

Relevant code:

- `dds-core/src/trust.rs`

This file is arguably the heart of the project.
It is where signed statements become an actual directory-like trust system.

### 8.1 What The Trust Graph Stores

The graph keeps:

- attestation tokens by JTI;
- vouch tokens by JTI;
- revocations as `target_jti -> revoker_urn`;
- burned identity URNs;
- two secondary indices:
  - `vouches_by_subject`
  - `attestations_by_iss`

Those secondary indices are not cosmetic.
The file comment explicitly explains they were added to keep query paths from degenerating into whole-graph scans and to help meet the repository's local-decision latency goals.

### 8.2 How Trust Actually Works

The trust algorithm is recursive:

1. Start with a subject URN.
2. Find vouches for that subject.
3. Reject revoked or expired ones.
4. If `vch_sum` is present, verify it matches the subject's attestation payload hash.
5. Walk upward through the issuer of that vouch.
6. Stop successfully if you reach a trusted root.
7. Fail if the chain is too deep, broken, revoked, expired, or burned.

This is closer to a graph walk than to a classical directory lookup.

### 8.3 Default Maximum Chain Depth

The default maximum trust-chain depth is 5.
That is a practical defense against pathological or malicious chains and also a performance control.

### 8.4 Revocation Semantics

A revocation is accepted if:

- the revoker issued the target token, or
- the target token is not yet known locally, in which case the revocation can be kept as a pending defensive marker.

This is subtle and good:

- if the target later appears, it is already considered revoked;
- if the target is known and the wrong identity tries to revoke it, the graph rejects the operation.

This is a security-conservative design.

### 8.5 Burn Semantics

A burn means "this identity is dead forever."

In the current code, adding a burn token:

- marks the issuer URN as burned;
- revokes all vouches previously issued by that identity.

That is stronger than a simple revocation of one claim.
It is an identity-level retirement.

### 8.6 Purpose Resolution

The two most important public trust-graph queries are:

- `has_purpose(subject, purpose, roots)`
- `purposes_for(subject, roots)`

These functions power the local authorization story.
They are how DDS turns raw signed tokens into effective group membership or scope.

### 8.7 Reality Check: This Is The Live Directory Today

If you want to know what DDS really uses as its directory today, it is this:

- signed attestations and vouches;
- revocation and burn logic;
- recursive chain validation to trusted roots;
- purpose extraction.

That is more concrete in the code than the more aspirational parts of the CRDT and sync story.

## 9. CRDTs And Operation Ordering

Relevant code:

- `dds-core/src/crdt/lww_register.rs`
- `dds-core/src/crdt/twop_set.rs`
- `dds-core/src/crdt/causal_dag.rs`

This is where DDS teaches an important distributed-systems lesson:

> the repo already contains the right convergence primitives, but the live node does not yet use all of them as the full directory state model.

### 9.1 LWW Register

`LwwRegister<T>` is a classic last-writer-wins register:

- newer timestamp wins;
- on equal timestamp, lexicographically greater value wins for deterministic convergence.

This is simple, deterministic, and useful for mutable attributes.

### 9.2 Two-Phase Set With Remove-Wins

`TwoPSet<T>` keeps:

- an add set;
- a remove set.

Membership means:

- present in add set;
- not present in remove set.

Once something is removed, a plain `add` no longer works.
You need `force_add`, which the code interprets as an explicit administrative override.

This is a good security posture for directory membership:

- accidental over-grant is worse than temporary under-grant.

### 9.3 Causal DAG

`CausalDag` stores operations with:

- `id`
- `author`
- `deps`
- `data`
- `timestamp`

This gives DDS three useful properties:

- it can express partial order instead of pretending everything has one perfect global order;
- it can identify heads;
- it can merge missing operations topologically.

### 9.4 What Is Actually Used Today

Current implementation reality:

- `CausalDag` is used in the sync module, load tests, and node gossip path.
- `LwwRegister` and `TwoPSet` are implemented, tested, and benchmarked, but they are not yet the central live representation of the node's directory state.
- the trust graph itself is not currently built out of CRDT objects like "group membership = TwoPSet" in the live node path.

So if you want to describe DDS honestly:

- CRDTs are present and meaningful;
- but the running node is still mostly a token/trust engine with DAG-backed operation propagation experiments.

## 10. Domain Documents: Typed Payloads Inside Tokens

Relevant code:

- `dds-domain/src/lib.rs`
- `dds-domain/src/types.rs`

`dds-domain` adds typed documents on top of generic tokens.
The core crate signs opaque bytes; this crate tells those bytes what they mean.

### 10.1 Document Types In Code

The repo defines six document bodies:

- `UserAuthAttestation`
- `DeviceJoinDocument`
- `WindowsPolicyDocument`
- `SoftwareAssignment`
- `ServicePrincipalDocument`
- `SessionDocument`

These are stored in:

- `body_type`
- `body_cbor`

inside `TokenPayload`.

### 10.2 Why This Design Is Good

This split is elegant:

- `dds-core` stays generic and compact;
- `dds-domain` carries higher-level semantics;
- other crates can ignore domain bodies if they only need signature and trust checks.

That is exactly the kind of separation you want if you eventually care about:

- embedded ports;
- different application verticals;
- language bindings.

### 10.3 The Session Document

The `SessionDocument` is especially important because it is the output of local authority decisions.
It contains:

- session ID;
- subject URN;
- optional device URN;
- granted purposes;
- authorized resources;
- start time and duration;
- MFA flag;
- optional TLS binding.

It is the most obvious "consumable" result for applications.

## 11. The WebAuthn / FIDO2 Bridge

Relevant code:

- `dds-domain/src/fido2.rs`
- `dds-node/src/service.rs`

This area deserves careful explanation, because the repo's design intent and the exact current implementation are not identical.

### 11.1 What The Parser Supports

The FIDO2 bridge currently supports:

- `none` attestation
- `packed` self-attestation
- Ed25519 credentials only

It explicitly does **not** support:

- full `x5c` certificate-chain validation;
- the whole browser/authenticator attestation matrix;
- non-Ed25519 public keys in this parser.

That limitation is clearly visible in `dds-domain/src/fido2.rs`.

### 11.2 What Happens During User Enrollment

The user-enrollment path in `LocalService::enroll_user` does the following:

1. Optionally verifies the WebAuthn attestation object.
2. Checks that the RP ID hash matches `SHA-256(rp_id)`.
3. Generates a **new DDS identity** for the user.
4. Embeds the WebAuthn evidence into `UserAuthAttestation`.
5. Creates a self-signed DDS attestation token for that newly generated DDS identity.
6. Stores the token and adds it to the trust graph.

This is very important:

> The current code does not make the WebAuthn credential key itself become the DDS identity key.

Instead, WebAuthn is treated as enrollment evidence, and DDS still creates its own identity keypair.

That is a valid design, but it is a different design from "my passkey is my DDS key."

### 11.3 Device Enrollment Is Similar

Device enrollment currently:

- generates a new DDS identity;
- wraps the submitted device metadata into `DeviceJoinDocument`;
- stores the resulting attestation token.

The code accepts fields like TPM EK hash, but it does not yet perform full TPM remote attestation verification.

So this part is best described as:

- strong data model;
- partial real attestation verification for users;
- lighter-weight evidence capture for devices.

## 12. Domain Identity And Admission Control

Relevant code:

- `dds-domain/src/domain.rs`
- `dds-node/src/domain_store.rs`
- `dds-node/src/p2p_identity.rs`
- `dds-node/src/main.rs`
- `dds-node/src/config.rs`

This is one of the cleanest parts of the repo.

### 12.1 Domain As A Cryptographic Realm

A DDS domain is defined by an Ed25519 keypair:

- `DomainKey`: the secret signing authority
- `Domain`: public info (`name`, `id`, `pubkey`)
- `DomainId`: `sha256(pubkey)`, shown as `dds-dom:<base32>`

This gives the system a cryptographic "realm" separate from individual user identities.

### 12.2 Admission Certificates

An `AdmissionCert` signs:

- `domain_id`
- `peer_id`
- `issued_at`
- `expires_at`

The intent is:

- domain admin creates the domain;
- sibling node generates persistent libp2p key;
- admin signs that node's `PeerId`;
- node refuses to start unless the cert matches its local `PeerId`.

### 12.3 What Is Persisted On Disk

The bootstrap files are:

- `domain.toml`: public domain descriptor
- `domain_key.bin`: secret domain key
- `admission.cbor`: admission certificate for one peer
- `p2p_key.bin`: persistent libp2p keypair
- `node_key.bin`: node's DDS signing identity

Both `domain_key.bin` and `node_key.bin` can be encrypted at rest with:

- Argon2id for key derivation
- ChaCha20-Poly1305 for encryption

using:

- `DDS_DOMAIN_PASSPHRASE`
- `DDS_NODE_PASSPHRASE`

### 12.4 Why Persistent `PeerId` Matters

If a node regenerated its libp2p key every time it started, its `PeerId` would change, and the admission certificate would no longer match.

So the persistent transport identity is not optional decoration.
It is part of the security model.

### 12.5 Per-Peer Admission Handshake (H-12, 2026-04-20)

Updated since earlier drafts of this whitepaper. The node now
performs a full mutual admission-verification exchange in addition
to verifying its own cert at startup:

- a dedicated `request_response::cbor::Behaviour` on
  `/dds/admission/1.0.0/<domain_tag>` runs immediately after Noise;
- each side asks the other for its admission cert; the response
  carries the cert as opaque CBOR bytes so `dds-net` stays
  layer-independent of `dds-domain`;
- `DdsNode::admitted_peers: BTreeSet<PeerId>` is populated only
  after `AdmissionCert::verify(&domain_pubkey, &domain_id,
  &peer_id.to_string(), now)` succeeds — a peer whose cert was
  issued for a different `peer_id`, a different domain, or has
  expired stays unadmitted;
- gossip (`Event::Message { propagation_source, .. }`) and the
  sync request/response stream are both gated on the peer being
  in `admitted_peers`; unadmitted messages are dropped at the
  behaviour layer before they reach the ingest helpers;
- `ConnectionClosed` clears the peer from the set, so reconnects
  re-verify.

Domain enforcement today is therefore:

- **local startup validation** (unchanged);
- **per-peer admission exchange post-Noise** (H-12);
- **namespaced protocol strings** on every behaviour (domain tag
  baked into the protocol IDs for kad, identify, sync, admission);
- **namespaced gossip topics**;
- **publisher-capability filter (C-3)** on gossip ingest, as the
  last line of defence against an admitted but unauthorised
  policy/software publisher.

## 13. Storage Layer

Relevant code:

- `dds-store/src/traits.rs`
- `dds-store/src/memory_backend.rs`
- `dds-store/src/redb_backend.rs`

The storage layer is well-factored.

### 13.1 The Four Store Roles

The traits split storage into four responsibilities:

- `TokenStore`
- `RevocationStore`
- `OperationStore`
- `AuditStore`

This is a strong design because it separates:

- current signed state;
- negative state (revoked / burned);
- operation log state;
- audit history.

### 13.2 Memory Backend

`MemoryBackend` is a straightforward in-memory implementation based on:

- `BTreeMap`
- `BTreeSet`
- raw CBOR bytes

It is good for:

- tests;
- load tests;
- embedded experiments;
- algorithm work before persistence is chosen.

### 13.3 Redb Backend

`RedbBackend` is the persistent implementation.
It uses tables named:

- `tokens`
- `revoked`
- `burned`
- `operations`
- `audit_log`

This gives DDS a durable local store without bringing in an external service.

### 13.4 Current Reality: What The Node Persists

The code architecture supports persistent operations and audit entries.
However, the current live node path mainly persists:

- tokens;
- revoked JTIs;
- burned URNs;
- audit entries if audit is enabled and entries arrive.

Two things are less complete than the trait design suggests:

1. The node does not currently write every ingested DAG operation into `OperationStore`.
2. The node does not rebuild its in-memory DAG from persistent operation storage on restart.

So the persistence design is ahead of the current node wiring.

## 14. Networking: What Travels Between Peers

Relevant code:

- `dds-net/src/transport.rs`
- `dds-net/src/discovery.rs`
- `dds-net/src/gossip.rs`
- `dds-net/src/sync.rs`
- `dds-node/src/node.rs`

This is the P2P half of DDS.

### 14.1 libp2p Stack Used By The Node

The swarm builder enables:

- TCP
- QUIC
- Noise secure channels
- Yamux stream multiplexing on TCP
- Gossipsub
- Kademlia
- optional mDNS
- Identify

That matches mainstream libp2p architecture [R7][R8][R9][R10].

One subtle but important implementation detail:

- Kademlia and Identify are domain-tagged at the protocol-name level;
- Gossipsub separation is achieved by domain- and org-namespaced topic names.

### 14.2 Discovery Versus Replication

One of the easiest mistakes in P2P design discussions is to confuse:

- **how peers find each other**, and
- **how state is actually replicated**

In current DDS code:

- Kademlia is mainly used for peer discovery and routing setup.
- mDNS is used for zero-config LAN discovery.
- Gossipsub is the main dissemination mechanism for new directory messages.

The code adds bootstrap peers to Kademlia and can trigger `bootstrap()`, but it does **not** currently call things like:

- `put_record`
- `get_record`

for directory state.

So today the DHT is not the directory database.

### 14.3 Topic Layout

Gossip topics are namespaced by:

- domain tag
- organization hash

The topic set is:

- `/dds/v1/dom/<domain>/org/<org>/ops`
- `/dds/v1/dom/<domain>/org/<org>/revocations`
- `/dds/v1/dom/<domain>/org/<org>/burns`
- `/dds/v1/dom/<domain>/org/<org>/audit`

This is a simple and teachable model:

- normal updates;
- urgent negative updates;
- identity death;
- optional history.

### 14.4 Gossipsub Message Types

The repo defines:

- `DirectoryOp { op_bytes, token_bytes }`
- `Revocation { token_bytes }`
- `Burn { token_bytes }`
- `AuditLog { entry_bytes }`

So the fundamental network message is not just an opaque token.
For normal updates it is:

- a DAG operation, plus
- the signed token that authorizes or explains it.

That pairing is a good design direction because it keeps causality and authorization coupled.

### 14.5 How The Node Ingests Messages

On the live node path:

- operations topic:
  - decode op
  - decode token
  - validate token
  - add token to trust graph
  - store token
  - insert op into in-memory DAG

- revocation topic:
  - decode token
  - validate token
  - add to trust graph
  - store token
  - mark target revoked in store

- burn topic:
  - decode token
  - validate token
  - add to trust graph
  - store token
  - mark issuer burned in store

- audit topic:
  - if enabled, decode audit entry and append to audit store

### 14.6 Message De-Duplication

The Gossipsub message ID is derived from hashing the raw message data.
That means identical serialized messages de-duplicate naturally in the mesh.

### 14.7 mDNS Behavior

When mDNS discovers a peer, DDS:

- adds the address to Kademlia;
- adds the peer as an explicit Gossipsub peer.

That is a practical small-network bootstrapping pattern and matches libp2p's role for mDNS [R11].

### 14.8 Important Limitations In Live Networking

There are three major "design ahead of implementation" gaps here:

#### 14.8.1 Sync module exists, but is not wired into the live node

`dds-net/src/sync.rs` defines:

- summaries;
- operation ID exchange;
- missing-op calculation;
- payload application with topological retry.

It is well tested.

But the running `dds-node` event loop does **not** currently:

- open sync streams;
- negotiate sync sessions;
- use `apply_sync_payloads` during real peer interaction.

So this is a library-level capability and a tested prototype, not yet a live node protocol path.

#### 14.8.2 Operation persistence is incomplete

The node keeps an in-memory `CausalDag`, but does not persist each operation to `OperationStore` in the normal ingest path.

That means:

- the trust-bearing tokens persist;
- the exact causal operation history does not fully persist through node restarts.

#### 14.8.3 Audit publication is only partially present

The node can ingest audit log entries if they arrive and audit is enabled.
What the code does not currently show is a matching publication path for local mutations.

So audit is better described as:

- schema plus storage plus receive path;
- not yet full end-to-end distributed audit generation.

## 15. The Node Process: What A Running DDS Node Actually Is

Relevant code:

- `dds-node/src/node.rs`
- `dds-node/src/main.rs`
- `dds-node/src/config.rs`
- `dds-node/src/expiry.rs`

The node combines several roles that are worth keeping separate in your head.

### 15.1 A DDS Node Has Three Different Identities

This is one of the most important conceptual details in the project.

The node process deals with three distinct identity layers:

1. **Domain identity**
   - the domain authority key
   - used to issue admission certs
   - not normally held by every node

2. **libp2p transport identity**
   - persistent `p2p_key.bin`
   - determines the node's `PeerId`
   - used for network transport authentication and addressing

3. **Node DDS signing identity**
   - persistent `node_key.bin`
   - a Vouchsafe-style identity used by the local service, for example when issuing session tokens

Those are not interchangeable.

### 15.2 Node Startup

On startup, `dds-node`:

1. loads config;
2. loads or creates persistent libp2p key;
3. derives local `PeerId`;
4. initializes the `DdsNode`;
5. verifies domain config and local admission certificate;
6. starts listening and subscribes to topics;
7. loads or creates the node's DDS signing identity;
8. starts the localhost HTTP API;
9. runs the swarm event loop plus expiry sweeper.

### 15.3 Expiry Sweeping

The expiry loop periodically:

- scans token expiries from the trust graph;
- removes expired tokens from the graph;
- marks their JTIs as revoked in the store.

That is a pragmatic cleanup strategy.
It keeps the graph bounded without requiring a full historical ledger forever.

### 15.4 Another Important Limitation

The node's in-memory `trust_graph` and `dag` start empty on process start.
The current `DdsNode::init` path does not rebuild them from persistent store.

This means:

- the persistent database may contain durable tokens;
- the HTTP local service can reconstruct a fresh trust graph snapshot from the store when asked;
- but the node's own in-memory swarm-side trust graph is not automatically rehydrated from disk at startup.

This is a real implementation gap and worth calling out.

## 16. Local Authority Service And HTTP API

Relevant code:

- `dds-node/src/service.rs`
- `dds-node/src/http.rs`

This is the other half of the node.
It is what local applications talk to.

### 16.1 Conceptual Split

`dds-node` is both:

- a P2P replication peer, and
- a localhost service for applications on the same machine

That is a powerful shape.
It means an application does not need to embed libp2p just to:

- enroll a user;
- enroll a device;
- issue a local session;
- evaluate policy;
- ask for status.

### 16.2 User Enrollment

`LocalService::enroll_user`:

- verifies WebAuthn evidence if enabled;
- creates a fresh DDS identity for the user;
- embeds a `UserAuthAttestation` body;
- signs the token with the new user's DDS key;
- stores the token;
- adds it to the trust graph.

The most important conceptual point is:

- enrollment creates an identity and packages evidence;
- trust still depends on later vouches from roots or delegated authorities.

### 16.3 Device Enrollment

`LocalService::enroll_device`:

- creates a fresh device identity;
- embeds a `DeviceJoinDocument`;
- signs and stores the token.

This is structurally similar to user enrollment, but currently less cryptographically heavy than a full hardware-attestation pipeline.

### 16.4 Session Issuance

This path is especially interesting because it shows how local authorization is supposed to work.

Session issuance:

1. rebuilds a trust graph snapshot from store if store state exists;
2. computes granted purposes for the subject;
3. rejects session issuance if no purposes are granted;
4. intersects `requested_resources` with granted purposes;
5. creates a `SessionDocument`;
6. signs the session token with the **node's** DDS identity;
7. returns the token to the caller.

Two important observations:

#### 16.4.1 It does not persist or gossip sessions

The session token is returned to the caller.
It is not stored into the persistent directory and not gossiped across the mesh.

That makes sense for short-lived local authority decisions.

#### 16.4.2 Resource authorization is currently a set intersection

The service does not run the policy engine inside `issue_session`.
Instead it computes:

- `authorized_resources = requested_resources intersect granted_purposes`

That is simpler than a full ABAC engine and easy to explain, but it is also narrower than the overall policy model in the repo.

### 16.5 Policy Evaluation

The actual policy endpoint uses the `PolicyEngine`.
That engine:

- matches rules by resource and action;
- checks deny rules first;
- checks allow rules next;
- defaults to deny.

So the repo has both:

- a standalone local policy evaluator, and
- a simpler session issuance filter based on granted purposes.

### 16.6 HTTP API Surface

Endpoints:

- `POST /v1/enroll/user`
- `POST /v1/enroll/device`
- `GET  /v1/enroll/challenge` (server-issued enrollment nonce; closes WebAuthn §7.1 step 9)
- `POST /v1/session/assert`
- `GET  /v1/session/challenge`
- `POST /v1/admin/setup`
- `POST /v1/admin/vouch`
- `GET  /v1/admin/challenge`
- `POST /v1/policy/evaluate`
- `GET /v1/status`

The API uses:

- JSON for request/response envelopes;
- base64 for CBOR token payloads.

This is a practical cross-language choice.

### 16.7 Current Status Endpoint Limitation

The HTTP status route currently calls:

- `svc.status(peer_id, 0, 0)`

which means the HTTP-exposed status does not currently report the live node's actual:

- connected peer count;
- DAG operation count.

So `/v1/status` is informative, but not yet a full live view of the swarm.

## 17. CLI, FFI, And Language Bindings

Relevant code:

- `dds-node/src/main.rs`
- `dds-cli/src/main.rs`
- `dds-ffi/src/ffi_core.rs`
- `bindings/*`

These are the human and non-Rust entry points.

### 17.1 `dds-node`: The Operational Bootstrap Tool

The node binary supports:

- `init-domain`
- `gen-node-key`
- `admit`
- `run`

This is the actual operational bootstrap story for domain formation.

### 17.2 `dds`: The Lightweight CLI

The separate CLI supports:

- identity creation and parsing;
- simple group vouch/revoke commands;
- trivial offline policy check;
- store status.

This is useful for demonstrations and smoke tests, but it is not yet a full administrative client.

The strongest evidence is in the `group vouch` path:

- it generates a fresh voucher identity each run;
- it uses a synthetic `vch_sum` rather than hashing a real target attestation.

That makes it fine as scaffolding and test input, but not a complete real-world operator workflow.

### 17.3 FFI Scope

The C ABI exposes mostly `dds-core` functionality:

- create identity
- parse URN
- create attestation token
- validate token
- evaluate policy
- get version

It does **not** expose the whole node or the full P2P runtime.

That means the bindings are best thought of as:

- language access to DDS primitives,

not:

- full remote control of the decentralized node.

### 17.4 Bindings Strategy

Python, C#, Swift, and Kotlin wrappers are intentionally thin.
They mostly:

- marshal strings in;
- receive JSON strings out;
- free buffers correctly.

This is pragmatic and teachable.
It also makes DDS easier to explore from multiple ecosystems without immediately designing a large SDK.

## 18. Testing, Benchmarks, And Load Testing

Relevant code:

- `dds-core/tests/integration.rs`
- `dds-node/tests/*`
- `dds-cli/tests/smoke.rs`
- `dds-core/benches/*`
- `dds-node/benches/session_lifecycle.rs`
- `dds-loadtest/*`

### 18.1 Rust Test Posture

I ran:

```bash
~/.cargo/bin/cargo test --workspace --quiet
```

on 2026-04-09 in this workspace.

Result:

- 249 Rust tests passed
- 0 Rust test failures

Observed warnings were non-fatal and related to a few unused imports or variables.

### 18.2 Python Binding Tests

The repo also contains Python binding tests.
There are 13 test cases in `bindings/python/test_dds.py`, but I did not run them in this pass.

### 18.3 Benchmarks

Criterion benchmarks exist for:

- crypto verification
- CRDT merge behavior
- policy evaluation
- session issue/validate lifecycle

This is a strong sign that the repo cares about local-decision latency as a first-class property.

### 18.4 What The Integration Tests Prove

The integration tests demonstrate:

- end-to-end trust chains;
- revocation removing access;
- policy checks from trusted purposes;
- store round-trips;
- sync payload application;
- hybrid-key lifecycle.

The multinode node tests further show:

- gossip-based propagation;
- revocation propagation;
- convergence behavior after temporary partitioning.

### 18.5 Load Test Harness

The load test harness is unusually educational.
It spins up in-process nodes, drives realistic-looking workloads, records histograms, and produces KPI summaries.

Important details:

- it measures the in-process Rust API, not the HTTP API;
- it can simulate node pause/rejoin churn;
- it records propagation latency and rejoin convergence;
- it uses `MemoryBackend` for per-node local service KPIs while still running real swarms for network behavior.

This is good engineering because it separates:

- local algorithm cost, and
- network-side dynamics.

## 19. What Is Implemented Today Versus What Is Still Transitional

This section is the most important for anyone who wants to build on DDS responsibly.

### 19.1 Solid, Present, And Easy To Build On

These areas are concrete in the code:

- self-verifying identity URNs
- scheme-tagged public key and signature bundles
- Ed25519 and hybrid signature verification
- signed CBOR token format
- trust graph with vouch, revoke, and burn semantics
- local policy engine
- typed domain documents
- domain bootstrap and local admission-cert verification
- persistent node and libp2p identities
- redb and memory storage backends
- libp2p transport, gossip, mDNS discovery
- HTTP localhost API
- FFI and language bindings for core primitives
- strong automated test coverage

### 19.2 Implemented But Not Fully Wired Into The Live Node

These exist in code but are not yet end-to-end operational in the main node path:

- delta-sync protocol module
- operation-store-backed restartable DAG
- full distributed audit publication
- live status plumbing from swarm to HTTP API
- automatic node-side trust-graph rehydration from store on startup

### 19.3 Present As Data Models More Than End-To-End Features

These are more "shaped" than "finished":

- Windows policy distribution
- software assignment rollout
- service-principal lifecycle beyond token format
- deeper device-attestation verification
- full passkey-as-identity-key semantics

### 19.4 Design Gaps That Matter For Security Discussions

These are the biggest architectural caveats in the current code. The
2026-04-17 → 2026-04-21 security-remediation sweep closed several of
them; the remainder are genuine open work.

1. ~~Remote peer admission is not mutually verified during live
   connection setup.~~ **Closed by H-12 (2026-04-20)**: a
   `request_response` behaviour on `/dds/admission/1.0.0/<domain>`
   runs immediately after Noise, each side verifies the other's
   admission cert, and gossip / sync from unadmitted peers is
   dropped at the behaviour layer.
2. Kademlia is used for discovery, not as the directory state store.
3. The node-side in-memory graph is not rebuilt from disk at startup.
4. The HTTP status endpoint does not expose live peer and DAG counters.
5. Sessions are local artifacts, not replicated state.

These are not fatal flaws for a prototype or research system.
They are just important truths.

### 19.5 Security Remediation Status (as of 2026-04-21)

The full per-finding ledger lives in
[`Claude_sec_review.md`](../Claude_sec_review.md). Summary:

- **All Critical (3/3) and High (12/12) findings** are Fixed
  (pending verify — the Windows CI run still needs to confirm the
  C++ Auth Bridge / WiX-MSI pieces of H-6 and H-7 step-2b).
- **19 of 22 Medium** and **17 of 18 Low** findings are closed.
- Remaining deferred items and the rationale for each: M-13 (FIDO
  MDS integration — external design), M-15 (node-bound FIDO2
  `hmac_salt` via bundle re-wrap — blocked on export-format
  design), M-18 (WiX service-account split — multi-day Windows
  refactor, unverifiable without Windows CI), L-17 (29 HTTP
  handler lock sites — L-18's atomic `bump_sign_count` already
  closed the underlying replay race, so the remaining gain is
  throughput not security).

Notable things a reader / builder should be aware of:

- **Transport auth**: HTTP API `api_addr` dispatches on scheme —
  `127.0.0.1:…` (legacy TCP) vs `unix:/…` (UDS) vs `pipe:<name>`
  (Windows named pipe). Only the UDS / pipe paths carry peer
  credentials that the admin-gate and the TOFU device-binding
  helper can pin a caller to. **Windows MSI installs default to
  `pipe:dds-api` since A-2 (2026-04-25)**: `node.toml` ships with
  `api_addr = 'pipe:dds-api'` and
  `trust_loopback_tcp_admin = false`, the Auth Bridge reads
  `HKLM\SOFTWARE\DDS\AuthBridge\ApiAddr = pipe:dds-api`, and the
  Policy Agent's `appsettings.json` `NodeBaseUrl` matches.
  Linux/macOS dev deployments still default to TCP — operators
  flip them manually.
- **Response MAC**: every HTTP response is signed with
  `X-DDS-Body-MAC = base64(HMAC-SHA256(key, method || 0 || path
  || 0 || body))` when `network.api_auth.node_hmac_secret_path`
  is set; the Windows Auth Bridge verifies the MAC to defeat
  port-squatting attacks.
- **Publisher capabilities (C-3)**: policy / software
  attestations require the issuer to chain back to a trusted
  root with the matching `dds:policy-publisher-*` or
  `dds:software-publisher` vouch. Enforced at both gossip ingest
  and at serve time.
- **Token envelope**: default is `v=2` canonical CBOR with
  domain-prefixed signing input; hybrid + triple-hybrid
  signatures now domain-separated per component. Legacy `v=1` is
  readable but only ingested when
  `network.allow_legacy_v1_tokens = true`.

## 20. Why DDS Is Educationally Interesting

This repo is useful to study because it sits at the intersection of several ideas that are often taught separately:

- public-key identity
- signed statements and delegated trust
- revocation
- local authorization
- CRDT convergence
- peer discovery
- gossip dissemination
- post-quantum transition
- constrained-device design pressure

It is rare to find all of those in one codebase that is still small enough to read.

## 21. How To Learn From This Repo In The Right Order

If you are using DDS as a study project, this is the best reading and hacking order:

1. Read `dds-core/src/identity.rs` and `dds-core/src/token.rs`.
2. Read `dds-core/src/trust.rs`.
3. Read `dds-core/src/policy.rs`.
4. Read `dds-domain/src/types.rs` and `dds-domain/src/domain.rs`.
5. Read `dds-store/src/*`.
6. Read `dds-net/src/gossip.rs` and `dds-net/src/transport.rs`.
7. Read `dds-node/src/service.rs`.
8. Read `dds-node/src/node.rs`.
9. Read the integration tests and multinode tests.

That order goes from local truth to distributed behavior.
It is also the right order for porting pieces to smaller systems.

## 22. How To Experiment On MCUs Or Very Small Devices

This was one of the user goals for this whitepaper, so here is the blunt answer.

### 22.1 The Best Starting Point

Start with `dds-core`, not `dds-node`.

Why:

- `dds-core` is `no_std`-compatible with `alloc`;
- it contains the actual logic for identity, signature verification, tokens, trust, policy, and CRDTs;
- `dds-net` and `dds-node` depend on much heavier runtime and networking stacks.

### 22.2 A Good MCU Experiment Ladder

#### Tier 1: Offline token verifier

Implement only:

- Ed25519 identity verification
- token parsing
- token signature validation
- expiry check

Use case:

- badge, lock, or sensor verifies a short-lived session token locally.

#### Tier 2: Small trust evaluator

Add:

- `TrustGraph`
- one or two trusted roots
- purpose lookup
- small policy table

Use case:

- edge device enforces "group:oncall may open this enclosure."

#### Tier 3: Tiny replicated authority

Add:

- `CausalDag`
- your own simple transport
- flooding or radio broadcast instead of libp2p

Use case:

- disconnected mesh experiments across dev boards.

#### Tier 4: Mixed-class fleet

Keep:

- small devices as validators and policy enforcers

Use:

- a bigger Linux node or SBC as the P2P replicator and local authority service.

This is probably the most realistic near-term architecture.

### 22.3 What To Strip First

For very constrained targets, strip in this order:

1. hybrid PQ signatures
2. ECDSA and triple-hybrid support
3. FIDO2 parsing
4. large trust graphs
5. full store backends

Then keep:

- CBOR token format
- Ed25519
- trust-root list
- purpose check
- minimal session document validation

### 22.4 The Biggest Embedded Pain Points

Be realistic about these:

- `BTreeMap` / `BTreeSet` memory overhead
- hybrid signature size
- CBOR parsing buffers
- cloning in snapshot-oriented paths
- lack of a purpose-built compact persistent backend in `dds-core`

### 22.5 Why The Repo Is Still Worth Using For MCU Work

Even if you never port the whole thing, the repo already gives you:

- a good identity format;
- a compact signed object format;
- a trust model with real revocation semantics;
- a policy engine you can reason about;
- tests that describe intended behavior.

That is a very good foundation.

## 23. Similar Concepts And Related Systems

This section compares DDS to projects and products that implement nearby ideas.
The goal is not to claim that DDS is the first system to use signed logs, gossip,
DHTs, local authorization, or decentralized identity.
Those ideas have a long history.

The more useful question is:

> Has anyone already built the same combination of a peer-to-peer directory,
> signed delegation graph, offline authorization engine, explicit revocation and
> burn semantics, domain admission, and practical node/service API?

Based on the related systems surveyed here, the answer appears to be:

- many systems overlap with one or two DDS ideas;
- several are very educationally close;
- none appear to be a direct drop-in equivalent to DDS as implemented in this repo.

That matters because DDS is not competing with one single category.
It sits between several categories:

- decentralized identity;
- P2P databases;
- signed append-only logs;
- authorization graph systems;
- distributed application frameworks;
- mesh-network control planes;
- enterprise directory services.

### 23.1 Quick Comparison Matrix

The table below is intentionally pragmatic.
"Close to DDS" means close to the total shape of the project, not just close to
one technical mechanism.

| System | Open / Closed | Closest DDS overlap | Biggest difference |
|---|---|---|---|
| p2panda | Open source | P2P operation graph, schemas, decentralized permissions | Application/data framework rather than enterprise directory/session authority |
| GNUnet re:claimID | Open source | Decentralized identity and attribute sharing | Identity and attribute system, not a full trust-graph directory with policy/session issuance |
| Holochain | Open source | Agent-centric DHT, validation, no global consensus | General app framework, not a ready-made directory service |
| OrbitDB | Open source | P2P database, libp2p pubsub, Merkle-CRDT-style replication | Database substrate, not identity/trust/policy semantics |
| Secure Scuttlebutt | Open source | Signed append-only logs and gossip replication | Social/feed protocol, not IAM or directory authorization |
| Biscuit | Open source | Offline authorization tokens with attenuation and public-key verification | Token authorization only; no P2P replication layer or directory graph |
| Peergos | Open source / hosted | Decentralized storage, portable identity, offline/self-hosted use | Encrypted storage/application platform, not delegated directory authority |
| Tailscale / Tailnet Lock | Commercial with open clients | P2P data plane, cached policy, signed node-key control | Centralized SaaS/control-plane architecture, not decentralized directory replication |
| Keybase teams / sigchains | Commercial history, open clients/protocol docs | Signed team membership history and server-verifiable state | Server-backed collaboration identity, not P2P directory runtime |
| SpiceDB / Authzed | Open source core plus commercial service | Relationship graph authorization semantics | Centralized authorization database, not P2P/offline replicated trust graph |

### 23.2 p2panda

p2panda is probably the closest open-source conceptual neighbor if you focus on
replicated data and decentralized permissions [R13] [R14].

The overlap with DDS is strong in these areas:

- application data is represented as signed operations;
- peers can replicate data without a central authority in the middle;
- the model is interested in local validation rather than blockchain-style global consensus;
- access control and schema validation are first-class concerns.

That makes p2panda a good project to study next to `dds-net`, `dds-core/src/crdt/*`,
and the DDS sync prototype.

The difference is equally important.
p2panda is shaped like a decentralized application data framework.
DDS is shaped like a decentralized directory and authority system.
DDS has explicit directory concepts such as user attestation, device enrollment,
service-principal documents, session documents, trust roots, purpose-bearing
vouches, revocation, burn semantics, domain identity, and a local authority API.

In plain language:

- p2panda asks, "How do decentralized apps model, validate, and replicate data?"
- DDS asks, "How does an organization keep identity, trust, and authorization usable when central services are unavailable?"

Those questions overlap, but they are not the same question.

### 23.3 GNUnet re:claimID

GNUnet re:claimID is close to DDS from the decentralized identity direction [R15] [R16].
It focuses on letting users manage identity attributes and selectively share them
without relying on a conventional centralized identity provider.

The overlap with DDS is strongest in these areas:

- identity is cryptographic rather than just a row in a central database;
- attribute-like data can be represented and shared in decentralized ways;
- the system is interested in privacy-preserving identity disclosure;
- it treats the network as something more decentralized than a normal web app backend.

For a DDS reader, re:claimID is useful because it shows a mature research lineage
for decentralized identity and attribute management.
It is especially relevant to DDS domain documents such as `UserAuthAttestation`,
`DeviceJoinDocument`, and `ServicePrincipalDocument`.

The main difference is that re:claimID is not trying to be an enterprise-like
offline authorization fabric.
DDS includes a trust graph, local policy evaluation, signed sessions, revocation,
burns, storage backends, libp2p node runtime, and API service.
re:claimID is closer to "self-sovereign attributes" than "replicated directory authority."

### 23.4 Holochain

Holochain is a major reference point for people who want decentralized applications
without blockchain consensus [R17] [R18] [R19].
Its architecture is agent-centric: each participant has a source chain, and DHT
operations are published and validated across the network.

The overlap with DDS is conceptual:

- both avoid global blockchain consensus;
- both use local validation as a core design idea;
- both are comfortable with eventual consistency;
- both use DHT-oriented thinking;
- both separate "valid data" from "globally ordered data."

This is a useful lesson for non-experts.
Many systems need cryptographic integrity and replication.
Not all of them need a blockchain.
Holochain and DDS both live in that design space.

The difference is scope.
Holochain is a framework for building distributed applications.
DDS is a concrete directory/trust/authorization implementation.
If DDS were rebuilt as a Holochain application, Holochain would provide much of
the distributed application substrate, while DDS would still need to define the
identity semantics, vouch semantics, revocation behavior, policy engine, session
issuance, and domain admission model.

### 23.5 OrbitDB

OrbitDB is close to DDS from the P2P database side [R20] [R21] [R22].
It is a peer-to-peer database ecosystem built around libp2p-style networking,
replication, and conflict-tolerant data structures.

The overlap with DDS is mostly infrastructural:

- peers replicate state;
- replication is designed for decentralized networks;
- Merkle-CRDT-style ideas appear in the data model;
- libp2p pubsub is a natural dissemination mechanism;
- applications can operate without a conventional central database.

OrbitDB is therefore a good comparison for the future version of DDS where
`dds-net/src/sync.rs`, `dds-store`, and the CRDT modules are wired into a fuller
directory object store.

The current difference is that DDS has domain-specific trust semantics that
OrbitDB does not provide by itself.
OrbitDB can help store and replicate data.
DDS defines what the data means for identity, trust, revocation, and authorization.

In short:

- OrbitDB is closer to "replicated database substrate."
- DDS is closer to "replicated authority semantics plus a database substrate."

### 23.6 Secure Scuttlebutt

Secure Scuttlebutt, often shortened to SSB, is a signed-log and gossip system
originally associated with decentralized social networking [R23] [R24].

The overlap with DDS is educationally important:

- each participant has a cryptographic identity;
- messages are signed;
- append-only feeds make history tampering detectable;
- gossip moves data across intermittently connected peers;
- peers can keep local state and catch up later.

Those are exactly the kinds of ideas a DDS learner should understand.
SSB is one of the clearest examples of how signed histories and gossip can support
offline-friendly decentralized systems without blockchain mining or staking.

DDS differs because its object model is not a social feed.
It uses signed tokens to express attestations, vouches, revocations, burns, and
domain documents.
Its core question is not "what did this person publish?" but "what can this node
locally verify and authorize?"

### 23.7 Biscuit

Biscuit is a very strong comparison for DDS tokens and sessions [R25].
It is an authorization-token system where tokens can carry logic, be attenuated,
and be verified offline using public-key cryptography.

The overlap with DDS is strongest here:

- authorization can be checked locally;
- signed tokens are portable;
- verification does not require always calling a central server;
- delegation and attenuation are central ideas;
- policy-like checks are part of the token evaluation story.

For a DDS reader, Biscuit is worth studying before designing session-token
formats or embedded token verifiers.
It has a mature mental model for constrained, offline-capable authorization.

The difference is that Biscuit is not a P2P directory.
It does not try to discover peers, replicate trust state, maintain a domain
directory, enroll devices, gossip revocations, or run a local authority node.
DDS could learn from Biscuit's token logic model, but DDS is trying to solve a
larger distributed state problem.

### 23.8 Peergos

Peergos is a decentralized, encrypted storage and application platform with an
emphasis on privacy, self-hosting, and user-controlled identity [R26].

The overlap with DDS is less direct than p2panda or Holochain, but still useful:

- users can own their data and identity more directly;
- local/offline and self-hosted operation matter;
- decentralized storage is treated as a practical application platform, not just a research toy;
- cryptography is part of the application architecture.

Peergos is valuable as a product-level example of decentralized infrastructure
being packaged for real users.
That is relevant to DDS because a directory system also has to become usable
in practice, not merely correct in protocol diagrams.

The difference is that Peergos is primarily about private storage and application
data.
DDS is about trust, delegation, and authorization state.
They could be complementary, but they are not substitutes.

### 23.9 Tailscale And Tailnet Lock

Tailscale is the closest commercial comparison in spirit, especially when looking
at its split between a coordination/control plane and a peer-to-peer encrypted
data plane [R27] [R28] [R29] [R30].
Tailnet Lock adds a particularly relevant idea: network nodes are not accepted
only because a SaaS control plane says so; trusted signing nodes also sign node
keys before they are allowed into the tailnet.

The overlap with DDS is strong at the product-goal level:

- nodes need to keep working even when they cannot constantly ask a central service;
- policy and network membership need local cached meaning;
- public keys identify nodes;
- signed admission of nodes improves the trust model;
- operators want practical tooling, not just protocol theory.

This is an important comparison because it shows that local trust material and
signed node admission are not just academic ideas.
They are useful in real operational systems.

The difference is architectural.
Tailscale still has a control plane.
The peers form encrypted connections for data traffic, but the coordination model
is not the same as a fully decentralized directory replicated among peers.
DDS is exploring what happens when more of the directory authority itself becomes
local, signed, replicated, and offline-verifiable.

### 23.10 Keybase Teams And Sigchains

Keybase is a useful comparison for signed identity history and team membership [R31] [R32] [R33].
Its sigchain and team-chain design showed how clients can verify a sequence of
identity and team changes instead of blindly trusting a server's current answer.

The overlap with DDS is strongest in:

- signed history;
- team/group membership as verifiable state;
- cryptographic proofs around identity changes;
- defense against unauthorized or hidden membership changes;
- client-side reconstruction of meaningful trust state.

DDS has similar instincts.
It wants nodes to verify signed trust material locally instead of treating a
central database answer as inherently true.

The difference is that Keybase was server-backed and collaboration-oriented.
DDS is P2P-oriented and directory-authority-oriented.
Keybase is still extremely useful prior art for thinking about group membership,
chain readability, auditability, and "ghost user" problems.

### 23.11 SpiceDB And Authzed

SpiceDB is not a P2P system, but it is one of the most relevant references for
authorization graph thinking [R34] [R35].
It is inspired by Google's Zanzibar model and represents permissions as
relationships that can be queried consistently.

The overlap with DDS is conceptual rather than infrastructural:

- authorization is graph-shaped;
- group membership and object relationships matter;
- policy decisions need precise semantics;
- the system needs to answer "does subject S have permission P on object O?"

This is useful because DDS should not confuse "decentralized" with "underspecified."
Even if DDS distributes trust state across peers, authorization semantics still
need to be clear, testable, and explainable.
SpiceDB is a good benchmark for that level of semantic seriousness.

The difference is that SpiceDB is a centralized authorization database/service.
DDS is exploring local verification and P2P replication.
In a hybrid deployment, SpiceDB-like semantics could inform DDS policy design,
while DDS would provide the signed/offline/distributed trust substrate.

### 23.12 What DDS Appears To Add

After comparing these systems, DDS's distinctive combination is:

- a self-verifying identity format;
- signed tokens for attestations, vouches, revokes, and burns;
- a trust graph that validates purpose-bearing delegation chains;
- explicit burn semantics for compromised or retired identities;
- local policy evaluation that can work without a central online authority;
- typed domain documents for users, devices, services, policy, software, and sessions;
- domain keys and node admission certificates;
- libp2p-based peer discovery and gossip;
- storage backends for token and revocation state;
- an embeddable `no_std`-leaning core;
- FFI and language-binding direction;
- a load-testing harness for multinode behavior.

Other projects often implement one or two of those ideas better or more maturely.
For example:

- Biscuit is much more mature as an authorization-token design.
- Holochain is much broader as a distributed application framework.
- OrbitDB is more directly a P2P database substrate.
- Tailscale is much more mature operationally.
- SpiceDB is much more mature as an authorization graph service.

DDS is interesting because it pulls several of those ideas into one relatively
small codebase with an enterprise-directory flavor.

### 23.13 Lessons DDS Can Borrow

The comparison suggests several practical lessons for DDS development.

From p2panda and OrbitDB:

- make operation synchronization a first-class live path, not just a tested module;
- treat schema evolution and application-level validation as core protocol problems;
- make conflict behavior visible to application developers.

From Holochain:

- document exactly what each node is responsible for validating;
- separate "data exists in the network" from "data is valid for this application";
- lean into local validation rather than apologizing for lack of global consensus.

From SSB and Keybase:

- signed histories should be easy to inspect and explain;
- human-debuggable trust history matters;
- group membership changes deserve strong audit semantics.

From Biscuit:

- session and authorization token formats should support attenuation cleanly;
- embedded verification should be treated as a first-class target;
- policy logic needs a small, precise mental model.

From Tailscale:

- operational usability matters as much as protocol elegance;
- node admission and key rotation need clear tools;
- local cached policy should degrade predictably when disconnected.

From SpiceDB:

- authorization graph semantics need rigorous tests;
- permission questions should have stable vocabulary;
- users need a way to explain why access was allowed or denied.

## 24. Final Assessment

DDS is already a serious technical prototype.

Its strongest implemented ideas are:

- self-verifying identities;
- signed token semantics;
- recursive trust-chain validation;
- offline policy evaluation;
- domain bootstrap with admission certs;
- practical libp2p-based dissemination;
- good tests and meaningful load instrumentation.

Its weakest or most transitional areas are not conceptual weakness so much as wiring gaps:

- sync exists but is not live;
- operation persistence exists but is not live in the main path;
- audit is schema-first, not full lifecycle-first;
- domain admission is not yet a live remote peer-auth protocol;
- the node and HTTP service share persistence better than they share live in-memory state.

That is still a very respectable place for a project to be.

For learners, DDS is valuable because it shows how to combine cryptography, offline authorization, and P2P replication without immediately reaching for a blockchain.

For builders, DDS is valuable because it already contains enough concrete machinery to support:

- edge/offline experiments;
- embedded validators;
- local authority prototypes;
- trust-graph research;
- post-quantum transition experiments.

## 25. References

[R1] S. Josefsson, I. Liusvaara. *RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)*. IETF RFC Editor, 2017.  
https://www.rfc-editor.org/rfc/rfc8032

[R2] NIST. *FIPS 186-5: Digital Signature Standard (DSS)*, 2023.  
https://csrc.nist.gov/pubs/fips/186-5/final

[R3] NIST. *FIPS 204: Module-Lattice-Based Digital Signature Standard*, 2024.  
https://doi.org/10.6028/NIST.FIPS.204  
PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

[R4] W3C. *Web Authentication: An API for Accessing Public Key Credentials - Level 2*, W3C Recommendation, 2021.  
https://www.w3.org/TR/webauthn-2/

[R5] J. Schaad. *RFC 9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms*, 2022.  
https://www.rfc-editor.org/info/rfc9053

[R6] P. Maymounkov, D. Mazières. *Kademlia: A Peer-to-peer Information System Based on the XOR Metric*, 2002.  
https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia.pdf

[R7] libp2p. *What are Secure Channels*.  
https://docs.libp2p.io/concepts/secure-comm/overview/

[R8] libp2p. *What is Stream Multiplexing*.  
https://docs.libp2p.io/concepts/multiplex/overview/

[R9] libp2p. *What is Publish/Subscribe*.  
https://docs.libp2p.io/concepts/pubsub/overview/

[R10] libp2p Specs. *gossipsub: An extensible baseline pubsub protocol*.  
https://github.com/libp2p/specs/tree/master/pubsub/gossipsub

[R11] libp2p. *mDNS*.  
https://docs.libp2p.io/concepts/discovery-routing/mdns/

[R12] M. Shapiro, N. Preguica, C. Baquero, M. Zawirski. *Conflict-Free Replicated Data Types*, INRIA Research Report RR-7687, 2011.  
https://www.lip6.fr/Marc.Shapiro/papers/RR-7687.pdf

[R13] p2panda. *p2panda project repository*.  
https://github.com/p2panda/p2panda

[R14] p2panda. *Access Control*.  
https://p2panda.org/2025/07/28/access-control.html

[R15] GNUnet. *re:claimID FAQ*.  
https://www.gnunet.org/en/reclaim/faq.html

[R16] GNUnet. *re:claimID Technical Details*.  
https://www.gnunet.org/en/reclaim/tech.html

[R17] Holochain Developer Portal. *Validation*.  
https://developer.holochain.org/build/validation/

[R18] Holochain Developer Portal. *DHT Operations*.  
https://developer.holochain.org/build/dht-operations/

[R19] Holochain. *The RRDHT: A Distributed Hash Table for Holochain*.  
https://developer.holochain.org/assets/files/RRDHT-whitepaper-final.pdf

[R20] OrbitDB. *OrbitDB project site*.  
https://orbitdb.org/

[R21] OrbitDB. *OrbitDB API documentation*.  
https://api.orbitdb.org/index.html

[R22] OrbitDB. *Sync API source documentation*.  
https://api.orbitdb.org/sync.js.html

[R23] Secure Scuttlebutt Consortium. *Scuttlebutt Protocol Guide*.  
https://ssbc.github.io/scuttlebutt-protocol-guide/

[R24] Secure Scuttlebutt Handbook. *Gossip*.  
https://handbook.scuttlebutt.nz/concepts/gossip

[R25] Biscuit. *Biscuit Authorization*.  
https://doc.biscuitsec.org/

[R26] Peergos. *Peergos project site*.  
https://peergos.org/

[R27] Tailscale. *Control plane vs. data plane*.  
https://tailscale.com/docs/concepts/control-data-planes

[R28] Tailscale. *Tailnet Lock*.  
https://tailscale.com/docs/features/tailnet-lock

[R29] Tailscale. *Tailnet Lock whitepaper*.  
https://tailscale.com/docs/concepts/tailnet-lock-whitepaper

[R30] Tailscale. *Device management*.  
https://tailscale.com/docs/manage

[R31] Keybase. *Keybase Book*.  
https://book.keybase.io/docs

[R32] Keybase. *Team Sigchains*.  
https://book.keybase.io/docs/teams/sigchain

[R33] Keybase. *Box Auditor*.  
https://book.keybase.io/docs/teams/box-auditor

[R34] Authzed. *Discovering SpiceDB*.  
https://authzed.com/docs/spicedb/getting-started/discovering-spicedb

[R35] Authzed. *SpiceDB*.  
https://authzed.com/spicedb

## Appendix A: Key Files To Read

If you want to keep one short map while reading the repo, use this:

- identity and crypto: `dds-core/src/identity.rs`, `dds-core/src/crypto/*`
- token format: `dds-core/src/token.rs`
- trust model: `dds-core/src/trust.rs`
- policy engine: `dds-core/src/policy.rs`
- CRDTs: `dds-core/src/crdt/*`
- typed domain docs: `dds-domain/src/types.rs`
- FIDO2 bridge: `dds-domain/src/fido2.rs`
- domain and admission: `dds-domain/src/domain.rs`, `dds-node/src/domain_store.rs`
- storage: `dds-store/src/*`
- transport and gossip: `dds-net/src/transport.rs`, `dds-net/src/gossip.rs`
- sync prototype: `dds-net/src/sync.rs`
- node runtime: `dds-node/src/node.rs`
- local authority API: `dds-node/src/service.rs`, `dds-node/src/http.rs`
- node bootstrap commands: `dds-node/src/main.rs`
- cross-module behavior: `dds-core/tests/integration.rs`, `dds-node/tests/multinode.rs`
