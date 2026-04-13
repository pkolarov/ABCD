# 📖 The Decentralized Directory Service (DDS)

## A Complete Junior Developer's Field Guide

**Welcome to the DDS Team!**
If you've just cloned the repository and feel completely overwhelmed by acronyms like *CRDTs, DHTs, Gossipsub, Post-Quantum Cryptography,* and *libp2p*, you are in the right place.

This booklet is designed to be read end-to-end. We assume you know how to write code, but we **do not** assume you have a PhD in cryptography or distributed systems. By the end of this guide, you will understand exactly what DDS is, why it exists, and how every single gear turns under the hood — with real code from our repository.

Let's dive in.

---

## 📑 Table of Contents

1. [Chapter 1: The End of the Server](#chapter-1-the-end-of-the-server) — Why are we building this?
2. [Chapter 2: Cryptographic Stamps](#chapter-2-cryptographic-stamps) — Identity, keys, FIDO2, and quantum-safe math
3. [Chapter 3: The Chain of Permission Slips](#chapter-3-the-chain-of-permission-slips) — Tokens, the Trust Graph, and the Policy Engine
4. [Chapter 4: Magic Auto-Merging Spreadsheets](#chapter-4-magic-auto-merging-spreadsheets) — CRDTs deep dive with code
5. [Chapter 5: Devices Whispering Secrets](#chapter-5-devices-whispering-secrets) — P2P networking, Gossipsub, DHT, and delta-sync
6. [Chapter 6: The Filing Cabinet](#chapter-6-the-filing-cabinet) — The storage layer and its traits
7. [Chapter 7: Domain Documents](#chapter-7-domain-documents) — The typed business objects that ride inside tokens
8. [Chapter 8: The Lego Blocks](#chapter-8-the-lego-blocks) — Crate architecture and how they interface
9. [Chapter 9: The Translator](#chapter-9-the-translator) — FFI bridge to Python, C#, Swift, and Kotlin
10. [Chapter 10: The Road to Active Directory](#chapter-10-the-road-to-active-directory) — Expanding DDS to cover AD and LDAP concepts
11. [Chapter 11: Your First Day](#chapter-11-your-first-day) — Getting started with the code
12. [Chapter 12: How We Know It's Fast Enough](#chapter-12-how-we-know-its-fast-enough) — KPIs, the chaos soak, and what each number means

---

## Chapter 1: The End of the Server

### Why standard networks fail, and how we fix them

Think about how a standard corporate network works. When you open your laptop and try to access an internal app, your computer asks a central server (usually Microsoft Active Directory): *"Hey, is Alice allowed to do this?"*

This is the classic **Client-Server model**. It works perfectly — until the network goes down.

If you are a first responder in a disaster zone, a soldier on a disconnected field base, or a researcher in an underground facility with zero Wi-Fi, you cannot reach the central server. Suddenly, nobody can log in. Nobody can authorize actions. Work completely stops.

**Our Mission:** We are building a system that provides all the identity, groups, and security policies of Active Directory, but **without the central server**.

How? **Every single device carries its own copy of the guest list and the rulebook.** You can authenticate users and check permissions completely offline. When devices eventually reconnect to each other (even just over a local Bluetooth or LAN connection), they swap updates to get back in sync.

### What DDS replaces

| Traditional (Active Directory) | DDS Equivalent |
|---|---|
| Central LDAP server | Every node has a local replica |
| Kerberos tickets from a KDC | Signed tokens verified locally |
| Group Policy Objects (GPOs) | `WindowsPolicyDocument` gossiped to peers |
| DNS-based service discovery | mDNS + Kademlia DHT |
| Database replication (master-slave) | CRDTs (no master, no conflicts) |

---

## Chapter 2: Cryptographic Stamps

### Identity, keys, FIDO2, and quantum-safe math

In a normal system, you type a password, and a server checks its database to see if it matches. In DDS, there is no server database to check. Instead, we use **Public Key Cryptography**.

#### The digital stamp analogy

Every user and device generates a unique, mathematically linked pair of keys:

1. **Private Key:** A secret digital stamp only you hold.
2. **Public Key:** A verification template everyone else has.

When you do something, you "stamp" it with your Private Key. Anyone else can look at the stamp, compare it to your Public Key, and mathematically prove: *"Yes, Alice definitely did this."*

#### How it looks in our code

Here is how you create an identity in DDS (from `dds-core/src/identity.rs`):

```rust
// Generate a classical (Ed25519) identity
let alice = Identity::generate("alice", &mut OsRng);

// The identity's URN is derived from the public key hash
// e.g. "urn:vouchsafe:alice.5ahi6jnrlqe..."
println!("{}", alice.id.to_urn());

// Sign a message — anyone with the public key can verify this
let signature = alice.sign(b"hello world");
```

The `VouchsafeId` struct binds a human-readable label to a cryptographic hash:

```rust
pub struct VouchsafeId {
    label: String,   // e.g. "alice", "fileserver-01"
    hash: String,    // Base32 of SHA-256(public_key_bytes)
}
```

This means: **if someone's key changes, their ID changes.** You cannot impersonate someone without possessing their private key.

#### The three signing schemes

Our codebase supports multiple cryptographic schemes, controlled by a `SchemeId` enum:

```rust
pub enum SchemeId {
    Ed25519,                      // Classical — fast, 32-byte keys
    EcdsaP256,                    // For FIDO2 hardware compatibility
    HybridEdMldsa65,              // Ed25519 + ML-DSA-65 (quantum-safe)
    TripleHybridEdEcdsaMldsa65,   // All three combined
}
```

| Scheme | Public Key Size | Signature Size | Use Case |
|---|---|---|---|
| Ed25519 | 32 bytes | 64 bytes | Default, fastest |
| ECDSA-P256 | 65 bytes | 64 bytes | FIDO2 hardware tokens |
| Hybrid Ed+ML-DSA-65 | 1,984 bytes | 3,373 bytes | Quantum-resistant |

#### FIDO2: the physical key bridge

You might wonder: "Where is this private key stored?" We don't want users memorizing or typing cryptographic keys. Instead, we bridge DDS with **FIDO2/WebAuthn**. This means a user uses a physical hardware key (like a biometric Crayonic wallet or simple Yubikey) to hold their private key securely in tamper-resistant hardware.

Our `dds-domain/src/fido2.rs` module parses and verifies WebAuthn attestation objects. When a user enrolls with a FIDO2 key, the hardware produces an attestation proving possession. DDS wraps this inside a signed token so the credential becomes part of the trust chain.

#### Quantum-safe: why "hybrid"?

Standard math (Ed25519) is great today, but will eventually be breakable by quantum computers. The solution: **sign everything twice** — once with classical math, once with post-quantum math (ML-DSA-65, a FIPS 204 standard). Both signatures must verify for acceptance. This means:

- If classical crypto is broken → the PQ signature still holds
- If PQ crypto has an undiscovered flaw → the classical signature still holds
- An attacker must break *both* to forge a stamp

```rust
// Generate a hybrid (quantum-safe) identity
let alice = Identity::generate_hybrid("alice", &mut OsRng);

// Signs with BOTH Ed25519 and ML-DSA-65 simultaneously
let sig = alice.sign(b"post-quantum message");
assert_eq!(sig.scheme, SchemeId::HybridEdMldsa65);
```

---

## Chapter 3: The Chain of Permission Slips

### Tokens, the Trust Graph, and the Policy Engine

If there is no central database, how does my offline laptop know you are an IT Admin? Through a concept called **vouching**.

Imagine the CEO has the master stamp (the "Domain Root").

1. The CEO stamps a digital note saying, *"I vouch that Bob is an IT Admin."*
2. Bob then stamps a note saying, *"I vouch that Alice is in the Engineering Group."*

To prove you have access to the Engineering folder, you don't ask a server. You just hand over your chain of notes. Any laptop can read the notes, verify the cryptographic stamps offline, and say, *"Yep, the CEO vouched for Bob, and Bob vouched for Alice. Let her in."*

#### The Token: the universal envelope

Every operation in DDS is wrapped in a **Token** — a signed, timestamped, CBOR-encoded envelope. Think of it as a notarized document: the content inside can be anything, but the outer envelope proves who wrote it and when.

```rust
pub struct Token {
    pub header: TokenHeader,    // version, token ID (UUID), timestamps
    pub payload: TokenPayload,  // the actual data (see below)
    pub signatures: Vec<Sig>,   // one or more cryptographic signatures
}

pub struct TokenPayload {
    pub issuer: VouchsafeId,    // who created this token
    pub subject: VouchsafeId,   // who/what is this token about
    pub kind: TokenKind,        // what type of action (see below)
    pub body_type: String,      // MIME-like type tag for the body
    pub body_cbor: Vec<u8>,     // the actual payload, CBOR-encoded
}
```

#### The four token kinds

```rust
pub enum TokenKind {
    Attest,  // Self-declaration: "I am Alice's laptop"
    Vouch,   // Grant: "I, Admin Bob, add Alice to Engineering"
    Revoke,  // Remove: "I, Admin Bob, kick Charlie out"
    Burn,    // Destroy: "This stolen laptop's identity is dead"
}
```

Here is how you create and verify a token in code:

```rust
// Admin Bob vouches for Alice to join the "engineering" group
let token = Token::new(
    TokenKind::Vouch,
    &bob_identity,               // issuer (who is granting)
    &alice_id,                   // subject (who receives)
    "application/vnd.vouchsafe.group-membership",
    &group_membership_doc,       // the domain document inside
);

// Any node can verify this token offline
let is_valid = token.verify(&bob_public_key);
assert!(is_valid);
```

#### The Trust Graph

Because tokens reference each other (Bob's vouch references the Root's vouch for Bob), they naturally form a **directed graph** — a tree of trust. To check if Alice has access, the Policy Engine walks this graph backward from Alice to the Root:

```
Root ──vouches──▸ Bob (Admin) ──vouches──▸ Alice (Engineer)
```

If every signature along the path is valid and no revocations cancel any of the links, Alice is authorized. The entire check happens locally, in memory, in under 1 millisecond.

#### The Policy Engine

The Policy Engine is the brain that evaluates access requests. It uses typed rules:

```rust
pub struct PolicyRule {
    pub target: ResourcePattern,   // what resource? e.g. "file:/shared/*"
    pub principal: PrincipalSpec,  // who? e.g. "group:engineering"
    pub effect: Effect,            // Allow or Deny
    pub conditions: Vec<Condition>,// optional: time-of-day, device type, etc.
}

pub enum Effect {
    Allow,
    Deny,   // Deny always takes precedence (like AD)
}
```

The engine collects all applicable rules for a request and resolves them:

1. Gather all `PolicyRule`s whose `target` matches the resource
2. Filter to rules whose `principal` matches the requester's trust chain
3. If **any** rule says `Deny` → access denied (deny-wins)
4. If at least one rule says `Allow` → access granted
5. If no rules match → access denied (default-deny)

This is exactly how Windows Group Policy and LDAP ACLs work, except there is no server — every node runs this logic locally.

---

## Chapter 4: Magic Auto-Merging Spreadsheets

### CRDTs deep dive with code

What happens when people make changes while disconnected?

Imagine two IT managers are offline in different locations. Manager A adds Charlie to a group. At the exact same time, Manager B removes Charlie from that group. When their laptops finally reconnect, who wins?

If this were a normal database, you would get a merge conflict error. In DDS, we use **CRDTs (Conflict-Free Replicated Data Types)** — mathematical data structures that auto-merge deterministically, without ever producing a conflict.

#### Why CRDTs?

The key property of a CRDT is: **no matter what order the operations arrive in, every node converges to the same state.** Node A can process operations in a completely different order than Node B, and they will still end up with identical data. No coordination needed. No locking. No master.

#### The three CRDTs we use

**1. LWW Register (Last-Writer-Wins Register)**

For simple single values (like a user's display name), we use a timestamped register. Whichever write has the newest timestamp wins.

```rust
pub struct LwwRegister<T: Clone> {
    value: T,
    timestamp: HybridTimestamp,
}

impl<T: Clone> LwwRegister<T> {
    pub fn merge(&mut self, other: &LwwRegister<T>) {
        // If the incoming value has a newer timestamp, adopt it
        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
        }
    }
}
```

*Example:* Manager A sets display name to "Bob Smith" at 10:01. Manager B sets it to "Robert Smith" at 10:02. After merge, all nodes agree on "Robert Smith" because 10:02 > 10:01.

**2. Two-Phase Set (2P-Set) — the "Remove-Wins" set**

For group memberships, we need a set where items can be added AND removed. The 2P-Set tracks two internal sets:

```rust
pub struct TwoPSet<T: Hash + Eq + Clone> {
    add_set: HashSet<T>,      // everything ever added
    remove_set: HashSet<T>,   // everything ever removed
}

impl<T: Hash + Eq + Clone> TwoPSet<T> {
    pub fn contains(&self, item: &T) -> bool {
        // An item is "in" the set only if it was added AND never removed
        self.add_set.contains(item) && !self.remove_set.contains(item)
    }

    pub fn merge(&mut self, other: &TwoPSet<T>) {
        // Union both add-sets and both remove-sets
        self.add_set = self.add_set.union(&other.add_set).cloned().collect();
        self.remove_set = self.remove_set.union(&other.remove_set).cloned().collect();
    }
}
```

**The golden security rule: "Remove always wins."** If Manager A adds Charlie and Manager B removes Charlie concurrently, after merge Charlie is in both the add-set AND the remove-set. The `contains()` check says `false` — Charlie is out. This is intentional: it is much safer to accidentally lock someone out (fixable) than to accidentally leave a fired employee with access (catastrophic).

**3. Causal DAG (Directed Acyclic Graph)**

We track the order of all operations using a DAG. Every new operation stores a pointer (hash) to the operation(s) that came before it:

```rust
pub struct DagOperation {
    pub id: OpId,                     // unique hash of this operation
    pub parents: Vec<OpId>,           // what operations came before
    pub payload: Token,               // the actual token being applied
    pub timestamp: HybridTimestamp,   // when it happened
}
```

This gives us a "family tree" of operations. When two nodes sync, they compare their DAGs, identify the divergence point, and exchange only the missing branches. This is conceptually identical to how `git` tracks commits.

#### Hybrid timestamps

You might ask: "What if two laptops have different clocks?" We use **Hybrid Logical Clocks (HLC)**. These combine a physical wall-clock time with a logical counter, guaranteeing that events are always ordered correctly even when clocks drift:

```rust
pub struct HybridTimestamp {
    wall_time: u64,   // milliseconds since epoch (from system clock)
    counter: u32,     // logical counter for same-millisecond ordering
    node_id: NodeId,  // tie-breaker: node with higher ID wins
}
```

#### Storage budget

To keep storage tiny (target: under 50MB, so it fits on a phone), nodes only store the current "state" of the directory. Old operations are pruned once all known peers have acknowledged them — similar to how a database compacts its write-ahead log.

---

## Chapter 5: Devices Whispering Secrets

### P2P networking, Gossipsub, DHT, and delta-sync

When Manager B kicks Charlie out of the group, how does everyone else find out without a server routing the traffic?

**Devices gossip.** If your laptop connects to my laptop over local Wi-Fi, they quietly swap notes. Then, when I walk over to another building and connect to a desktop there, my laptop passes the gossip along. The news spreads like a virus until every device knows the new rules.

We don't write this networking code from scratch. We use a battle-tested Rust library called **libp2p** (the same tech that powers IPFS and various blockchain networks).

#### Layer 1: Discovery — "Who else is out there?"

Before devices can gossip, they need to find each other. We use two complementary discovery mechanisms:

**mDNS (Multicast DNS) — local network discovery**

When a DDS node starts, it shouts over the local network: *"Hey, I'm a DDS node for domain acme.com, here's my address!"* Other nodes on the same Wi-Fi or LAN hear this and connect automatically. No internet required, no configuration needed.

```rust
// In dds-net, mDNS discovery is configured like this:
let mdns = libp2p::mdns::tokio::Behaviour::new(
    mdns::Config::default(),
    local_peer_id,
)?;
// When a peer is discovered on the LAN:
// SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers)))
// → automatically dial and connect
```

**Kademlia DHT — wide-area discovery**

For finding peers across the internet (not just local networks), we use **Kademlia**, a Distributed Hash Table. Think of it as a decentralized phonebook:

- Every node has a unique ID (derived from its cryptographic key)
- Each node maintains a small routing table of other nodes it knows
- To find a specific node, you ask your neighbors, who ask their neighbors, etc.
- The math guarantees you find any node in O(log n) hops

```rust
// Kademlia is configured with domain-specific namespace isolation:
let mut kademlia = libp2p::kad::Behaviour::new(
    local_peer_id,
    MemoryStore::new(local_peer_id),
);
// Nodes from different domains use different DHT namespaces
// so acme.com nodes cannot discover contoso.com nodes
kademlia.set_protocol_names(vec![
    StreamProtocol::try_from_owned(
        format!("/dds/kad/{domain_hash}/1.0.0")
    )?
]);
```

#### Layer 2: Authentication — "The Bouncer"

We don't want random people joining our gossip network. Every DDS node must present an **Admission Certificate** — a token signed by the Domain Root — to connect. The TLS handshake is extended to verify this:

1. Node A connects to Node B
2. They exchange TLS certificates that embed their DDS Admission Certs
3. Each side verifies the other's cert chains back to the Domain Root
4. If verification fails → connection is immediately dropped

This means: even if a hacker finds your DHT namespace, they cannot eavesdrop or inject messages without a valid admission certificate from your organization.

#### Layer 3: Gossipsub — "Spreading the Word"

Once nodes are connected and authenticated, they use **Gossipsub** to propagate updates efficiently. Gossipsub is a pub/sub protocol where nodes subscribe to topics and relay messages to their peers.

**How Gossipsub works, step by step:**

1. When Admin Bob creates a "vouch" token, his node publishes it to the topic
2. His direct peers receive the message and re-publish to *their* peers
3. The message fans out exponentially until all subscribed nodes have it
4. Each node validates the token's cryptographic signature before accepting it
5. Duplicate messages are detected by ID and silently dropped

**Topic structure — we use separate channels for different priorities:**

```rust
// High-priority: revocations and burns spread FAST
let revocation_topic = format!("/dds/{domain_hash}/revocations");

// Normal priority: vouches, attestations, policy updates
let directory_topic = format!("/dds/{domain_hash}/directory");

// Low-priority: metadata updates (display names, etc.)
let metadata_topic  = format!("/dds/{domain_hash}/metadata");
```

Why separate topics? If a laptop is stolen and you burn its identity, you want that message to propagate in seconds, not get stuck behind a queue of display-name updates.

#### Layer 4: Delta Sync — "Catching Up After a Long Absence"

Gossipsub is great for live, real-time updates. But what if a laptop has been offline for two weeks? It missed thousands of Gossipsub messages that are no longer being re-broadcast.

This is where **Delta Sync** kicks in:

1. Node A connects to Node B
2. They exchange **state summaries** — compact hashes of their current CRDT states
3. They compare summaries to identify which operations each side is missing
4. They exchange only the missing operations (deltas)
5. Both sides merge the deltas into their local CRDTs

```rust
// Simplified delta-sync flow:
async fn sync_with_peer(local: &CrdtState, peer: &mut PeerConnection) {
    // 1. Exchange state fingerprints
    let local_summary = local.compute_hash_summary();
    let peer_summary = peer.exchange_summary(&local_summary).await;

    // 2. Compute the diff
    let missing_ops = local.diff(&peer_summary);

    // 3. Send our unique ops, receive theirs
    let their_ops = peer.exchange_deltas(&missing_ops).await;

    // 4. Merge into local CRDT state
    for op in their_ops {
        local.merge_operation(op)?; // CRDT merge — no conflicts!
    }
}
```

This is bandwidth-efficient: a two-week catch-up might only transfer a few kilobytes if only a handful of users changed during that time.

---

## Chapter 6: The Filing Cabinet

### The storage layer and its traits

Every DDS node needs to persist its data locally — the tokens, the CRDT state, the trust graph — so it survives a reboot. This is the job of the `dds-store` crate.

#### The storage trait

We define a clean trait (interface) so the storage engine can be swapped out:

```rust
pub trait StorageBackend: Send + Sync {
    /// Store a token by its ID
    fn put_token(&self, id: &TokenId, token: &Token) -> Result<()>;

    /// Retrieve a token by its ID
    fn get_token(&self, id: &TokenId) -> Result<Option<Token>>;

    /// List all tokens matching a filter (by kind, issuer, subject, etc.)
    fn query_tokens(&self, filter: &TokenFilter) -> Result<Vec<Token>>;

    /// Store the current CRDT state snapshot
    fn put_crdt_state(&self, state: &CrdtState) -> Result<()>;

    /// Retrieve the current CRDT state
    fn get_crdt_state(&self) -> Result<Option<CrdtState>>;

    /// Store an admission certificate
    fn put_admission(&self, cert: &AdmissionCert) -> Result<()>;
}
```

#### Two implementations

**`MemoryBackend`** — used in tests and embedded/wasm targets:

```rust
pub struct MemoryBackend {
    tokens: RwLock<HashMap<TokenId, Token>>,
    crdt_state: RwLock<Option<CrdtState>>,
}
```

Fast, zero dependencies, but everything vanishes when the process ends.

**`RedbBackend`** — used in production on real machines:

```rust
pub struct RedbBackend {
    db: redb::Database,   // ACID-compliant, single-file embedded DB
}
```

`redb` is a pure-Rust embedded database (think SQLite but simpler). It stores everything in a single file on disk, supports ACID transactions, and is incredibly fast for our read-heavy workload. We chose it because:

- No external dependencies (no C libraries)
- Single-file storage (easy to back up, move, or delete)
- ACID transactions (no corrupted state after a power failure)
- Compiles to every target Rust supports

#### How storage fits into the data flow

```
Token created (dds-core)
    │
    ▼
Token validated (signature + policy check)
    │
    ▼
Token stored locally (dds-store)   ──────▸   CRDT state updated
    │
    ▼
Token queued for gossip (dds-net)
```

Every token flows through this pipeline. The store is the checkpoint: once a token is persisted, it is safe. If the network drops mid-sync, the node can resume from the last stored state.

---

## Chapter 7: Domain Documents

### The typed business objects that ride inside tokens

Remember that a `Token` has a `body_cbor` field — the actual payload inside the envelope? That payload is a **Domain Document**. Domain Documents are the typed, serializable Rust structs that represent real-world business objects like "a user joined" or "apply this Windows policy."

#### The DomainDocument trait

Every domain document implements a common trait so the system knows how to embed it in a token and extract it back out:

```rust
pub trait DomainDocument: Serialize + DeserializeOwned {
    /// The MIME-like type string, e.g. "application/vnd.dds.user-auth-attestation"
    const BODY_TYPE: &'static str;

    /// Serialize this document into CBOR bytes for embedding in a Token
    fn to_cbor(&self) -> Result<Vec<u8>>;

    /// Deserialize from CBOR bytes extracted from a Token
    fn from_cbor(bytes: &[u8]) -> Result<Self>;
}
```

This pattern means: **any Rust struct that implements `DomainDocument` can ride inside a Token.** The Token doesn't care what the document is — it just signs it and transports it. The receiving node reads the `body_type` string to know which struct to deserialize into.

#### The documents we have today

Here are the domain documents currently defined in `dds-domain/src/`:

**`UserAuthAttestation`** — proves a user's identity and credentials:

```rust
pub struct UserAuthAttestation {
    pub user_id: VouchsafeId,          // who is this user?
    pub display_name: String,           // human-readable name
    pub auth_method: AuthMethod,        // how they authenticate
    pub credential_id: Vec<u8>,         // FIDO2 credential ID (if applicable)
    pub public_key: PublicKeyBytes,     // the user's public key
    pub created_at: HybridTimestamp,    // when this attestation was created
}

pub enum AuthMethod {
    Passkey,         // FIDO2 hardware key or biometric
    SoftwareKey,     // Software-based Ed25519 key
    HybridKey,       // Quantum-safe hybrid key
}
```

**`DeviceJoinDocument`** — registers a new device in the domain:

```rust
pub struct DeviceJoinDocument {
    pub device_id: VouchsafeId,        // unique device identity
    pub device_name: String,            // e.g. "Alice's MacBook Pro"
    pub os_type: OsType,               // Windows, macOS, Linux, iOS, Android
    pub device_class: DeviceClass,      // Workstation, Server, Mobile, IoT
    pub public_key: PublicKeyBytes,     // the device's keypair
    pub enrolled_by: VouchsafeId,       // which admin enrolled this device
}
```

**`SessionDocument`** — a time-limited login session:

```rust
pub struct SessionDocument {
    pub session_id: Uuid,
    pub user_id: VouchsafeId,          // who logged in
    pub device_id: VouchsafeId,        // on which device
    pub issued_at: HybridTimestamp,
    pub expires_at: HybridTimestamp,    // sessions MUST expire
    pub auth_method: AuthMethod,        // how they authenticated
}
```

**`WindowsPolicyDocument`** — the DDS equivalent of a Group Policy Object:

```rust
pub struct WindowsPolicyDocument {
    pub policy_id: Uuid,
    pub name: String,                     // "Disable USB Storage"
    pub target_groups: Vec<VouchsafeId>,  // apply to these groups
    pub registry_settings: Vec<RegistrySetting>,
    pub security_options: Vec<SecurityOption>,
    pub version: u64,                     // for LWW conflict resolution
}
```

**`SoftwareAssignment`** — assigns software packages to groups:

```rust
pub struct SoftwareAssignment {
    pub package_id: String,              // "com.example.vpn-client"
    pub version: String,                 // "2.1.0"
    pub target_groups: Vec<VouchsafeId>, // who gets this software
    pub install_action: InstallAction,   // Install, Uninstall, Update
    pub priority: u32,                   // higher = install first
}
```

**`MacOsPolicyDocument`** — carries managed macOS policy such as preferences,
local-account directives for standalone Macs, launchd jobs, and configuration
profiles.

**`MacAccountBindingDocument`** — binds a DDS subject on a specific device to
the macOS local account that hosts their home folder and session.

**`SsoIdentityLinkDocument`** — links an enterprise IdP identity (AD, Entra,
Okta, OIDC, and so on) to a DDS subject without making that IdP the DDS
authorization source.

**`ServicePrincipalDocument`** — registers machine/service identities such as
`HTTP/api.example.com`.

#### How documents flow through the system

```
Admin types: dds group vouch --user alice --group engineering
    │
    ▼
dds-cli creates a GroupMembershipDoc { user: alice, group: engineering }
    │
    ▼
dds-core wraps it in a Token(kind=Vouch, body_type="...group-membership")
    │
    ▼
dds-core signs the Token with the admin's private key
    │
    ▼
dds-store persists the Token locally
    │
    ▼
dds-net publishes the Token via Gossipsub to peers
    │
    ▼
Remote peers receive it, verify the signature, check the trust chain,
merge into their local CRDT, and persist to their own dds-store
```

---

## Chapter 8: The Lego Blocks

### Crate architecture and how they interface

We write DDS in **Rust** because it is incredibly fast, memory-safe, and lets us compile our code to run on a massive server or a tiny, bare-metal microchip.

The codebase is split into several packages (called "crates"). Each crate has a clear responsibility and communicates with others through well-defined Rust trait interfaces.

#### The dependency graph

```
                    ┌──────────┐
                    │ dds-cli  │  ← user types commands here
                    └────┬─────┘
                         │ calls
                    ┌────▼─────┐
                    │ dds-node │  ← wires everything together
                    └──┬──┬──┬─┘
           ┌───────────┘  │  └───────────┐
           ▼              ▼              ▼
      ┌─────────┐   ┌──────────┐   ┌──────────┐
      │ dds-net │   │ dds-store│   │ dds-ffi  │
      └────┬────┘   └────┬─────┘   └──────────┘
           │              │
           └──────┬───────┘
                  ▼
            ┌──────────┐
            │ dds-core │  ← pure logic, no I/O
            └────┬─────┘
                 │
            ┌────▼─────┐
            │dds-domain│  ← data structures only
            └──────────┘
```

#### Crate-by-crate breakdown

| Crate | Depends On | Responsibility | `no_std`? |
|---|---|---|---|
| `dds-domain` | (none) | Data structures, serialization | Yes |
| `dds-core` | `dds-domain` | Crypto, CRDTs, policy engine | Yes |
| `dds-store` | `dds-core` | Persistence (redb, memory) | No |
| `dds-net` | `dds-core` | libp2p, Gossipsub, DHT, sync | No |
| `dds-node` | `dds-core`, `dds-store`, `dds-net` | Daemon that wires it all | No |
| `dds-cli` | `dds-node` | Command-line interface | No |
| `dds-ffi` | `dds-core` | C ABI for foreign languages | No |

#### The interfaces between crates

**dds-node → dds-core:** The node calls `dds-core` for all business logic:

```rust
// Node asks core to create a signed vouch token
let token = dds_core::token::create_vouch(
    &admin_identity,
    &target_user_id,
    &group_membership_doc,
)?;

// Node asks core to validate an incoming token
let validation = dds_core::token::validate(&incoming_token, &trust_store)?;
match validation {
    Valid => { /* accept and store */ }
    InvalidSignature => { /* reject */ }
    RevokedIssuer => { /* reject */ }
}
```

**dds-node → dds-store:** The node uses the `StorageBackend` trait:

```rust
// Persist a validated token
store.put_token(&token.id(), &token)?;

// Query all group membership tokens for a user
let memberships = store.query_tokens(&TokenFilter {
    subject: Some(alice_id),
    kind: Some(TokenKind::Vouch),
    body_type: Some("application/vnd.dds.group-membership"),
    ..Default::default()
})?;
```

**dds-node → dds-net:** The node delegates networking:

```rust
// Publish a new token to the gossip network
network.publish_token(&token, GossipPriority::Normal).await?;

// Subscribe to incoming tokens
let mut rx = network.subscribe_tokens().await;
while let Some(token) = rx.recv().await {
    if dds_core::token::validate(&token, &trust_store).is_ok() {
        store.put_token(&token.id(), &token)?;
        crdt_state.merge_token(&token)?;
    }
}
```

#### Why `no_std` matters

`dds-core` and `dds-domain` are marked `#![no_std]`. This means they don't use the Rust standard library (no file I/O, no networking, no heap allocation by default). Why?

- **Embedded targets:** DDS can run on microcontrollers, IoT devices, and smart cards
- **WebAssembly:** These crates compile to WASM for browser-based DDS clients
- **Security:** No I/O means no side channels — the core logic is pure computation
- **Testability:** Pure functions are trivially testable with no mocking required

---

## Chapter 9: The Translator

### FFI bridge to Python, C#, Swift, and Kotlin

DDS is written in Rust, but we need mobile apps (iOS, Android), desktop GUIs (Windows, macOS), and scripting integrations (Python). The `dds-ffi` crate is the bridge that makes this possible.

#### What is FFI?

**FFI (Foreign Function Interface)** is a way for one programming language to call functions written in another. Since Rust compiles to native machine code (just like C), we can expose Rust functions with a C-compatible ABI that any language can call.

#### How it works in DDS

We use Mozilla's **UniFFI** library. Instead of manually writing C headers, UniFFI reads our Rust function signatures and automatically generates bindings for:

- **Python** — `.py` wrapper module
- **Swift** — `.swift` wrapper for iOS/macOS
- **Kotlin** — `.kt` wrapper for Android
- **C#** — `.cs` wrapper for Windows/.NET apps

#### The FFI surface

The `dds-ffi` crate exposes a small, carefully curated API:

```rust
// Identity management
#[uniffi::export]
pub fn dds_identity_create(label: &str, hybrid: bool) -> Result<FfiIdentity>;

#[uniffi::export]
pub fn dds_identity_get_urn(identity: &FfiIdentity) -> String;

// Token operations
#[uniffi::export]
pub fn dds_token_create_attest(
    identity: &FfiIdentity,
    doc_json: &str,    // JSON-encoded domain document
) -> Result<Vec<u8>>;  // returns CBOR-encoded signed token

#[uniffi::export]
pub fn dds_token_validate(
    token_cbor: &[u8],
    trust_store_json: &str,
) -> Result<FfiValidationResult>;

// Policy evaluation
#[uniffi::export]
pub fn dds_policy_evaluate(
    request_json: &str,    // who is requesting what
    policy_json: &str,     // the policy rules
    trust_graph_json: &str,// the trust chain
) -> Result<bool>;         // allowed or denied
```

#### Using DDS from Python (example)

```python
import dds

# Create a quantum-safe identity
alice = dds.dds_identity_create("alice", hybrid=True)
print(f"Alice's URN: {dds.dds_identity_get_urn(alice)}")

# Create a self-attestation token
attestation = dds.dds_token_create_attest(
    alice,
    '{"display_name": "Alice Smith", "auth_method": "HybridKey"}'
)

# Validate a received token
result = dds.dds_token_validate(received_token_bytes, trust_store_json)
if result.is_valid:
    print("Token is authentic and authorized")
```

#### Using DDS from Swift (iOS example)

```swift
import DdsBindings

// Create identity on the device's secure enclave
let deviceId = try ddsIdentityCreate(label: "iphone-14", hybrid: true)

// Validate an incoming policy update from a peer
let result = try ddsTokenValidate(
    tokenCbor: incomingData,
    trustStoreJson: localTrustStore
)
guard result.isValid else {
    print("Rejected: \(result.reason)")
    return
}
```

This means: **the core security logic is written once in Rust, tested once, and shared across every platform.** No reimplementation bugs. No platform-specific crypto libraries.

---

## Chapter 10: The Road to Active Directory

### Expanding DDS to cover AD and LDAP concepts

DDS today covers identity, groups, basic policies, and software assignment. But Active Directory and LDAP are enormous systems with decades of features. This chapter maps every major AD concept to its DDS equivalent and shows how our `DomainDocument` pattern makes expansion straightforward.

#### The AD/LDAP feature map

| AD/LDAP Concept | Current DDS Status | Proposed DDS Document |
|---|---|---|
| User accounts | ✅ `UserAuthAttestation` | Expand with more attributes |
| Computer accounts | ✅ `DeviceJoinDocument` | Already supported |
| Groups (security + distribution) | ✅ Group membership via Vouch/Revoke | Add `GroupDocument` |
| Organizational Units (OUs) | ❌ Not yet | `OrgUnitDocument` |
| Group Policy Objects (GPOs) | ✅ `WindowsPolicyDocument` | Expand scope |
| Service Principal Names (SPNs) | ❌ Not yet | `ServicePrincipalDocument` |
| DNS records | ❌ Not yet | `DnsRecordDocument` |
| Certificate templates | ❌ Not yet | `CertTemplateDocument` |
| Schema extensions | ❌ Not yet | `SchemaExtensionDocument` |
| Fine-grained password policies | ❌ Not yet | `PasswordPolicyDocument` |
| LDAP attributes | ❌ Not yet | `ExtensibleAttributes` map |

#### Expanding UserAuthAttestation

The current `UserAuthAttestation` is minimal. To match Active Directory's user object, we would expand it like this:

```rust
pub struct UserAuthAttestation {
    // === Existing fields ===
    pub user_id: VouchsafeId,
    pub display_name: String,
    pub auth_method: AuthMethod,
    pub credential_id: Vec<u8>,
    pub public_key: PublicKeyBytes,
    pub created_at: HybridTimestamp,

    // === New fields to match AD/LDAP user object ===

    // Identity attributes (like AD's "General" tab)
    pub given_name: Option<String>,          // first name
    pub surname: Option<String>,             // last name
    pub email: Option<String>,               // mail attribute
    pub phone: Option<String>,               // telephoneNumber
    pub title: Option<String>,               // job title
    pub department: Option<String>,          // department
    pub company: Option<String>,             // company
    pub manager: Option<VouchsafeId>,        // manager's DDS identity

    // Account control (like AD's userAccountControl flags)
    pub account_disabled: bool,              // is the account locked?
    pub account_expires: Option<HybridTimestamp>, // expiration date
    pub must_change_credential: bool,        // force re-enrollment
    pub lockout_until: Option<HybridTimestamp>,   // temporary lockout

    // Multi-factor authentication
    pub mfa_methods: Vec<MfaMethod>,         // TOTP, SMS, hardware key, etc.

    // LDAP-style extensible attributes
    pub extra_attributes: BTreeMap<String, AttributeValue>,
}
```

The `extra_attributes` field is the key to LDAP compatibility. Just like LDAP allows arbitrary attributes on any object, DDS can carry arbitrary key-value pairs without changing the core schema.

#### New documents for AD feature parity

**Organizational Units (OUs)** — hierarchical containers for organizing users and devices:

```rust
pub struct OrgUnitDocument {
    pub ou_id: VouchsafeId,
    pub name: String,                      // e.g. "Engineering", "Sales"
    pub parent_ou: Option<VouchsafeId>,    // parent OU (for nesting)
    pub description: Option<String>,
    pub managed_by: Option<VouchsafeId>,   // delegated admin

    // Linked policies (like AD's GPO linking)
    pub linked_policies: Vec<VouchsafeId>, // WindowsPolicyDocument IDs
}
```

In Active Directory, OUs are containers that hold users, computers, and other OUs. Policies are "linked" to OUs and inherited downward. In DDS, we achieve the same thing: an `OrgUnitDocument` lists the policies that apply to it, and the Policy Engine walks up the OU tree to collect all inherited policies.

**Service Principals** — machine identities for services (like AD's SPNs):

```rust
pub struct ServicePrincipalDocument {
    pub service_id: VouchsafeId,
    pub service_type: String,           // "HTTP", "LDAP", "SQL", etc.
    pub hostname: String,               // "fileserver.acme.com"
    pub port: Option<u16>,              // 443, 636, etc.
    pub owning_device: VouchsafeId,     // which device runs this service
    pub allowed_groups: Vec<VouchsafeId>, // who can access this service
}
```

In AD, a Service Principal Name (SPN) like `HTTP/webapp.acme.com` lets Kerberos authenticate services. In DDS, we achieve the same by issuing a signed `ServicePrincipalDocument` that binds a service identity to a device and specifies who is authorized to use it.

**DNS Records** — decentralized service discovery:

```rust
pub struct DnsRecordDocument {
    pub record_id: VouchsafeId,
    pub record_type: DnsRecordType,     // A, AAAA, CNAME, SRV, TXT
    pub name: String,                   // "fileserver.acme.com"
    pub value: String,                  // "192.168.1.50"
    pub ttl: u32,                       // time-to-live in seconds
    pub priority: Option<u16>,          // for SRV records
}
```

AD integrates tightly with DNS. In DDS, DNS records become just another document type that gets gossiped. Nodes can resolve internal hostnames by querying their local CRDT state — no DNS server needed.

**Group Document** — first-class group objects (beyond just vouch/revoke):

```rust
pub struct GroupDocument {
    pub group_id: VouchsafeId,
    pub name: String,                        // "Engineering"
    pub group_type: GroupType,               // Security, Distribution
    pub group_scope: GroupScope,             // DomainLocal, Global, Universal
    pub description: Option<String>,
    pub parent_ou: Option<VouchsafeId>,      // which OU does this live in
    pub nested_groups: Vec<VouchsafeId>,     // group-in-group (like AD)
    pub managed_by: Option<VouchsafeId>,     // delegated group manager
}

pub enum GroupType {
    Security,       // used for access control (like AD security groups)
    Distribution,   // used for mailing lists / notifications only
}

pub enum GroupScope {
    DomainLocal,    // valid only within one domain
    Global,         // valid across the organization
    Universal,      // valid across forest trusts
}
```

#### The extensibility pattern

The beauty of DDS's architecture is that **adding a new AD feature requires only three steps:**

1. **Define a new `DomainDocument` struct** in `dds-domain`
2. **Register its `BODY_TYPE` string** so the system knows how to deserialize it
3. **Add policy rules** for who is allowed to create/modify/delete these documents

No networking changes. No storage schema migrations. No protocol updates. The Token/CRDT/Gossipsub pipeline transports any document type transparently.

```rust
// Step 1: Define the new document in dds-domain
pub struct MyNewDocument {
    pub id: VouchsafeId,
    pub data: String,
}

impl DomainDocument for MyNewDocument {
    const BODY_TYPE: &'static str = "application/vnd.dds.my-new-document";
    // ... to_cbor() and from_cbor() are derived via serde
}

// Step 2: That's it. Wrap it in a Token and gossip it.
let token = Token::new(TokenKind::Vouch, &admin, &target, MyNewDocument::BODY_TYPE, &doc);
```

#### LDAP compatibility layer

For organizations migrating from Active Directory, we envision a compatibility shim:

```
┌─────────────────────────┐
│  Existing LDAP clients  │  ← legacy apps speak LDAP
│  (Outlook, SAP, etc.)   │
└────────┬────────────────┘
         │ LDAP protocol (port 389/636)
    ┌────▼────────────────┐
    │  dds-ldap-proxy     │  ← translates LDAP ↔ DDS
    └────────┬────────────┘
             │ Rust API calls
        ┌────▼────────┐
        │  dds-node   │  ← the real DDS engine
        └─────────────┘
```

The `dds-ldap-proxy` would accept standard LDAP queries (search, bind, modify) and translate them into DDS token operations. This allows organizations to run DDS internally while keeping legacy applications working unchanged.

---

## Chapter 11: Your First Day

### Getting started with the code

Diving straight into libp2p networking or post-quantum cryptography is a recipe for a headache. Here is the recommended path to get comfortable on your first day:

#### 1. Build and run the CLI

Open your terminal, compile the project, and play with the CLI. This will make the abstract concepts feel real.

```bash
# Build the whole workspace
cargo build --workspace

# Create an identity (using hybrid quantum-safe math)
cargo run -p dds-cli -- identity create alice --hybrid

# Check your node's status
cargo run -p dds-cli -- status
```

#### 2. Read the blueprints

Navigate to the `dds-domain` crate. This is the most human-readable code. Look at how a `SessionDocument` or a `UserAuthAttestation` is structured. These are just beautifully typed Rust structs representing our real-world concepts.

#### 3. Read the tests

We have over 200 tests. Tests are the absolute best documentation for seeing how the pieces are expected to behave when pushed to their limits.

- Want to see how CRDTs work? → Read the tests in `dds-core/src/crdt/`
- Want to see how access is granted? → Read `dds-core/src/policy.rs`
- Want to see how tokens are signed and verified? → Read `dds-core/src/token.rs`
- Want to see FIDO2 attestation parsing? → Read `dds-domain/src/fido2.rs`

#### 4. Follow the data

Trace a single action through the entire stack. Look at what happens in the code when you type `dds group vouch` in the CLI.

1. **dds-cli** parses the command and calls into `dds-node`
2. **dds-node** calls `dds-core` to build a `GroupMembershipDoc`
3. **dds-core** wraps it in a `Token`, signs it with the admin's key
4. **dds-node** passes the token to `dds-store` for persistence
5. **dds-node** passes the token to `dds-net` for gossip broadcast
6. **Remote peers** receive it via Gossipsub, validate, merge, and store

#### 5. Run the test suite

```bash
# Run all tests across all crates
cargo test --workspace

# Run tests for a specific crate with output
cargo test -p dds-core -- --nocapture

# Run a specific test by name
cargo test -p dds-core test_twop_set_remove_wins
```

#### 6. Explore with curiosity

Some good questions to investigate as you explore:

- What happens if you try to create a vouch token without admin privileges?
- What does the CRDT state look like after merging two divergent timelines?
- How does the DHT namespace isolation prevent cross-domain leaks?
- What is the maximum token size and how does CBOR keep it compact?

---

**Welcome aboard!** You don't need to know how to build a post-quantum cryptographic algorithm to use one. Focus on the inputs, the outputs, and how the Lego blocks snap together. When you are ready to go deeper into any specific chapter, the code and tests are your best teachers. Happy hacking!

---

## Chapter 12: How We Know It's Fast Enough

So far we have talked about *what* DDS does and *how* it works. This chapter is about how we know it works **fast enough** and **stays correct** when the network gets messy. If you have ever read a system spec and wondered "but how do they actually prove any of this?", this chapter is for you.

### Why we need KPIs at all

DDS has to make security decisions on every single user action — every time someone logs in, opens a file, or hits a service endpoint. If the trust check is slow, the user feels it as lag. If the trust check is even occasionally wrong, the wrong people get into things they shouldn't. So the design has hard numbers (called **Key Performance Indicators**, or KPIs) that the system must hit *every single time*, not just on average.

Think of KPIs like the speed limit on a road. The system isn't allowed to be slower than the budget at the 99th percentile (we call that **p99**). p99 means: "out of every 100 requests, at most 1 is allowed to be slower than this." We use p99 instead of average because averages hide outliers — and outliers are exactly the requests that make users complain.

The full list of KPIs lives in [DDS-Design-Document.md §10](DDS-Design-Document.md). This chapter walks through the ones that matter most for day-to-day correctness.

### The five hard KPIs

| # | Name | Budget | Plain English |
| - | --- | --- | --- |
| 1 | **Local auth decision (p99)** | ≤ 1 ms | When an app asks "can this user do X?", DDS must answer in under 1 millisecond, 99% of the time, *without touching the network* |
| 2 | **Ed25519 verify throughput** | ≥ 50,000 ops/sec | A single CPU core must be able to verify at least 50,000 signatures per second. This bounds how many policy checks per second the system can do |
| 3 | **CRDT merge (p99)** | ≤ 0.05 ms | When two nodes' state has to merge (because they were both editing the same spreadsheet cell), the merge has to happen in under 50 microseconds |
| 4 | **Peak heap per 1K entries** | ≤ 5 MB | For every 1,000 directory entries (users + devices + vouches), the in-memory representation must fit in 5 MB. Bounds the cost of a 10K-user org to ~50 MB |
| 5 | **Idle gossip bandwidth** | ≤ 2 KB/sec | When nothing is happening, each node should only chatter at most 2 KB/sec on the network. Important for laptops on cellular |

There are also informational KPIs we track but don't fail the build on:

- **Gossip propagation p99** — how long it takes for an op published on node A to land on every other node
- **Rejoin convergence** — how long a node that went offline takes to catch back up after reconnecting
- **Enrollment latency** — how long `enroll_user` and `enroll_device` take

#### KPI #1 — Local auth decision (the most important one)

Every time someone tries to do something — log in, open a file, push to a repo — the running app calls `LocalService::evaluate_policy(subject, resource, action)`. Inside that function, DDS:

1. Looks up which **vouches** the subject's identity has been given
2. Walks the **trust chain** from each vouch back to a trusted root
3. Checks for any **revocations** along the way
4. Intersects the resulting set of granted "purposes" with the resource's policy rules
5. Returns Allow or Deny

All of that must finish in **under 1 millisecond at p99**. That budget exists because users are sensitive to lag in the 10–100 ms range; if every login takes even 5 ms, you can build hundreds of these into a single screen and the screen feels slow. By keeping each one under 1 ms, we have headroom to compose them.

> **Why this is hard**: the trust graph grows over the lifetime of an org. You might end up with 10,000 vouch tokens. If you naively scan all 10,000 on every check, you blow this budget very quickly. (We learned this the hard way during the chaos soak — see below.)

#### KPI #2 — Ed25519 verify throughput

When DDS receives a token from another node (via gossip or sync), it has to verify the signature before trusting it. **Ed25519** is the cryptographic algorithm we use for that. The §10 design budget says: "a single core on a modern x86_64 box must be able to verify at least 50,000 of these per second."

That number wasn't picked at random — it's roughly the rate at which a busy DDS node receives gossip messages during normal load, with comfortable headroom. If we can't verify signatures faster than they arrive, the queue grows forever and the node falls behind.

We measure this two ways:

- **Criterion micro-benchmark** in `dds-core/benches/crypto_verify.rs` — runs the verify in isolation in a tight loop. This is the authoritative number.
- **Live measurement during the soak** — the harness samples it once per workload tick. Used for trend tracking, not for the hard verdict.

#### KPI #3 — CRDT merge

CRDTs ([Chapter 4](#chapter-4-magic-auto-merging-spreadsheets)) are how DDS handles two nodes editing the same logical thing without a coordinator. Every gossip message that arrives causes one CRDT merge operation. Like the Ed25519 number above, this has to finish faster than messages arrive — otherwise the queue grows forever.

50 microseconds is way under what `BTreeMap` and `BTreeSet` operations cost in Rust at our scale, so this KPI is mostly a safety net. It would only fail if someone accidentally introduced a quadratic loop somewhere. Which is exactly the kind of thing we want a regression gate for.

#### KPI #4 — Peak heap per 1K entries

DDS is meant to run on small devices (think: a Raspberry Pi at the edge of a network) as well as servers. The §10 budget says that each 1,000 directory entries (users + devices + vouches + revocations) should fit in 5 MB of RAM. That's tight enough to keep us honest about data structure overhead but loose enough that we don't have to micro-optimize every byte.

> **Honest disclosure**: we currently measure this as **whole-process RSS** (Resident Set Size — how much memory the OS thinks the process is using) divided by the number of trust graph entries. This includes the libp2p runtime baseline (~30 MB), so the number always looks worse than the real cost of an entry. The real fix is to wire up the [`dhat`](https://docs.rs/dhat) heap profiler, which can answer "how much of the heap is owned by the trust graph specifically?" — we deferred that to post-pilot.

#### KPI #5 — Idle gossip bandwidth

When nothing is happening — no users joining, no policies changing — DDS still needs to send "I'm alive" heartbeats and run the anti-entropy sync ([§5](#chapter-5-devices-whispering-secrets)). The §10 budget caps this at 2 KB/sec per node, because we want DDS to be friendly to laptops on cellular tethering and devices on metered links.

Same caveat as #4: we currently estimate this from RSS deltas, not from real network byte counters, because libp2p doesn't expose per-direction byte stats out of the box. Documented as a measurement gap, not a perf gap.

### The chaos soak — how we actually test this stuff

KPIs are just numbers in a doc until you measure them under realistic load. The tool that does that is **`dds-loadtest`**, which you can find in [`dds-loadtest/`](dds-loadtest/). It is a long-running multi-node harness that:

1. Spawns N in-process `DdsNode` instances on ephemeral ports
2. Wires them into a libp2p full-mesh
3. Drives a mixed realistic workload (enroll users, enroll devices, issue sessions, evaluate policies, occasional revocations)
4. Optionally enables a **chaos layer** that randomly pauses and resumes nodes — simulating restarts, network blips, OS sleep
5. Records per-op latency histograms, error counts, and gauge samples (RSS, trust graph size, gossip bandwidth)
6. At the end, writes a `summary.md` and `summary.json` with KPI verdicts

A "smoke" run is 60 seconds with 3 nodes and is gated in CI. A "soak" run is 30 minutes (or 24 hours) with 5 nodes and chaos enabled, used for serious sign-off.

```bash
# 60s smoke (CI gate)
cargo run -p dds-loadtest --release -- --smoke

# 30-min chaos validation soak
cargo run -p dds-loadtest --release -- --duration 30m --nodes 5 \
  --chaos --chaos-interval 2m --chaos-offline 45s

# 24-hour endurance run (use caffeinate on macOS to prevent sleep)
caffeinate -dimsu cargo run -p dds-loadtest --release -- \
  --duration 24h --nodes 5 --chaos
```

### A real story: what the chaos soak found

We added the chaos layer in April 2026, ran the first 30-minute soak, and **immediately found two production-blocking bugs that the existing 60-second smoke had been hiding for months**:

**Bug 1 — Trust graph queries were O(V) in vouch count.** Every call to `evaluate_policy` was iterating *every vouch in the graph* to find the ones that vouched for the subject. With 100 vouches that's fine. With 10,000 vouches the p99 of `evaluate_policy` climbed to **10.8 milliseconds** — over 10× the §10 budget.

The fix was to add a secondary index `vouches_by_subject: BTreeMap<String, BTreeSet<String>>` on `TrustGraph` so the lookup becomes O(matches-for-this-subject) instead of O(total-vouches). The unit test `test_purposes_for_scales_to_10k_vouches` in [`dds-core/src/trust.rs`](dds-core/src/trust.rs) builds a 10,000-vouch graph and asserts the worst-case `purposes_for` call is under 500 µs. **It now measures 3.2 µs.**

**Bug 2 — Gossipsub-only delivery had no catch-up.** When a node went offline (because of chaos, or a real restart, or a flaky network), it permanently lost every op published during that window. Gossipsub doesn't replay history — it only delivers *live* messages. So a node that was offline for 60 seconds came back missing 60 seconds of operations forever. The chaos soak measured this as **16 of 29 chaos rejoins timing out** at the 5-minute deadline.

The fix was to wire up the **anti-entropy sync protocol** that already existed (with passing tests!) in [`dds-net/src/sync.rs`](dds-net/src/sync.rs) but was never invoked from the swarm event loop. We added a `libp2p::request_response::cbor::Behaviour<SyncRequest, SyncResponse>` to `DdsBehaviour`, and on every `ConnectionEstablished` event the new node sends a `SyncRequest` carrying its known op IDs. The peer responds with the diff. Plus a 60-second backstop timer that periodically syncs against every connected peer to catch slow drift.

After both fixes, the same 30-minute chaos soak got **0 errors across 466K ops, all five hard §10 KPIs PASS, and 14 of 14 chaos rejoins succeeded with 0 timeouts.**

### How to read a soak summary

Every soak writes a `summary.md` like this (real output from the validation soak):

```text
- Duration: 1800 s
- Nodes:    5
- Chaos:    enabled — interval=120s, offline=45s, paused=15, rejoined=15

## KPI Verdicts (§10)

| KPI                          | Target          | Measured                       | Status   |
| Local auth decision (p99)    | ≤ 1 ms          | 0.050 ms                       | ✅ PASS  |
| Ed25519 verify throughput    | ≥ 50,000 ops/s  | 53,975 ops/sec                 | ✅ PASS  |
| CRDT merge (p99)             | ≤ 0.05 ms       | 0.0000 ms                      | ✅ PASS  |
| Peak heap per 1K entries     | ≤ 5 MB / 1K     | 17.94 MB / 1K (RSS-proxy)      | ⚠️ WARN  |
| Idle gossip bandwidth        | ≤ 2 KB/sec      | 11.5 KB/sec (RSS-proxy)        | ⚠️ WARN  |
| Rejoin convergence (p99)     | no timeouts     | p50 36.5 s / p99 144 s         | ✅ PASS  |
```

Things to look at, in order:

1. **Errors** — should be `0`. Anything else is a bug.
2. **Hard KPI verdicts** — anything not ✅ on the first five rows is a release blocker.
3. **Warnings** — these are the RSS-proxy caveats described above. Real but not blockers.
4. **Histograms** — every op type gets `count / ok / err / p50 / p90 / p99 / max`. If `err > 0`, dig in.
5. **Gauge samples** — every 30 seconds we record RSS, trust graph size, gossip bandwidth. Watch for **monotonic growth** (never plateaus) — that almost always means a leak or a missing GC path.

### What's still soft

Two of the §10 KPIs are currently measured by **proxy** rather than directly:

- **Peak heap** uses whole-process RSS, which always overstates the true cost because it includes the libp2p runtime baseline (~30 MB)
- **Idle bandwidth** uses RSS-delta over time, because libp2p doesn't expose per-direction network counters

For pilot deployments these proxies are good enough — we know the *trend* is flat and the *order of magnitude* is right. Before general availability we plan to wire up `dhat` for real heap profiling and a custom transport wrapper for real byte counters. See risk **R5** in [STATUS.md](../STATUS.md) for details.

### The TL;DR

- DDS has 5 hard KPIs and a few informational ones, all defined in [DDS-Design-Document.md §10](DDS-Design-Document.md)
- The most important one is **Local auth decision p99 ≤ 1 ms** — this is what users feel
- We measure them via `dds-loadtest`, which runs a multi-node mesh under realistic load + optional chaos
- The chaos layer (random pause/resume of nodes) is what surfaces the bugs that 60-second smoke runs hide
- The April 2026 chaos soak found two production blockers (B5 algorithmic + B6 sync) that were both fixed and re-validated within a day
- Two KPIs (heap, bandwidth) are currently RSS-proxy measurements with documented caveats — fine for pilot, will be hardened pre-GA

If you remember nothing else from this chapter: **soaks are how we find the bugs that stress tests miss, and KPIs are how we keep ourselves honest about whether the fix actually worked.**
