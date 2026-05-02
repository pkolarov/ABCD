# DDS Blob Distribution — libp2p Request-Response Proposal

**Status:** Proposal — not yet implemented.
**Date:** 2026-05-02.
**Tracking ID:** `BLOB-1`. Future phase tags use `BLOB-D-N`.
**Owner:** TBD.
**Closes (when implemented):** the bulk-data gap surfaced by the L-1
hybrid smoke. Today `dds-node` can gossip a signed manifest at the
`/v1/{platform}/software` envelope path, but the binary itself has to
come from an external mirror (apt, dnf, S3, …) — that mirror is the
SPOF and bandwidth bottleneck for fleet-wide updates at 1000+ nodes.

---

## 1. Problem

Gossipsub caps a single message at **64 KiB**
([`max_transmit_size`](https://docs.rs/libp2p-gossipsub/0.55) default;
not overridden in [dds-net/src/transport.rs:168](../dds-net/src/transport.rs:168)).
DDS already uses gossip for small signed operations (≤ ~1 KB
typical), the H-12 admission piggy-back, and Phase-B
`EpochKeyRelease` blobs (≤ 5 KB). Anything larger needs a different
transport.

Concretely, the surfaces that break at fleet size today:

- **Software updates.** `/v1/{windows,macos,linux}/software` ships a
  signed [`SoftwareBundle`-shaped envelope](../dds-node/src/http.rs:770)
  with package metadata. The applier (Windows / macOS / Linux agent)
  then has to fetch the binary from `apt`/`dnf`/`winget`/an S3 URL.
  In a 1000-node fleet a 50 MB rollout pulls 50 GB through one
  external endpoint. The "thundering herd" pattern is a routine
  outage cause for large fleets.
- **Configuration / policy bundles** above ~32 KB (large compliance
  baselines, signed allowlists) — same shape, today no in-band path
  to ship the bytes.
- **Recovery bundles** (a fresh node provisioned via
  `dds-node create-provision-bundle`) — currently fit in `< 64 KB` but
  trend upward as Phase-A hybrid keys + Phase-B KEM material
  inflate the bundle.

We want a **content-addressed, peer-to-peer blob fetch** that:

1. Reuses the trust posture DDS already has (admission gating + PQ
   envelope on `enc-v3` domains).
2. Costs O(log N) hops to ship a blob from one publisher to N
   members, with each member contributing upload bandwidth.
3. Ships **only signed, manifest-bound bytes** — no surprise content.
4. Does not regress the security review for the existing protocols
   (`admission`, `sync`, `epoch-keys`).

## 2. Goals

1. New libp2p request-response protocol
   `/dds/blob/1.0.0/<domain>` carrying chunked, content-addressed
   blob fetches between admitted peers.
2. A signed `BlobManifest` envelope (extends the existing
   `SoftwareBundle` shape) that names the blob's `root_hash`,
   chunk size, total size, and a list of seed `peer_ids` known to
   already have it.
3. Manifest delivery rides existing gossip / sync /
   `/v1/{platform}/software` paths — the new protocol only handles
   bytes-in-flight, not the discovery surface.
4. Receiver-side verify-as-you-go: each chunk is hash-checked against
   a Merkle root signed in the manifest, before it touches disk.
5. AEAD-wrapped on `enc-v3` domains using the responder's epoch key
   (the same envelope the sync responder already uses, B.8).
6. Anti-DoS: per-peer concurrent-fetch limits, per-blob backpressure,
   admitted-peers-only, signed-manifest-required.
7. Cache lives in `<data_dir>/blobs/`, content-addressed by
   `sha256(content)`, LRU-evicted with a configurable budget.

## 3. Non-goals (this proposal)

- BitTorrent / IPFS Bitswap parity. We pick the simplest scheme that
  satisfies the fleet update + policy-bundle case. Any chunk
  scheduler smarter than "round-robin among peers in the manifest's
  seed list" is out of scope for D-1; revisit after measurement.
- Cross-domain blob sharing. A blob is scoped to its domain by the
  protocol path; no inter-domain relay.
- Content discovery via DHT. Blob `peer_ids` come from the signed
  manifest; we do not advertise blob content over Kademlia.
- Compression. The transport ships exactly the bytes the publisher
  signed; if the publisher wants compression they compress before
  hashing.
- Resumable uploads. The publisher mints a manifest only when its
  local copy is complete; partial-upload state is the publisher's
  problem.

## 4. Architecture

```text
                 ┌────────────────────────────────────────────┐
                 │           Admin (publisher node)           │
                 │  signs SoftwareBundle{ ..., manifest: …}   │
                 │  emits via /v1/{platform}/software         │
                 │  + gossip(operations topic, B-2 channel)   │
                 └────────────────┬───────────────────────────┘
                                  │  signed manifest in envelope
                                  ▼
            ┌─────────────────────────────────────────────────┐
            │  Domain peers (admitted)  —  receive manifest    │
            │  via gossip OR sync OR direct platform pull     │
            └────────┬─────────────────────────┬──────────────┘
                     │                         │
                     │ blob not present?       │
                     │ pull from any peer in   │
                     │ manifest.seed_peers     │
                     ▼                         ▼
            ┌────────────────────┐   ┌────────────────────┐
            │ Peer A (has blob)  │◀──│ Peer B (fetcher)   │
            │ libp2p RR proto    │   │ verifies chunks    │
            │ /dds/blob/1.0.0/…  │   │ as they arrive,    │
            │  chunk request →  │   │ writes to local    │
            │  ←  chunk + proof  │   │ <data_dir>/blobs/  │
            └────────────────────┘   └────────────────────┘
                     │                         │
                     └──── once peer B has ────┘
                          full blob, it adds itself
                          to local seed set; subsequent
                          fetchers can pull from B too.
```

Two new subsystems on top of the existing libp2p stack:

- **`dds-net::blob`** — wire types + libp2p `request_response::cbor::Behaviour`,
  matching the convention from
  [`admission.rs`](../dds-net/src/admission.rs),
  [`sync.rs`](../dds-net/src/sync.rs),
  and [`pq_envelope.rs`](../dds-net/src/pq_envelope.rs).
- **`dds-node::blob_store`** — local content-addressed store with
  LRU eviction, atomic writes, manifest-bound chunk verification,
  and an anti-DoS scheduler.

## 5. Wire types

Module `dds-net/src/blob.rs`. CBOR-encoded via `request_response::cbor`
exactly like `admission.rs` and `sync.rs`. All field names are
`#[serde]`-stable so future versions can add fields with `default` /
`skip_serializing_if = "Option::is_none"`.

### 5.1 Envelope: `BlobManifest` (delivered out-of-band)

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlobManifest {
    /// `sha256(blob_bytes)`. Content address. 32 bytes.
    pub root_hash: [u8; 32],
    /// Total blob size in bytes (post-compression / post-signing —
    /// exactly what a successful fetch yields on disk).
    pub size: u64,
    /// Chunk size in bytes. Receiver allocates this much per
    /// in-flight chunk. Default 256 KiB; capped at 1 MiB by
    /// [`MAX_BLOB_CHUNK_SIZE`].
    pub chunk_size: u32,
    /// Number of chunks. Equals `(size + chunk_size - 1) / chunk_size`.
    pub chunk_count: u32,
    /// Merkle root of the chunk hashes (binary tree, sha256, leaf
    /// = sha256(chunk_bytes)). Receiver requires the per-chunk
    /// inclusion proof in `BlobChunkResponse.proof` to short-
    /// circuit a hostile peer feeding garbage chunks. If
    /// `chunk_count == 1` the merkle root equals
    /// `sha256(chunk_bytes)` and `proof` is empty.
    pub chunks_root: [u8; 32],
    /// Stable list of peer IDs that the publisher believes already
    /// have the blob. Capped at [`MAX_BLOB_SEED_PEERS`]. Receiver
    /// rotates through these on each chunk request and falls back
    /// to any other peer that announces (via a future gossip
    /// extension) that it has the blob.
    pub seed_peers: Vec<String>,
    /// Optional MIME-style hint for the applier (e.g.
    /// `"application/vnd.dds.linux-software-bundle.v1"`). Receivers
    /// MUST treat unknown values as opaque bytes — no auto-execute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_kind: Option<String>,
    /// Optional issuance + expiry. Manifests past `not_after` are
    /// rejected by the local store. Mirrors the
    /// `AdmissionCert` lifetime fields.
    pub not_before: u64,
    pub not_after: Option<u64>,
}
```

This struct is wrapped in the existing
[`SignedPolicyEnvelope`](../dds-core/src/envelope.rs) so it inherits
PQ-hybrid signature verification, capability gating, and audience
binding. On `enc-v3` domains the *envelope* (not the chunks) rides
sync / gossip wrapped in `SyncEnvelopeV3` / `GossipEnvelopeV3`.

### 5.2 Request type: `BlobRequest`

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlobRequest {
    /// "Do you have this manifest's blob, fully or partially?"
    /// Cheap. Used by the scheduler to pick a peer for the next
    /// chunk before sending the heavier `Chunk` request.
    Has { root_hash: [u8; 32] },

    /// Fetch chunk `index` (0-based). Receiver MUST also send the
    /// merkle proof.
    Chunk { root_hash: [u8; 32], index: u32 },
}
```

### 5.3 Response type: `BlobResponse`

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlobResponse {
    /// Outcome of a `Has` query.
    Has { state: BlobAvailability },

    /// Successful chunk delivery + inclusion proof.
    Chunk {
        index: u32,
        bytes: Vec<u8>,
        /// Sibling hashes from chunk leaf up to `chunks_root`.
        /// Length `ceil(log2(chunk_count))`. Empty when
        /// `chunk_count == 1`.
        proof: Vec<[u8; 32]>,
    },

    /// Failure outcomes — explicit so receiver telemetry can
    /// distinguish "peer disagrees" from "peer rate-limited" from
    /// "peer never had it".
    Err(BlobErr),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlobAvailability {
    Full,                 // every chunk
    Partial(Vec<u32>),    // sorted, deduped, capped
    Absent,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlobErr {
    NotFound,             // root_hash unknown locally
    OutOfRange,           // index >= chunk_count
    Throttled,            // per-peer concurrency cap hit; retry
    Expired,              // manifest's not_after passed
    Internal(String),     // I/O / store error, opaque
}
```

### 5.4 Wire-cap constants

Module-level, mirroring `pq_envelope.rs:43-50`:

```rust
/// Maximum chunk size a manifest may declare.
/// Chosen so `BlobResponse::Chunk` stays well under libp2p's
/// 1 MiB request-response budget after CBOR + proof overhead.
pub const MAX_BLOB_CHUNK_SIZE: u32 = 1024 * 1024;

/// Default chunk size when an issuer doesn't override it.
/// 256 KiB → ~200 chunks for a 50 MB binary, ~4 KB chunks for
/// a 1 MB policy bundle. Balances request count against per-
/// chunk verify cost.
pub const DEFAULT_BLOB_CHUNK_SIZE: u32 = 256 * 1024;

/// Maximum total blob size. Hard ceiling above which manifests
/// are rejected at deserialise time. 1 GiB is well past current
/// fleet-update sizes; raise once we have measurement.
pub const MAX_BLOB_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum seed-peer hint list per manifest. Bigger than this and
/// the receiver scheduler doesn't get value from new entries
/// (libp2p connection fan-out still gates effective parallelism).
pub const MAX_BLOB_SEED_PEERS: usize = 64;

/// Per-peer concurrent in-flight chunk requests the receiver may
/// issue. Anti-DoS for the responder; tuned with the existing
/// admission rate-limit.
pub const MAX_CONCURRENT_CHUNKS_PER_PEER: usize = 4;
```

`BlobManifest::validate()` (mirroring `EpochKeyRelease::validate()`,
[`pq_envelope.rs:478`](../dds-net/src/pq_envelope.rs:478)) gates every
field at the decode boundary so a downstream caller never reasons
about a half-shaped manifest.

## 6. Protocol semantics

### 6.1 Receiver state machine

```text
        manifest received & verified
                   │
                   ▼
      ┌─────► look up blob in <data_dir>/blobs/<root_hash>
      │            │
      │   present? │ yes ──── done; return path
      │            │
      │            ▼ no
      │   schedule chunk fetches:
      │     for chunk_index in 0..chunk_count:
      │         peer = next seed_peer (round-robin)
      │         in-flight ↓-= 1
      │         send /dds/blob/1.0.0/<dom>: Chunk{...}
      │
      │   on response:
      │     verify proof against manifest.chunks_root
      │     on failure → demote peer, re-queue chunk to next peer
      │     on success → write chunk to a temp file, advance
      │
      │   when all chunks present:
      │     final sha256 == manifest.root_hash, else hard fail
      │     atomic-rename into <data_dir>/blobs/<root_hash>
      │     announce "have" to behaviour layer (future gossip
      │     topic so peers stop re-asking us)
      │
      └─── on any peer-level fail (throttled, timeout, bad proof):
           swap that peer out for a different seed_peer; manifest
           sets a hard floor at min(seed_peers.len(), 3) before
           giving up.
```

### 6.2 Responder side

- Accepts requests **only from admitted peers** (same gate as
  `sync` / `epoch-keys`). Rejects unadmitted with `Throttled` after
  silent drop.
- Cap concurrent chunk requests per peer at
  `MAX_CONCURRENT_CHUNKS_PER_PEER`. Excess returns `Throttled`.
- Cap total in-flight chunk responses (across all peers) at a
  configurable `[network.blob].max_concurrent_send`. Default 16.
- Optional bandwidth shaper (token bucket) on the chunk-emission
  path; disabled by default, configurable via
  `[network.blob].max_send_bps`.

### 6.3 enc-v3 wrapping

When the domain advertises `enc-v3`:

- Each `BlobResponse::Chunk` is wrapped with the responder's epoch
  key in a `SyncEnvelopeV3`-shaped wire form (see `pq_envelope.rs`
  §B.8). The receiver decrypts before merkle-verifying.
- `BlobRequest` and `BlobResponse::Has` / `Err` are NOT encrypted —
  they carry no payload secrets and stay legible for diagnostics.

## 7. Security properties

| Threat | Mitigation |
|---|---|
| Malicious admitted peer feeds garbage bytes | per-chunk merkle proof against `manifest.chunks_root`; manifest is hybrid-signed by the publisher (root cannot be forged absent domain-key compromise — same trust root as today) |
| Hostile peer balloons a single response | `MAX_BLOB_CHUNK_SIZE`, `BlobManifest::validate()` rejects oversize at decode |
| Peer floods with `Has` queries | each query is cheap; rate-limit at the same layer as admission RR |
| Peer occupies all our send-side capacity | `MAX_CONCURRENT_CHUNKS_PER_PEER` + global `max_concurrent_send` |
| Peer sends correct hashes but lies about availability | `Has` is a hint, never load-bearing; if `Chunk` fails the receiver demotes that peer |
| Replay of an old manifest after revocation | `not_after` field; admission revocation gossip already kicks the peer out, so its blobs become un-fetchable |
| Quantum-equipped passive recorder | `enc-v3` AEAD wrap with publisher epoch key (same posture as sync, B.8) |
| Storage exhaustion via large blobs | `MAX_BLOB_SIZE` ceiling + per-node configurable cache budget; LRU eviction |
| Cross-domain leakage | protocol path includes `<domain>` like every other DDS RR; libp2p denies streams on a different protocol |

The chunk-level merkle proof is the load-bearing piece: it lets a
receiver throw away a single bad chunk and re-ask a different peer
without rolling back the whole transfer. We **do not** rely on
transport-level integrity — a hostile admitted peer could otherwise
flip bits and DoS rollouts.

## 8. Storage + lifecycle

- Local store: `<data_dir>/blobs/<root_hash_hex>` (single file per
  blob, not per chunk — chunked layout is in-flight only).
- LRU eviction: `[blob_store].cache_max_bytes`, default 2 GiB.
  Manifest cache (small) is separate from blob cache (potentially
  huge); evict blobs first.
- Pinning: an applier (Linux / macOS / Windows) that's about to
  install a blob calls a future `dds blob pin <root_hash>` so the
  cache won't evict it mid-install. Unpinned automatically once
  the applier reports `applied`.
- Invariants enforced at startup:
  - Every file in `<data_dir>/blobs/` whose name parses as a hex
    sha256 is treated as content-addressed; mismatched files are
    quarantined to `<data_dir>/blobs.quarantine/` and logged at
    WARN. (Mirrors the L-2 / L-3 file-ACL hardening.)
  - 0o700 dir / 0o600 files, owned by the dds-node service user.

## 9. Integration with existing platform/software endpoint

`SoftwareBundle` (the body of [list_linux_software](../dds-node/src/http.rs:780)
and the windows / macos siblings) gains an optional field:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub blob_manifest: Option<BlobManifest>,
```

Old appliers (no blob support) ignore the field and continue to
fetch from the existing repo URL. New appliers prefer the blob
manifest when present and fall back to the existing URL on fetch
failure (graceful degradation; lets us flip blob distribution on
without coordinating an applier upgrade across the fleet).

The applier asks `dds-node` (over the local UDS API) for a path:

```
GET /v1/blob/<root_hash>?wait=true   (new)
→ 200 + JSON { "path": "/var/lib/dds/blobs/<root_hash>" }
→ 202 + JSON { "state": "fetching", "complete_bytes": N, "total_bytes": M }
→ 404 if no manifest seen for that root_hash
```

`dds-node` returns the cached path immediately when present, or
opens a fetch (against any peer in the most recent matching
manifest's `seed_peers`) and either streams progress (long-poll) or
returns 202 for poll-style appliers.

## 10. Phases

### D-0: Design freeze

- Wire types finalised in `dds-net/src/blob.rs`.
- `BlobManifest::validate()` + cap constants pinned by unit tests.
- `SoftwareBundle` extension agreed and back-compat tested
  (v1-shaped envelope still decodes under v2-extended schema, same
  pattern as Z-1 Phase A `legacy_v1_domain_wire_decodes_under_v2_schema`).
- Exit gate: this doc lands; reviewer sign-off recorded in the file.

### D-1: Wire layer + responder skeleton

- Add `request_response::cbor::Behaviour<BlobRequest, BlobResponse>`
  to `DdsBehaviour` ([dds-net/src/transport.rs:42](../dds-net/src/transport.rs:42)).
- Implement responder side that serves a manifest pre-staged in
  `<data_dir>/blobs/`. No fetcher yet, no scheduler — this lets
  unit tests exercise the wire without any rollout machinery.
- Tests: round-trip CBOR for all variants, validate caps reject
  oversize, admitted-peers gate.

### D-2: Receiver + scheduler

- `dds-node::blob_store` content-addressed cache with atomic write.
- Per-peer round-robin scheduler with merkle proof verify.
- Throttled-fallback path; configurable concurrency caps.
- Tests: 4-node smoke fetches a 5 MB synthetic blob; check
  bandwidth fairness; check failure-injection (peer flips a bit)
  swaps to alternate peer cleanly.

### D-3: Manifest path

- `SoftwareBundle.blob_manifest` field + signing helper in `dds-cli`
  (`dds blob mint --in <FILE> --domain ... --out <SIGNED_MANIFEST>`).
- Manifest gossip via existing
  `gossipsub::publish` on the operations topic so it's not bound to
  the platform applier endpoints.
- Tests: 4-node smoke gossips a manifest; receivers auto-fetch.

### D-4: enc-v3 wrap

- AEAD-wrap chunks under the responder's epoch key on `enc-v3`
  domains. Reuse `SyncEnvelopeV3` shape.
- Tests: encrypted-domain end-to-end round-trip; reject
  plaintext-chunk path on `enc-v3` enforcement.

### D-5: Local API + applier integration

- `GET /v1/blob/<root_hash>` UDS endpoint.
- Linux applier (`platform/linux/DdsPolicyAgent`) prefers blob path
  when manifest present, falls back to URL.
- Tests: VM e2e with one anchor + one Linux member; deploy a
  signed `.deb` over the blob channel; agent installs.

### D-6: Anti-DoS hardening + bandwidth shaping

- Token-bucket bandwidth limiter on responder.
- Sender + receiver fairness across blobs (no head-of-line
  blocking when one large blob is in flight).
- Real-fleet load test (`dds-loadtest`) with 32+ nodes pulling a
  shared 100 MB blob.

### D-7: Production rollout

- Default the `[blob_store]` config to safe values.
- Document the operator surface in `docs/blob-distribution.md`.
- Open the cleanup PR for any temporary feature gates.

Exit gate (overall): A signed 50 MB blob can be published by an
admin, gossiped by manifest, and reach 100 % of admitted nodes in
a multi-datacentre fleet within < 90 s, with no node uploading more
than `O(blob_size · log N / N)` worth of bytes.

## 11. Open questions

- **Chunk-level vs. file-level manifest signature.** The current
  design signs the merkle root of chunk hashes plus the metadata.
  An alternative is to sign each chunk individually so a receiver
  can verify a chunk without the manifest — at the cost of N
  signatures. Given ML-DSA-65 sigs are 3.3 KB each, file-level
  merkle wins at any chunk count > 1.
- **Should we also gossip `Has` announcements?** Today seed-peer
  discovery is via the manifest's `seed_peers` list. We could add a
  small gossip topic where any node that finishes a fetch
  announces its `(root_hash, peer_id)` so other fetchers can
  expand the candidate set. Trade-off: extra gossip volume
  proportional to fleet × concurrent rollouts. Defer to D-2
  measurement.
- **Pinning lifetime.** Should `dds-node` auto-pin the most recent
  N manifests of each `content_kind`, or only on applier request?
  Auto-pin avoids races where a long-running applier loses its
  blob to LRU; explicit pin avoids unbounded retention.
- **Multi-publisher manifests.** A `BlobManifest` is signed by one
  identity. For Phase-A hybrid domains do we want to allow
  threshold or quorum signatures (e.g. two admins must co-sign a
  fleet-wide rollout)? Probably yes, but it's a Phase D-X concern
  and orthogonal to the byte-shipping protocol.
- **Quic vs TCP for chunk transport.** libp2p multiplexes both;
  measurement during D-2 should tell us whether QUIC's
  loss-recovery wins on lossy links. No change required to the
  protocol; the question is config.
- **Anti-eclipse during rollout.** A hostile responder could send
  hashes that match the manifest's leaf hashes but are bytes the
  receiver later refuses to install. The manifest binds bytes,
  not behaviour — appliers must keep the package-manager
  signature check in place even when bytes came from a DDS peer.
  (Already documented in this doc; worth re-emphasising in the
  applier docs.)

## 12. Out of scope but adjacent

- **A DDS-native package mirror.** The manifest currently carries
  fallback URLs that point at apt/dnf repos. A future doc could
  define a DDS-signed mirror that *is* a peer with the blob
  protocol — turning a fleet into its own apt mirror. The
  protocol here is the foundation for that, not the mirror
  itself.
- **Receive-side compression.** If a blob is gzip-compressed before
  signing the manifest, the chunked transport ships the
  compressed bytes; the applier decompresses after verify. No
  protocol changes needed; doc-only convention.

---

**Reviewer checklist (to be filled in before D-0 exits):**

- [ ] Wire types reviewed against `admission.rs` / `sync.rs` /
      `pq_envelope.rs` style.
- [ ] Cap constants justified.
- [ ] Threat model (§7) signed off by `Claude_sec_review.md` owner.
- [ ] Backward-compat strategy for `SoftwareBundle` field reviewed.
- [ ] Phase plan (§10) sized for owner availability.
