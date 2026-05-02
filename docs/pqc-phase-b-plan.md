# DDS Z-1 Phase B Plan — Encrypted Gossip + Sync via Per-Publisher Hybrid KEM

**Status:** Complete — B.1–B.12 all landed.
**Date:** 2026-04-29. **Updated:** 2026-05-01 (5th pass).
**Closes (when implemented):** the confidentiality piece of Z-1 from
[Claude_sec_review.md](../Claude_sec_review.md) "2026-04-26 Zero-Trust
Principles Audit". Phase A landed 2026-04-28 and closed the H-12
admission-cert forgeability piece of Z-1; **Phase B closes the
Harvest-Now-Decrypt-Later (HNDL) exposure on application-layer
content** — the gossipsub directory operations, the sync responses,
and the H-12 piggy-backed revocation distribution.
**Owner:** TBD.

---

## 1. Problem

Phase A made `AdmissionCert` and `AdmissionRevocation` hybrid-signed
(Ed25519 + ML-DSA-65) so a future quantum-equipped adversary can't
mint admission credentials. **It did not** close the bigger HNDL
story: the libp2p Noise transport handshake is still classical
X25519 ([dds-net/src/transport.rs:118-122](../dds-net/src/transport.rs)),
and an adversary recording today's gossip / sync / admission traffic
recovers all of it once a CRQC arrives. Phase A protects the *who*
(signatures); Phase B has to protect the *what* (content).

Phase C (hybrid Noise upstream) is the cleanest fix and is blocked on
rust-libp2p `rs/9595`. Phase B is the application-layer fallback that
does not wait on libp2p — wrap each gossip / sync payload in a hybrid
KEM-DEM envelope so transport compromise alone does not yield
plaintext.

The naive shape — "per-recipient KEM envelope on every message" —
does not fit gossipsub: gossip is broadcast to N peers and a
per-recipient envelope means N envelopes per message. The
architectural choice this doc commits to is **per-publisher epoch
keys** distributed via per-recipient hybrid KEM at handshake time
and rotated periodically.

## 2. Goals

1. Every gossipsub `Op` envelope carries an AEAD ciphertext over the
   original CBOR payload, encrypted with a per-publisher epoch key
   the sender derived for the current epoch. Plaintext gossip is
   rejected on a domain that advertises the `enc-v3` capability.
2. Every sync `Response` payload is wrapped in the same envelope
   shape, using the responder's epoch key.
3. Each admitted node carries a Phase-B hybrid KEM keypair (X25519 +
   ML-KEM-768, FIPS 203). The pubkey is advertised on the existing
   `AdmissionCert` so distribution rides the H-12 admission
   handshake we already have.
4. Epoch keys rotate on a fixed timer (default 24h) **and**
   immediately on any admission revocation gossiping through the
   fleet.
5. Mixed-fleet rollout: Phase-B-capable code can ship first, then
   the admin flips a `enc-v3` capability bit on the domain to
   enforce.

## 3. Non-goals (Phase B scope only)

- Hybrid Noise / QUIC keyshare upgrade — Phase C, blocked on
  rust-libp2p `rs/9595`.
- Forward secrecy *within* an epoch — there is no per-message
  ratchet. Compromise of an epoch key reveals every message published
  in that epoch (default 24h window).
- MLS-style group-key agreement — out of scope; the per-publisher
  epoch model is intentionally simpler.
- Hardware-bound KEM secret keys — hardware binding is Z-2, not
  coupled to Phase B (the KEM key can be moved to a HW-bound store
  later without wire-format changes).
- Encrypted-at-rest of the on-disk redb store — that's Z-4.
  Plaintext `sync_payloads` cache and plaintext `<data_dir>/epoch_keys.cbor`
  are the existing per-store posture.
- **MCU / no_std with the `pq` feature.** dds-core is
  `#![cfg_attr(not(feature = "std"), no_std)]` for the *classical*
  feature set, but Phase A's `pqcrypto-mldsa = { features = ["std"] }`
  workspace pin already gates the `pq` feature on `std` (the crate
  wraps a C reference implementation that needs libc). Phase B's
  `ml-kem 0.3` / `x25519-dalek 2` / `hkdf 0.12` deps are all
  `default-features = false` and stay no_std-friendly, so they don't
  make this worse — but the `pq` feature as a whole remains
  std-only until a pure-Rust ML-DSA backend (e.g. `fips204` crate)
  is swapped in. Tracked separately; not a Phase B goal.

## 4. Architecture

### 4.1 Per-publisher epoch key

Every admitted node generates a hybrid KEM keypair at first start.
The pubkey rides the `AdmissionCert` so every other admitted peer
learns it via the H-12 handshake. Each node also generates a
32-byte symmetric AEAD key — the *epoch key* — and KEM-encapsulates
it once per peer (the recipient list is "every other admitted peer
the publisher has handshaken with"). For the duration of an epoch
(default 24h), every gossip message the publisher publishes uses
that same key with a fresh nonce.

```
publisher P
  ├─ epoch_id = 17
  ├─ K_P_17 = AEAD key (32 random bytes)
  ├─ for each admitted peer R:
  │     KEM_encap(R.pq_kem_pubkey, K_P_17) → kem_ct, derived_aead_key
  │     EpochKeyRelease { publisher: P, epoch_id: 17, kem_ct, ... } → R
  └─ on every gossip publish:
        AEAD_encrypt(K_P_17, nonce, op_cbor) → ct
        GossipEnvelopeV3 { publisher: P, epoch_id: 17, nonce, ct } → gossipsub flood
```

Recipient `R` caches `(publisher P, epoch_id 17) → K_P_17` and
AEAD-decrypts every envelope from `P` locally.

### 4.2 Why epochs and not session keys

A session key would require a per-recipient handshake on every
reconnect — that's the H-12 cost paid every time a peer flaps. An
epoch key is set up once per peer per ~24h and reused, so the cost
is amortized and connection churn doesn't trigger rekeying.
Trade-off accepted: no intra-epoch forward secrecy.

### 4.3 Hybrid KEM construction

X25519 + ML-KEM-768 in parallel, combined via HKDF-SHA256. Mirrors
IETF `draft-ietf-tls-hybrid-design`:

```
ss_classical = X25519(eph_x_sk, recipient_x_pk)        # 32 bytes
(kem_ct_pq, ss_pq) = ML-KEM-768.encap(recipient_pq_pk) # ct=1088 B, ss=32 B

binding = sender_kem_pk || recipient_kem_pk || epoch_id_be
secret  = HKDF-SHA256-Expand(
            HKDF-SHA256-Extract(salt = b"dds-pqc-kem-hybrid-v1",
                                ikm  = ss_classical || ss_pq),
            info = binding,
            len  = 32)

# Use `secret` as the AEAD key for one-shot ChaCha20-Poly1305
# encryption of the 32-byte epoch key K_P_epoch.
```

Component-lifting defence: the `binding` field includes both peer
pubkeys and the epoch id, so an attacker can't lift the X25519 leg
or the ML-KEM leg out of one (publisher, recipient, epoch) tuple
and replay it elsewhere. Mirrors the M-2 / Phase A domain-separation
pattern.

### 4.4 Wire formats

Three new types in `dds-net`:

```rust
/// Replaces the plaintext CBOR `Op` shipping that gossipsub does today.
/// V3 envelope is the only shape gossiped on a domain with the `enc-v3`
/// capability. V2 (plaintext) is accepted in the cutover window and
/// rejected once the capability is set.
pub struct GossipEnvelopeV3 {
    pub publisher:  PeerId,        // base58 string
    pub epoch_id:   u64,
    pub nonce:      [u8; 12],      // ChaCha20-Poly1305 nonce
    pub ciphertext: Vec<u8>,       // AEAD over original Op CBOR
}

/// Sync response payloads use the same shape (responder is the publisher).
pub struct SyncEnvelopeV3 {
    pub responder:  PeerId,
    pub epoch_id:   u64,
    pub nonce:      [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Per-recipient release of K_publisher_epoch. Signed by the publisher
/// (Ed25519 + ML-DSA-65 if Phase A v2 hybrid, so the release inherits
/// Phase A forgeability protection).
pub struct EpochKeyRelease {
    pub publisher:        PeerId,
    pub epoch_id:         u64,
    pub issued_at:        u64,
    pub expires_at:       u64,           // when this epoch ends
    pub recipient:        PeerId,
    pub kem_ct:           Vec<u8>,       // 1120 B (32 X25519 + 1088 ML-KEM)
    pub aead_nonce:       [u8; 12],
    pub aead_ciphertext:  Vec<u8>,       // K_publisher_epoch (32 B) AEAD'd
    pub signature:        Vec<u8>,       // 64 B Ed25519
    pub pq_signature:     Option<Vec<u8>>,// 3309 B ML-DSA-65 (Phase A v2)
}
```

Gossipsub continues to use the `/dds/ops/.../...` topic; the
envelope itself versions via the on-wire CBOR shape. A v3 envelope
is detected by presence of the `epoch_id` + `ciphertext` fields and
absence of the v2 plaintext op fields.

### 4.5 Distribution

Two delivery channels for `EpochKeyRelease`:

1. **H-12 piggy-back.** `AdmissionResponse` grows an optional
   `epoch_key_releases: Vec<Vec<u8>>` (opaque CBOR, mirrors the
   `revocations` piggy-back from
   [dds-net/src/admission.rs](../dds-net/src/admission.rs)). When
   peer `A` admits peer `B`, `A` includes its own current
   `EpochKeyRelease` for `B` in the response. Symmetric: `B`'s
   response also carries `B`'s release for `A`. Capped via a new
   `MAX_EPOCH_KEY_RELEASES_PER_RESPONSE` constant.

2. **Dedicated request-response protocol.** A new libp2p
   `request_response::cbor::Behaviour` on
   `/dds/epoch-keys/1.0.0/<domain>` so a publisher can push fresh
   releases to already-admitted peers when it rotates mid-connection.
   Gossipsub is wrong here — releases are per-recipient, not
   broadcast.

### 4.5.1 Replay window + late-join recovery

Mirrors the M-9 token replay window pattern. Two new constants:

- `EPOCH_RELEASE_REPLAY_WINDOW_SECS = 7 * 86_400` — receivers reject
  any `EpochKeyRelease` whose `issued_at` is more than 7 days in the
  past relative to local clock. Bounds an attacker's ability to
  shelve an old release and replay it after the publisher has rotated
  away.
- `EPOCH_KEY_GRACE_SECS = 300` — after a publisher rotates, receivers
  retain the previous `(publisher, prev_epoch_id) → key` entry for 5
  minutes so in-flight gossip with the older `epoch_id` still
  decrypts. Cleared on the next rotation tick.

**Late-join request-response shape** on
`/dds/epoch-keys/1.0.0/<domain>`:

```rust
pub struct EpochKeyRequest {
    pub publishers: Vec<PeerId>, // peers we want current epoch keys for
}
pub struct EpochKeyResponse {
    pub releases: Vec<Vec<u8>>,  // opaque CBOR EpochKeyRelease, capped
}
```

A receiver that observes a `GossipEnvelopeV3` it can't decrypt
(no cached key for `(publisher, epoch_id)`) emits one
`EpochKeyRequest` to the *publisher* (preferred) or to a peer that
recently spoke for the publisher (fallback). The responder ships
its current release for the requester. Cap on `releases.len()`
mirrors `MAX_REVOCATIONS_PER_RESPONSE` semantics.

### 4.6 Rotation policy

| Trigger | Action | Cadence |
|---|---|---|
| Time | Publisher rolls a new K_pub_epoch and re-emits `EpochKeyRelease` to every admitted peer | every 24h, configurable per-domain |
| Revocation | Every node receiving an admission revocation rolls its own epoch key + re-emits releases (excluding the revoked peer) | within 60s of revocation gossip arrival |
| New peer admission | Publisher emits a release for the new peer; existing receivers' epoch keys unchanged | on H-12 success |
| Local PQ key rotation | Publisher rolls epoch key + re-emits to everyone (the old key was bound to the old KEM pubkey) | rare, manual via `dds-cli pq rotate` |

Receivers cache the previous epoch key for a short window (default
5 minutes after `epoch_id` changes) so in-flight messages with the
old `epoch_id` still decrypt cleanly. After the grace window, the
old key is dropped from memory.

### 4.6.1 Sync responder re-wraps under its own epoch key

A non-obvious decision Phase B has to commit to: **`sync_payloads`
holds plaintext after the gossip-decrypt step, and the sync
responder re-encrypts each payload under its own current epoch key
when serving a `SyncRequest`** — it does *not* forward the
publisher's original `GossipEnvelopeV3`. Two reasons:

1. The requester may not have the original publisher's epoch key
   for that `epoch_id` (the publisher may be offline, or the
   epoch may be far in the past).
2. Sync gap-fill must work transitively: peer `Q` must be able to
   ship payloads originally published by peer `P` to a third peer
   `R`, even if `R` has never directly admitted `P`. Re-wrapping
   under `Q`'s key makes this composition straightforward.

Trade-off: the in-memory `sync_payloads` cache holds plaintext (same
posture as the existing on-disk redb store; both gated by Z-4 for
at-rest encryption). An attacker who compromises the cache reads
plaintext directory ops — same threat as today. Phase B does not
regress this; it just means the application-layer encryption stops
at the per-node trust boundary, not the per-publisher boundary.

### 4.6.2 Receivers cache other peers' AdmissionCerts

Today the H-12 admission handshake verifies a remote cert once and
records the remote `PeerId` in `admitted_peers` — the cert itself is
not retained. Phase B needs the cert (specifically `pq_kem_pubkey`)
to look up the publisher's KEM pubkey for `EpochKeyRelease` decap
binding. New `peer_cert_store` module in `dds-node`:
`BTreeMap<PeerId, AdmissionCert>` populated on every successful
H-12 handshake, persisted at `<data_dir>/peer_certs.cbor`. A
re-handshake (e.g. after publisher KEM key rotation re-issues the
cert) overwrites the cached entry. Storage budget for a 1000-peer
domain: ~1.2 MB (1000 × 1216 B `pq_kem_pubkey` + envelope), plus the
sigs (~3.4 KB each in v2 hybrid). Acceptable.

**§4.6.2 wired into `DdsNode` 2026-05-01 follow-on (Phase B.3
follow-on).** The `peer_cert_store` module landed in B.3 but was not
yet held by the running node. `DdsNode` now carries
`peer_certs: PeerCertStore` and `peer_certs_path: PathBuf`; `init`
restores the cache from disk; `verify_peer_admission` calls a new
`cache_peer_admission_cert` helper *after* `verify_with_domain`
succeeds (never before — a wrong-length / wrong-signer cert can
never pollute the cache); `merge_piggybacked_revocations` drops
cached certs for any newly-revoked peers and persists the trimmed
file so a Phase B.7+ KEM lookup cannot reuse a revoked publisher's
pubkey. Three regression tests in
[`dds-node/tests/peer_cert_cache.rs`](../dds-node/tests/peer_cert_cache.rs)
pin the cache-on-success, re-handshake-overwrites, and
revocation-evicts contracts without depending on a libp2p swarm
spin-up — the end-to-end H-12 cache path is already exercised by
[`dds-node/tests/h12_admission.rs`](../dds-node/tests/h12_admission.rs).

### 4.7 Mixed-fleet rollout

Three stages, all under a single `Domain.capabilities: Vec<String>`
field:

| Stage | Capability set | Behaviour |
|---|---|---|
| 0 | (empty) | v3-capable code shipped; gossip + sync still plaintext. v3 nodes accept both encrypted and plaintext on receive; publish plaintext. |
| 1 | (empty) | v3 nodes have generated a hybrid KEM keypair and re-issued their `AdmissionCert` with `pq_kem_pubkey`. Pubkey distribution catches up via H-12. Still plaintext on the wire. |
| 2 | `["enc-v3"]` | Admin re-issues `domain.toml` with `enc-v3`. v3 nodes flip to encrypted publish + reject plaintext receive. v2-only nodes drop off (they can't decrypt). Admin should run `dds-cli pq list-pubkeys` to confirm 100% v3 coverage before flipping. |

A rollback from Stage 2 → Stage 1 is supported by re-issuing
`domain.toml` without the capability — receivers go back to
accepting plaintext, publishers back to plaintext publish on the
next epoch.

### 4.8 Offline > 24h recovery

A node that has been disconnected for longer than the rotation
period (default 24h) wakes up with stale cached epoch keys for every
admitted peer. Three cases, all benign:

**Receiver offline N days, then reconnects.** H-12 fires per
neighbour as connections come back; each remote piggy-backs its
*current* `EpochKeyRelease` for us in the `AdmissionResponse`. After
a few seconds (parallelizable across neighbours), we have fresh
keys for every publisher we'll see gossip from. New gossip flowing
in **after** reconnect decrypts cleanly under the freshly-delivered
keys. Gossip we missed during the offline window is gone — same as
today (gossipsub is fire-and-forget). The gap-fill story is sync,
which by §4.6.1 re-wraps payloads under the responder's *current*
epoch key, so we decrypt cleanly with the freshly-delivered key
without needing any historical epoch keys.

**Publisher offline N days, then reconnects.** On startup, if
`now > my_epoch.expires_at`, force-rotate before publishing
anything. Rotation timer ticks normally afterwards. No special
"wake up and catch up" code path; the rotation path covers it.

**Both offline simultaneously.** Composes cleanly — same flow on
each side independently.

**KEM pubkey rotation while offline (the only real cliff).** If a
publisher's `pq_kem_pubkey` rotated during our offline window, the
publisher's `AdmissionCert` was re-issued. Our cached cert in
`peer_cert_store` (§4.6.2) is stale. Resolution: the H-12
handshake on reconnect ships the publisher's *current* cert, which
overwrites the stale entry. The piggy-backed `EpochKeyRelease` is
encapsulated to the new pubkey, so decap works. If the old cert was
explicitly revoked while we were offline, we pick up the revocation
via H-12 piggy-back from any admitted peer — same flow as today's
revocation propagation.

**Cap on offline tolerance:** there is no hard cap. Even a node
offline for months recovers cleanly via the same H-12 + sync
catch-up. The only operational consideration is
`EPOCH_RELEASE_REPLAY_WINDOW_SECS = 7 days` — releases that the
late-joiner *receives* must have been issued within the last 7 days,
which is naturally true because the publisher rotates daily and
re-emits a fresh release on every H-12 handshake.

## 5. Crate / module changes

### 5.1 dds-core

- Workspace dep: `ml-kem = "0.2"` (RustCrypto pure-Rust impl of
  FIPS 203 final). Selection rationale: same family as the existing
  `ed25519-dalek` / `sha2` / `hkdf` deps, FIPS 203 final-spec
  compliant, used in upstream `rustls` for TLS hybrid
  `X25519MLKEM768`. Sibling `pqcrypto-mlkem` was considered for
  consistency with Phase A's `pqcrypto-mldsa`, but the RustCrypto API
  integrates more cleanly with the classical crypto already in
  `dds-core::crypto`.
- Workspace dep: `hkdf = "0.12"` (RustCrypto, already a transitive).
- New module `dds_core::crypto::kem`: `HybridKem`,
  `HybridKemPublicKey`, `HybridKemSecretKey`, `KemCiphertext`,
  `encap()`, `decap()`. KAT vectors from the FIPS 203 ACVP test
  suite.
- New module `dds_core::crypto::epoch_key`: AEAD wrap/unwrap of a
  32-byte symmetric key under a hybrid-KEM-derived secret. Pure
  glue; no new primitive.
- Domain-separation prefix: `b"dds-pqc-kem-hybrid-v1\0"` for
  HKDF-Extract salt; matches the M-2 / Phase A naming pattern
  (`dds-hybrid-v2/...`, `dds-admission-v2/...`,
  `dds-revocation-v2/...`).

### 5.2 dds-domain

- `AdmissionCert.pq_kem_pubkey: Option<Vec<u8>>` (1216 B when set).
  `#[serde(default, skip_serializing_if = "Option::is_none")]` keeps
  v1/v2 wire-compat exactly as Phase A's `pq_signature` does.
- `Domain.capabilities: Vec<String>` (`#[serde(default)]`, empty
  vec). Recognized values for v3: `["enc-v3"]`. Future expansions
  reserved.
- Sibling `DomainKemKey` type next to Phase A's `DomainPqKey` — the
  X25519 + ML-KEM-768 keypair held by `DomainKey` (or a separate
  `NodeKemKey` if we keep KEM keys at the node level rather than
  the domain level — see Open Decision §9.6).

### 5.3 dds-net

- `GossipEnvelopeV3`, `SyncEnvelopeV3`, `EpochKeyRelease` types in a
  new `dds_net::pq_envelope` module.
- `AdmissionResponse.epoch_key_releases: Vec<Vec<u8>>` (opaque CBOR,
  `#[serde(default)]`). Cap mirrors the existing
  `MAX_REVOCATIONS_PER_RESPONSE` (1024 entries) — actual budget will
  be ~64 per response since releases are larger (~1.5 KB each vs
  ~120 B for a revocation).
- New behaviour
  `epoch_keys: request_response::cbor::Behaviour<EpochKeyRequest, EpochKeyResponse>`
  on `/dds/epoch-keys/1.0.0/<domain>` — domain-tagged like `sync` /
  `admission`.
- Capability negotiation: nothing in `dds-net`; the `enc-v3` flip
  is enforced by `dds-node` based on `Domain.capabilities` it loads
  from `domain.toml`.

### 5.4 dds-node

- New `epoch_key_store` module (mirrors `admission_revocation_store`'s
  shape):
  ```rust
  pub struct EpochKeyStore {
      kem_keypair: HybridKemSecretKey,
      my_epoch:    (u64, [u8; 32]),                         // current epoch
      previous_my_epoch: Option<(u64, [u8; 32], Instant)>,  // grace window
      peer_releases: BTreeMap<(PeerId, u64), [u8; 32]>,     // cached
      last_rotation: Instant,
  }
  ```
  Persisted under `<data_dir>/epoch_keys.cbor`. Plaintext today
  (same posture as the other stores until Z-4 lands DPAPI / per-file
  encryption).
- `DdsNode` grows `epoch_keys: EpochKeyStore`, plus a rotation timer
  task that ticks daily.
- `handle_gossip_message`: detect envelope shape (v2 plaintext vs v3
  encrypted); when domain has `enc-v3` capability, reject v2;
  otherwise accept either. Decrypt v3 with the cached epoch key;
  drop with `dropped_reason="no_epoch_key"` audit + metric on
  missing/expired key.
- `handle_sync_response`: same pattern.
- `verify_peer_admission`: on H-12 success, emit a fresh
  `EpochKeyRelease` for the new peer via the dedicated
  `/dds/epoch-keys/...` channel (and if H-12 was the inbound side,
  piggy-back our release in the `AdmissionResponse`).
- `ingest_revocation`: trigger immediate epoch rotation.

### 5.5 dds-cli

- `dds-cli pq status` — show local KEM pubkey hash, current
  `epoch_id`, count of cached peer releases, time to next rotation.
- `dds-cli pq rotate` — force-rotate the local epoch key
  (operator escape hatch).
- `dds-cli pq list-pubkeys` — list every admitted peer's Phase-B
  KEM pubkey hash, used by admin to confirm 100% v3 coverage before
  flipping `enc-v3` on `domain.toml`.

## 6. Performance budget

Per FIPS 203 reference timings on x86_64:
- ML-KEM-768 keygen ~80 µs (one-shot at first start)
- ML-KEM-768 encap ~50 µs (per release issued)
- ML-KEM-768 decap ~70 µs (per release received)
- ChaCha20-Poly1305 encrypt/decrypt ~5 µs per 1 KB message
- HKDF-SHA256 ~3 µs

Steady-state per-message overhead (the hot path) is **just AEAD** —
~5 µs. The KEM ops happen only when an epoch rotates or a new peer
is admitted. For a 100-peer domain with the default 24h epoch:

- Per-publisher per-epoch KEM cost: 100 × 50 µs = **5 ms once a
  day** = negligible.
- Per-receiver per-epoch decap cost: 100 publishers × 70 µs = **7 ms
  once a day** = negligible.

Wire size:
- Original `Op` CBOR: ~200-2000 B typical. AEAD overhead = 16 B tag
  + 12 B nonce + ~32 B envelope framing ≈ 60 B per message.
- `EpochKeyRelease`: ~1500 B (1120 KEM ct + 64 sig + 3309 ML-DSA +
  framing). Sent once per peer-pair per epoch.

For a 100-peer domain with 1000 ops/day, the daily wire overhead is:
- Encrypted gossip: 1000 × 60 B = **60 KB/day per node**.
- Epoch releases: 100 peers × 1500 B = **150 KB/day per node**.

Both negligible against the existing gossip + sync traffic.

### 6.1 Scale considerations (1000+ peer domains)

The 100-peer numbers scale linearly until we hit the
revocation-triggered-rotation thundering-herd cliff. Recomputing for
1000 peers:

- Per-publisher per-rotation KEM cost: 1000 × 50 µs = **50 ms** —
  still negligible.
- Per-publisher per-rotation egress: 1000 × 1500 B = **1.5 MB**.
- **Revocation thundering herd:** every publisher rotates within
  60 s of revocation gossip arrival. 1000 publishers × 1000
  receivers = ~1.5 GB of release traffic mesh-wide in a few
  seconds. **This is the load-bearing scale concern.**

Mitigations baked into the implementation (B.9):

1. **Stagger by jitter.** Revocation-triggered rotation includes
   `tokio::time::sleep(rng.gen_range(0..30_secs))` before
   re-emitting releases. Spreads the herd over a 30-second window;
   a 1000-publisher domain emits ~33 publishers/sec instead of all
   at once.
2. **Per-publisher concurrency cap.** A publisher emits at most 10
   in-flight `EpochKeyRelease` request-response calls at a time
   (existing libp2p request_response semantics); the rest queue.
   Recipient-side parallelism is naturally bounded by the libp2p
   substream limit.
3. **Time-based rotation is naturally staggered.** Each publisher's
   epoch boundary is set at first-start, not synchronized to a
   wall-clock midnight. So daily rotations are uniformly distributed
   across a 24h window — no synchronized peak.
4. **Cert pubkey caching.** `peer_cert_store` (§4.6.2) means we
   don't re-fetch the 1216-byte `pq_kem_pubkey` on every handshake
   — only on a re-issued cert. Storage cost for 1000 peers:
   ~1.2 MB on disk.

If the herd mitigations turn out insufficient at 10k+ peers, the
follow-up is exponential backoff on retries plus optional sharded
rotation (rotate only "dirty" peer-pairs touched by the
revocation, not the full Cartesian product). Out of scope for v1
Phase B; revisit if loadtest signals a problem.

## 7. Test strategy

| Layer | Tests |
|---|---|
| `dds_core::crypto::kem` | KAT vectors from FIPS 203 ACVP suite; encap/decap roundtrip; hybrid component lifting (X25519 leg cannot be replayed standalone, ML-KEM leg cannot be replayed standalone — analog of the M-2 hybrid sig test); wrong-recipient decap fails; tampered ciphertext fails. |
| `dds_core::crypto::epoch_key` | AEAD wrap/unwrap of a 32-byte epoch key; nonce uniqueness across rotations; HKDF binding includes pubkey transcript. |
| `dds_domain::AdmissionCert` | Cert with `pq_kem_pubkey` round-trips through CBOR; v1 cert wire-decodes under v3 schema with `pq_kem_pubkey: None` (mirrors the Phase A `legacy_v1_domain_wire_decodes_under_v2_schema` test). |
| `dds_net::pq_envelope` | `GossipEnvelopeV3` / `SyncEnvelopeV3` / `EpochKeyRelease` CBOR round-trips; cap-violation rejection on `AdmissionResponse.epoch_key_releases`; v1 `AdmissionResponse` decodes cleanly under v3 schema. |
| `dds_node::epoch_key_store` | Persist/load round-trip; rotation increments `epoch_id` monotonically; old epoch key kept in cache for 5 minutes after rotation; revocation triggers immediate rotation. |
| Integration: mixed fleet | A v2-only node + a v3-capable node coexist on a domain without `enc-v3` capability; gossip flows plaintext both ways. Admin flips `enc-v3`; v2-only node stops receiving (its decrypt is a no-op); v3 node continues. |
| Integration: rotation | 3-node mesh, all v3 + `enc-v3`; trigger time-based rotation on node A; B and C continue receiving from A across the rotation boundary (old key stays in cache 5 min, new key takes over). |
| Integration: revocation-triggered rotation | 3-node mesh; admin issues admission revocation against C; A and B both rotate within 60 s; an op published by A after rotation must NOT decrypt under the pre-rotation epoch key cached by C. |
| Integration: offline > 24h reconnect (§4.8) | 3-node mesh with `enc-v3`; node C is partitioned for 48h while A and B run normal rotation cycles; C rejoins, completes H-12 with both, and decrypts the next gossip op from each within ~5 s without manual intervention. Variant: A's KEM pubkey rotated during C's offline window (cert re-issued); C's reconnect picks up the new cert via H-12 and decrypts the next release encapsulated to the new pubkey. |
| Integration: late-join `EpochKeyRequest` recovery (§4.5.1) | Inject a `GossipEnvelopeV3` from publisher P into receiver R that R has no cached key for (simulating a missed release); R must emit a single `EpochKeyRequest{publishers: [P]}` to P, receive a release, and decrypt the envelope. |
| Loadtest | Steady-state per-message overhead < 10 µs/message at 1k ops/sec; epoch rotation completes within 5 s for a 100-peer domain; revocation-triggered rotation in a 1000-peer simulated mesh stays under 60 s end-to-end thanks to jittered staggering (§6.1). |

## 8. Phased implementation

| Step | Scope | Wall-clock |
|---|---|---|
| B.1 | `dds-core::crypto::kem` module — **landed** in commit `da2c706` at [dds-core/src/crypto/kem.rs](../dds-core/src/crypto/kem.rs) (569 lines, matches the §4.3 construction). 14 unit tests cover sizes, encap/decap roundtrip, wire-format parsing and length rejection, wrong-recipient decap, ciphertext tampering on either leg, binding-info replay defence, the component-lifting defence, and the version-pinned HKDF salt. KAT vectors from the FIPS 203 ACVP suite are deferred to a follow-on (the upstream RustCrypto `ml-kem 0.3` crate already runs the ACVP vectors in its own CI; we depend on that). The workspace ML-KEM pin is at `ml-kem = "0.3"` in [Cargo.toml](../Cargo.toml) — note the version is **0.3 (final)**, not the 0.2 the original draft of this doc named. | done |
| B.2 | `dds-core::crypto::epoch_key` AEAD wrapper — **landed** at [dds-core/src/crypto/epoch_key.rs](../dds-core/src/crypto/epoch_key.rs). Thin ChaCha20-Poly1305 glue layer over the B.1 KEM-derived shared secret: `wrap(rng, kem_shared, epoch_key) → ([u8;12], Vec<u8>)`, `unwrap(kem_shared, &nonce, &ct) → [u8;32]`. Constant version-tag AAD `b"dds-pqc-epoch-key-v1"`. New workspace dep `chacha20poly1305 = "0.10"` (already a transitive through dds-node, so no new vendored crate). 11 unit tests cover roundtrip, wrong-key / tampered-ct / tampered-tag / tampered-nonce failure, wrong-length rejection, nonce uniqueness, end-to-end composition with B.1, and AAD version-pinning. | done |
| B.3 | `AdmissionCert.pq_kem_pubkey` + `Domain.capabilities` + `peer_cert_store` — **landed** 2026-04-30. `AdmissionCert` grew an optional `pq_kem_pubkey: Option<Vec<u8>>` (1216 B X25519 + ML-KEM-768 wire form, mirrors Phase A's `pq_signature` `#[serde(default, skip_serializing_if = "Option::is_none")]` byte-compat shape); a new `DomainKey::issue_admission_with_kem` helper is the only constructor that populates it (`issue_admission` keeps the Phase A signature). `AdmissionCert::pq_kem_pubkey_validate` and `verify_with_domain` reject any wrong-length blob with `DomainError::Mismatch` *before* a downstream KEM consumer sees it. `Domain` grew `capabilities: Vec<String>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`) plus `Domain::has_capability(&str)` (case-sensitive exact match) and a new `CAPABILITY_ENC_V3 = "enc-v3"` constant; `verify_self_consistent` rejects any empty capability tag. `DomainConfig` and `DomainFile` (TOML) gained matching pass-through fields, so `[domain].capabilities = ["enc-v3"]` in `dds.toml` is the operator surface for the v3 gate. New `dds_node::peer_cert_store` (`PeerCertStore` keyed on stringified `PeerId`) persists at `<data_dir>/peer_certs.cbor` via the same atomic-write + `0o600` posture as `admission_revocation_store::save`; `iter_kem_pubkeys()` filters to the publishers that already advertise a Phase-B KEM pubkey on their cached cert (the Phase B.4 epoch-key-release loop will consume this). Wire-format backward compat is pinned by `legacy_v1_admission_cert_wire_decodes_under_v3_schema` and `legacy_v2_domain_wire_decodes_under_v3_schema`. | done |
| B.4 | `dds-net::pq_envelope` types + `AdmissionResponse.epoch_key_releases` field + caps + `EpochKeyRequest` / `EpochKeyResponse` shapes for the late-join recovery protocol (§4.5.1) — **landed** in commit `bb63a91` at [dds-net/src/pq_envelope.rs](../dds-net/src/pq_envelope.rs). New module ships `GossipEnvelopeV3` / `SyncEnvelopeV3` (publisher-keyed and responder-keyed AEAD envelopes), `EpochKeyRelease` (per-recipient release of the publisher's epoch key — KEM ciphertext + AEAD ciphertext + Ed25519 signature + optional ML-DSA-65 signature), `EpochKeyRequest` / `EpochKeyResponse` (late-join recovery shape consumed by the B.5 `/dds/epoch-keys/1.0.0/<domain>` libp2p protocol). Cap constants `MAX_EPOCH_KEY_RELEASES_PER_RESPONSE = 256`, `MAX_EPOCH_KEY_REQUEST_PUBLISHERS = 256`, `EPOCH_RELEASE_REPLAY_WINDOW_SECS = 7 days`, `EPOCH_KEY_GRACE_SECS = 300`. `AdmissionResponse` grew an optional `epoch_key_releases: Vec<Vec<u8>>` piggy-back field (`#[serde(default)]` so v1/v2 wire encodings stay byte-identical and a v2 reader of a v3 response decodes cleanly). 14 new unit tests cover CBOR round-trips for all five types, v1↔v2 wire compat for the optional `pq_signature` on `EpochKeyRelease`, default-empty `EpochKeyResponse`, the cap-constants pin, and v2→v3 wire-compat for the new `AdmissionResponse` field. **2026-04-30 follow-on (this commit):** `EpochKeyRelease::validate()` schema-layer gate landed alongside four wire-form length constants (`EPOCH_KEY_RELEASE_KEM_CT_LEN = 1120`, `EPOCH_KEY_RELEASE_AEAD_CT_LEN = 48`, `EPOCH_KEY_RELEASE_ED25519_SIG_LEN = 64`, `EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN = 3309`) and a typed `EpochKeyReleaseValidateError` enum. Mirrors the `dds_domain::PublisherIdentity::validate` fail-closed pattern: a malformed shape (empty publisher / recipient, `expires_at <= issued_at`, wrong-length `kem_ct` / `aead_ciphertext` / `signature` / `pq_signature`) is rejected at the decode boundary so a downstream consumer (B.5 epoch-key store, B.6 release ingest, B.7 / B.8 envelope decrypt) never has to reason about a half-shaped release — receivers about to spend an ML-KEM-768 decap on the release's `kem_ct` short-circuit the wasted work when the blob never could have decapped. 13 new unit tests pin the error variants, length constants, and the v1 (Ed25519-only) accept path. **2026-04-30 follow-on #2 (this commit):** companion schema-layer gates landed for the request-response wire types — `EpochKeyRequest::validate()` enforces `MAX_EPOCH_KEY_REQUEST_PUBLISHERS` (drop-wholesale, do not truncate) and rejects empty PeerId strings; `EpochKeyResponse::validate()` enforces `MAX_EPOCH_KEY_RELEASES_PER_RESPONSE` (the outer cap; per-blob `EpochKeyRelease::validate()` still runs at the B.6 ingest call site). Two new typed error enums (`EpochKeyRequestValidateError` with `TooManyPublishers` / `EmptyPublisher` variants; `EpochKeyResponseValidateError` with `TooManyReleases`) mirror the `EpochKeyReleaseValidateError` shape so the audit / log surface is uniform across all three wire types. 11 new unit tests pin the cap-at, cap-over, default-empty, empty-string, and Display-formatting paths. The B.5 request-response handler will run both gates after `ciborium::from_reader` and before any downstream key-store work. | done |
| B.5 | `EpochKeyRelease` request-response protocol on `/dds/epoch-keys/1.0.0/<domain>` libp2p behaviour — **landed** 2026-05-01 at [`dds-node/src/node.rs`](../dds-node/src/node.rs) (handler dispatch + receive pipeline) and [`dds-node/src/config.rs`](../dds-node/src/config.rs) (epoch_keys path). `DdsNode` grew `epoch_keys: EpochKeyStore` + `epoch_keys_path: PathBuf`; `init` calls `EpochKeyStore::load_or_create` and persists the freshly-generated KEM keypair on first start so the same identity survives restart. New `handle_epoch_keys_event` routes `RrEvent<EpochKeyRequest, EpochKeyResponse>` through the same H-12 admitted-peer gate the sync + admission handlers use. Inbound requests run through `EpochKeyRequest::validate` (cap + empty-string) and are answered by `build_epoch_key_response` — today an empty-releases default; the publisher-side mint flow lands in B.7 / B.9 with the rotation timer and the dispatch surface stays unchanged. Inbound responses run through `handle_epoch_key_response` → outer `EpochKeyResponse::validate` cap → per-blob bounded CBOR decode → `install_epoch_key_release` → install in `EpochKeyStore` and persist on success. The new public funnel `DdsNode::install_epoch_key_release` enforces the §4.5.1 receive gates in order: schema (`EpochKeyRelease::validate`), recipient binding (`recipient == self.peer_id`), replay window (`is_release_within_replay_window`, mirrors M-9), KEM decap with the canonical `epoch_key_binding(publisher, recipient, epoch_id)` (the M-2 / Phase A `dds-pqc-epoch-key/v1/...` domain-separation prefix), and AEAD unwrap. A wrong-binding / wrong-recipient / shelf-replayed / tampered release fails-loud at the matching layer and never reaches `install_peer_release`. Publisher-signature verification (Ed25519 + optional ML-DSA-65 over the canonical body bytes) is intentionally deferred to a B.6 follow-on once the canonical signing-bytes shape is finalised — at this layer the load-bearing forgery defence is the decap+unwrap pipeline (a forger that has neither the publisher's epoch key nor the recipient's KEM secret cannot construct a `(kem_ct, aead_ciphertext)` pair that recovers a usable epoch key). Wire plumbing (`epoch_keys: request_response::cbor::Behaviour<...>`) was already in place in `dds_net::transport` from the B.4 follow-on. 7 new integration tests in [`dds-node/tests/epoch_key_release_ingest.rs`](../dds-node/tests/epoch_key_release_ingest.rs) pin the receive contract end-to-end without a libp2p swarm (`mint_release` is the test-only mirror of the B.7 publisher-side mint helper): well-formed release accepted + cached + survives `save`/`load_or_create` round-trip; recipient mismatch rejected before decap; out-of-window stale `issued_at` rejected before decap; tampered AEAD ciphertext fails at the AEAD verify; wrong `epoch_id` (publisher used binding for epoch 7 but published as epoch 8) fails at AEAD verify (component-binding defence); wrong-length `kem_ct` short-circuits at the schema gate. Full end-to-end via the `/dds/epoch-keys/...` libp2p stream (publisher mint → swarm dispatch → receiver install) lands once B.7 wires the publisher-side mint flow and a multi-node integration harness can drive both sides. | done |
| B.6 | `dds-node::epoch_key_store` + on-disk persistence + `EPOCH_KEY_GRACE_SECS` decay cache + `EPOCH_RELEASE_REPLAY_WINDOW_SECS` enforcement — **landed** 2026-05-01 at [dds-node/src/epoch_key_store.rs](../dds-node/src/epoch_key_store.rs). New `EpochKeyStore` carries the local node's hybrid KEM keypair (via `dds_core::crypto::kem::generate`), the local node's current `(epoch_id, K_me)` epoch AEAD key, an in-memory `previous_my_epoch` grace entry, the `BTreeMap<String, PeerReleaseEntry>` of cached publisher releases, and a sibling `peer_grace` map for per-publisher previous epochs. The `InstallOutcome` enum (`Inserted` / `Rotated` / `AlreadyCurrent` / `Stale`) drives metric labelling at the future B.6 ingest call site and short-circuits replay attempts that try to inject an out-of-order release past the M-9 issued_at gate. `rotate_my_epoch(rng)` + `install_peer_release(...)` move the superseded entry into the appropriate grace cache anchored at `Instant::now()`; `prune_grace(now: Instant)` drops both kinds past `EPOCH_KEY_GRACE_SECS` (uses monotonic clock so wall-clock jumps cannot widen / shrink the window). Free function `is_release_within_replay_window(issued_at, now_unix)` is the schema-layer pre-decap gate, mirroring `EpochKeyRelease::validate` from B.4 — receivers reject any release older than `EPOCH_RELEASE_REPLAY_WINDOW_SECS` (7 days) before spending an ML-KEM-768 decap. On-disk format `OnDiskV1` persists `kem_x_sk` (32 B) + `kem_mlkem_seed` (64 B) + `(my_epoch_id, my_epoch_key)` + the per-publisher release map; grace caches are runtime-only so a process restart starts with a fresh `previous_my_epoch = None`. Atomic write via `tempfile::NamedTempFile::new_in(parent)` + `tmp.persist(path)` with `0o600` on Unix — same posture as `peer_cert_store::save` / `admission_revocation_store::save`. 16 new unit tests pin: bootstrap (`new` seeds `epoch_id = 1`), rotation (old → grace, current bumps), the four `InstallOutcome` paths, stale-release ignore, `remove_peer` drops only the current entry (grace ages out independently), `prune_grace` past the window, save/load round-trip preserves both KEM legs and the release map, `load_or_create` on missing file generates without touching disk, garbage-bytes / unknown-version / wrong-length fields all rejected at load, `0o600` permissions on the persisted file, the three replay-window paths (fresh / stale / clock-skew-future), and end-to-end KEM encap/decap proves the freshly-generated keypair is usable. `cargo test --workspace` — 836 / 836 passing (was 820 before B.6); `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all -- --check` clean. New workspace dep `rand_core` on dds-node (matches dds-domain's existing pin). | done |
| B.7 | Encrypted gossip envelope publish + ingest decode + mixed-fleet enforcement + sync responder re-wrap (§4.6.1). **Step 1 (publisher-side `EpochKeyRelease` mint + `EpochKeyResponse` responder) landed** 2026-05-01 at [`dds-node/src/node.rs`](../dds-node/src/node.rs): new public free function `mint_epoch_key_release_for_recipient(rng, publisher_id, epoch_id, epoch_key, recipient_id, recipient_kem_pk, issued_at, expires_at) -> Result<EpochKeyRelease, &'static str>` is the inverse of `DdsNode::install_epoch_key_release` — it derives the canonical `epoch_key_binding(publisher, recipient, epoch_id)`, runs `dds_core::crypto::kem::encap` against the recipient's hybrid X25519 + ML-KEM-768 pubkey, AEAD-wraps the 32-byte epoch key under the derived shared secret via `dds_core::crypto::epoch_key::wrap`, and returns a fully-formed `EpochKeyRelease` with a 64-byte zero-byte signature placeholder (the canonical signing-bytes shape is intentionally deferred to a B.6 / B.9 follow-on; the load-bearing forgery defence at the install layer is the per-recipient hybrid-KEM decap + AEAD unwrap pipeline). `DdsNode::build_epoch_key_response` (the B.5 responder funnel) now mints a real release for any `EpochKeyRequest` whose `publishers` list names the responder's own peer id, encapsulated to the requester's KEM pubkey looked up in `peer_certs` — the publisher-side half of §4.5.1 late-join recovery. Skipped reasons (no cached cert, cert without `pq_kem_pubkey`, malformed cached pubkey, mint failure) all fall through to the empty-releases response so the libp2p request_response channel doesn't time out. The forwarding case ("re-encapsulate a peer's epoch key for a third party") is intentionally not wired here — the original publisher's signature wouldn't verify against a re-encapsulation, and the safe semantics until the signing-bytes shape lands are "I speak only for myself". 7 new integration tests in [`dds-node/tests/epoch_key_release_mint.rs`](../dds-node/tests/epoch_key_release_mint.rs) pin the mint↔install round-trip end-to-end without a libp2p swarm: well-formed mint decapsulates + unwraps cleanly at the recipient; empty-publisher / empty-recipient / `expires_at <= issued_at` rejected at the schema gate; component-binding holds (a release minted for R1 cannot be lifted into R2's slot — fails at `recipient_mismatch` with the original recipient label, fails at `decap` / `aead` with a forged label); responder mints for self when requester has a cached v3 cert; responder ships empty when the request asks for a non-self publisher, when the requester has no cached cert, and when the cached cert is v1/v2 (no `pq_kem_pubkey`). **Step 2 (encrypted gossip ingest decode + enc-v3 enforcement gate) landed** 2026-05-01 at [`dds-node/src/node.rs`](../dds-node/src/node.rs) and [`dds-core/src/crypto/epoch_key.rs`](../dds-core/src/crypto/epoch_key.rs): `epoch_key::encrypt_payload` / `decrypt_payload` (AEAD wrap/unwrap for gossip payloads), `GossipEnvelopeV3::to_cbor` / `from_cbor` (publisher-keyed CBOR wire encoding), `DdsNode::handle_gossip_message` now branches on `GossipEnvelopeV3` CBOR prefix — decrypts with the cached epoch key, bumps `dds_pq_envelope_decrypt_total{result=ok|no_key|aead_fail}` at every exit branch, and drops plaintext gossip on `enc-v3` domains. `DdsNode::publish_gossip_op` wrapper exists for the publish side but is not yet called from production publishers (see PQ-B7-WIRE-1). 10 regression tests in [`dds-node/tests/gossip_encrypt.rs`](../dds-node/tests/gossip_encrypt.rs) cover decrypt+ingest, enc-v3 plaintext-drop enforcement, non-enc-v3 plaintext acceptance, no-cached-key drop, tampered-ciphertext drop, wrong-epoch-id drop, and encrypt/decrypt roundtrips. **Step 3 (PQ-B7-WIRE-1 + PQ-B7-RECOVERY-1 + H-12 piggy-back) landed 2026-05-01:** (a) **PQ-B7-WIRE-1** — `publish_gossip_op` is now the single publish entry-point for all production gossip: both `dds-loadtest/src/harness.rs` publish paths (revocation + DirectoryOp) and `dds-node/src/bin/dds-macos-e2e.rs` now call `DdsNode::publish_gossip_op`, so enc-v3 wrapping is applied transparently in all harness and e2e contexts. (b) **PQ-B7-RECOVERY-1** — late-join recovery request: `DdsNode::try_epoch_key_request(publisher_id)` added; called from the `no_key` drop path in `handle_gossip_message` so a node that doesn't yet hold an epoch key automatically requests one from the publisher (throttled by 30 s per-publisher cooldown via `epoch_key_request_last` map). (c) **H-12 epoch-key piggy-back** — `AdmissionResponse::epoch_key_releases` is now populated by `epoch_key_releases_for_admission_response` when the responder has a cached cert for the requester; ingest side added as `ingest_piggybacked_epoch_key_releases`, called from `verify_peer_admission` after a successful admission. Together these close the §4.5 H-12 distribution channel end-to-end for re-connects where both sides already have each other's certs. §4.6.1 sync responder re-wrap closed by B.8 (this commit). | done |
| B.8 | **Encrypted sync envelope publish + ingest decode — landed 2026-05-01** at [`dds-net/src/sync.rs`](../dds-net/src/sync.rs) and [`dds-node/src/node.rs`](../dds-node/src/node.rs). `SyncResponse` grew an optional `enc_payloads: Vec<Vec<u8>>` field (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`) carrying CBOR-encoded `SyncEnvelopeV3` blobs — one per diff entry — enabling backward-compat wire encoding so v2 requesters decode the response with `enc_payloads` absent and v3 requesters can produce both shapes depending on domain capability. **Responder side** (`DdsNode::build_sync_response`): when the domain has the `enc-v3` capability, CBOR-encodes each `SyncPayload` then AEAD-encrypts it under the responder's current epoch key into a `SyncEnvelopeV3`; `payloads` is left empty and `enc_payloads` carries the ciphertext list. On non-`enc-v3` domains the response is plaintext as before (§4.7 Stage 0–1 mixed-fleet window preserved). **Requester side** (`DdsNode::handle_sync_response`): when `enc_payloads` is non-empty, decodes each blob as a `SyncEnvelopeV3`, validates responder identity, looks up the responder's cached epoch key, AEAD-decrypts, then CBOR-decodes the inner `SyncPayload` — all bumping `dds_pq_envelope_decrypt_total{result=ok\|no_key\|aead_fail}` at each exit branch; on `no_key` triggers `try_epoch_key_request` for late-join recovery (§4.5.1) just as the gossip path does. After decryption the payload list flows through the existing publisher-capability + replay-window + trust-graph merge pipeline unchanged. `try_epoch_key_request` is also called from the sync decrypt `no_key` path, so a node that loses the responder's epoch key mid-epoch can recover via the dedicated request-response protocol rather than waiting for reconnect. 8 new regression tests in [`dds-node/tests/sync_encrypt.rs`](../dds-node/tests/sync_encrypt.rs): plaintext build on non-enc-v3 domain; encrypted build on enc-v3 domain; known-op-id diff-filter respected under enc-v3; decrypt-ok with cached key bumps `result=ok`; decrypt no-key drops with `result=no_key`; tampered ciphertext drops with `result=aead_fail`; plaintext response accepted on non-enc-v3 requester; full enc-v3 round-trip (2 payloads, 2 ok bumps). `SyncEnvelopeV3` CBOR round-trip pinned. Test hooks `build_sync_response_for_tests` + `handle_sync_response_for_tests` added following the Phase B.7 pattern. | done |
| B.9 | **Rotation timer + revocation hook + jittered staggering + fan-out to admitted peers — landed 2026-05-01** at [`dds-node/src/node.rs`](../dds-node/src/node.rs), [`dds-node/src/config.rs`](../dds-node/src/config.rs), and [`dds-net/src/pq_envelope.rs`](../dds-net/src/pq_envelope.rs). `DomainConfig` gained `epoch_rotation_secs: u64` (default 86400, i.e. 24 h). `DdsNode` grew `pending_revocation_rotation: Option<Pin<Box<Sleep>>>` (jittered 0–30 s sleep) and `manual_rotate: Arc<Notify>` (HTTP-to-run-loop signal channel). `DdsNode::run()` drives three new `select!` branches: (a) `epoch_rotation_timer.tick()` — fires every `epoch_rotation_secs`, (b) `pending_revocation_rotation.await` — consumed once and reset to `None`, (c) `manual_rotate.notified()` — consumed on `POST /v1/pq/rotate`. All three call the shared `rotate_and_fan_out(reason)` helper which calls `EpochKeyStore::rotate_my_epoch`, persists the updated store to disk, logs `epoch_id + reason`, bumps `dds_pq_rotation_total{reason}`, and calls `emit_epoch_key_releases_to_all_admitted_peers`. Fan-out iterates admitted + connected peers whose cached certs carry a KEM pubkey, mints a per-recipient release, and sends an `EpochKeyRequest { publishers: [], outbound_releases: [blob] }` over the existing request-response channel (no new wire type needed). The responder side of `handle_epoch_keys_event` now processes `outbound_releases` blobs by passing them through the existing `handle_epoch_key_response` pipeline. Fan-out concurrency is capped at `EPOCH_KEY_FANOUT_CONCURRENCY = 10` sequential sends to avoid a burst of simultaneous outbound libp2p requests. `ingest_revocation` schedules a jittered sleep (0–30 s) on the first revocation in an epoch, clearing once the sleep fires. `EpochKeyRequest` grew `outbound_releases: Vec<Vec<u8>>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]` for backward-compat wire encoding; `EpochKeyRequest::validate()` enforces the same `MAX_EPOCH_KEY_RELEASES_PER_RESPONSE` cap on the new field. | done |
| B.10 | **`dds-cli pq status / rotate / list-pubkeys` operator surface — fully landed 2026-05-01** at [`dds-cli/src/main.rs`](../dds-cli/src/main.rs). `dds pq status` and `dds pq list-pubkeys` (read-only, offline reads) were already landed. `dds pq rotate` now wired: `PqAction::Rotate` variant added; `handle_pq_rotate(node_url)` calls `POST /v1/pq/rotate` via `post_no_body`; HTTP handler `pq_rotate<S>` added to the admin-gated sub-router in [`dds-node/src/http.rs`](../dds-node/src/http.rs). The handler signals the node's `Arc<Notify>` (wired through `AppState.manual_rotate` → `serve()` → `router()` → `AppState`) and returns 200 OK; returns 503 when the node has no `Notify` handle. `http::serve`, `serve_unix`, and `serve_pipe` each grew a `manual_rotate: Option<Arc<Notify>>` parameter threaded from `main.rs` (`Some(node.manual_rotate.clone())`). | done |
| B.11 | **Phase C/E observability — fully landed 2026-05-02** at [`dds-node/src/telemetry.rs`](../dds-node/src/telemetry.rs). All six Phase B PQC metric families are now implemented: `dds_pq_releases_installed_total`, `dds_pq_releases_emitted_total`, `dds_pq_envelope_decrypt_total`, `dds_pq_rotation_total` (all previously landed), plus **`dds_pq_epoch_id`** (current epoch_id gauge — `AtomicU64` in `Telemetry`, set by `record_pq_epoch_id` at `DdsNode::init` and every `rotate_and_fan_out`; `dds_pq_epoch_id 0` on an uninitialised node, non-zero from first scrape after `init`), and **`dds_pq_release_requests_total`** (per-`result` late-join request counter — `sent|cooldown|not_admitted|malformed_peer_id` buckets bumped from every exit branch of `DdsNode::try_epoch_key_request`). Metric catalog comment in `telemetry.rs` module doc updated. `dds-node/tests/sync_encrypt.rs` cleaned of 3 `needless_borrow` clippy warnings (pre-existing from the B.8 commit). **2 new unit tests** pin the two new families: `render_emits_pq_epoch_id_gauge` (zero default, single-set, overwrite), `render_emits_pq_release_requests_total_after_bumps` (empty-family header present, value lines after bucket bumps). Updated the `render_includes_build_info_and_uptime_for_empty_telemetry` test to also assert `# TYPE dds_pq_rotation_total counter\n`, `# TYPE dds_pq_epoch_id gauge\n`, `dds_pq_epoch_id 0\n`, and `# TYPE dds_pq_release_requests_total counter\n`. **Phase E alert rules** (`DdsPqcDecryptFailureSpike`, `DdsPqcKeyRequestSpike`) landed 2026-05-02 — the two deferred alert rules are now active in [`observability/alerts/dds.rules.yml`](../docs/observability/alerts/dds.rules.yml) `dds-pqc` group; see observability-plan.md follow-up #45. `cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo fmt --all -- --check` clean; `cargo test -p dds-node` 411 / 411 passing. | done |
| B.12 | **Integration tests — landed 2026-05-01** at [`dds-node/tests/pqc_b12_integration.rs`](../dds-node/tests/pqc_b12_integration.rs). 10 tests cover all five lifecycle scenarios from §7 without a live libp2p swarm: (1) **Mixed-fleet** — plaintext accepted on non-enc-v3 domain; rejected on enc-v3 domain; encrypted gossip flows cleanly between two enc-v3 nodes. (2) **Epoch-key rotation + grace window** — receiver B decrypts in-flight messages under the old epoch_id via the grace cache after publisher A rotates; installs new release and decrypts new-epoch gossip; after `prune_grace` with a far-future instant, old epoch_id drops from cache and subsequent decrypt drops with `no_key`. (3) **Revocation-triggered rotation** — `rotate_and_fan_out("revocation")` bumps `dds_pq_rotation_total{reason=revocation}`; B (which got the new release) decrypts post-rotation gossip; C (which did not — simulating a revoked peer) drops with `no_key`. (4) **Offline > 24h reconnect** — B misses multiple rotation cycles; decryption fails with `no_key` until B installs a fresh release (via `distribute_epoch_key` shorthand); full §4.5.1 late-join recovery also exercised end-to-end via `build_epoch_key_response_for_tests` + `install_epoch_key_release`. (5) **KEM-pubkey-rotated-while-offline** — new node instance (new KEM keypair) for same domain; B updates cached cert via `cache_peer_admission_cert`; release minted to new KEM pubkey decaps at B; a release minted to the *old* KEM pubkey fails with `decap` or `aead` at B, proving the component-binding defence holds across a KEM rotation. | done |
| **Total** | | **~27 d ≈ 5-6 weeks dev + buffer ⇒ 2 months wall-clock** |

## 9. Open decisions to confirm before B.1

1. **KEM library**: doc proposes `ml-kem = "0.2"` (RustCrypto, FIPS
   203 final). Alternative: `pqcrypto-mlkem` (matches Phase A's
   `pqcrypto-mldsa` family). Confirm direction.
2. **AEAD primitive**: doc proposes ChaCha20-Poly1305 (already used
   elsewhere in dds-node — `domain_store.rs`, `identity_store.rs`).
   Alternative: AES-256-GCM (faster on AES-NI hardware, but
   cross-platform consistency favours ChaCha).
3. **Default epoch length**: doc proposes 24h. Shorter (1h) reduces
   the HNDL window if a key leaks but increases churn.
   Operator-overridable per-domain.
4. **5-minute decay cache** for previous epoch key: tunable.
   Trade-off between in-flight smoothness and post-rotation
   forward-secrecy.
5. **Capability negotiation transport**: doc proposes
   `Domain.capabilities` field (re-using the same admin-signed
   `domain.toml` distribution that ships `pq_pubkey` today).
   Alternative: per-peer capability advertisement on libp2p
   `Identify`.
6. **KEM key ownership**: domain-level (the domain key holds it,
   like the Phase A ML-DSA half) vs node-level (each PeerId has its
   own KEM keypair, advertised via its own `AdmissionCert`). Doc
   proposes node-level — KEM is per-recipient, and a per-PeerId key
   matches the H-12 trust binding more naturally. Domain-level
   would force the admin to be online for every rekey.
7. **Should `EpochKeyRelease` itself carry the publisher's KEM
   pubkey** in addition to the recipient looking it up via the
   publisher's `AdmissionCert`? Doc proposes "no" — the cert is the
   authoritative source and binding the release to a specific cert
   avoids confusion if the publisher rotates KEM keys.

## 10. References

- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- IETF `draft-ietf-tls-hybrid-design` — hybrid KEM construction
  reference
- Phase A landed: [STATUS.md](../STATUS.md) §Z-1 Plan
- Phase C upstream tracking: rust-libp2p `rs/9595` (no hybrid Noise
  feature flag in mainline 0.55)
- M-2 hybrid signature pattern (basis for the domain-separation
  prefix shape used here): [Claude_sec_review.md](../Claude_sec_review.md)
