//! Per-publisher epoch-key store for the Z-1 Phase B.6 PQC rollout.
//!
//! See [`docs/pqc-phase-b-plan.md`](../../docs/pqc-phase-b-plan.md) §4.4
//! / §4.5 / §4.6 for the full design. The receiver-side state for the
//! "per-publisher epoch keys, distributed via per-recipient hybrid
//! KEM" model lives here:
//!
//! - the local node's hybrid KEM keypair (used by other publishers
//!   to encrypt their `EpochKeyRelease` payloads to *us*);
//! - the local node's *current* epoch AEAD key (the symmetric key we
//!   encrypt every outbound gossip / sync envelope under);
//! - a short-lived in-memory grace cache for the *previous* epoch
//!   AEAD key so in-flight gossip with the older `epoch_id` still
//!   decrypts on the receiver side after we rotate;
//! - the cached `(publisher, epoch_id) → epoch_key` map of every
//!   release we've decapped from peers, with the same grace-cache
//!   posture for previous epochs from each publisher.
//!
//! ## Replay window
//!
//! [`EPOCH_RELEASE_REPLAY_WINDOW_SECS`] (7 days) gates inbound
//! `EpochKeyRelease` payloads at the [`is_release_within_replay_window`]
//! call site below. Releases older than the window are rejected before
//! any KEM decap is attempted — receivers cannot waste an ML-KEM-768
//! decap on a stale shelf-replayed release. Mirrors the M-9 token
//! replay-window pattern.
//!
//! ## Grace window
//!
//! [`EPOCH_KEY_GRACE_SECS`] (5 minutes) is how long a previous epoch
//! key (mine or a peer's) is kept after rotation. Operates in
//! [`std::time::Instant`] (monotonic, process-scoped) so a wall-clock
//! jump cannot widen or shrink the window.
//!
//! ## On-disk format
//!
//! `<data_dir>/epoch_keys.cbor` carries a versioned `OnDiskV1` record:
//!
//! ```text
//! {
//!   v:                1,
//!   kem_x_sk:         32 B,    // X25519 secret scalar
//!   kem_mlkem_seed:   64 B,    // ML-KEM-768 seed
//!   my_epoch_id:      u64,
//!   my_epoch_key:     32 B,    // current epoch AEAD key
//!   peer_releases:    [{ publisher, epoch_id, key, expires_at }],
//! }
//! ```
//!
//! `previous_my_epoch` and the per-publisher grace entries are
//! *runtime-only*: a process restart drops them, which is safe because
//! grace keys are by definition for in-flight gossip we sent in the
//! last 5 minutes — re-decrypting that in-flight gossip on the
//! receiver after our restart is not a reachable state (the
//! receiver's connection to us drops on restart, gossipsub flushes,
//! and the next message it sees is keyed to our *new* epoch).
//!
//! **M-3 (pre-prod review 2026-07-24)** — the record above is the
//! *inner* payload. When `DDS_NODE_PASSPHRASE` is set it is wrapped in
//! a `v=2` envelope:
//!
//! ```text
//! {
//!   v:      2,
//!   salt:   16 B,   // Argon2id salt
//!   nonce:  12 B,   // ChaCha20-Poly1305 nonce
//!   m_cost: u32, t_cost: u32, p_cost: u32,
//!   blob:   ciphertext over the CBOR-encoded v=1 record
//! }
//! ```
//!
//! Atomic write via `tempfile::NamedTempFile::new_in(parent)` +
//! `tmp.persist(path)` with `0o600` on Unix and an owner-only DACL on
//! Windows — mirrors the L-3 follow-on posture used by
//! `admission_revocation_store::save` and `peer_cert_store::save`.
//!
//! ## Threat-model footnote
//!
//! The KEM secret key is the load-bearing secret here: an attacker
//! with read access to `epoch_keys.cbor` can decap every
//! `EpochKeyRelease` ever sent to this node and recover every peer's
//! epoch key for the recorded epochs.
//!
//! Until M-3 this file was the *only* node secret store written in the
//! clear: `identity_store` and `domain_store` both honour
//! `DDS_NODE_PASSPHRASE` / `DDS_DOMAIN_PASSPHRASE` and
//! `DDS_REQUIRE_ENCRYPTED_KEYS`, while this one serialized `kem_x_sk`,
//! `kem_mlkem_seed`, `my_epoch_key` and every cached peer epoch key as
//! raw CBOR byte strings. The owner-only DACL blocks a live co-tenant
//! read, so the residual exposure was an offline one — a stolen disk
//! image, a backup, or a VSS snapshot, where every *other* key file was
//! encrypted and this one was not. It now rides the same Argon2id +
//! ChaCha20-Poly1305 envelope, and honours `DDS_REQUIRE_ENCRYPTED_KEYS`
//! by failing closed rather than silently writing plaintext.
//!
//! Legacy plaintext (`v=1`) files still load, and the next `save()`
//! with a passphrase set transparently rewrites them as `v=2`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use ciborium::value::Value as CborValue;
use dds_core::crypto::epoch_key::EPOCH_KEY_LEN;
use dds_core::crypto::kem::{
    HybridKemPublicKey, HybridKemSecretKey, MLKEM768_SEED_LEN, X25519_KEY_LEN, generate,
    public_from_secret,
};
use dds_net::pq_envelope::{EPOCH_KEY_GRACE_SECS, EPOCH_RELEASE_REPLAY_WINDOW_SECS};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug)]
pub enum EpochKeyStoreError {
    Io(String),
    Cbor(String),
    Format(String),
    /// **M-3** — passphrase / AEAD failure, or a refusal to write
    /// plaintext under `DDS_REQUIRE_ENCRYPTED_KEYS`.
    Crypto(String),
}

impl std::fmt::Display for EpochKeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Cbor(e) => write!(f, "cbor: {e}"),
            Self::Format(e) => write!(f, "format: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for EpochKeyStoreError {}

/// Plaintext record (legacy; still readable).
const VERSION_V1: i64 = 1;

/// **M-3** — passphrase-encrypted envelope wrapping a `VERSION_V1`
/// record. Written whenever `DDS_NODE_PASSPHRASE` is non-empty.
const VERSION_V2_ENCRYPTED: i64 = 2;

/// Cached release for a single publisher: the last-known current
/// `(epoch_id, key)` plus the publisher-asserted `expires_at`. The
/// `expires_at` is recorded for telemetry / future expiry-driven
/// pruning — the load-bearing replay defence is the issued_at gate
/// at ingest time ([`is_release_within_replay_window`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReleaseEntry {
    pub epoch_id: u64,
    pub key: [u8; EPOCH_KEY_LEN],
    pub expires_at: u64,
}

/// Outcome of installing a peer release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// First release we've seen for this publisher.
    Inserted,
    /// Newer epoch than what we had — old entry moved to the grace
    /// cache.
    Rotated,
    /// Same epoch_id as cached — no-op.
    AlreadyCurrent,
    /// `epoch_id` strictly older than the cached current — ignored
    /// (the cached current is fresher, and grace is never extended
    /// backwards).
    Stale,
}

/// In-memory store of every epoch-key the local node depends on:
/// our own current key, our previous key during the grace window,
/// and the per-publisher releases we've decapped + cached.
#[derive(Debug, Clone)]
pub struct EpochKeyStore {
    kem_secret: HybridKemSecretKey,
    /// Cached at construction so call sites don't have to re-derive
    /// it on every advertise — `public_from_secret` is cheap but the
    /// cache makes the API harder to misuse (no hidden allocation in
    /// the hot path).
    kem_public: HybridKemPublicKey,

    my_epoch: (u64, [u8; EPOCH_KEY_LEN]),

    /// Process-scoped previous-epoch entry. Cleared on the next
    /// `prune_grace(now)` past [`EPOCH_KEY_GRACE_SECS`].
    previous_my_epoch: Option<(u64, [u8; EPOCH_KEY_LEN], Instant)>,

    peer_releases: BTreeMap<String, PeerReleaseEntry>,

    /// Process-scoped grace cache: the last release for each
    /// publisher just before they rotated. Cleared on the next
    /// `prune_grace(now)` past [`EPOCH_KEY_GRACE_SECS`].
    peer_grace: BTreeMap<(String, u64), ([u8; EPOCH_KEY_LEN], Instant)>,
}

/// **L-14 (pre-prod review 2026-07-24)** — wipe every secret this store
/// holds when it goes out of scope.
///
/// Cloning the store (it is `Clone`, and the node clones it into the
/// epoch-key fan-out path) previously left copies of the hybrid-KEM
/// secret, the local epoch key, and every cached peer epoch key sitting
/// in freed heap. `HybridKemSecretKey` and the `[u8; 32]` epoch keys are
/// plain byte arrays with no drop glue of their own, so this has to be
/// explicit.
///
/// `ZeroizeOnDrop` is derived from this manual `Drop` rather than the
/// derive macro because `BTreeMap` keys (`String`, `(String, u64)`) and
/// `Instant` are not `Zeroize`; only the key material is wiped, which is
/// the material that matters — the publisher URNs and timestamps are not
/// secret.
impl Drop for EpochKeyStore {
    fn drop(&mut self) {
        self.kem_secret.x_sk.zeroize();
        self.kem_secret.mlkem_seed.zeroize();
        self.my_epoch.1.zeroize();
        if let Some((_, ref mut key, _)) = self.previous_my_epoch {
            key.zeroize();
        }
        for entry in self.peer_releases.values_mut() {
            entry.key.zeroize();
        }
        for (key, _) in self.peer_grace.values_mut() {
            key.zeroize();
        }
    }
}

impl ZeroizeOnDrop for EpochKeyStore {}

impl EpochKeyStore {
    /// Construct a fresh store: generate a new hybrid KEM keypair and
    /// seed `epoch_id = 1` with a random 32-byte AEAD key.
    pub fn new<R: CryptoRngCore>(rng: &mut R) -> Self {
        let (kem_secret, kem_public) = generate(rng);
        let mut epoch_key = [0u8; EPOCH_KEY_LEN];
        rng.fill_bytes(&mut epoch_key);
        Self {
            kem_secret,
            kem_public,
            my_epoch: (1, epoch_key),
            previous_my_epoch: None,
            peer_releases: BTreeMap::new(),
            peer_grace: BTreeMap::new(),
        }
    }

    /// Hybrid KEM public key — the value advertised on
    /// [`AdmissionCert::pq_kem_pubkey`](dds_domain::AdmissionCert) so
    /// peers can encapsulate `EpochKeyRelease` payloads to us.
    pub fn kem_public(&self) -> &HybridKemPublicKey {
        &self.kem_public
    }

    /// Hybrid KEM secret key — used by `kem::decap` on inbound
    /// `EpochKeyRelease` ingest. Callers must NOT serialize this
    /// outside the persisted store.
    pub fn kem_secret(&self) -> &HybridKemSecretKey {
        &self.kem_secret
    }

    /// `(epoch_id, &epoch_key)` for the local node's current epoch.
    pub fn my_current_epoch(&self) -> (u64, &[u8; EPOCH_KEY_LEN]) {
        (self.my_epoch.0, &self.my_epoch.1)
    }

    /// Look up the local node's epoch key for `epoch_id` — returns
    /// the current key if `epoch_id` matches, the grace-cache key if
    /// it matches the recently-superseded epoch, or `None` otherwise.
    /// Call sites that want grace-cache visibility must invoke
    /// [`Self::prune_grace`] first if their notion of "now" has
    /// advanced; the lookup itself never times out an entry.
    pub fn my_epoch_key(&self, epoch_id: u64) -> Option<&[u8; EPOCH_KEY_LEN]> {
        if self.my_epoch.0 == epoch_id {
            return Some(&self.my_epoch.1);
        }
        if let Some((prev_id, prev_key, _)) = self.previous_my_epoch.as_ref()
            && *prev_id == epoch_id
        {
            return Some(prev_key);
        }
        None
    }

    /// Rotate the local node's epoch: bump `epoch_id` by one,
    /// generate a fresh 32-byte AEAD key, and move the previous
    /// `(epoch_id, key)` into the grace cache anchored at
    /// `Instant::now()` (so it ages out at the next prune past
    /// [`EPOCH_KEY_GRACE_SECS`]). Returns the new `epoch_id`.
    pub fn rotate_my_epoch<R: CryptoRngCore>(&mut self, rng: &mut R) -> u64 {
        let mut next_key = [0u8; EPOCH_KEY_LEN];
        rng.fill_bytes(&mut next_key);
        let prev = self.my_epoch;
        let new_id = prev.0.saturating_add(1);
        self.my_epoch = (new_id, next_key);
        self.previous_my_epoch = Some((prev.0, prev.1, Instant::now()));
        new_id
    }

    /// Install a peer's epoch-key release (caller has already verified
    /// signatures + replay window + decapped the AEAD-wrapped key).
    ///
    /// Returns the [`InstallOutcome`] so the caller can drive metrics
    /// / audit on the rotation classification:
    /// - `Inserted`: first release from this publisher.
    /// - `Rotated`: newer epoch than what we had — old entry moved
    ///   to the grace cache.
    /// - `AlreadyCurrent`: identical `epoch_id` already present.
    /// - `Stale`: `epoch_id` strictly older than the cached current —
    ///   ignored. Defends against an out-of-order release slipping
    ///   in past the replay-window check (the per-publisher
    ///   monotonicity is the second line).
    pub fn install_peer_release(
        &mut self,
        publisher: &str,
        epoch_id: u64,
        key: [u8; EPOCH_KEY_LEN],
        expires_at: u64,
    ) -> InstallOutcome {
        match self.peer_releases.get(publisher) {
            None => {
                self.peer_releases.insert(
                    publisher.to_string(),
                    PeerReleaseEntry {
                        epoch_id,
                        key,
                        expires_at,
                    },
                );
                InstallOutcome::Inserted
            }
            Some(existing) if existing.epoch_id == epoch_id => InstallOutcome::AlreadyCurrent,
            Some(existing) if existing.epoch_id > epoch_id => InstallOutcome::Stale,
            Some(existing) => {
                // existing.epoch_id < epoch_id — rotation. Move the old
                // entry into the grace cache and overwrite.
                let prev_id = existing.epoch_id;
                let prev_key = existing.key;
                self.peer_grace
                    .insert((publisher.to_string(), prev_id), (prev_key, Instant::now()));
                self.peer_releases.insert(
                    publisher.to_string(),
                    PeerReleaseEntry {
                        epoch_id,
                        key,
                        expires_at,
                    },
                );
                InstallOutcome::Rotated
            }
        }
    }

    /// Look up the cached epoch key for `(publisher, epoch_id)`.
    /// Searches the current map first, then the grace cache. Does
    /// not call [`Self::prune_grace`]; callers that want time-bound
    /// grace lookups must prune first if their `now` has advanced.
    pub fn peer_epoch_key(&self, publisher: &str, epoch_id: u64) -> Option<&[u8; EPOCH_KEY_LEN]> {
        if let Some(entry) = self.peer_releases.get(publisher)
            && entry.epoch_id == epoch_id
        {
            return Some(&entry.key);
        }
        self.peer_grace
            .get(&(publisher.to_string(), epoch_id))
            .map(|(key, _)| key)
    }

    /// `true` when we hold a decapped current release (any epoch)
    /// from `publisher` — i.e. we can decrypt what they send today.
    pub fn has_peer_release(&self, publisher: &str) -> bool {
        self.peer_releases.contains_key(publisher)
    }

    /// Drop grace-cache entries (mine + peers') older than
    /// [`EPOCH_KEY_GRACE_SECS`] relative to `now`. Returns the number
    /// of entries pruned across both caches.
    pub fn prune_grace(&mut self, now: Instant) -> usize {
        let grace = std::time::Duration::from_secs(EPOCH_KEY_GRACE_SECS);
        let mut pruned = 0usize;

        if let Some((_, _, anchor)) = self.previous_my_epoch.as_ref()
            && now.saturating_duration_since(*anchor) >= grace
        {
            self.previous_my_epoch = None;
            pruned += 1;
        }

        let before = self.peer_grace.len();
        self.peer_grace
            .retain(|_, (_, anchor)| now.saturating_duration_since(*anchor) < grace);
        pruned += before - self.peer_grace.len();
        pruned
    }

    /// Number of cached current peer releases.
    pub fn peer_release_count(&self) -> usize {
        self.peer_releases.len()
    }

    /// Number of grace-cache entries (mine + peers') still in memory.
    /// `prune_grace` may shrink this; the count is informational
    /// telemetry, not a load-bearing security boundary.
    pub fn grace_count(&self) -> usize {
        self.peer_grace.len() + usize::from(self.previous_my_epoch.is_some())
    }

    /// Drop the cached current release for `publisher` (e.g. on
    /// admission revocation). Returns the entry that was removed,
    /// if any. Grace entries for the same publisher are intentionally
    /// left in place — they age out via [`Self::prune_grace`] within
    /// `EPOCH_KEY_GRACE_SECS` regardless.
    pub fn remove_peer(&mut self, publisher: &str) -> Option<PeerReleaseEntry> {
        self.peer_releases.remove(publisher)
    }

    /// Persist the store to `path` via the same atomic-write +
    /// `0o600` posture used by `peer_cert_store::save` /
    /// `admission_revocation_store::save`.
    pub fn save(&self, path: &Path) -> Result<(), EpochKeyStoreError> {
        save(path, self)
    }

    /// Load `path`, or generate a fresh store (with a fresh KEM
    /// keypair) if the file does not exist. The fresh-store path
    /// does NOT touch disk — callers must invoke [`Self::save`]
    /// after the bootstrap if they want the freshly-generated KEM
    /// keypair to survive a restart.
    pub fn load_or_create<R: CryptoRngCore>(
        path: &Path,
        rng: &mut R,
    ) -> Result<Self, EpochKeyStoreError> {
        if !path.exists() {
            return Ok(Self::new(rng));
        }
        load(path)
    }
}

/// Replay-window gate on inbound `EpochKeyRelease.issued_at`. Mirrors
/// the M-9 revocation replay window and the §4.5.1 design pin.
/// Returns `true` when the release was issued at most
/// [`EPOCH_RELEASE_REPLAY_WINDOW_SECS`] seconds before `now_unix`,
/// `false` otherwise. A release with `issued_at > now_unix` (clock
/// skew) is admitted — receiver-side clock-skew handling lives at
/// the same call sites that gate token freshness, and the AEAD
/// decap will fail-loud if the release was actually forged from the
/// future.
pub fn is_release_within_replay_window(issued_at: u64, now_unix: u64) -> bool {
    if issued_at >= now_unix {
        return true;
    }
    now_unix - issued_at <= EPOCH_RELEASE_REPLAY_WINDOW_SECS
}

/// **M-3 (pre-prod review 2026-07-24)** — path of the sticky
/// "this store was once encrypted" marker.
///
/// Same shape and rationale as `identity_store`'s M-14 marker: once a
/// `v=2` blob has been written, an attacker with filesystem write who
/// clears `DDS_NODE_PASSPHRASE` must not be able to make the next save
/// silently roll the hybrid-KEM secret back to plaintext. A side file
/// rather than a field inside the record, because the invariant has to
/// be checkable *without* first parsing (and therefore trusting) a file
/// an attacker may have swapped in.
fn encrypted_marker_path(key_path: &Path) -> std::path::PathBuf {
    let mut p = key_path.as_os_str().to_os_string();
    p.push(".encrypted-marker");
    std::path::PathBuf::from(p)
}

/// **M-3** — wrap `inner` (the CBOR `v=1` record) in the `v=2`
/// passphrase envelope when `DDS_NODE_PASSPHRASE` is set; otherwise
/// return it unchanged.
///
/// Fails closed — rather than writing plaintext — when
/// `DDS_REQUIRE_ENCRYPTED_KEYS` is on but no passphrase is available, or
/// when a previous save already produced an encrypted blob (the sticky
/// marker) and no explicit downgrade override is set. This is the gate
/// the store previously lacked entirely.
fn seal_payload(path: &Path, inner: &[u8]) -> Result<(Vec<u8>, bool), EpochKeyStoreError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use rand::RngCore;
    use rand::rngs::OsRng;

    let passphrase = std::env::var(crate::identity_store::PASSPHRASE_ENV).map(Zeroizing::new);
    let will_be_plaintext = !matches!(&passphrase, Ok(p) if !p.is_empty());

    if will_be_plaintext && crate::identity_store::require_encrypted_keys() {
        return Err(EpochKeyStoreError::Crypto(format!(
            "refusing to write plaintext epoch-key store at {} — {} is set but {} is empty. \
             This file holds the hybrid-KEM secret that decapsulates every EpochKeyRelease \
             sent to this node.",
            path.display(),
            crate::identity_store::REQUIRE_ENCRYPTED_KEYS_ENV,
            crate::identity_store::PASSPHRASE_ENV,
        )));
    }

    if will_be_plaintext && encrypted_marker_path(path).exists() {
        let allow_downgrade = std::env::var(crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV)
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !allow_downgrade {
            return Err(EpochKeyStoreError::Crypto(format!(
                "refusing to overwrite encrypted epoch-key store at {} with plaintext \
                 ({} is empty but an encrypted-marker is present). If this is intentional, \
                 set {}=1 to override.",
                path.display(),
                crate::identity_store::PASSPHRASE_ENV,
                crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV,
            )));
        }
        tracing::warn!(
            "plaintext downgrade of encrypted epoch-key store at {} permitted by {}",
            path.display(),
            crate::identity_store::ALLOW_PLAINTEXT_DOWNGRADE_ENV,
        );
    }

    let Ok(pass) = passphrase else {
        tracing::info!(
            "epoch-key store written unencrypted at {} ({} unset). Set a passphrase — and \
             {} — to encrypt the hybrid-KEM secret at rest.",
            path.display(),
            crate::identity_store::PASSPHRASE_ENV,
            crate::identity_store::REQUIRE_ENCRYPTED_KEYS_ENV,
        );
        return Ok((inner.to_vec(), false));
    };
    if pass.is_empty() {
        return Ok((inner.to_vec(), false));
    }

    let (m_cost_kib, t_cost, p_cost) = crate::identity_store::SHARED_KDF_PARAMS;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = crate::identity_store::derive_argon2id_key(
        pass.as_bytes(),
        &salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )
    .map_err(EpochKeyStoreError::Crypto)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), inner)
        .map_err(|e| EpochKeyStoreError::Crypto(format!("encrypt: {e}")))?;
    key.zeroize();

    let envelope = CborValue::Map(vec![
        (
            CborValue::Text("v".into()),
            CborValue::Integer(VERSION_V2_ENCRYPTED.into()),
        ),
        (
            CborValue::Text("salt".into()),
            CborValue::Bytes(salt.to_vec()),
        ),
        (
            CborValue::Text("nonce".into()),
            CborValue::Bytes(nonce_bytes.to_vec()),
        ),
        (
            CborValue::Text("m_cost".into()),
            CborValue::Integer(m_cost_kib.into()),
        ),
        (
            CborValue::Text("t_cost".into()),
            CborValue::Integer(t_cost.into()),
        ),
        (
            CborValue::Text("p_cost".into()),
            CborValue::Integer(p_cost.into()),
        ),
        (CborValue::Text("blob".into()), CborValue::Bytes(ct)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&envelope, &mut out)
        .map_err(|e| EpochKeyStoreError::Cbor(e.to_string()))?;
    Ok((out, true))
}

/// **M-3** — unwrap a `v=2` envelope. Returns the inner `v=1` CBOR
/// record. `v=1` files pass straight through so existing deployments
/// keep loading; they are rewritten as `v=2` on the next save that has a
/// passphrase available.
fn unseal_payload(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, EpochKeyStoreError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let value: CborValue =
        ciborium::from_reader(bytes).map_err(|e| EpochKeyStoreError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| EpochKeyStoreError::Format("not a map".into()))?;

    let version = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("v"))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i64::try_from(i).ok())
        .ok_or_else(|| EpochKeyStoreError::Format("missing v".into()))?;

    if version != VERSION_V2_ENCRYPTED {
        // v=1 (or anything else) — hand the original bytes to the
        // plaintext parser, which validates the version properly.
        return Ok(Zeroizing::new(bytes.to_vec()));
    }

    let field_bytes = |name: &str| -> Option<Vec<u8>> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .and_then(|(_, v)| v.as_bytes().cloned())
    };
    let field_u32 = |name: &str| -> Option<u32> {
        map.iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .and_then(|(_, v)| v.as_integer())
            .and_then(|i| i128::from(i).try_into().ok())
    };

    let salt =
        field_bytes("salt").ok_or_else(|| EpochKeyStoreError::Format("missing salt".into()))?;
    let nonce =
        field_bytes("nonce").ok_or_else(|| EpochKeyStoreError::Format("missing nonce".into()))?;
    if nonce.len() != 12 {
        return Err(EpochKeyStoreError::Format(format!(
            "nonce: expected 12 bytes, got {}",
            nonce.len()
        )));
    }
    let ct =
        field_bytes("blob").ok_or_else(|| EpochKeyStoreError::Format("missing blob".into()))?;
    // KDF parameters ride in the blob so a future bump needs no new
    // version — same design as `identity_store`'s v=3.
    let (dm, dt, dp) = crate::identity_store::SHARED_KDF_PARAMS;
    let m_cost_kib = field_u32("m_cost").unwrap_or(dm);
    let t_cost = field_u32("t_cost").unwrap_or(dt);
    let p_cost = field_u32("p_cost").unwrap_or(dp);

    let pass = std::env::var(crate::identity_store::PASSPHRASE_ENV)
        .map(Zeroizing::new)
        .map_err(|_| {
            EpochKeyStoreError::Crypto(format!(
                "epoch-key store is encrypted but {} is not set",
                crate::identity_store::PASSPHRASE_ENV
            ))
        })?;

    let mut key = crate::identity_store::derive_argon2id_key(
        pass.as_bytes(),
        &salt,
        m_cost_kib,
        t_cost,
        p_cost,
    )
    .map_err(EpochKeyStoreError::Crypto)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|e| EpochKeyStoreError::Crypto(format!("decrypt: {e}")))?;
    key.zeroize();
    Ok(Zeroizing::new(plaintext))
}

fn save(path: &Path, store: &EpochKeyStore) -> Result<(), EpochKeyStoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    }

    let mut peer_entries: Vec<CborValue> = Vec::with_capacity(store.peer_releases.len());
    for (peer, entry) in store.peer_releases.iter() {
        peer_entries.push(CborValue::Array(vec![
            CborValue::Text(peer.clone()),
            CborValue::Integer(i128_from_u64(entry.epoch_id)),
            CborValue::Bytes(entry.key.to_vec()),
            CborValue::Integer(i128_from_u64(entry.expires_at)),
        ]));
    }

    let payload = CborValue::Map(vec![
        (
            CborValue::Text("v".into()),
            CborValue::Integer(VERSION_V1.into()),
        ),
        (
            CborValue::Text("kem_x_sk".into()),
            CborValue::Bytes(store.kem_secret.x_sk.to_vec()),
        ),
        (
            CborValue::Text("kem_mlkem_seed".into()),
            CborValue::Bytes(store.kem_secret.mlkem_seed.to_vec()),
        ),
        (
            CborValue::Text("my_epoch_id".into()),
            CborValue::Integer(i128_from_u64(store.my_epoch.0)),
        ),
        (
            CborValue::Text("my_epoch_key".into()),
            CborValue::Bytes(store.my_epoch.1.to_vec()),
        ),
        (
            CborValue::Text("peer_releases".into()),
            CborValue::Array(peer_entries),
        ),
    ]);

    // **M-3** — the plaintext record above is the *inner* payload. It is
    // wrapped below whenever a passphrase is available, and never
    // touches disk in this form when one is.
    let mut inner = Vec::new();
    ciborium::into_writer(&payload, &mut inner)
        .map_err(|e| EpochKeyStoreError::Cbor(e.to_string()))?;
    let mut inner = Zeroizing::new(inner);

    // `was_encrypted` drives the sticky-marker write below.
    let (buf, was_encrypted) = seal_payload(path, &inner)?;
    inner.zeroize();

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    tmp.write_all(&buf)
        .map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    tmp.flush()
        .map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    }
    // AUDIT-2026-06-11 #35: apply the owner-only restriction on the
    // tempfile before the rename (Unix 0o600 + Windows protected DACL)
    // so the hybrid-KEM secret file is ACL-restricted on Windows like
    // the other secret stores (identity_store / domain_store), not just
    // chmod'd on Unix.
    crate::file_acl::restrict_to_owner(tmp.path());
    tmp.persist(path)
        .map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    // Re-apply on the final path: NamedTempFile::persist preserves perms
    // on Unix, but mirror identity_store/domain_store which harden the
    // post-rename path too (defensive on platforms where persist resets).
    crate::file_acl::restrict_to_owner(path);

    // **M-3** — drop the sticky marker once an encrypted blob is on
    // disk, so a later save with the passphrase cleared cannot silently
    // downgrade this file to plaintext. Only ever created, never removed.
    if was_encrypted {
        let marker = encrypted_marker_path(path);
        if !marker.exists() {
            let _ = std::fs::write(&marker, []);
            crate::file_acl::restrict_to_owner(&marker);
        }
    }
    Ok(())
}

fn load(path: &Path) -> Result<EpochKeyStore, EpochKeyStoreError> {
    let bytes = std::fs::read(path).map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    if bytes.is_empty() {
        return Err(EpochKeyStoreError::Format("empty file".into()));
    }
    // **M-3** — transparently unwrap the v=2 passphrase envelope; v=1
    // plaintext records pass through unchanged.
    let bytes = unseal_payload(&bytes)?;
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| EpochKeyStoreError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| EpochKeyStoreError::Format("not a map".into()))?;

    let mut version: Option<i64> = None;
    let mut kem_x_sk: Option<Vec<u8>> = None;
    let mut kem_mlkem_seed: Option<Vec<u8>> = None;
    let mut my_epoch_id: Option<u64> = None;
    let mut my_epoch_key: Option<Vec<u8>> = None;
    let mut peer_releases: Option<Vec<CborValue>> = None;
    for (k, v) in map.iter() {
        match k.as_text() {
            Some("v") => {
                version = v.as_integer().and_then(|i| i64::try_from(i).ok());
            }
            Some("kem_x_sk") => {
                kem_x_sk = v.as_bytes().cloned();
            }
            Some("kem_mlkem_seed") => {
                kem_mlkem_seed = v.as_bytes().cloned();
            }
            Some("my_epoch_id") => {
                my_epoch_id = v.as_integer().and_then(|i| i128::from(i).try_into().ok());
            }
            Some("my_epoch_key") => {
                my_epoch_key = v.as_bytes().cloned();
            }
            Some("peer_releases") => {
                peer_releases = v.as_array().cloned();
            }
            _ => {}
        }
    }
    let version = version.ok_or_else(|| EpochKeyStoreError::Format("missing v".into()))?;
    if version != VERSION_V1 {
        return Err(EpochKeyStoreError::Format(format!(
            "unsupported version: {version} (expected {VERSION_V1})"
        )));
    }
    let x_sk_bytes =
        kem_x_sk.ok_or_else(|| EpochKeyStoreError::Format("missing kem_x_sk".into()))?;
    if x_sk_bytes.len() != X25519_KEY_LEN {
        return Err(EpochKeyStoreError::Format(format!(
            "kem_x_sk: expected {X25519_KEY_LEN} bytes, got {}",
            x_sk_bytes.len()
        )));
    }
    let seed_bytes = kem_mlkem_seed
        .ok_or_else(|| EpochKeyStoreError::Format("missing kem_mlkem_seed".into()))?;
    if seed_bytes.len() != MLKEM768_SEED_LEN {
        return Err(EpochKeyStoreError::Format(format!(
            "kem_mlkem_seed: expected {MLKEM768_SEED_LEN} bytes, got {}",
            seed_bytes.len()
        )));
    }
    let my_epoch_id =
        my_epoch_id.ok_or_else(|| EpochKeyStoreError::Format("missing my_epoch_id".into()))?;
    let my_key_bytes =
        my_epoch_key.ok_or_else(|| EpochKeyStoreError::Format("missing my_epoch_key".into()))?;
    if my_key_bytes.len() != EPOCH_KEY_LEN {
        return Err(EpochKeyStoreError::Format(format!(
            "my_epoch_key: expected {EPOCH_KEY_LEN} bytes, got {}",
            my_key_bytes.len()
        )));
    }
    let peer_release_array =
        peer_releases.ok_or_else(|| EpochKeyStoreError::Format("missing peer_releases".into()))?;

    let mut x_sk = [0u8; X25519_KEY_LEN];
    x_sk.copy_from_slice(&x_sk_bytes);
    let mut mlkem_seed = [0u8; MLKEM768_SEED_LEN];
    mlkem_seed.copy_from_slice(&seed_bytes);
    let kem_secret = HybridKemSecretKey { x_sk, mlkem_seed };
    let kem_public = public_from_secret(&kem_secret);

    let mut my_epoch_key_arr = [0u8; EPOCH_KEY_LEN];
    my_epoch_key_arr.copy_from_slice(&my_key_bytes);

    let mut peer_releases_map: BTreeMap<String, PeerReleaseEntry> = BTreeMap::new();
    for entry in peer_release_array {
        let arr = entry
            .as_array()
            .ok_or_else(|| EpochKeyStoreError::Format("peer entry not array".into()))?;
        if arr.len() != 4 {
            return Err(EpochKeyStoreError::Format(format!(
                "peer entry: expected 4 elements, got {}",
                arr.len()
            )));
        }
        let publisher = arr[0]
            .as_text()
            .ok_or_else(|| EpochKeyStoreError::Format("peer publisher not text".into()))?
            .to_string();
        let epoch_id: u64 = arr[1]
            .as_integer()
            .and_then(|i| i128::from(i).try_into().ok())
            .ok_or_else(|| EpochKeyStoreError::Format("peer epoch_id not u64".into()))?;
        let key_bytes = arr[2]
            .as_bytes()
            .ok_or_else(|| EpochKeyStoreError::Format("peer key not bytes".into()))?;
        if key_bytes.len() != EPOCH_KEY_LEN {
            return Err(EpochKeyStoreError::Format(format!(
                "peer key: expected {EPOCH_KEY_LEN} bytes, got {}",
                key_bytes.len()
            )));
        }
        let expires_at: u64 = arr[3]
            .as_integer()
            .and_then(|i| i128::from(i).try_into().ok())
            .ok_or_else(|| EpochKeyStoreError::Format("peer expires_at not u64".into()))?;
        let mut key = [0u8; EPOCH_KEY_LEN];
        key.copy_from_slice(key_bytes);
        peer_releases_map.insert(
            publisher,
            PeerReleaseEntry {
                epoch_id,
                key,
                expires_at,
            },
        );
    }

    Ok(EpochKeyStore {
        kem_secret,
        kem_public,
        my_epoch: (my_epoch_id, my_epoch_key_arr),
        previous_my_epoch: None,
        peer_releases: peer_releases_map,
        peer_grace: BTreeMap::new(),
    })
}

fn i128_from_u64(v: u64) -> ciborium::value::Integer {
    ciborium::value::Integer::from(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::time::Duration;
    use tempfile::tempdir;

    fn fresh_key() -> [u8; EPOCH_KEY_LEN] {
        let mut k = [0u8; EPOCH_KEY_LEN];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut k);
        k
    }

    #[test]
    fn new_seeds_first_epoch_at_one() {
        let mut rng = OsRng;
        let store = EpochKeyStore::new(&mut rng);
        let (id, _) = store.my_current_epoch();
        assert_eq!(id, 1);
        assert_eq!(store.peer_release_count(), 0);
        assert_eq!(store.grace_count(), 0);
        // KEM public matches the derived form of the secret —
        // pinning the bootstrap invariant.
        let derived = public_from_secret(store.kem_secret());
        assert_eq!(store.kem_public(), &derived);
    }

    #[test]
    fn rotate_my_epoch_bumps_id_and_moves_old_to_grace() {
        let mut rng = OsRng;
        let mut store = EpochKeyStore::new(&mut rng);
        let (id_0, key_0) = {
            let (i, k) = store.my_current_epoch();
            (i, *k)
        };
        let id_1 = store.rotate_my_epoch(&mut rng);
        assert_eq!(id_1, id_0 + 1);

        // Lookup by old epoch_id still resolves (grace cache).
        let recovered = store.my_epoch_key(id_0).expect("grace");
        assert_eq!(recovered, &key_0);

        // Lookup by new epoch_id resolves to a distinct key.
        let new_key = store.my_epoch_key(id_1).expect("current");
        assert_ne!(new_key, &key_0);
    }

    #[test]
    fn install_peer_release_inserts_then_rotates() {
        let mut rng = OsRng;
        let mut store = EpochKeyStore::new(&mut rng);

        let k1 = fresh_key();
        assert_eq!(
            store.install_peer_release("12D3KooWPub", 1, k1, 100),
            InstallOutcome::Inserted
        );
        assert_eq!(store.peer_epoch_key("12D3KooWPub", 1), Some(&k1));

        // Same epoch — no-op.
        assert_eq!(
            store.install_peer_release("12D3KooWPub", 1, k1, 100),
            InstallOutcome::AlreadyCurrent
        );

        // Newer epoch — rotation, old goes to grace.
        let k2 = fresh_key();
        assert_eq!(
            store.install_peer_release("12D3KooWPub", 2, k2, 200),
            InstallOutcome::Rotated
        );
        // Current is k2.
        assert_eq!(store.peer_epoch_key("12D3KooWPub", 2), Some(&k2));
        // Old is in grace.
        assert_eq!(store.peer_epoch_key("12D3KooWPub", 1), Some(&k1));
        assert_eq!(store.grace_count(), 1);
    }

    #[test]
    fn install_stale_release_is_ignored() {
        let mut rng = OsRng;
        let mut store = EpochKeyStore::new(&mut rng);
        let k_new = fresh_key();
        store.install_peer_release("12D3KooWPub", 5, k_new, 100);

        let k_old = fresh_key();
        let outcome = store.install_peer_release("12D3KooWPub", 3, k_old, 50);
        assert_eq!(outcome, InstallOutcome::Stale);
        // Cache still holds the newer key only.
        assert_eq!(store.peer_epoch_key("12D3KooWPub", 5), Some(&k_new));
        assert_eq!(store.peer_epoch_key("12D3KooWPub", 3), None);
    }

    #[test]
    fn remove_peer_drops_current_release() {
        let mut rng = OsRng;
        let mut store = EpochKeyStore::new(&mut rng);
        let k = fresh_key();
        store.install_peer_release("12D3KooWPub", 1, k, 100);
        let removed = store.remove_peer("12D3KooWPub").expect("entry was present");
        assert_eq!(removed.key, k);
        assert!(store.peer_epoch_key("12D3KooWPub", 1).is_none());
    }

    #[test]
    fn prune_grace_drops_expired_entries() {
        let mut rng = OsRng;
        let mut store = EpochKeyStore::new(&mut rng);
        // Rotate so we have a `previous_my_epoch` grace entry.
        store.rotate_my_epoch(&mut rng);
        let (_, _) = store.my_current_epoch();
        // Install + rotate a peer to seed the peer grace cache.
        let k1 = fresh_key();
        store.install_peer_release("12D3KooWPub", 1, k1, 100);
        let k2 = fresh_key();
        store.install_peer_release("12D3KooWPub", 2, k2, 200);
        assert_eq!(store.grace_count(), 2); // mine + peer

        // Backdate the grace entries by extending `now` past the grace
        // window. We pass a future `now` rather than sleeping.
        let future = Instant::now() + Duration::from_secs(EPOCH_KEY_GRACE_SECS + 1);
        let pruned = store.prune_grace(future);
        assert_eq!(pruned, 2);
        assert_eq!(store.grace_count(), 0);
    }

    #[test]
    fn save_then_load_roundtrip_preserves_kem_and_releases() {
        // M-3: save/load now consult `DDS_NODE_PASSPHRASE` and
        // `DDS_REQUIRE_ENCRYPTED_KEYS`, which are process-global. Take
        // the shared env lock (and start from a clean slate) so a
        // concurrently-running encryption test can't leak a passphrase
        // into this plaintext round-trip.
        let _g = env_guard();
        clear_env();
        let mut rng = OsRng;
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");

        let mut store = EpochKeyStore::new(&mut rng);
        let k_pub_a = fresh_key();
        let k_pub_b = fresh_key();
        store.install_peer_release("12D3KooWPubA", 7, k_pub_a, 1_000);
        store.install_peer_release("12D3KooWPubB", 9, k_pub_b, 2_000);
        store.save(&path).unwrap();

        let loaded = EpochKeyStore::load_or_create(&path, &mut rng).unwrap();
        // KEM keypair survives.
        assert_eq!(
            loaded.kem_secret().x_sk,
            store.kem_secret().x_sk,
            "x_sk preserved across save/load"
        );
        assert_eq!(
            loaded.kem_secret().mlkem_seed,
            store.kem_secret().mlkem_seed,
            "mlkem_seed preserved across save/load"
        );
        // Derived public matches.
        assert_eq!(loaded.kem_public(), store.kem_public());
        // my_epoch survives.
        assert_eq!(loaded.my_current_epoch().0, store.my_current_epoch().0);
        assert_eq!(loaded.my_current_epoch().1, store.my_current_epoch().1);
        // Peer releases survive.
        assert_eq!(loaded.peer_release_count(), 2);
        assert_eq!(loaded.peer_epoch_key("12D3KooWPubA", 7), Some(&k_pub_a));
        assert_eq!(loaded.peer_epoch_key("12D3KooWPubB", 9), Some(&k_pub_b));
        // Grace cache is process-scoped — fresh on load.
        assert_eq!(loaded.grace_count(), 0);
    }

    #[test]
    fn load_or_create_generates_when_missing() {
        let mut rng = OsRng;
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.cbor");
        let store = EpochKeyStore::load_or_create(&path, &mut rng).unwrap();
        // Bootstrap path returns a fresh epoch_id=1 store.
        assert_eq!(store.my_current_epoch().0, 1);
        // And does NOT touch disk on the bootstrap path — the caller
        // must save() if they want persistence.
        assert!(!path.exists());
    }

    #[test]
    fn load_rejects_garbage_bytes() {
        let _g = env_guard();
        clear_env();
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        std::fs::write(&path, b"not cbor at all").unwrap();
        let mut rng = OsRng;
        let err = EpochKeyStore::load_or_create(&path, &mut rng).unwrap_err();
        assert!(matches!(
            err,
            EpochKeyStoreError::Cbor(_) | EpochKeyStoreError::Format(_)
        ));
    }

    #[test]
    fn load_rejects_unknown_version() {
        let _g = env_guard();
        clear_env();
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let payload = CborValue::Map(vec![
            (CborValue::Text("v".into()), CborValue::Integer(99.into())),
            (
                CborValue::Text("kem_x_sk".into()),
                CborValue::Bytes(vec![0u8; X25519_KEY_LEN]),
            ),
            (
                CborValue::Text("kem_mlkem_seed".into()),
                CborValue::Bytes(vec![0u8; MLKEM768_SEED_LEN]),
            ),
            (
                CborValue::Text("my_epoch_id".into()),
                CborValue::Integer(1.into()),
            ),
            (
                CborValue::Text("my_epoch_key".into()),
                CborValue::Bytes(vec![0u8; EPOCH_KEY_LEN]),
            ),
            (
                CborValue::Text("peer_releases".into()),
                CborValue::Array(vec![]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();
        let mut rng = OsRng;
        let err = EpochKeyStore::load_or_create(&path, &mut rng).unwrap_err();
        assert!(matches!(err, EpochKeyStoreError::Format(_)));
    }

    #[test]
    fn load_rejects_wrong_length_kem_secret() {
        let _g = env_guard();
        clear_env();
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let payload = CborValue::Map(vec![
            (CborValue::Text("v".into()), CborValue::Integer(1.into())),
            // Wrong length on x_sk — should bounce.
            (
                CborValue::Text("kem_x_sk".into()),
                CborValue::Bytes(vec![0u8; X25519_KEY_LEN - 1]),
            ),
            (
                CborValue::Text("kem_mlkem_seed".into()),
                CborValue::Bytes(vec![0u8; MLKEM768_SEED_LEN]),
            ),
            (
                CborValue::Text("my_epoch_id".into()),
                CborValue::Integer(1.into()),
            ),
            (
                CborValue::Text("my_epoch_key".into()),
                CborValue::Bytes(vec![0u8; EPOCH_KEY_LEN]),
            ),
            (
                CborValue::Text("peer_releases".into()),
                CborValue::Array(vec![]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();
        let mut rng = OsRng;
        let err = EpochKeyStore::load_or_create(&path, &mut rng).unwrap_err();
        assert!(matches!(err, EpochKeyStoreError::Format(_)));
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let _g = env_guard();
        clear_env();
        let mut rng = OsRng;
        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let store = EpochKeyStore::new(&mut rng);
        store.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }

    #[test]
    fn replay_window_admits_fresh_release() {
        let now = 1_700_000_000;
        // Same instant.
        assert!(is_release_within_replay_window(now, now));
        // Slightly old, well within window.
        assert!(is_release_within_replay_window(now - 60, now));
        // Right at the edge.
        assert!(is_release_within_replay_window(
            now - EPOCH_RELEASE_REPLAY_WINDOW_SECS,
            now
        ));
    }

    #[test]
    fn replay_window_rejects_stale_release() {
        let now = 1_700_000_000;
        // Just past the edge.
        assert!(!is_release_within_replay_window(
            now - EPOCH_RELEASE_REPLAY_WINDOW_SECS - 1,
            now
        ));
        // Way past — classic shelf-replay.
        assert!(!is_release_within_replay_window(0, now));
    }

    #[test]
    fn replay_window_admits_future_issued_at() {
        // A release with issued_at in the future is admitted by the
        // replay-window gate; the AEAD verify will reject if the
        // release was actually forged. Receiver-side clock-skew
        // handling lives at higher layers.
        let now = 1_700_000_000;
        assert!(is_release_within_replay_window(now + 60, now));
    }

    #[test]
    fn end_to_end_kem_encap_decap_via_store_secret() {
        // Pin the contract that the store's kem_secret round-trips
        // through `kem::encap` against `kem_public`. Caller-facing
        // proof that `EpochKeyStore::new` produces a usable keypair.
        let mut rng = OsRng;
        let store = EpochKeyStore::new(&mut rng);
        let binding = b"unit-test-binding";
        let (ct, ss_send) =
            dds_core::crypto::kem::encap(&mut rng, store.kem_public(), binding).unwrap();
        let ss_recv = dds_core::crypto::kem::decap(store.kem_secret(), &ct, binding).unwrap();
        assert_eq!(ss_send, ss_recv);
    }

    // ---- M-3: encrypted-at-rest -------------------------------------

    use crate::identity_store::{
        ALLOW_PLAINTEXT_DOWNGRADE_ENV, PASSPHRASE_ENV, REQUIRE_ENCRYPTED_KEYS_ENV,
    };

    /// Every test below mutates process-wide env vars, so they share the
    /// crate-wide lock with `identity_store` / `domain_store`.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn clear_env() {
        unsafe {
            std::env::remove_var(PASSPHRASE_ENV);
            std::env::remove_var(REQUIRE_ENCRYPTED_KEYS_ENV);
            std::env::remove_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV);
        }
    }

    /// **M-3** — with a passphrase set, the KEM secret and every epoch
    /// key must be absent from the on-disk bytes, and the file must
    /// still round-trip.
    #[test]
    fn m3_encrypted_roundtrip_hides_key_material() {
        let _g = env_guard();
        clear_env();
        unsafe { std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple") };

        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let mut rng = OsRng;
        let mut store = EpochKeyStore::new(&mut rng);
        let peer_key = fresh_key();
        store.install_peer_release("peer-a", 7, peer_key, u64::MAX);

        let (my_epoch_id, my_key) = {
            let (i, k) = store.my_current_epoch();
            (i, *k)
        };
        let x_sk = store.kem_secret().x_sk;
        let mlkem_seed = store.kem_secret().mlkem_seed;
        store.save(&path).expect("encrypted save");

        let raw = std::fs::read(&path).unwrap();
        let contains = |needle: &[u8]| raw.windows(needle.len()).any(|w| w == needle);
        assert!(
            !contains(&x_sk),
            "X25519 secret scalar must not appear in the ciphertext file"
        );
        assert!(
            !contains(&mlkem_seed),
            "ML-KEM seed must not appear in the ciphertext file"
        );
        assert!(
            !contains(&my_key),
            "local epoch key must not appear in the ciphertext file"
        );
        assert!(
            !contains(&peer_key),
            "cached peer epoch key must not appear in the ciphertext file"
        );

        let loaded = load(&path).expect("decrypt + parse");
        assert_eq!(loaded.my_current_epoch().0, my_epoch_id);
        assert_eq!(*loaded.my_current_epoch().1, my_key);
        assert_eq!(loaded.kem_secret().x_sk, x_sk);
        assert_eq!(loaded.kem_secret().mlkem_seed, mlkem_seed);
        assert_eq!(loaded.peer_epoch_key("peer-a", 7), Some(&peer_key));

        clear_env();
    }

    /// **M-3** — the wrong passphrase must fail loudly rather than
    /// yielding a garbage store.
    #[test]
    fn m3_wrong_passphrase_fails_closed() {
        let _g = env_guard();
        clear_env();
        unsafe { std::env::set_var(PASSPHRASE_ENV, "right") };

        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let mut rng = OsRng;
        EpochKeyStore::new(&mut rng).save(&path).unwrap();

        unsafe { std::env::set_var(PASSPHRASE_ENV, "wrong") };
        assert!(matches!(load(&path), Err(EpochKeyStoreError::Crypto(_))));

        // And with no passphrase at all.
        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        assert!(matches!(load(&path), Err(EpochKeyStoreError::Crypto(_))));

        clear_env();
    }

    /// **M-3** — `DDS_REQUIRE_ENCRYPTED_KEYS` must make a passphrase-less
    /// save fail instead of silently writing the hybrid-KEM secret in
    /// the clear. This is the gate the store had no notion of before.
    #[test]
    fn m3_require_encrypted_keys_refuses_plaintext_save() {
        let _g = env_guard();
        clear_env();
        unsafe { std::env::set_var(REQUIRE_ENCRYPTED_KEYS_ENV, "1") };

        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let mut rng = OsRng;
        let store = EpochKeyStore::new(&mut rng);
        let err = store
            .save(&path)
            .expect_err("plaintext save must be refused");
        assert!(matches!(err, EpochKeyStoreError::Crypto(_)), "got {err:?}");
        assert!(!path.exists(), "no file may be left behind on refusal");

        // With a passphrase the same save proceeds.
        unsafe { std::env::set_var(PASSPHRASE_ENV, "pass") };
        store
            .save(&path)
            .expect("encrypted save satisfies the gate");
        assert!(path.exists());

        clear_env();
    }

    /// **M-3** — a legacy plaintext (`v=1`) file still loads, and the
    /// next save with a passphrase transparently upgrades it to `v=2`.
    #[test]
    fn m3_legacy_plaintext_upgrades_on_next_save() {
        let _g = env_guard();
        clear_env();

        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let mut rng = OsRng;
        let store = EpochKeyStore::new(&mut rng);
        let x_sk = store.kem_secret().x_sk;
        // No passphrase → v=1 plaintext, as before this change.
        store.save(&path).expect("plaintext save");
        let raw_v1 = std::fs::read(&path).unwrap();
        assert!(
            raw_v1.windows(x_sk.len()).any(|w| w == x_sk),
            "sanity: the legacy format really is plaintext"
        );

        // Legacy file loads without a passphrase.
        let loaded = load(&path).expect("v=1 load");
        assert_eq!(loaded.kem_secret().x_sk, x_sk);

        // Save again with a passphrase → upgraded to v=2.
        unsafe { std::env::set_var(PASSPHRASE_ENV, "upgrade") };
        loaded.save(&path).expect("upgrade save");
        let raw_v2 = std::fs::read(&path).unwrap();
        assert!(
            !raw_v2.windows(x_sk.len()).any(|w| w == x_sk),
            "after upgrade the secret must no longer be on disk in the clear"
        );
        assert_eq!(load(&path).unwrap().kem_secret().x_sk, x_sk);

        clear_env();
    }

    /// **M-3** — once encrypted, clearing the passphrase must not
    /// silently roll the file back to plaintext.
    #[test]
    fn m3_sticky_marker_blocks_silent_plaintext_downgrade() {
        let _g = env_guard();
        clear_env();
        unsafe { std::env::set_var(PASSPHRASE_ENV, "sticky") };

        let dir = tempdir().unwrap();
        let path = dir.path().join("epoch_keys.cbor");
        let mut rng = OsRng;
        let store = EpochKeyStore::new(&mut rng);
        store.save(&path).unwrap();
        assert!(encrypted_marker_path(&path).exists(), "marker must be set");

        unsafe { std::env::remove_var(PASSPHRASE_ENV) };
        let err = store
            .save(&path)
            .expect_err("plaintext downgrade must be refused");
        assert!(matches!(err, EpochKeyStoreError::Crypto(_)), "got {err:?}");

        // Explicit operator override still works.
        unsafe { std::env::set_var(ALLOW_PLAINTEXT_DOWNGRADE_ENV, "1") };
        store.save(&path).expect("explicit downgrade is permitted");

        clear_env();
    }
}
