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
//! Plaintext on disk today (same posture as the Phase A
//! `domain_store` / `peer_cert_store`); the eventual encrypted-at-rest
//! tier rides the Z-4 plan. Atomic write via
//! `tempfile::NamedTempFile::new_in(parent)` + `tmp.persist(path)`
//! with `0o600` on Unix — mirrors the L-3 follow-on posture used by
//! `admission_revocation_store::save` and `peer_cert_store::save`.
//!
//! ## Threat-model footnote
//!
//! The KEM secret key is the load-bearing secret here: an attacker
//! with read access to `epoch_keys.cbor` can decap every
//! `EpochKeyRelease` ever sent to this node and recover every peer's
//! epoch key for the recorded epochs. The `0o600` posture +
//! `<data_dir>` umask defended by the L-3 tightening defends the
//! file at rest under OS ACLs only; the Z-4 encryption tier is what
//! makes this file rotate-safe under disk-image exfiltration.

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

#[derive(Debug)]
pub enum EpochKeyStoreError {
    Io(String),
    Cbor(String),
    Format(String),
}

impl std::fmt::Display for EpochKeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Cbor(e) => write!(f, "cbor: {e}"),
            Self::Format(e) => write!(f, "format: {e}"),
        }
    }
}

impl std::error::Error for EpochKeyStoreError {}

const VERSION_V1: i64 = 1;

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

    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .map_err(|e| EpochKeyStoreError::Cbor(e.to_string()))?;

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
    tmp.persist(path)
        .map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    Ok(())
}

fn load(path: &Path) -> Result<EpochKeyStore, EpochKeyStoreError> {
    let bytes = std::fs::read(path).map_err(|e| EpochKeyStoreError::Io(e.to_string()))?;
    if bytes.is_empty() {
        return Err(EpochKeyStoreError::Format("empty file".into()));
    }
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
}
