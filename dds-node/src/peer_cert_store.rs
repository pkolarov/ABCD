//! Local cache of remote nodes' [`AdmissionCert`]s, populated on every
//! successful H-12 admission handshake and persisted at
//! `<data_dir>/peer_certs.cbor`.
//!
//! **Z-1 Phase B.3.** Phase A's H-12 handshake already verified each
//! remote cert against the domain key, but did not retain the cert
//! body — only the remote `PeerId` was stored in `admitted_peers`.
//! Phase B needs the cert (specifically [`AdmissionCert::pq_kem_pubkey`])
//! to look up the publisher's hybrid KEM pubkey for `EpochKeyRelease`
//! decap binding (§4.6.2 of [`docs/pqc-phase-b-plan.md`]).
//!
//! ## Lifetime + integrity
//!
//! - **Insert.** Callers re-verify every cert under the live `Domain`
//!   *before* inserting (the H-12 verifier runs first); this store is
//!   a write-after-verify cache, not a trust anchor in itself.
//!   Re-inserting under the same `peer_id` overwrites the previous
//!   entry — necessary so a publisher's KEM-key rotation re-issues a
//!   fresh `AdmissionCert` and the cached entry tracks the new
//!   pubkey.
//! - **Disk format.** A single CBOR blob carrying a versioned
//!   `OnDiskV1` record. `version: 1` is the only shape today. The
//!   atomic-write idiom matches the `0o600` tempfile-rename pattern
//!   used by [`crate::admission_revocation_store::save`] (L-3
//!   follow-on); torn writes are impossible by construction.
//! - **No trust on load.** `load_or_empty` does not re-verify the
//!   cached certs — that is the live H-12 path's responsibility on
//!   each reconnect. A stale entry can only delay a freshly-issued
//!   cert by one handshake; it cannot admit a peer that is not
//!   currently re-verified.
//!
//! ## Storage budget
//!
//! For a 1000-peer hybrid v3 domain: each entry is ≈ 4.5 KB
//! (`AdmissionBody` ~80 B + Ed25519 sig 64 B + ML-DSA-65 sig 3309 B +
//! hybrid KEM pubkey 1216 B + framing). Worst case ≈ 4.5 MB on disk.
//! The Phase B plan (§4.6.2) calls this acceptable.

use std::collections::BTreeMap;
use std::path::Path;

use ciborium::value::Value as CborValue;
use dds_domain::AdmissionCert;

#[derive(Debug)]
pub enum PeerCertStoreError {
    Io(String),
    Cbor(String),
    Format(String),
}

impl std::fmt::Display for PeerCertStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Cbor(e) => write!(f, "cbor: {e}"),
            Self::Format(e) => write!(f, "format: {e}"),
        }
    }
}

impl std::error::Error for PeerCertStoreError {}

const VERSION_V1: i64 = 1;

/// In-memory cache keyed by stringified libp2p `PeerId`.
#[derive(Debug, Default, Clone)]
pub struct PeerCertStore {
    inner: BTreeMap<String, AdmissionCert>,
}

impl PeerCertStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or overwrite) the cert for `peer_id`. Returns the
    /// previously-cached cert, if any. Callers must verify the cert
    /// against the live `Domain` *before* calling `insert` — this
    /// helper is a passive cache, not a trust gate.
    pub fn insert(&mut self, peer_id: String, cert: AdmissionCert) -> Option<AdmissionCert> {
        self.inner.insert(peer_id, cert)
    }

    /// Look up the cached cert for `peer_id`. Returns `None` if no
    /// handshake has yet completed against this peer (or the cache
    /// has been pruned via [`Self::remove`]).
    pub fn get(&self, peer_id: &str) -> Option<&AdmissionCert> {
        self.inner.get(peer_id)
    }

    /// Drop the cached cert for `peer_id`. Used by the Phase A
    /// revocation path so a revoked peer's pubkey is forgotten as
    /// soon as the revocation is observed.
    pub fn remove(&mut self, peer_id: &str) -> Option<AdmissionCert> {
        self.inner.remove(peer_id)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over `(peer_id, cert)` pairs in ascending `peer_id`
    /// order (BTreeMap). Useful for the Phase B.4 epoch-key-release
    /// loop that emits one envelope per admitted peer.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &AdmissionCert)> {
        self.inner.iter()
    }

    /// Convenience: collect every cached `(peer_id, hybrid KEM pubkey)`
    /// pair for the publishers that already advertise a Phase-B KEM
    /// pubkey on their cert. Phase B.4 onward consumes this list to
    /// drive [`dds_core::crypto::kem::encap`].
    pub fn iter_kem_pubkeys(&self) -> impl Iterator<Item = (&String, &Vec<u8>)> {
        self.inner
            .iter()
            .filter_map(|(peer, cert)| cert.pq_kem_pubkey.as_ref().map(|pk| (peer, pk)))
    }

    pub fn save(&self, path: &Path) -> Result<(), PeerCertStoreError> {
        save(path, self)
    }

    pub fn load_or_empty(path: &Path) -> Result<Self, PeerCertStoreError> {
        load_or_empty(path)
    }
}

/// Read the on-disk cache. Returns an empty store if `path` does not
/// exist (first start, or the file was wiped). Returns
/// [`PeerCertStoreError::Cbor`] / [`PeerCertStoreError::Format`] on a
/// torn or version-mismatched file so a corrupted cache fails loud
/// rather than silently dropping cached pubkeys.
pub fn load_or_empty(path: &Path) -> Result<PeerCertStore, PeerCertStoreError> {
    if !path.exists() {
        return Ok(PeerCertStore::default());
    }
    let bytes = std::fs::read(path).map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    if bytes.is_empty() {
        return Ok(PeerCertStore::default());
    }
    let value: CborValue =
        ciborium::from_reader(&bytes[..]).map_err(|e| PeerCertStoreError::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| PeerCertStoreError::Format("not a map".into()))?;

    let mut version: Option<i64> = None;
    let mut entries: Option<Vec<CborValue>> = None;
    for (k, v) in map.iter() {
        match k.as_text() {
            Some("v") => {
                version = v.as_integer().and_then(|i| i64::try_from(i).ok());
            }
            Some("entries") => {
                entries = v.as_array().cloned();
            }
            _ => {}
        }
    }
    let version = version.ok_or_else(|| PeerCertStoreError::Format("missing v".into()))?;
    if version != VERSION_V1 {
        return Err(PeerCertStoreError::Format(format!(
            "unsupported version: {version} (expected {VERSION_V1})"
        )));
    }
    let entries = entries.ok_or_else(|| PeerCertStoreError::Format("missing entries".into()))?;

    let mut inner = BTreeMap::new();
    for entry in entries {
        let pair = entry
            .as_array()
            .ok_or_else(|| PeerCertStoreError::Format("entry not an array".into()))?;
        if pair.len() != 2 {
            return Err(PeerCertStoreError::Format(format!(
                "entry: expected 2 elements, got {}",
                pair.len()
            )));
        }
        let peer = pair[0]
            .as_text()
            .ok_or_else(|| PeerCertStoreError::Format("peer id not text".into()))?
            .to_string();
        let cert_bytes = pair[1]
            .as_bytes()
            .ok_or_else(|| PeerCertStoreError::Format("cert not bytes".into()))?;
        let cert = AdmissionCert::from_cbor(cert_bytes)
            .map_err(|e| PeerCertStoreError::Cbor(e.to_string()))?;
        inner.insert(peer, cert);
    }
    Ok(PeerCertStore { inner })
}

/// Atomically write the cache to disk via tempfile + rename, with
/// owner-only `0o600` permissions on Unix. Mirrors
/// [`crate::admission_revocation_store::save`]'s posture: cached
/// pubkeys are not secret per se but are inputs to KEM encapsulation,
/// so a torn or world-readable file would be a defence-in-depth
/// regression.
pub fn save(path: &Path, store: &PeerCertStore) -> Result<(), PeerCertStoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    }

    let mut entries: Vec<CborValue> = Vec::with_capacity(store.inner.len());
    for (peer, cert) in store.inner.iter() {
        let cert_bytes = cert
            .to_cbor()
            .map_err(|e| PeerCertStoreError::Cbor(e.to_string()))?;
        entries.push(CborValue::Array(vec![
            CborValue::Text(peer.clone()),
            CborValue::Bytes(cert_bytes),
        ]));
    }
    let payload = CborValue::Map(vec![
        (
            CborValue::Text("v".into()),
            CborValue::Integer(VERSION_V1.into()),
        ),
        (CborValue::Text("entries".into()), CborValue::Array(entries)),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .map_err(|e| PeerCertStoreError::Cbor(e.to_string()))?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    tmp.write_all(&buf)
        .map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    tmp.flush()
        .map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    }
    tmp.persist(path)
        .map_err(|e| PeerCertStoreError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dds_domain::DomainKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn issue_cert(peer_id: &str) -> AdmissionCert {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        key.issue_admission(peer_id.into(), 0, None)
    }

    fn issue_hybrid_cert_with_kem(peer_id: &str, kem_pk: Option<Vec<u8>>) -> AdmissionCert {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        key.issue_admission_with_kem(peer_id.into(), 0, None, kem_pk)
    }

    #[test]
    fn empty_store_round_trip_creates_no_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer_certs.cbor");
        // Loading from a non-existent path returns an empty store.
        let loaded = PeerCertStore::load_or_empty(&path).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer_certs.cbor");

        let mut store = PeerCertStore::new();
        let cert_a = issue_cert("12D3KooWPeerA");
        let cert_b = issue_cert("12D3KooWPeerB");
        store.insert("12D3KooWPeerA".into(), cert_a.clone());
        store.insert("12D3KooWPeerB".into(), cert_b.clone());
        store.save(&path).unwrap();

        let loaded = PeerCertStore::load_or_empty(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        let got_a = loaded.get("12D3KooWPeerA").expect("A present");
        let got_b = loaded.get("12D3KooWPeerB").expect("B present");
        assert_eq!(got_a.body, cert_a.body);
        assert_eq!(got_a.signature, cert_a.signature);
        assert_eq!(got_b.body, cert_b.body);
    }

    #[test]
    fn insert_overwrites_previous_entry() {
        let mut store = PeerCertStore::new();
        let cert_v1 = issue_cert("12D3KooWPeer");
        let cert_v2 = issue_cert("12D3KooWPeer");
        // Two issuances yield distinct signatures (and distinct PQ
        // signatures if hybrid).
        assert_ne!(cert_v1.signature, cert_v2.signature);

        let prev_none = store.insert("12D3KooWPeer".into(), cert_v1.clone());
        assert!(prev_none.is_none());
        let prev_some = store.insert("12D3KooWPeer".into(), cert_v2.clone());
        let prev = prev_some.expect("prev returned on overwrite");
        assert_eq!(prev.signature, cert_v1.signature);
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.get("12D3KooWPeer").unwrap().signature,
            cert_v2.signature
        );
    }

    #[test]
    fn remove_drops_entry() {
        let mut store = PeerCertStore::new();
        store.insert("peer".into(), issue_cert("peer"));
        assert_eq!(store.len(), 1);
        let removed = store.remove("peer");
        assert!(removed.is_some());
        assert!(store.is_empty());
        assert!(store.remove("peer").is_none());
    }

    #[test]
    fn iter_kem_pubkeys_filters_to_phase_b_entries() {
        // 1216-byte KEM pubkey shape — exact bytes are arbitrary at
        // this layer; dds-core validates the wire structure when the
        // pubkey is consumed for encap. The schema-layer length check
        // lives in `AdmissionCert::pq_kem_pubkey_validate`.
        let pk_bytes = vec![0u8; dds_domain::HYBRID_KEM_PUBKEY_LEN];
        let cert_with = issue_hybrid_cert_with_kem("12D3KooWWith", Some(pk_bytes.clone()));
        let cert_without = issue_hybrid_cert_with_kem("12D3KooWWithout", None);
        let mut store = PeerCertStore::new();
        store.insert("12D3KooWWith".into(), cert_with);
        store.insert("12D3KooWWithout".into(), cert_without);
        let with_kem: Vec<_> = store.iter_kem_pubkeys().collect();
        assert_eq!(with_kem.len(), 1);
        assert_eq!(with_kem[0].0, "12D3KooWWith");
        assert_eq!(with_kem[0].1, &pk_bytes);
    }

    #[test]
    fn save_then_load_preserves_pq_kem_pubkey() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer_certs.cbor");
        let pk_bytes = vec![0xabu8; dds_domain::HYBRID_KEM_PUBKEY_LEN];
        let mut store = PeerCertStore::new();
        store.insert(
            "12D3KooWHybrid".into(),
            issue_hybrid_cert_with_kem("12D3KooWHybrid", Some(pk_bytes.clone())),
        );
        store.save(&path).unwrap();

        let loaded = PeerCertStore::load_or_empty(&path).unwrap();
        let cert = loaded.get("12D3KooWHybrid").expect("hybrid entry");
        assert_eq!(cert.pq_kem_pubkey.as_ref().unwrap(), &pk_bytes);
        // Phase A pq_signature also survives the round-trip.
        assert!(cert.pq_signature.is_some());
    }

    #[test]
    fn load_rejects_garbage_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer_certs.cbor");
        std::fs::write(&path, b"not cbor at all").unwrap();
        let err = PeerCertStore::load_or_empty(&path).unwrap_err();
        // Either the CBOR parser rejects it (Cbor) or the CBOR-Value
        // shape inspector rejects it (Format) — both indicate the
        // corrupted-on-disk path is loud, not silent.
        assert!(matches!(
            err,
            PeerCertStoreError::Cbor(_) | PeerCertStoreError::Format(_)
        ));
    }

    #[test]
    fn load_rejects_unknown_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer_certs.cbor");
        let payload = CborValue::Map(vec![
            (CborValue::Text("v".into()), CborValue::Integer(99.into())),
            (CborValue::Text("entries".into()), CborValue::Array(vec![])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();
        let err = PeerCertStore::load_or_empty(&path).unwrap_err();
        assert!(matches!(err, PeerCertStoreError::Format(_)));
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer_certs.cbor");
        let mut store = PeerCertStore::new();
        store.insert("12D3KooWX".into(), issue_cert("12D3KooWX"));
        store.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600, got {mode:o}");
    }
}
