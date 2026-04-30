//! On-disk store for [`dds_domain::AdmissionRevocation`] entries.
//!
//! **Threat-model §1 — admission cert revocation list (open item #4).**
//! Without this store there was no mechanism to revoke a node's
//! admission once issued: a compromised node stayed admitted until the
//! domain key was rotated. This store gives admins a domain-signed
//! "deny list" that nodes consult during the H-12 admission handshake,
//! and that DdsNode itself consults at startup so a revoked node
//! refuses to (re)start.
//!
//! ## On-disk format
//!
//! `<data_dir>/admission_revocations.cbor` contains a CBOR-encoded
//! [`RevocationListV1`] — `{ v: 1, entries: [AdmissionRevocation, ...] }`.
//! Empty / missing file is equivalent to an empty list. Every entry is
//! verified against the domain pubkey on load; entries that fail
//! verification are dropped (with a warn log) so a tampered file is
//! gracefully degraded to "verified entries only".
//!
//! ## Distribution
//!
//! Two complementary paths:
//!
//! 1. **Admin-driven (`dds-node revoke-admission` + `import-revocation`)**
//!    — the admin issues a revocation against any node and the
//!    operator can ship the resulting CBOR file to other nodes
//!    out-of-band. This is the original v1 manual flow; it stays
//!    available as a "force-immediate" path for emergency rollouts.
//!
//! 2. **H-12 piggy-back (`AdmissionResponse.revocations`)** — every
//!    H-12 admission handshake also ships the local revocation list
//!    (capped at `dds_net::admission::MAX_REVOCATIONS_PER_RESPONSE =
//!    1024` entries per response). Receivers route the list through
//!    [`AdmissionRevocationStore::merge`], which verifies each entry
//!    against the domain pubkey before insertion, then atomically
//!    rewrites the on-disk file via [`save`] so the new entries
//!    survive restart. As neighbours reconnect they pull and re-fan
//!    so a single `revoke-admission` against any node propagates
//!    domain-wide on the order of a handshake round trip.
//!
//! Both paths share the same verification gate, so a malicious
//! admitted peer cannot forge or rewrite revocations — the worst it
//! can do on the gossip path is *omit* them, which is no worse than
//! an offline node under the manual flow.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use dds_domain::{AdmissionRevocation, Domain, DomainId};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// On-disk schema for the revocation list. The `v` discriminator is
/// reserved for future format bumps (e.g. once distribution is moved
/// off raw filesystem and onto gossip).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationListV1 {
    pub v: u8,
    pub entries: Vec<AdmissionRevocation>,
}

const SCHEMA_VERSION: u8 = 1;

#[derive(Debug)]
pub enum RevocationStoreError {
    Io(String),
    Cbor(String),
    Format(String),
    Verify(String),
}

impl std::fmt::Display for RevocationStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationStoreError::Io(e) => write!(f, "io: {e}"),
            RevocationStoreError::Cbor(e) => write!(f, "cbor: {e}"),
            RevocationStoreError::Format(e) => write!(f, "format: {e}"),
            RevocationStoreError::Verify(e) => write!(f, "verify: {e}"),
        }
    }
}

impl std::error::Error for RevocationStoreError {}

/// In-memory view of the revocation list. Built by
/// [`load_or_empty`]; updated in-place via [`Self::add`] or [`Self::merge`].
///
/// Every contained [`AdmissionRevocation`] has been verified against
/// the domain pubkey on insert — callers can trust `is_revoked` without
/// re-verifying signatures on every lookup.
///
/// **Z-1 Phase A** — when bound to a v2-hybrid domain via
/// [`Self::for_hybrid_domain`] / [`load_or_empty_with_pq`], the store
/// also enforces the ML-DSA-65 component on every inserted revocation;
/// v1 (Ed25519-only) revocations are rejected with `Verify`.
#[derive(Debug, Clone, Default)]
pub struct AdmissionRevocationStore {
    domain_id: Option<DomainId>,
    domain_pubkey: Option<[u8; 32]>,
    /// **Z-1 Phase A** — ML-DSA-65 public key (1,952 bytes) when the
    /// store is bound to a v2-hybrid domain. Routes verification
    /// through `AdmissionRevocation::verify_with_domain` instead of
    /// the v1 `verify`.
    domain_pq_pubkey: Option<Vec<u8>>,
    entries: Vec<AdmissionRevocation>,
    revoked_peer_ids: BTreeSet<String>,
}

impl AdmissionRevocationStore {
    /// Empty store, not yet bound to a domain. Used by tests and by
    /// the early-startup path before the domain pubkey is known.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Empty store bound to a v1 (Ed25519-only) domain. Subsequent
    /// `add` / `merge` calls will reject revocations that don't verify
    /// under this domain.
    pub fn for_domain(domain_id: DomainId, domain_pubkey: [u8; 32]) -> Self {
        Self {
            domain_id: Some(domain_id),
            domain_pubkey: Some(domain_pubkey),
            domain_pq_pubkey: None,
            entries: Vec::new(),
            revoked_peer_ids: BTreeSet::new(),
        }
    }

    /// **Z-1 Phase A** — empty store bound to a v2-hybrid domain.
    /// Inserts now require both the Ed25519 signature *and* the
    /// ML-DSA-65 `pq_signature` to verify; v1-only revocations are
    /// rejected.
    pub fn for_hybrid_domain(
        domain_id: DomainId,
        domain_pubkey: [u8; 32],
        pq_pubkey: Vec<u8>,
    ) -> Self {
        Self {
            domain_id: Some(domain_id),
            domain_pubkey: Some(domain_pubkey),
            domain_pq_pubkey: Some(pq_pubkey),
            entries: Vec::new(),
            revoked_peer_ids: BTreeSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[AdmissionRevocation] {
        &self.entries
    }

    /// True if `peer_id` (the libp2p PeerId string) appears in the list.
    /// O(log n) via the secondary index. Callers should treat a `true`
    /// return value as "refuse this peer" with no further checks needed.
    pub fn is_revoked(&self, peer_id: &str) -> bool {
        self.revoked_peer_ids.contains(peer_id)
    }

    /// Insert a new revocation after verifying its signature against
    /// the bound domain. Returns `Ok(true)` if the entry is new,
    /// `Ok(false)` if the same `(peer_id, signature)` pair was already
    /// present (idempotent).
    ///
    /// **Z-1 Phase A** — verification routes through
    /// `AdmissionRevocation::verify_with_domain`, which enforces the
    /// ML-DSA-65 component when the store is bound to a v2-hybrid
    /// domain.
    pub fn add(&mut self, rev: AdmissionRevocation) -> Result<bool, RevocationStoreError> {
        let (Some(id), Some(pk)) = (self.domain_id.as_ref(), self.domain_pubkey.as_ref()) else {
            return Err(RevocationStoreError::Format(
                "store is not bound to a domain — call for_domain or load_or_empty first".into(),
            ));
        };
        // Synthesize a Domain for the v2 verifier. `name` is unused by
        // verification and intentionally empty to avoid cloning a
        // string we don't need.
        let domain = Domain {
            name: String::new(),
            id: *id,
            pubkey: *pk,
            pq_pubkey: self.domain_pq_pubkey.clone(),
            // capabilities don't affect revocation verification.
            capabilities: Vec::new(),
        };
        rev.verify_with_domain(&domain)
            .map_err(|e| RevocationStoreError::Verify(e.to_string()))?;
        // Dedupe by (peer_id, signature). Two revocations with the same
        // peer_id but different signatures are kept separately so an
        // operator audit can see every issuance — they collapse into a
        // single "revoked" verdict via the secondary index.
        let already_present = self
            .entries
            .iter()
            .any(|e| e.body.peer_id == rev.body.peer_id && e.signature == rev.signature);
        if already_present {
            return Ok(false);
        }
        self.revoked_peer_ids.insert(rev.body.peer_id.clone());
        self.entries.push(rev);
        Ok(true)
    }

    /// Merge a list of revocations into this store. Each entry is
    /// verified individually; entries that fail are skipped with a
    /// warn log so a single bad entry does not block the rest. Returns
    /// the number of new entries actually inserted.
    pub fn merge(&mut self, list: RevocationListV1) -> usize {
        let mut added = 0usize;
        for rev in list.entries {
            match self.add(rev) {
                Ok(true) => added += 1,
                Ok(false) => {}
                Err(e) => warn!(error = %e, "skipping revocation that failed to verify"),
            }
        }
        added
    }

    pub fn to_list(&self) -> RevocationListV1 {
        RevocationListV1 {
            v: SCHEMA_VERSION,
            entries: self.entries.clone(),
        }
    }
}

/// Load the revocation list from `path`, validating every entry
/// against the domain pubkey. Missing file is treated as an empty
/// list. Entries that fail verification are dropped with a warn.
///
/// V1 shorthand for [`load_or_empty_with_pq`] — equivalent to calling
/// it with `pq_pubkey = None`.
pub fn load_or_empty(
    path: &Path,
    domain_id: DomainId,
    domain_pubkey: [u8; 32],
) -> Result<AdmissionRevocationStore, RevocationStoreError> {
    load_or_empty_with_pq(path, domain_id, domain_pubkey, None)
}

/// **Z-1 Phase A** — same as [`load_or_empty`] but optionally binds
/// the store to a v2-hybrid domain so `add` / `merge` enforce the
/// ML-DSA-65 component on every entry. Pass `pq_pubkey = None` for a
/// legacy Ed25519-only domain (identical to [`load_or_empty`]).
pub fn load_or_empty_with_pq(
    path: &Path,
    domain_id: DomainId,
    domain_pubkey: [u8; 32],
    pq_pubkey: Option<Vec<u8>>,
) -> Result<AdmissionRevocationStore, RevocationStoreError> {
    let mut store = match pq_pubkey {
        Some(pq) => AdmissionRevocationStore::for_hybrid_domain(domain_id, domain_pubkey, pq),
        None => AdmissionRevocationStore::for_domain(domain_id, domain_pubkey),
    };
    if !path.exists() {
        return Ok(store);
    }
    let bytes = std::fs::read(path).map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    if bytes.is_empty() {
        return Ok(store);
    }
    // Bounded depth: contents originate from `dds-node import-revocation`
    // (admin-supplied file) or H-12 piggy-back gossip (peer-supplied). The
    // outer wrapper is shallow; per-entry CBOR is decoded under the same
    // cap when the H-12 receive path calls `AdmissionRevocation::from_cbor`.
    // Security review I-6.
    let list: RevocationListV1 = dds_core::cbor_bounded::from_reader(&bytes[..])
        .map_err(|e| RevocationStoreError::Cbor(e.to_string()))?;
    if list.v != SCHEMA_VERSION {
        return Err(RevocationStoreError::Format(format!(
            "unsupported revocation list schema v{} (expected v{SCHEMA_VERSION})",
            list.v
        )));
    }
    let total = list.entries.len();
    let added = store.merge(list);
    if added < total {
        warn!(
            total,
            added,
            "loaded revocation list with {} entries that failed to verify",
            total - added
        );
    }
    Ok(store)
}

/// Atomically save the in-memory store to `path` as
/// [`RevocationListV1`]. On Unix, the file is written via tempfile +
/// rename with `0o600` so a crash mid-write cannot leave a torn or
/// world-readable file.
pub fn save(path: &Path, store: &AdmissionRevocationStore) -> Result<(), RevocationStoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    }
    let mut buf = Vec::new();
    ciborium::into_writer(&store.to_list(), &mut buf)
        .map_err(|e| RevocationStoreError::Cbor(e.to_string()))?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    tmp.write_all(&buf)
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    tmp.flush()
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    }
    tmp.persist(path)
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    Ok(())
}

/// Read a single CBOR-encoded [`AdmissionRevocation`] from disk.
/// Used by the CLI flow where the admin produces a single-revocation
/// file and the operator on each node imports it.
pub fn load_revocation_file(path: &Path) -> Result<AdmissionRevocation, RevocationStoreError> {
    let bytes = std::fs::read(path).map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    AdmissionRevocation::from_cbor(&bytes).map_err(|e| RevocationStoreError::Cbor(e.to_string()))
}

/// Write a single CBOR-encoded [`AdmissionRevocation`] to disk.
///
/// **L-3 (security review) follow-on (2026-04-29):** atomic via
/// `tempfile::NamedTempFile::new_in(parent)` + `tmp.persist(path)` so a
/// crash mid-write cannot leave a torn revocation file on disk — operators
/// distribute these out-of-band to other nodes (`dds-node revoke-admission
/// --out` writes through this helper) and a torn file would surface as a
/// CBOR decode failure on the receiving end. Mirrors the same idiom in
/// [`save`] above (and in `dds-node::domain_store::atomic_write_owner_only`)
/// minus the owner-only chmod, since revocations are public — they only
/// become enforceable once a node loads them.
pub fn save_revocation_file(
    path: &Path,
    rev: &AdmissionRevocation,
) -> Result<(), RevocationStoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    }
    let bytes = rev
        .to_cbor()
        .map_err(|e| RevocationStoreError::Cbor(e.to_string()))?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    tmp.write_all(&bytes)
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    tmp.flush()
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    tmp.persist(path)
        .map_err(|e| RevocationStoreError::Io(e.to_string()))?;
    Ok(())
}

/// Convenience: append a single revocation file produced by the CLI
/// into the local store at `<data_dir>/admission_revocations.cbor`.
/// Used by `dds-node import-revocation` and tests. Returns `true` if
/// the entry was new, `false` if already present.
///
/// V1 shorthand for [`import_into_with_pq`] — equivalent to calling
/// it with `pq_pubkey = None`.
pub fn import_into(
    list_path: &Path,
    rev_path: &Path,
    domain_id: DomainId,
    domain_pubkey: [u8; 32],
) -> Result<(bool, PathBuf), RevocationStoreError> {
    import_into_with_pq(list_path, rev_path, domain_id, domain_pubkey, None)
}

/// **Z-1 Phase A** — same as [`import_into`] but routes through the
/// hybrid-aware loader so a v2-hybrid domain enforces the ML-DSA-65
/// component on the imported revocation.
pub fn import_into_with_pq(
    list_path: &Path,
    rev_path: &Path,
    domain_id: DomainId,
    domain_pubkey: [u8; 32],
    pq_pubkey: Option<Vec<u8>>,
) -> Result<(bool, PathBuf), RevocationStoreError> {
    let mut store = load_or_empty_with_pq(list_path, domain_id, domain_pubkey, pq_pubkey)?;
    let rev = load_revocation_file(rev_path)?;
    let added = store.add(rev)?;
    save(list_path, &store)?;
    Ok((added, list_path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dds_domain::DomainKey;
    use rand::rngs::OsRng;
    use tempfile::tempdir;

    fn fresh_domain() -> (DomainKey, DomainId, [u8; 32]) {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let d = key.domain();
        (key, d.id, d.pubkey)
    }

    #[test]
    fn empty_store_reports_no_revocations() {
        let (_k, id, pk) = fresh_domain();
        let s = AdmissionRevocationStore::for_domain(id, pk);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.is_revoked("12D3KooWAny"));
    }

    #[test]
    fn add_marks_peer_revoked() {
        let (k, id, pk) = fresh_domain();
        let mut s = AdmissionRevocationStore::for_domain(id, pk);
        let rev = k.revoke_admission("peer-A".into(), 100, Some("test".into()));
        assert!(s.add(rev).unwrap());
        assert!(s.is_revoked("peer-A"));
        assert!(!s.is_revoked("peer-B"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn add_is_idempotent_for_same_signature() {
        let (k, id, pk) = fresh_domain();
        let mut s = AdmissionRevocationStore::for_domain(id, pk);
        let rev = k.revoke_admission("peer-A".into(), 100, None);
        assert!(s.add(rev.clone()).unwrap());
        assert!(!s.add(rev).unwrap()); // second insert returns false
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn add_rejects_wrong_domain() {
        let (_a, _aid, _apk) = fresh_domain();
        let (b, bid, bpk) = fresh_domain();
        let mut s = AdmissionRevocationStore::for_domain(bid, bpk);
        // Issue under domain a, then try to inject into store bound to b.
        let foreign =
            DomainKey::generate("globex.com", &mut OsRng).revoke_admission("peer".into(), 0, None);
        assert!(s.add(foreign).is_err());
        assert!(s.is_empty());
        // sanity: a revocation under b's key is still accepted.
        let ok = b.revoke_admission("peer".into(), 0, None);
        assert!(s.add(ok).unwrap());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let (k, id, pk) = fresh_domain();
        let mut s = AdmissionRevocationStore::for_domain(id, pk);
        s.add(k.revoke_admission("peer-1".into(), 100, None))
            .unwrap();
        s.add(k.revoke_admission("peer-2".into(), 200, Some("decommissioned".into())))
            .unwrap();

        let dir = tempdir().unwrap();
        let path = dir.path().join("admission_revocations.cbor");
        save(&path, &s).unwrap();

        let loaded = load_or_empty(&path, id, pk).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.is_revoked("peer-1"));
        assert!(loaded.is_revoked("peer-2"));
        assert!(!loaded.is_revoked("peer-3"));
    }

    #[test]
    fn load_or_empty_returns_empty_when_file_missing() {
        let (_k, id, pk) = fresh_domain();
        let dir = tempdir().unwrap();
        let path = dir.path().join("does-not-exist.cbor");
        let s = load_or_empty(&path, id, pk).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn load_drops_entries_that_fail_to_verify() {
        // Write a list whose entries are signed by a foreign domain,
        // then load it under our domain pubkey — every entry should
        // be dropped, but the load itself should succeed.
        let (_k, id, pk) = fresh_domain();
        let foreign = DomainKey::generate("evil.com", &mut OsRng);
        let bad_rev = foreign.revoke_admission("peer-evil".into(), 0, None);
        let list = RevocationListV1 {
            v: SCHEMA_VERSION,
            entries: vec![bad_rev],
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("revocations.cbor");
        let mut buf = Vec::new();
        ciborium::into_writer(&list, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let loaded = load_or_empty(&path, id, pk).unwrap();
        assert!(loaded.is_empty());
        assert!(!loaded.is_revoked("peer-evil"));
    }

    #[test]
    fn load_rejects_wrong_schema_version() {
        let (_k, id, pk) = fresh_domain();
        let list = RevocationListV1 {
            v: 99,
            entries: Vec::new(),
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("revocations.cbor");
        let mut buf = Vec::new();
        ciborium::into_writer(&list, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();
        assert!(load_or_empty(&path, id, pk).is_err());
    }

    #[test]
    fn import_into_appends_to_existing_list() {
        let (k, id, pk) = fresh_domain();
        let dir = tempdir().unwrap();
        let list_path = dir.path().join("admission_revocations.cbor");
        let rev_path = dir.path().join("rev1.cbor");

        // Create a single-revocation file and import it.
        let rev = k.revoke_admission("peer-1".into(), 100, None);
        save_revocation_file(&rev_path, &rev).unwrap();
        let (added, _) = import_into(&list_path, &rev_path, id, pk).unwrap();
        assert!(added);
        let loaded = load_or_empty(&list_path, id, pk).unwrap();
        assert!(loaded.is_revoked("peer-1"));

        // Re-importing the same file is idempotent.
        let (added2, _) = import_into(&list_path, &rev_path, id, pk).unwrap();
        assert!(!added2);
        let loaded = load_or_empty(&list_path, id, pk).unwrap();
        assert_eq!(loaded.len(), 1);

        // A second, distinct revocation is appended.
        let rev2_path = dir.path().join("rev2.cbor");
        let rev2 = k.revoke_admission("peer-2".into(), 200, Some("rotated".into()));
        save_revocation_file(&rev2_path, &rev2).unwrap();
        let (added3, _) = import_into(&list_path, &rev2_path, id, pk).unwrap();
        assert!(added3);
        let loaded = load_or_empty(&list_path, id, pk).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.is_revoked("peer-2"));
    }

    #[test]
    fn save_then_load_empty_store_roundtrip() {
        let (_k, id, pk) = fresh_domain();
        let s = AdmissionRevocationStore::for_domain(id, pk);
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.cbor");
        save(&path, &s).unwrap();
        let loaded = load_or_empty(&path, id, pk).unwrap();
        assert!(loaded.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (k, id, pk) = fresh_domain();
        let mut s = AdmissionRevocationStore::for_domain(id, pk);
        s.add(k.revoke_admission("peer".into(), 0, None)).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("revocations.cbor");
        save(&path, &s).unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    /// **L-3 follow-on (2026-04-29)**: `save_revocation_file` writes through
    /// `tempfile::NamedTempFile::new_in` + `persist`, so a successful call
    /// (a) leaves no `.tmp*` siblings in the parent dir, (b) round-trips
    /// the revocation through `load_revocation_file` byte-for-byte, and
    /// (c) is overwrite-safe across two consecutive saves on the same
    /// path. Pins the docstring's atomicity claim that the prior
    /// `std::fs::write` implementation silently violated.
    #[test]
    fn save_revocation_file_is_atomic_and_overwrite_safe() {
        let (k, _id, _pk) = fresh_domain();
        let dir = tempdir().unwrap();
        let path = dir.path().join("rev.cbor");

        let rev1 = k.revoke_admission("peer-1".into(), 100, None);
        save_revocation_file(&path, &rev1).unwrap();

        // No tempfile leftovers from the persist step.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "rev.cbor")
            .collect();
        assert!(
            leftovers.is_empty(),
            "tempfile leaked into parent dir: {leftovers:?}"
        );

        let loaded = load_revocation_file(&path).unwrap();
        assert_eq!(loaded.body.peer_id, rev1.body.peer_id);
        assert_eq!(loaded.body.revoked_at, rev1.body.revoked_at);

        // Overwrite with a different revocation; both the rename and the
        // load must succeed and pick up the *new* contents.
        let rev2 = k.revoke_admission("peer-2".into(), 200, Some("decom".into()));
        save_revocation_file(&path, &rev2).unwrap();
        let loaded2 = load_revocation_file(&path).unwrap();
        assert_eq!(loaded2.body.peer_id, "peer-2");
        assert_eq!(loaded2.body.reason.as_deref(), Some("decom"));
    }

    // -----------------------------------------------------------------
    // Z-1 Phase A — v2-hybrid store enforcement
    // -----------------------------------------------------------------

    fn fresh_hybrid_domain() -> (DomainKey, DomainId, [u8; 32], Vec<u8>) {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let d = key.domain();
        let pq_pk = d.pq_pubkey.clone().expect("hybrid pq_pubkey");
        (key, d.id, d.pubkey, pq_pk)
    }

    /// A hybrid-bound store accepts a v2-signed revocation (the one
    /// that carries `pq_signature`) and surfaces `is_revoked` for
    /// it. Sanity baseline before the negative tests below.
    #[test]
    fn hybrid_store_accepts_hybrid_revocation() {
        let (key, id, pk, pq_pk) = fresh_hybrid_domain();
        let mut s = AdmissionRevocationStore::for_hybrid_domain(id, pk, pq_pk);
        let rev = key.revoke_admission("peer-A".into(), 100, None);
        assert!(rev.pq_signature.is_some());
        assert!(s.add(rev).unwrap());
        assert!(s.is_revoked("peer-A"));
    }

    /// **The store-side Phase A gate.** A hybrid-bound store rejects a
    /// v1 (Ed25519-only) revocation that lacks `pq_signature` — even
    /// when issued by the same DomainKey. Mirrors the cert-side gate
    /// in `dds_domain::AdmissionCert::verify_with_domain`.
    #[test]
    fn hybrid_store_rejects_v1_revocation_lacking_pq_signature() {
        let (key, id, pk, pq_pk) = fresh_hybrid_domain();
        let mut s = AdmissionRevocationStore::for_hybrid_domain(id, pk, pq_pk);
        // Strip the pq_signature to simulate an attacker presenting a
        // v1-shaped revocation under a v2-hybrid domain.
        let mut rev = key.revoke_admission("peer-A".into(), 100, None);
        rev.pq_signature = None;
        let err = s.add(rev).expect_err("hybrid store must reject v1 rev");
        assert!(matches!(err, RevocationStoreError::Verify(_)));
        assert!(!s.is_revoked("peer-A"));
    }

    /// Backward compat: a v1-bound store (no `pq_pubkey`) accepts both
    /// v1 and v2 revocations from the same key. The PQ component is
    /// carried as inert metadata and persisted alongside the entry.
    #[test]
    fn v1_store_accepts_both_v1_and_v2_revocations() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let d = key.domain();
        let mut s = AdmissionRevocationStore::for_domain(d.id, d.pubkey);
        // v2-shaped (carries pq_signature); v1 store ignores the PQ field.
        let rev_v2 = key.revoke_admission("peer-A".into(), 0, None);
        assert!(rev_v2.pq_signature.is_some());
        assert!(s.add(rev_v2).unwrap());
        // v1-shaped (pq_signature stripped).
        let mut rev_v1 = key.revoke_admission("peer-B".into(), 0, None);
        rev_v1.pq_signature = None;
        assert!(s.add(rev_v1).unwrap());
        assert!(s.is_revoked("peer-A"));
        assert!(s.is_revoked("peer-B"));
    }

    /// `load_or_empty_with_pq` parses the persisted CBOR and re-runs
    /// the v2 hybrid check at load time — entries that don't carry a
    /// valid `pq_signature` are silently dropped. Mirrors the existing
    /// `load_drops_entries_that_fail_to_verify` for foreign-domain
    /// entries.
    #[test]
    fn load_or_empty_with_pq_drops_v1_only_entries() {
        let (key, id, pk, pq_pk) = fresh_hybrid_domain();
        // Build a list with one v1-only entry and one v2 entry,
        // hand-crafted so the file pre-dates the hybrid rotation.
        let mut rev_v1 = key.revoke_admission("peer-old".into(), 100, None);
        rev_v1.pq_signature = None;
        let rev_v2 = key.revoke_admission("peer-new".into(), 200, None);
        let list = RevocationListV1 {
            v: SCHEMA_VERSION,
            entries: vec![rev_v1, rev_v2],
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("revocations.cbor");
        let mut buf = Vec::new();
        ciborium::into_writer(&list, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let loaded = load_or_empty_with_pq(&path, id, pk, Some(pq_pk)).unwrap();
        assert_eq!(loaded.len(), 1, "v1-only entry must be dropped");
        assert!(!loaded.is_revoked("peer-old"));
        assert!(loaded.is_revoked("peer-new"));
    }
}
