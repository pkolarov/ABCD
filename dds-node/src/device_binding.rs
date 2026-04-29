//! **M-8 (security review)** — node-local device⇄caller binding.
//!
//! The `/v1/windows/*` and `/v1/macos/*` endpoints accept any
//! `device_urn` from the caller. Before H-7 there is no transport-
//! level caller identity so any local process can enumerate every
//! enrolled device's policy / software assignment. The plan from the
//! security review closes M-8 once H-7 lands — the UDS / named-pipe
//! transport supplies a [`crate::http::CallerIdentity`], the first
//! call from that caller to `POST /v1/*/applied` TOFU-binds
//! `(device_urn, caller-principal)` into this store, and subsequent
//! reads from a different caller for the same URN are denied.
//!
//! The binding is **node-local** (not gossiped): a device's caller
//! on one node has no bearing on another node. A JSON file under
//! the data directory is the durable backing — it is tiny (one entry
//! per enrolled device) and write-infrequent (only on TOFU
//! establishment), so redb is overkill.
//!
//! Anonymous callers (loopback TCP during the transport migration)
//! bypass the binding check entirely so existing deployments keep
//! working. Once the transport flips (G1-S5) `CallerIdentity::Anonymous`
//! is disallowed at the admin gate and the binding becomes load-bearing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Stable identifier for a caller, derived from
/// [`crate::http::CallerIdentity`]. Opaque to the store; only used
/// for equality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CallerPrincipal {
    /// UDS caller identified by its effective UID.
    UnixUid { uid: u32 },
    /// Named-pipe caller identified by its primary SID.
    WindowsSid { sid: String },
}

impl CallerPrincipal {
    /// Returns `None` for [`crate::http::CallerIdentity::Anonymous`]
    /// — no stable identifier to record.
    pub fn from_caller(caller: &crate::http::CallerIdentity) -> Option<Self> {
        match caller {
            crate::http::CallerIdentity::Anonymous => None,
            #[cfg(unix)]
            crate::http::CallerIdentity::Uds { uid, .. } => {
                Some(CallerPrincipal::UnixUid { uid: *uid })
            }
            #[cfg(windows)]
            crate::http::CallerIdentity::Pipe { sid, .. } => {
                Some(CallerPrincipal::WindowsSid { sid: sid.clone() })
            }
        }
    }
}

/// Outcome of a TOFU bind attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingOutcome {
    /// No binding existed; the caller is now bound.
    Established,
    /// A binding existed and it matches the caller.
    Matched,
    /// A binding existed under a different principal. The stored
    /// principal is returned so the caller can log / audit.
    Mismatch { stored: CallerPrincipal },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct OnDisk {
    /// Schema version. Starts at `1`.
    #[serde(default = "default_version")]
    version: u8,
    #[serde(default)]
    bindings: BTreeMap<String, CallerPrincipal>,
}

fn default_version() -> u8 {
    1
}

/// In-memory cache plus durable JSON file under the data directory.
pub struct DeviceBindingStore {
    path: PathBuf,
    inner: Mutex<OnDisk>,
}

impl DeviceBindingStore {
    /// Default on-disk path.
    pub fn default_path(data_dir: &Path) -> PathBuf {
        data_dir.join("device_bindings.json")
    }

    /// Load an existing store or return an empty one. Missing file is
    /// not an error — first run.
    pub fn load_or_empty(path: PathBuf) -> io::Result<Self> {
        let inner = if path.exists() {
            let bytes = std::fs::read(&path)?;
            let disk: OnDisk = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            disk
        } else {
            OnDisk::default()
        };
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    /// Look up a binding. Returns `None` if the device URN has no
    /// binding yet.
    pub fn get(&self, device_urn: &str) -> Option<CallerPrincipal> {
        let g = self.inner.lock().expect("device-binding lock poisoned");
        g.bindings.get(device_urn).cloned()
    }

    /// TOFU-bind `device_urn → principal`. On conflict the returned
    /// [`BindingOutcome::Mismatch`] carries the previously stored
    /// principal so the caller can audit.
    ///
    /// Persists atomically (tempfile + rename) on `Established`.
    pub fn tofu_bind(
        &self,
        device_urn: &str,
        principal: CallerPrincipal,
    ) -> io::Result<BindingOutcome> {
        let mut g = self.inner.lock().expect("device-binding lock poisoned");
        match g.bindings.get(device_urn) {
            Some(existing) if *existing == principal => Ok(BindingOutcome::Matched),
            Some(other) => Ok(BindingOutcome::Mismatch {
                stored: other.clone(),
            }),
            None => {
                g.bindings.insert(device_urn.to_owned(), principal);
                let snapshot = g.clone();
                drop(g);
                Self::persist(&self.path, &snapshot)?;
                Ok(BindingOutcome::Established)
            }
        }
    }

    /// L-3 idiom (security review): atomic write — `tempfile::NamedTempFile`
    /// in the same parent directory + `persist` (POSIX `rename`) so a crash
    /// mid-write can't leave a torn binding file on disk. Owner-only
    /// permissions are applied to the *tempfile* before the rename so the
    /// final file is never observably world-readable. Mirrors the helper
    /// in [`crate::domain_store::atomic_write_owner_only`] and the per-file
    /// pattern in [`crate::identity_store::save`] /
    /// [`crate::p2p_identity::save`]; `crate::file_acl::restrict_to_owner`
    /// applies the protected DACL on Windows so a co-tenant can't
    /// enumerate the device⇄principal map either.
    fn persist(path: &Path, data: &OnDisk) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "binding path has no parent")
        })?;
        std::fs::create_dir_all(parent)?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        use std::io::Write as _;
        tmp.write_all(&bytes)?;
        tmp.flush()?;
        crate::file_acl::restrict_to_owner(tmp.path());
        tmp.persist(path).map_err(io::Error::other)?;
        crate::file_acl::restrict_to_owner(path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn uid_principal(uid: u32) -> CallerPrincipal {
        CallerPrincipal::UnixUid { uid }
    }

    #[test]
    fn tofu_establish_then_match() {
        let dir = TempDir::new().unwrap();
        let store = DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap();
        let p = uid_principal(1000);
        assert_eq!(
            store.tofu_bind("urn:device:x", p.clone()).unwrap(),
            BindingOutcome::Established
        );
        assert_eq!(
            store.tofu_bind("urn:device:x", p).unwrap(),
            BindingOutcome::Matched
        );
    }

    #[test]
    fn tofu_mismatch_returns_stored_principal() {
        let dir = TempDir::new().unwrap();
        let store = DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap();
        assert_eq!(
            store
                .tofu_bind("urn:device:x", uid_principal(1000))
                .unwrap(),
            BindingOutcome::Established
        );
        match store
            .tofu_bind("urn:device:x", uid_principal(2000))
            .unwrap()
        {
            BindingOutcome::Mismatch { stored } => {
                assert_eq!(stored, uid_principal(1000))
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bindings_persist_across_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        {
            let store = DeviceBindingStore::load_or_empty(path.clone()).unwrap();
            store.tofu_bind("urn:device:x", uid_principal(42)).unwrap();
        }
        let reopened = DeviceBindingStore::load_or_empty(path).unwrap();
        assert_eq!(reopened.get("urn:device:x"), Some(uid_principal(42)));
    }

    #[test]
    fn file_mode_is_0o600_on_unix() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        let store = DeviceBindingStore::load_or_empty(path.clone()).unwrap();
        store.tofu_bind("urn:device:x", uid_principal(1)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // On Windows the `PermissionsExt` check is a no-op; the store
        // still creates the file so just assert it exists.
        assert!(path.exists());
    }

    #[test]
    fn get_returns_none_for_unbound_urn() {
        let dir = TempDir::new().unwrap();
        let store = DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap();
        assert!(store.get("urn:device:missing").is_none());
    }

    /// **L-3 follow-on (2026-04-29)**: `persist` writes through
    /// `tempfile::NamedTempFile::new_in` + `restrict_to_owner` on the
    /// tempfile *before* `persist`, so (a) the parent dir contains no
    /// stray `.tmp*` siblings after the rename, (b) the final file
    /// is owner-only at the instant it appears under its target name
    /// (Unix: `0o600`; Windows: protected DACL via
    /// [`crate::file_acl::restrict_to_owner`]), and (c) the helper is
    /// overwrite-safe across two consecutive TOFU bind operations
    /// against the same path. Closes the L-3 "set-perms-after-rename"
    /// gap that left a brief observability window on the prior
    /// implementation.
    #[test]
    fn persist_is_atomic_and_owner_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        let store = DeviceBindingStore::load_or_empty(path.clone()).unwrap();

        store
            .tofu_bind("urn:device:a", uid_principal(1000))
            .unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "b.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "tempfile leaked into parent dir: {leftovers:?}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        store
            .tofu_bind("urn:device:b", uid_principal(2000))
            .unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "b.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "tempfile leaked across overwrite: {leftovers:?}"
        );

        let reopened = DeviceBindingStore::load_or_empty(path.clone()).unwrap();
        assert_eq!(reopened.get("urn:device:a"), Some(uid_principal(1000)));
        assert_eq!(reopened.get("urn:device:b"), Some(uid_principal(2000)));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
