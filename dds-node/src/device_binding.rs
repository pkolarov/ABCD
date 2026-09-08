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

/// A stored device⇄caller binding plus its provenance.
///
/// **S4 (2026-09-08 follow-up review)**: before F2, bindings were
/// established by trust-on-first-use — the first caller to report for a
/// device URN was bound to it, with no administrator involved. A node
/// that has been running since before F2 may still have such entries on
/// disk, and nothing distinguished them from a binding an administrator
/// actually provisioned. `admin_provisioned` makes that distinction
/// explicit: it is `true` only for a binding established (or replaced)
/// through `POST /v1/admin/device-binding`, and `false` for anything
/// loaded from a pre-S4 (schema version 1) file — including a binding an
/// attacker may have claimed for themselves before the node upgraded.
/// Only `admin_provisioned: true` entries are authoritative for the
/// read/write authorization checks in `http.rs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredBinding {
    pub principal: CallerPrincipal,
    pub admin_provisioned: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct OnDisk {
    /// Schema version. `1` is the pre-S4 shape (`bindings` values are
    /// bare [`CallerPrincipal`]s with no provenance). `2` is the current
    /// shape (`bindings` values are [`StoredBinding`]s). See
    /// [`DeviceBindingStore::parse_on_disk`] for how both are read.
    #[serde(default = "default_version")]
    version: u8,
    #[serde(default)]
    bindings: BTreeMap<String, StoredBinding>,
}

fn default_version() -> u8 {
    1
}

/// Current on-disk schema version. Every persist writes this version,
/// regardless of what was loaded — a legacy (version-1) file
/// self-upgrades its on-disk *format* the moment anything is written to
/// it, though individual legacy entries keep `admin_provisioned: false`
/// until an administrator explicitly re-binds them.
const CURRENT_VERSION: u8 = 2;

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
            Self::parse_on_disk(&bytes)?
        } else {
            OnDisk::default()
        };
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    /// **S4 (2026-09-08 follow-up review)**: parse the on-disk JSON,
    /// tolerating both the pre-S4 (version 1) shape — `bindings` values
    /// are bare [`CallerPrincipal`]s — and the current (version 2) shape
    /// — `bindings` values are [`StoredBinding`]s. A naive
    /// `#[derive(Deserialize)]` on the new wrapper shape would fail
    /// outright on a version-1 file (missing `principal` /
    /// `admin_provisioned` fields) and brick every existing deployment's
    /// binding store on upgrade, so this parses the raw JSON first and
    /// picks the shape explicitly.
    ///
    /// Every entry read from a version-1 (or otherwise legacy-shaped)
    /// file is wrapped as `admin_provisioned: false` — unconditionally,
    /// with no exceptions, because there is no way to distinguish a
    /// pre-S4 binding an administrator happened to establish from one an
    /// attacker claimed under the old trust-on-first-use behavior.
    fn parse_on_disk(bytes: &[u8]) -> io::Result<OnDisk> {
        let raw: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let version = raw
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1);
        let bindings_value = raw
            .get("bindings")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(Default::default()));

        if version >= 2 {
            if let Ok(bindings) =
                serde_json::from_value::<BTreeMap<String, StoredBinding>>(bindings_value.clone())
            {
                return Ok(OnDisk {
                    version: CURRENT_VERSION,
                    bindings,
                });
            }
            // Fall through: a file claiming version >= 2 whose `bindings`
            // don't actually match the new shape is treated as legacy
            // rather than rejected outright.
        }

        let legacy: BTreeMap<String, CallerPrincipal> = serde_json::from_value(bindings_value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if !legacy.is_empty() {
            tracing::warn!(
                legacy_binding_count = legacy.len(),
                "S4 (2026-09-08 follow-up review): loaded pre-S4 device binding(s) from a \
                 legacy schema-version-1 store; none are trusted for read/write authorization \
                 until an administrator re-provisions them via POST /v1/admin/device-binding"
            );
        }
        let bindings = legacy
            .into_iter()
            .map(|(urn, principal)| {
                (
                    urn,
                    StoredBinding {
                        principal,
                        admin_provisioned: false,
                    },
                )
            })
            .collect();
        Ok(OnDisk {
            version: CURRENT_VERSION,
            bindings,
        })
    }

    /// Look up a binding that is authoritative for authorization.
    /// Returns `None` if the device URN has no binding yet, or if its
    /// stored binding is not `admin_provisioned` (**S4**: a legacy
    /// pre-S4 entry does not count — as far as the caller is concerned
    /// it does not exist).
    pub fn get(&self, device_urn: &str) -> Option<CallerPrincipal> {
        let g = self.inner.lock().expect("device-binding lock poisoned");
        g.bindings
            .get(device_urn)
            .filter(|b| b.admin_provisioned)
            .map(|b| b.principal.clone())
    }

    /// Bind `device_urn → principal`. **F2 (2026-09-07 security
    /// review)**: bindings are provisioned by an administrator
    /// (`POST /v1/admin/device-binding`), never inferred from the first
    /// caller that reports for a device.
    ///
    /// - No existing entry: establishes it fresh, `admin_provisioned: true`.
    /// - Existing entry is `admin_provisioned: true` and matches: `Matched`.
    /// - Existing entry is `admin_provisioned: true` and differs:
    ///   `Mismatch` (409 at the HTTP layer) — a real admin-provisioned
    ///   binding is still protected from silent overwrite.
    /// - **S4 (2026-09-08 follow-up review)**: existing entry is
    ///   `admin_provisioned: false` (a legacy pre-S4 entry, which may
    ///   have been established by an attacker under the old
    ///   trust-on-first-use behavior): replaced unconditionally,
    ///   regardless of whether the requested principal matches it, and
    ///   marked `admin_provisioned: true`. This never returns `Mismatch`
    ///   — an administrator correcting a legacy entry must always
    ///   succeed in one call — and is logged at `WARN` with the device
    ///   URN and the old vs. new principal so an operator has an audit
    ///   trail of exactly which devices carried stale/attacker bindings.
    ///
    /// Persists atomically (tempfile + rename) whenever the store
    /// changes.
    pub fn bind(&self, device_urn: &str, principal: CallerPrincipal) -> io::Result<BindingOutcome> {
        let mut g = self.inner.lock().expect("device-binding lock poisoned");
        match g.bindings.get(device_urn) {
            Some(existing) if existing.admin_provisioned && existing.principal == principal => {
                Ok(BindingOutcome::Matched)
            }
            Some(existing) if existing.admin_provisioned => Ok(BindingOutcome::Mismatch {
                stored: existing.principal.clone(),
            }),
            Some(existing) => {
                // **S4**: legacy (pre-S4) entry — not admin_provisioned.
                // An administrator replaces it unconditionally; a legacy
                // entry carries no trust, so even a principal that
                // happens to match it does not earn `Matched`.
                let old_principal = existing.principal.clone();
                tracing::warn!(
                    device_urn,
                    ?old_principal,
                    new_principal = ?principal,
                    "S4 (2026-09-08 follow-up review): replacing a legacy pre-S4 device \
                     binding established before administrator-only provisioning; the prior \
                     principal was never authorized to act on this device"
                );
                g.bindings.insert(
                    device_urn.to_owned(),
                    StoredBinding {
                        principal,
                        admin_provisioned: true,
                    },
                );
                let snapshot = g.clone();
                drop(g);
                Self::persist(&self.path, &snapshot)?;
                Ok(BindingOutcome::Established)
            }
            None => {
                g.bindings.insert(
                    device_urn.to_owned(),
                    StoredBinding {
                        principal,
                        admin_provisioned: true,
                    },
                );
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
        // **S4**: every persisted write uses the current (version 2)
        // on-disk shape, regardless of the version that was loaded — a
        // legacy file self-upgrades its on-disk *format* the moment
        // anything is written to it. This does not promote any
        // individual legacy entry's `admin_provisioned` flag; only
        // `bind()` does that, and only for the entry it actually
        // touched.
        let data = OnDisk {
            version: CURRENT_VERSION,
            bindings: data.bindings.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&data)
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
    fn bind_establish_then_match() {
        let dir = TempDir::new().unwrap();
        let store = DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap();
        let p = uid_principal(1000);
        assert_eq!(
            store.bind("urn:device:x", p.clone()).unwrap(),
            BindingOutcome::Established
        );
        assert_eq!(
            store.bind("urn:device:x", p).unwrap(),
            BindingOutcome::Matched
        );
    }

    #[test]
    fn bind_mismatch_returns_stored_principal() {
        let dir = TempDir::new().unwrap();
        let store = DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap();
        assert_eq!(
            store.bind("urn:device:x", uid_principal(1000)).unwrap(),
            BindingOutcome::Established
        );
        match store.bind("urn:device:x", uid_principal(2000)).unwrap() {
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
            store.bind("urn:device:x", uid_principal(42)).unwrap();
        }
        let reopened = DeviceBindingStore::load_or_empty(path).unwrap();
        assert_eq!(reopened.get("urn:device:x"), Some(uid_principal(42)));
    }

    #[test]
    fn file_mode_is_0o600_on_unix() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        let store = DeviceBindingStore::load_or_empty(path.clone()).unwrap();
        store.bind("urn:device:x", uid_principal(1)).unwrap();
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

        store.bind("urn:device:a", uid_principal(1000)).unwrap();

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

        store.bind("urn:device:b", uid_principal(2000)).unwrap();

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

    // ---------- S4 (2026-09-08 follow-up review) ----------

    /// A hand-written version-1 fixture matching the OLD bare-
    /// `CallerPrincipal`-per-entry on-disk shape (no per-entry
    /// provenance field).
    fn legacy_v1_fixture(device_urn: &str, uid: u32) -> String {
        format!(
            r#"{{
  "version": 1,
  "bindings": {{
    "{device_urn}": {{"kind":"unix_uid","uid":{uid}}}
  }}
}}"#
        )
    }

    #[test]
    fn legacy_v1_binding_is_untrusted_and_admin_can_replace_it() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        std::fs::write(&path, legacy_v1_fixture("urn:device:legacy", 998)).unwrap();

        let store = DeviceBindingStore::load_or_empty(path).unwrap();

        // The legacy entry loaded without error, but it is not trusted
        // for authorization purposes — the authorized-view accessor
        // treats it as absent even though it is present in the file.
        assert!(
            store.get("urn:device:legacy").is_none(),
            "a pre-S4 legacy binding must not be authoritative"
        );

        // An administrator can now cleanly replace it with a DIFFERENT
        // principal than the legacy one, and this must succeed
        // (Established), not 409 (Mismatch).
        let outcome = store
            .bind("urn:device:legacy", uid_principal(4242))
            .unwrap();
        assert_eq!(outcome, BindingOutcome::Established);
        assert_eq!(store.get("urn:device:legacy"), Some(uid_principal(4242)));
    }

    #[test]
    fn legacy_v1_binding_with_version_field_absent_is_also_untrusted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        // No top-level "version" key at all — must be treated the same
        // as an explicit version 1.
        std::fs::write(
            &path,
            r#"{"bindings":{"urn:device:legacy":{"kind":"unix_uid","uid":1}}}"#,
        )
        .unwrap();

        let store = DeviceBindingStore::load_or_empty(path).unwrap();
        assert!(store.get("urn:device:legacy").is_none());
    }

    #[test]
    fn legacy_v1_binding_replace_succeeds_even_when_principal_matches() {
        // A legacy entry carries no trust — even a `bind()` call whose
        // requested principal happens to equal the legacy one must
        // promote it to admin_provisioned rather than treat it as
        // already-authorized.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        std::fs::write(&path, legacy_v1_fixture("urn:device:legacy", 998)).unwrap();

        let store = DeviceBindingStore::load_or_empty(path).unwrap();
        let outcome = store.bind("urn:device:legacy", uid_principal(998)).unwrap();
        assert_eq!(outcome, BindingOutcome::Established);
        assert_eq!(store.get("urn:device:legacy"), Some(uid_principal(998)));
    }

    #[test]
    fn admin_provisioned_binding_still_rejects_conflicting_rebind() {
        // Existing F2 guarantee, unaffected by S4: a binding that was
        // ALREADY admin_provisioned (established fresh via `bind()`)
        // still protects itself with Mismatch against a conflicting
        // re-bind attempt.
        let dir = TempDir::new().unwrap();
        let store = DeviceBindingStore::load_or_empty(dir.path().join("b.json")).unwrap();
        assert_eq!(
            store.bind("urn:device:x", uid_principal(1000)).unwrap(),
            BindingOutcome::Established
        );
        match store.bind("urn:device:x", uid_principal(2000)).unwrap() {
            BindingOutcome::Mismatch { stored } => assert_eq!(stored, uid_principal(1000)),
            other => panic!("expected Mismatch, got {other:?}"),
        }
        // Still bound to the original principal — the conflicting call
        // must not have mutated anything.
        assert_eq!(store.get("urn:device:x"), Some(uid_principal(1000)));
    }

    #[test]
    fn legacy_entries_are_not_promoted_by_unrelated_writes() {
        // Rewriting the file (to persist a bind on a DIFFERENT device
        // URN) must not silently promote untouched legacy entries to
        // admin_provisioned: true.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        let legacy_json = r#"{
  "version": 1,
  "bindings": {
    "urn:device:legacy": {"kind":"unix_uid","uid":998},
    "urn:device:other": {"kind":"unix_uid","uid":1}
  }
}"#;
        std::fs::write(&path, legacy_json).unwrap();
        let store = DeviceBindingStore::load_or_empty(path.clone()).unwrap();

        store.bind("urn:device:new", uid_principal(5)).unwrap();

        assert!(store.get("urn:device:legacy").is_none());
        assert!(store.get("urn:device:other").is_none());
        assert_eq!(store.get("urn:device:new"), Some(uid_principal(5)));

        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], 2);
        assert_eq!(
            raw["bindings"]["urn:device:legacy"]["admin_provisioned"],
            false
        );
        assert_eq!(
            raw["bindings"]["urn:device:other"]["admin_provisioned"],
            false
        );
        assert_eq!(raw["bindings"]["urn:device:new"]["admin_provisioned"], true);
    }

    #[test]
    fn admin_provisioned_flag_survives_persist_and_reload() {
        // Round-trip: persist a binding via `bind()`, reload the store
        // from disk, confirm the reloaded entry is still
        // admin_provisioned: true — catches a serialization bug in the
        // new `StoredBinding` wrapper.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("b.json");
        {
            let store = DeviceBindingStore::load_or_empty(path.clone()).unwrap();
            assert_eq!(
                store.bind("urn:device:x", uid_principal(1000)).unwrap(),
                BindingOutcome::Established
            );
        }

        // Confirm the raw on-disk shape actually marks the entry
        // admin_provisioned: true, not just that `get()` returns it
        // (which would already imply that, but would not catch a bug
        // where `get()` and the on-disk shape disagree).
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["version"], 2);
        assert_eq!(raw["bindings"]["urn:device:x"]["admin_provisioned"], true);

        let reopened = DeviceBindingStore::load_or_empty(path).unwrap();
        assert_eq!(reopened.get("urn:device:x"), Some(uid_principal(1000)));
    }
}
