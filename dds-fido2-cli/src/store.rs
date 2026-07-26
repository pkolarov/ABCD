//! Admin FIDO2 credential store — `${DDS_ROOT}/admin-fido2-credentials.toml`.
//!
//! No prior art for this exists anywhere in the repo (Windows included —
//! `DdsEnrollUser.exe` stores a single credential_id in the registry). This
//! store is keyed by `label` specifically so a shared bootstrap box with
//! more than one admin doesn't silently clobber one admin's credential_id
//! with another's: `admin-setup` refuses to overwrite an existing label
//! without `--force`, and `vouch`/`revoke-vouch` require an explicit
//! `--label` whenever the store holds more than one entry rather than
//! guessing which admin is running the ceremony.
//!
//! Written with the same tempfile-then-atomic-rename-then-owner-only-perms
//! idiom `dds-node/src/domain_store.rs`'s `atomic_write_owner_only` uses —
//! duplicated here (not depended on) so this crate never links `dds-node`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredential {
    pub label: String,
    pub credential_id: String,
    pub created_at: u64,
    /// The admin identity URN `admin-setup` minted for this credential.
    ///
    /// Recorded so a wizard can answer "is the admin on this machine
    /// trusted by the domain yet?" without the operator keeping the URN
    /// in a terminal scrollback: the on-disk signing key is named by
    /// `SHA256(urn)` and so can't be reversed, and an untrusted admin
    /// doesn't appear in `/v1/admin/roots` to be discovered from there.
    ///
    /// `#[serde(default)]` because stores written before this field
    /// existed have no value for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urn: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CredentialStore {
    #[serde(default, rename = "admin")]
    pub admins: Vec<AdminCredential>,
}

/// OS-appropriate default path. This tool only targets macOS/Linux
/// (Windows keeps `DdsEnrollUser.exe`); other targets fall back to a
/// path under the current directory so `--credential-store` becomes
/// mandatory rather than silently writing somewhere unexpected.
pub fn default_store_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/DDS/admin-fido2-credentials.toml")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/dds/admin-fido2-credentials.toml")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        PathBuf::from("./admin-fido2-credentials.toml")
    }
}

pub fn load(path: &Path) -> Result<CredentialStore, String> {
    if !path.exists() {
        return Ok(CredentialStore::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Atomic write: tempfile in the same parent dir, owner-only permissions
/// applied before the rename so the final file is never observably
/// world-readable, then `persist` (POSIX rename). Root-owned 0600 for
/// consistency with sibling files (`domain_key.bin`, `admission.cbor`)
/// even though the content itself (a public credential_id) isn't secret.
fn atomic_write_owner_only(path: &Path, buf: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create_dir_all {}: {e}", parent.display()))?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("tempfile in {}: {e}", parent.display()))?;
    std::fs::write(tmp.path(), buf).map_err(|e| format!("tempfile write: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600));
    }
    tmp.persist(path)
        .map_err(|e| format!("rename to {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub fn save(path: &Path, store: &CredentialStore) -> Result<(), String> {
    let header = "# Written by dds-fido2-cli only. Do not hand-edit or parse from shell —\n\
                  # use `dds-fido2 list-admins` / pass --label instead.\n";
    let body = toml::to_string_pretty(store).map_err(|e| format!("serialize: {e}"))?;
    atomic_write_owner_only(path, format!("{header}{body}").as_bytes())
}

/// Insert a new admin credential under `label`. Refuses to overwrite an
/// existing label unless `force` is set — this is the concrete guard
/// against one admin's re-enrollment silently clobbering another's
/// stored credential_id on a shared box.
pub fn add(
    store: &mut CredentialStore,
    label: &str,
    credential_id: &str,
    created_at: u64,
    urn: Option<&str>,
    force: bool,
) -> Result<(), String> {
    if let Some(pos) = store.admins.iter().position(|a| a.label == label) {
        if !force {
            return Err(format!(
                "an admin credential is already stored under label {label:?} — pass --force to overwrite"
            ));
        }
        store.admins.remove(pos);
    }
    store.admins.push(AdminCredential {
        label: label.to_string(),
        credential_id: credential_id.to_string(),
        created_at,
        urn: urn.map(str::to_string),
    });
    Ok(())
}

/// Resolve which admin credential a `vouch`/`revoke-vouch` ceremony
/// should use. Exactly one entry in the store is used unconditionally;
/// more than one requires an explicit `--label` rather than guessing —
/// this is the fix for the multi-admin collision risk a flat single-value
/// store would have.
pub fn resolve<'a>(
    store: &'a CredentialStore,
    requested_label: Option<&str>,
) -> Result<&'a AdminCredential, String> {
    if let Some(label) = requested_label {
        return store
            .admins
            .iter()
            .find(|a| a.label == label)
            .ok_or_else(|| {
                let known: Vec<&str> = store.admins.iter().map(|a| a.label.as_str()).collect();
                format!("no admin credential with label {label:?} on this box (known: {known:?})")
            });
    }
    match store.admins.len() {
        0 => Err(
            "no admin credentials on this box — run `dds-fido2 admin-setup` first, \
             or `dds-fido2 vouch` after an admin has been set up elsewhere"
                .to_string(),
        ),
        1 => Ok(&store.admins[0]),
        _ => {
            let known: Vec<&str> = store.admins.iter().map(|a| a.label.as_str()).collect();
            Err(format!(
                "multiple admin credentials on this box, pass --label: {known:?}"
            ))
        }
    }
}
