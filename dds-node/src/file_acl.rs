//! Cross-platform "owner-only" file hardening helper.
//!
//! Closes [`security-gaps.md`](../../security-gaps.md) Remaining Work #3
//! (Windows ACL hardening for key files). On Unix this is the existing
//! `chmod 0o600` behaviour; on Windows it applies a protected DACL
//! granting Full-Access to LocalSystem and `BUILTIN\Administrators` only,
//! mirroring the SDDL used by `restrict-data-dir-acl`,
//! `AppliedStateStore.SetWindowsDacl`, and `FileLog::Init`.
//!
//! Best-effort: failures are logged at warn but do not abort the save —
//! the data-dir-level protected DACL applied by the MSI custom action
//! `CA_RestrictDataDirAcl` is the production hardening, and key files
//! placed inside that directory inherit the same DACL via `OICI`. The
//! per-file call is defense-in-depth for non-MSI deployments and for
//! files that may pre-exist before the data-dir DACL was applied.

use std::path::Path;

/// Restrict `path` to owner-only access.
///
/// - Unix: `chmod 0o600` (best-effort; errors silently ignored, which
///   matches the prior behaviour of the per-module helpers this
///   replaces).
/// - Windows: apply protected DACL `D:PAI(A;;FA;;;SY)(A;;FA;;;BA)` via
///   `SetNamedSecurityInfoW`; failures are logged at warn.
pub(crate) fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
    #[cfg(windows)]
    {
        if let Err(e) = apply_windows_owner_only_dacl(path) {
            tracing::warn!(
                "best-effort Windows DACL hardening failed for {}: {e}",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
    }
}

/// Apply `D:PAI(A;;FA;;;SY)(A;;FA;;;BA)` to a file (no container
/// inheritance — this is per-file, not per-dir). Mirrors
/// [`crate::main::apply_windows_data_dir_dacl`] but without the `OICI`
/// flags that only apply to directories.
#[cfg(windows)]
fn apply_windows_owner_only_dacl(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    // D:PAI               -> protected DACL, drop inherited parent ACEs
    // (A;;FA;;;SY)        -> Allow, FileAll, LocalSystem
    // (A;;FA;;;BA)        -> Allow, FileAll, BUILTIN\Administrators
    //
    // No OI/CI inheritance flags — those only apply to containers.
    let sddl: Vec<u16> = std::ffi::OsStr::new("D:PAI(A;;FA;;;SY)(A;;FA;;;BA)")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut dacl_present: i32 = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted: i32 = 0;
    let got = unsafe {
        GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
    };
    if got == 0 || dacl_present == 0 || dacl.is_null() {
        unsafe { LocalFree(psd as *mut _) };
        return Err("SDDL produced no DACL — refusing to widen ACL".into());
    }

    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };

    unsafe { LocalFree(psd as *mut _) };

    if rc != 0 {
        return Err(format!(
            "SetNamedSecurityInfoW failed (Win32 err = {rc}): {}",
            std::io::Error::from_raw_os_error(rc as i32)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restrict_to_owner_does_not_panic_on_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.bin");
        std::fs::write(&p, b"x").unwrap();
        restrict_to_owner(&p);
        assert!(p.exists());
    }

    #[test]
    fn restrict_to_owner_does_not_panic_on_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does-not-exist");
        // Best-effort: a missing file must not crash the caller.
        restrict_to_owner(&p);
        assert!(!p.exists());
    }

    #[cfg(unix)]
    #[test]
    fn restrict_to_owner_sets_0o600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.bin");
        std::fs::write(&p, b"secret").unwrap();
        // Pre-condition: writable by group/other under the typical 0o644 default.
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644));
        restrict_to_owner(&p);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "expected owner-only 0o600 after restrict_to_owner, got {mode:o}"
        );
    }
}
