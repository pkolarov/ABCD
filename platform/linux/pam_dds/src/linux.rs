// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linux-PAM C entry points exported from `pam_dds.so`.
//!
//! These functions follow the Linux-PAM module ABI.  The PAM framework
//! dlopen-loads `pam_dds.so` and calls into these entry points; the PAM
//! utility functions (`pam_get_item`, etc.) are resolved from the calling
//! process which already has `libpam` loaded.

use libc::{c_char, c_int, c_void};
use std::ffi::CStr;

use crate::{HelperOutcome, parse_module_args};

// ─── PAM constants (Linux-PAM / POSIX) ───────────────────────────────────────

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_SYSTEM_ERR: c_int = 4;

/// `pam_get_item(3)` item identifier for the username.
const PAM_USER: c_int = 2;

// ─── PAM runtime symbols provided by the calling framework ───────────────────
//
// When `pam_dds.so` is dlopen-loaded by the PAM framework, the symbols
// below are provided by the already-loaded `libpam.so` in the calling
// process.  We declare them as `extern "C"` without a `#[link]` attribute
// so that the build succeeds without a compile-time dependency on
// `libpam-dev`; the dynamic linker resolves them at load time.

extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

/// Opaque PAM handle type — only ever used behind a raw pointer.
#[repr(C)]
pub struct PamHandle {
    _opaque: [u8; 0],
}

// ─── internal helpers ─────────────────────────────────────────────────────────

/// Extract the authenticated username from the PAM stack.
///
/// Returns `None` if `pam_get_item` fails or returns a null pointer.
fn get_pam_user(pamh: *const PamHandle) -> Option<String> {
    let mut user_ptr: *const c_void = std::ptr::null();
    let ret = unsafe { pam_get_item(pamh, PAM_USER, &mut user_ptr) };
    if ret != PAM_SUCCESS || user_ptr.is_null() {
        return None;
    }
    // SAFETY: PAM guarantees the pointer is a valid NUL-terminated C string
    // for the lifetime of the PAM transaction.
    let c_str = unsafe { CStr::from_ptr(user_ptr as *const c_char) };
    Some(c_str.to_string_lossy().into_owned())
}

/// Convert the raw `argc`/`argv` arguments forwarded by the PAM framework
/// into a Rust `Vec<&str>` for [`parse_module_args`].
unsafe fn collect_pam_args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    (0..argc as usize)
        .filter_map(|i| {
            let ptr = unsafe { *argv.add(i) };
            if ptr.is_null() {
                return None;
            }
            let cs = unsafe { CStr::from_ptr(ptr) };
            cs.to_str().ok().map(|s| s.to_owned())
        })
        .collect()
}

// ─── PAM entry points ─────────────────────────────────────────────────────────

/// `pam_sm_authenticate(3)` — verify the user's identity.
///
/// Flow:
/// 1. Read the username from the PAM stack.
/// 2. Resolve the `dds-pam-helper` binary (from the `helper=` arg or
///    a fixed search path list).
/// 3. Invoke the helper with `--node-sock` and `--user` arguments.
/// 4. Parse the helper's stdout as [`HelperOutcome`] JSON.
/// 5. Return `PAM_SUCCESS` when `ok == true`, `PAM_AUTH_ERR` otherwise.
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let raw_args: Vec<String> = unsafe { collect_pam_args(argc, argv) };
    let arg_refs: Vec<&str> = raw_args.iter().map(String::as_str).collect();
    let module_args = parse_module_args(&arg_refs);

    let username = match get_pam_user(pamh) {
        Some(u) if !u.is_empty() => u,
        _ => return PAM_AUTH_ERR,
    };

    let helper = match module_args.resolve_helper() {
        Some(h) => h,
        None => {
            // dds-pam-helper not found — fail closed rather than open.
            return PAM_SYSTEM_ERR;
        }
    };

    let result = std::process::Command::new(&helper)
        .arg("--node-sock")
        .arg(module_args.resolved_node_sock())
        .arg("--user")
        .arg(&username)
        .output();

    match result {
        Ok(out) if out.status.success() => match HelperOutcome::from_stdout(&out.stdout) {
            Some(outcome) if outcome.ok => PAM_SUCCESS,
            _ => PAM_AUTH_ERR,
        },
        _ => PAM_AUTH_ERR,
    }
}

/// `pam_sm_setcred(3)` — establish/delete credentials after authentication.
///
/// DDS sessions are managed by `dds-node`; no additional credential
/// material needs to be placed in the PAM environment by this module.
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// `pam_sm_acct_mgmt(3)` — check whether the account is valid and currently
/// permitted to access the service.
///
/// The DDS policy is evaluated at session-assertion time inside `dds-node`.
/// Account-management checks are therefore deferred to that evaluation; this
/// stub returns `PAM_SUCCESS` so the PAM stack continues normally.
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
