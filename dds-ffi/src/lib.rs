//! # dds-ffi
//!
//! C-compatible exported functions for cross-platform consumption.
//!
//! Provides a flat C ABI that can be consumed by:
//! - C# (P/Invoke)
//! - Swift (C bridging)
//! - Kotlin/JNI (via JNA)
//! - Python (ctypes)
//!
//! All complex data is passed as JSON strings.
//! Caller must free returned strings with `dds_free_string`.

use dds_core::identity::{Identity, VouchsafeId};
use rand::rngs::OsRng;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Error codes.
pub const DDS_OK: i32 = 0;
pub const DDS_ERR_INVALID_INPUT: i32 = -1;
pub const DDS_ERR_INTERNAL: i32 = -99;

/// Generate a new classical (Ed25519) identity.
/// Returns JSON `{ "urn": "...", "scheme": "Ed25519", "pubkey_len": 32 }` via `out`.
/// Caller must free the returned string with `dds_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn dds_identity_create(label: *const c_char, out: *mut *mut c_char) -> i32 {
    let label = match unsafe { CStr::from_ptr(label) }.to_str() {
        Ok(s) => s,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let ident = Identity::generate(label, &mut OsRng);
    let json = serde_json::json!({
        "urn": ident.id.to_urn(),
        "scheme": format!("{}", ident.public_key.scheme),
        "pubkey_len": ident.public_key.bytes.len(),
    });
    match CString::new(json.to_string()) {
        Ok(cs) => { unsafe { *out = cs.into_raw() }; DDS_OK }
        Err(_) => DDS_ERR_INTERNAL,
    }
}

/// Generate a hybrid (Ed25519+ML-DSA-65) identity.
#[cfg(feature = "pq")]
#[unsafe(no_mangle)]
pub extern "C" fn dds_identity_create_hybrid(label: *const c_char, out: *mut *mut c_char) -> i32 {
    let label = match unsafe { CStr::from_ptr(label) }.to_str() {
        Ok(s) => s,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let ident = Identity::generate_hybrid(label, &mut OsRng);
    let json = serde_json::json!({
        "urn": ident.id.to_urn(),
        "scheme": format!("{}", ident.public_key.scheme),
        "pubkey_len": ident.public_key.bytes.len(),
    });
    match CString::new(json.to_string()) {
        Ok(cs) => { unsafe { *out = cs.into_raw() }; DDS_OK }
        Err(_) => DDS_ERR_INTERNAL,
    }
}

/// Parse and validate a Vouchsafe URN.
/// Returns JSON `{ "label": "...", "hash": "...", "urn": "..." }` via `out`.
#[unsafe(no_mangle)]
pub extern "C" fn dds_identity_parse_urn(urn: *const c_char, out: *mut *mut c_char) -> i32 {
    let urn_str = match unsafe { CStr::from_ptr(urn) }.to_str() {
        Ok(s) => s,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let id = match VouchsafeId::from_urn(urn_str) {
        Ok(id) => id,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let json = serde_json::json!({
        "label": id.label(),
        "hash": id.hash(),
        "urn": id.to_urn(),
    });
    match CString::new(json.to_string()) {
        Ok(cs) => { unsafe { *out = cs.into_raw() }; DDS_OK }
        Err(_) => DDS_ERR_INTERNAL,
    }
}

/// Free a string allocated by DDS FFI functions.
#[unsafe(no_mangle)]
pub extern "C" fn dds_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); }
    }
}

/// Get the DDS library version.
#[unsafe(no_mangle)]
pub extern "C" fn dds_version(out: *mut *mut c_char) -> i32 {
    match CString::new(env!("CARGO_PKG_VERSION")) {
        Ok(cs) => { unsafe { *out = cs.into_raw() }; DDS_OK }
        Err(_) => DDS_ERR_INTERNAL,
    }
}
