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


#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    /// Helper: call an FFI function that returns a JSON string via out pointer,
    /// extract the string, free it, and return the parsed JSON.
    fn call_with_out<F>(f: F) -> (i32, Option<serde_json::Value>)
    where
        F: FnOnce(*mut *mut c_char) -> i32,
    {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = f(&mut out);
        if out.is_null() {
            return (rc, None);
        }
        let s = unsafe { CStr::from_ptr(out) }
            .to_str()
            .unwrap()
            .to_string();
        dds_free_string(out);
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        (rc, Some(json))
    }

    #[test]
    fn test_identity_create() {
        let label = CString::new("alice").unwrap();
        let (rc, json) = call_with_out(|out| dds_identity_create(label.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        let json = json.unwrap();
        assert!(json["urn"].as_str().unwrap().starts_with("urn:vouchsafe:alice."));
        assert_eq!(json["scheme"].as_str().unwrap(), "Ed25519");
        assert_eq!(json["pubkey_len"].as_u64().unwrap(), 32);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn test_identity_create_hybrid() {
        let label = CString::new("quantum-bob").unwrap();
        let (rc, json) = call_with_out(|out| dds_identity_create_hybrid(label.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        let json = json.unwrap();
        assert!(json["urn"].as_str().unwrap().starts_with("urn:vouchsafe:quantum-bob."));
        assert_eq!(json["scheme"].as_str().unwrap(), "Ed25519+ML-DSA-65");
        assert_eq!(json["pubkey_len"].as_u64().unwrap(), 1984);
    }

    #[test]
    fn test_identity_parse_urn_valid() {
        let urn = CString::new("urn:vouchsafe:alice.abcdef1234").unwrap();
        let (rc, json) = call_with_out(|out| dds_identity_parse_urn(urn.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        let json = json.unwrap();
        assert_eq!(json["label"].as_str().unwrap(), "alice");
        assert_eq!(json["hash"].as_str().unwrap(), "abcdef1234");
        assert_eq!(
            json["urn"].as_str().unwrap(),
            "urn:vouchsafe:alice.abcdef1234"
        );
    }

    #[test]
    fn test_identity_parse_urn_invalid() {
        let urn = CString::new("not-a-urn").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_identity_parse_urn(urn.as_ptr(), &mut out);
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);
        assert!(out.is_null());
    }

    #[test]
    fn test_version() {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_version(&mut out);
        assert_eq!(rc, DDS_OK);
        assert!(!out.is_null());
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        assert!(!s.is_empty());
        // Should look like a semver version
        assert!(s.contains('.'), "version should contain dots: {s}");
        dds_free_string(out);
    }

    #[test]
    fn test_free_null_is_safe() {
        dds_free_string(ptr::null_mut()); // must not crash
    }

    #[test]
    fn test_identity_create_roundtrip() {
        // Create an identity via FFI, then parse the URN back via FFI
        let label = CString::new("roundtrip").unwrap();
        let (rc, json) = call_with_out(|out| dds_identity_create(label.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        let urn = json.unwrap()["urn"].as_str().unwrap().to_string();

        let urn_c = CString::new(urn.clone()).unwrap();
        let (rc2, json2) = call_with_out(|out| dds_identity_parse_urn(urn_c.as_ptr(), out));
        assert_eq!(rc2, DDS_OK);
        let json2 = json2.unwrap();
        assert_eq!(json2["label"].as_str().unwrap(), "roundtrip");
        assert_eq!(json2["urn"].as_str().unwrap(), urn);
    }
}
