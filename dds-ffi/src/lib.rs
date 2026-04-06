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

mod ffi_core;

pub use ffi_core::*;


#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::ptr;

    fn call_with_out<F>(f: F) -> (i32, Option<serde_json::Value>)
    where F: FnOnce(*mut *mut c_char) -> i32 {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = f(&mut out);
        if out.is_null() { return (rc, None); }
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
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
        assert!(!json["signing_key_hex"].as_str().unwrap().is_empty());
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
    }

    #[test]
    fn test_identity_parse_urn_invalid() {
        let urn = CString::new("not-a-urn").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_identity_parse_urn(urn.as_ptr(), &mut out);
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);
    }

    #[test]
    fn test_version() {
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_version(&mut out);
        assert_eq!(rc, DDS_OK);
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        assert!(s.contains('.'));
        dds_free_string(out);
    }

    #[test]
    fn test_free_null_is_safe() {
        dds_free_string(ptr::null_mut());
    }

    #[test]
    fn test_identity_create_roundtrip() {
        let label = CString::new("roundtrip").unwrap();
        let (rc, json) = call_with_out(|out| dds_identity_create(label.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        let urn = json.unwrap()["urn"].as_str().unwrap().to_string();
        let urn_c = CString::new(urn.clone()).unwrap();
        let (rc2, json2) = call_with_out(|out| dds_identity_parse_urn(urn_c.as_ptr(), out));
        assert_eq!(rc2, DDS_OK);
        assert_eq!(json2.unwrap()["label"].as_str().unwrap(), "roundtrip");
    }

    #[test]
    fn test_token_create_and_validate() {
        // Create attestation token via FFI
        let config = CString::new(r#"{"label":"token-test"}"#).unwrap();
        let (rc, json) = call_with_out(|out| dds_token_create_attest(config.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        let json = json.unwrap();
        assert!(json["jti"].as_str().unwrap().starts_with("attest-"));
        let cbor_hex = json["token_cbor_hex"].as_str().unwrap();
        assert!(!cbor_hex.is_empty());

        // Validate the token via FFI
        let hex_c = CString::new(cbor_hex).unwrap();
        let (rc2, json2) = call_with_out(|out| dds_token_validate(hex_c.as_ptr(), out));
        assert_eq!(rc2, DDS_OK);
        let json2 = json2.unwrap();
        assert_eq!(json2["valid"].as_bool().unwrap(), true);
        assert_eq!(json2["kind"].as_str().unwrap(), "Attest");
    }

    #[test]
    fn test_token_validate_invalid_hex() {
        let bad = CString::new("not-hex-at-all!!").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_token_validate(bad.as_ptr(), &mut out);
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);
    }

    #[test]
    fn test_token_validate_invalid_cbor() {
        let bad = CString::new("deadbeef").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_token_validate(bad.as_ptr(), &mut out);
        assert_eq!(rc, DDS_ERR_TOKEN);
    }

    #[test]
    fn test_policy_evaluate_deny_no_trust() {
        let config = serde_json::json!({
            "subject_urn": "urn:vouchsafe:nobody.hash",
            "resource": "repo:main",
            "action": "read",
            "trusted_roots": [],
            "rules": [{"effect":"Allow","required_purpose":"group:dev","resource":"repo:main","actions":["read"]}],
            "tokens_cbor_hex": []
        });
        let config_c = CString::new(config.to_string()).unwrap();
        let (rc, json) = call_with_out(|out| dds_policy_evaluate(config_c.as_ptr(), out));
        assert_eq!(rc, DDS_OK);
        assert_eq!(json.unwrap()["decision"].as_str().unwrap(), "DENY");
    }

    #[test]
    fn test_policy_evaluate_invalid_json() {
        let bad = CString::new("not json").unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let rc = dds_policy_evaluate(bad.as_ptr(), &mut out);
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);
    }
}
