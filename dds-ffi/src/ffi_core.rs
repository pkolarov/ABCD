//! Core FFI exports — full DDS API surface over C ABI.
//!
//! All functions follow the pattern:
//! - Input: C strings (const char*) or JSON strings for complex data
//! - Output: JSON string via `*mut *mut c_char` out parameter
//! - Return: i32 error code (DDS_OK = 0, negative = error)
//! - Caller frees returned strings with `dds_free_string`

use dds_core::identity::{Identity, VouchsafeId};
use dds_core::policy::{Effect, PolicyEngine, PolicyRule};
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_core::trust::TrustGraph;
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// ---- Error codes ----
pub const DDS_OK: i32 = 0;
pub const DDS_ERR_INVALID_INPUT: i32 = -1;
pub const DDS_ERR_CRYPTO: i32 = -2;
pub const DDS_ERR_TOKEN: i32 = -3;
pub const DDS_ERR_TRUST: i32 = -4;
pub const DDS_ERR_POLICY_DENIED: i32 = -5;
pub const DDS_ERR_INTERNAL: i32 = -99;

// ---- Helpers ----
//
// **C-1 (security review): every helper checks for null pointers before
// dereferencing.** All `*mut *mut c_char` outputs and `*const c_char`
// inputs are caller-supplied. A buggy or adversarial language binding
// (Python, C#, Swift, Kotlin) could pass NULL — without these checks
// `read_cstr` would dereference 0x0 (segfault) and `write_*` would
// perform a raw store through the attacker-controlled pointer.

/// Maximum array length accepted from JSON input by FFI helpers
/// (rules / tokens). L-8 — caps deserialized array sizes so a
/// malicious JSON blob cannot consume unbounded memory.
const FFI_MAX_RULES: usize = 10_000;
const FFI_MAX_TOKENS: usize = 100_000;

fn read_cstr(ptr: *const c_char) -> Result<&'static str, i32> {
    if ptr.is_null() {
        return Err(DDS_ERR_INVALID_INPUT);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| DDS_ERR_INVALID_INPUT)
}

fn write_json(out: *mut *mut c_char, json: serde_json::Value) -> i32 {
    if out.is_null() {
        return DDS_ERR_INVALID_INPUT;
    }
    match CString::new(json.to_string()) {
        Ok(cs) => {
            unsafe { *out = cs.into_raw() };
            DDS_OK
        }
        Err(_) => DDS_ERR_INTERNAL,
    }
}

fn write_str(out: *mut *mut c_char, s: &str) -> i32 {
    if out.is_null() {
        return DDS_ERR_INVALID_INPUT;
    }
    match CString::new(s) {
        Ok(cs) => {
            unsafe { *out = cs.into_raw() };
            DDS_OK
        }
        Err(_) => DDS_ERR_INTERNAL,
    }
}

// ============================================================
// Identity
// ============================================================

/// Generate a classical (Ed25519) identity. Returns JSON.
///
/// I-9: the secret signing key is **not** exposed across the FFI. The
/// generated identity is dropped after the URN/pubkey metadata is
/// returned, so language bindings cannot accidentally retain plaintext
/// key material in GC'd strings. The hybrid variant has always
/// behaved this way; the classical path is now consistent.
///
/// # Safety
/// `label` must be a valid NUL-terminated C string. `out` must be a valid pointer
/// to a `*mut c_char` location that this function may write to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_identity_create(label: *const c_char, out: *mut *mut c_char) -> i32 {
    let label = match read_cstr(label) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ident = Identity::generate(label, &mut OsRng);
    write_json(
        out,
        serde_json::json!({
            "urn": ident.id.to_urn(),
            "scheme": format!("{}", ident.public_key.scheme),
            "pubkey_len": ident.public_key.bytes.len(),
        }),
    )
}

/// Generate a hybrid (Ed25519+ML-DSA-65) identity. Returns JSON.
///
/// # Safety
/// `label` must be a valid NUL-terminated C string. `out` must be a valid writable
/// pointer to a `*mut c_char` location.
#[cfg(feature = "pq")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_identity_create_hybrid(
    label: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    let label = match read_cstr(label) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let ident = Identity::generate_hybrid(label, &mut OsRng);
    write_json(
        out,
        serde_json::json!({
            "urn": ident.id.to_urn(),
            "scheme": format!("{}", ident.public_key.scheme),
            "pubkey_len": ident.public_key.bytes.len(),
        }),
    )
}

/// Parse and validate a Vouchsafe URN. Returns JSON.
///
/// # Safety
/// `urn` must be a valid NUL-terminated C string. `out` must be a valid writable
/// pointer to a `*mut c_char` location.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_identity_parse_urn(urn: *const c_char, out: *mut *mut c_char) -> i32 {
    let urn_str = match read_cstr(urn) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let id = match VouchsafeId::from_urn(urn_str) {
        Ok(id) => id,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    write_json(
        out,
        serde_json::json!({
            "label": id.label(),
            "hash": id.hash(),
            "urn": id.to_urn(),
        }),
    )
}

// ============================================================
// Token
// ============================================================

/// Create and sign an attestation token. Input: JSON config. Output: JSON token.
/// Input JSON: { "label": "alice" } — creates identity + self-attestation.
/// Output JSON: { "jti", "urn", "token_cbor_hex", "payload_hash" }
///
/// # Safety
/// `config_json` must be a valid NUL-terminated C string. `out` must be a valid
/// writable pointer to a `*mut c_char` location.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_token_create_attest(
    config_json: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    let config_str = match read_cstr(config_json) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let config: serde_json::Value = match serde_json::from_str(config_str) {
        Ok(v) => v,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let label = match config["label"].as_str() {
        Some(s) => s,
        None => return DDS_ERR_INVALID_INPUT,
    };
    let ident = Identity::generate(label, &mut OsRng);
    let payload = TokenPayload {
        iss: ident.id.to_urn(),
        iss_key: ident.public_key.clone(),
        jti: format!("attest-{}", ident.id.label()),
        sub: ident.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: config["purpose"].as_str().map(String::from),
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: now_epoch(),
        exp: Some(now_epoch() + 365 * 86400),
        body_type: None,
        body_cbor: None,
    };
    let token = match Token::sign(payload, &ident.signing_key) {
        Ok(t) => t,
        Err(e) => return write_err(out, DDS_ERR_TOKEN, &e.to_string()),
    };
    let cbor = match token.to_cbor() {
        Ok(b) => hex::encode(b),
        Err(e) => return write_err(out, DDS_ERR_TOKEN, &e.to_string()),
    };
    write_json(
        out,
        serde_json::json!({
            "jti": token.payload.jti,
            "urn": ident.id.to_urn(),
            "token_cbor_hex": cbor,
            "payload_hash": token.payload_hash(),
        }),
    )
}

/// Validate a token from CBOR hex. Returns JSON with validation result.
///
/// # Safety
/// `token_hex` must be a valid NUL-terminated C string. `out` must be a valid
/// writable pointer to a `*mut c_char` location.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_token_validate(
    token_hex: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    let hex_str = match read_cstr(token_hex) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let token = match Token::from_cbor(&bytes) {
        Ok(t) => t,
        Err(e) => return write_err(out, DDS_ERR_TOKEN, &e.to_string()),
    };
    match token.validate() {
        Ok(()) => write_json(
            out,
            serde_json::json!({
                "valid": true, "jti": token.payload.jti,
                "iss": token.payload.iss, "kind": format!("{:?}", token.payload.kind),
            }),
        ),
        Err(e) => write_json(
            out,
            serde_json::json!({
                "valid": false, "jti": token.payload.jti,
                "iss": token.payload.iss, "error": e.to_string(),
            }),
        ),
    }
}

/// Evaluate a policy decision. Input/output: JSON strings.
///
/// # Safety
/// `config_json` must be a valid NUL-terminated C string. `out` must be a valid
/// writable pointer to a `*mut c_char` location.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_policy_evaluate(
    config_json: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    let config_str = match read_cstr(config_json) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let config: serde_json::Value = match serde_json::from_str(config_str) {
        Ok(v) => v,
        Err(_) => return DDS_ERR_INVALID_INPUT,
    };
    let subject = match config["subject_urn"].as_str() {
        Some(s) => s,
        None => return DDS_ERR_INVALID_INPUT,
    };
    let resource = match config["resource"].as_str() {
        Some(s) => s,
        None => return DDS_ERR_INVALID_INPUT,
    };
    let action = match config["action"].as_str() {
        Some(s) => s,
        None => return DDS_ERR_INVALID_INPUT,
    };

    let roots: BTreeSet<String> = config["trusted_roots"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mut graph = TrustGraph::new();
    if let Some(tokens) = config["tokens_cbor_hex"].as_array() {
        if tokens.len() > FFI_MAX_TOKENS {
            return write_err(
                out,
                DDS_ERR_INVALID_INPUT,
                "tokens_cbor_hex exceeds maximum length",
            );
        }
        for tok_hex in tokens {
            if let Some(s) = tok_hex.as_str() {
                if let Ok(bytes) = hex::decode(s) {
                    if let Ok(token) = Token::from_cbor(&bytes) {
                        let _ = graph.add_token(token);
                    }
                }
            }
        }
    }

    let mut engine = PolicyEngine::new();
    if let Some(rules) = config["rules"].as_array() {
        if rules.len() > FFI_MAX_RULES {
            return write_err(out, DDS_ERR_INVALID_INPUT, "rules exceeds maximum length");
        }
        for r in rules {
            let effect = match r["effect"].as_str() {
                Some("Allow") => Effect::Allow,
                Some("Deny") => Effect::Deny,
                _ => continue,
            };
            let rp = match r["required_purpose"].as_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let res = match r["resource"].as_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let acts: Vec<String> = r["actions"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            engine.add_rule(PolicyRule {
                effect,
                required_purpose: rp,
                resource: res,
                actions: acts,
            });
        }
    }

    let decision = engine.evaluate(subject, resource, action, &graph, &roots);
    write_json(
        out,
        serde_json::json!({
            "decision": if decision.is_allowed() { "ALLOW" } else { "DENY" },
            "reason": format!("{decision}"),
        }),
    )
}

/// Free a string allocated by DDS FFI functions.
///
/// # Safety
/// `s` must be either null or a pointer previously returned by a DDS FFI
/// function via its `out` parameter, and not already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let cs = CString::from_raw(s);
            // Zeroize the buffer before dropping to avoid leaving secrets in memory.
            let bytes = cs.into_bytes_with_nul();
            let mut v = bytes;
            for b in v.iter_mut() {
                // Use volatile write to prevent the compiler from optimizing this away.
                std::ptr::write_volatile(b as *mut u8, 0);
            }
            drop(v);
        }
    }
}

/// Get the DDS library version.
///
/// # Safety
/// `out` must be a valid writable pointer to a `*mut c_char` location.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dds_version(out: *mut *mut c_char) -> i32 {
    write_str(out, env!("CARGO_PKG_VERSION"))
}

fn now_epoch() -> u64 {
    // L-7: never panic across the FFI boundary on a pre-1970 clock
    // (SystemTime::duration_since(UNIX_EPOCH) errors when the system
    // clock is set before 1970). Treat it as 0; downstream callers
    // already tolerate `iat == 0` for legacy/unstamped tokens.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_err(out: *mut *mut c_char, code: i32, msg: &str) -> i32 {
    let _ = write_json(out, serde_json::json!({ "error": msg }));
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    /// C-1 regression: every FFI helper rejects null inputs/outputs
    /// without dereferencing.
    #[test]
    fn null_input_returns_invalid_input() {
        // dds_identity_create with null label
        let mut out: *mut c_char = ptr::null_mut();
        let rc = unsafe { dds_identity_create(ptr::null(), &mut out as *mut _) };
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);
        assert!(
            out.is_null(),
            "out must not be written when input is invalid"
        );

        // dds_identity_create with null out
        let label = CString::new("alice").unwrap();
        let rc = unsafe { dds_identity_create(label.as_ptr(), ptr::null_mut()) };
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);

        // dds_version with null out
        let rc = unsafe { dds_version(ptr::null_mut()) };
        assert_eq!(rc, DDS_ERR_INVALID_INPUT);

        // dds_free_string is null-safe (no panic)
        unsafe { dds_free_string(ptr::null_mut()) };
    }
}
