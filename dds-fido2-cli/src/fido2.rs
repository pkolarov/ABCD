//! FIDO2 ceremony helpers — raw CTAP2 via `ctap-hid-fido2`, replicating
//! the manual clientDataJSON construction already proven in
//! `dds-fido2-test/src/main.rs` (that tool talks to the same server
//! verification code: `verify_assertion_common` / `verify_enrollment_client_data`
//! in `dds-node/src/service.rs`).
//!
//! Two ceremonies:
//! - `make_credential` (registration) — used by `new-user` and
//!   `admin-setup`. No PIN/UV needed; the server does not gate
//!   registration on UV (only `admin_vouch`/`admin_revoke_vouch` do).
//! - `get_assertion` (authentication) — used by `vouch`/`revoke-vouch`.
//!   MUST achieve User Verification (UV, CTAP2 flags bit 0x04) via a
//!   FIDO2 PIN, or the server hard-rejects it ("AUDIT-2026-06-12 R2").

use base64::Engine;
use ctap_hid_fido2::{
    Cfg, FidoKeyHid, FidoKeyHidFactory,
    fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    verifier,
};
use sha2::{Digest, Sha256};

pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("invalid base64url: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    Set,
    NotSet,
    Unsupported,
}

pub struct Device {
    inner: FidoKeyHid,
}

/// Result of a successful `MakeCredential` ceremony.
pub struct EnrollmentOutcome {
    pub credential_id: Vec<u8>,
    /// CBOR attestation object, ready for `attestation_object_b64`.
    pub attestation_object: Vec<u8>,
    /// Raw challenge bytes used directly as `client_data_hash_b64` —
    /// matches `dds-fido2-test`'s proven approach: `ctap-hid-fido2`'s
    /// MakeCredential API takes the raw challenge and hashes it
    /// internally before wiring it into the CTAP2 command, so there is
    /// no real WebAuthn clientDataJSON to reconstruct here (unlike the
    /// GetAssertion path below, where the caller controls what bytes
    /// get hashed). The server's legacy (no `client_data_json_b64`)
    /// verification path accepts this.
    pub client_data_hash: Vec<u8>,
}

/// Result of a successful `GetAssertion` ceremony.
pub struct AssertionOutcome {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// SHA-256 of the clientDataJSON this tool constructed — must match
    /// what `verify_assertion_common` reconstructs server-side byte for
    /// byte, or verification fails.
    pub client_data_hash: Vec<u8>,
}

impl Device {
    pub fn open() -> Result<Self, String> {
        let inner = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| {
            format!(
                "failed to open FIDO2 authenticator: {e}\n\
                 Plug in a FIDO2 security key (YubiKey, SoloKey, etc.)."
            )
        })?;
        Ok(Self { inner })
    }

    /// CTAP2 `authenticatorGetInfo`'s `clientPin` option, three-valued:
    /// the key is present-and-true (PIN set, UV via PIN available),
    /// present-and-false (PIN capability exists but none set yet — can
    /// call `set_new_pin`), or absent entirely (no PIN capability at
    /// all, e.g. some resident-key-only or biometric-only devices —
    /// `set_new_pin` will fail on these).
    pub fn pin_status(&self) -> Result<PinStatus, String> {
        let info = self
            .inner
            .get_info()
            .map_err(|e| format!("GetInfo failed: {e}"))?;
        Ok(match info.options.iter().find(|(k, _)| k == "clientPin") {
            Some((_, true)) => PinStatus::Set,
            Some((_, false)) => PinStatus::NotSet,
            None => PinStatus::Unsupported,
        })
    }

    /// Set a PIN on an authenticator that doesn't have one yet. Without
    /// this, a fresh security key could never produce a UV-capable
    /// assertion, permanently blocking `vouch`/`revoke-vouch` for that
    /// admin. Only valid when `pin_status()` returned `NotSet` — calling
    /// this on a key that already has a PIN set fails; use `change_pin`
    /// instead (not exposed here — out of scope, changing an existing
    /// PIN isn't part of any ceremony this tool drives).
    pub fn set_new_pin(&self, pin: &str) -> Result<(), String> {
        self.inner
            .set_new_pin(pin)
            .map_err(|e| format!("failed to set a new PIN on the authenticator: {e}"))
    }

    /// Registration ceremony. No PIN/UV required — the server does not
    /// gate `enroll_user`/`admin_setup` on UV, only on the credential
    /// existing at all.
    pub fn make_credential(
        &self,
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        display_name: &str,
    ) -> Result<EnrollmentOutcome, String> {
        let challenge = verifier::create_challenge();
        let user_entity = PublicKeyCredentialUserEntity::new(
            Some(user_id),
            Some(user_name),
            Some(display_name),
        );
        let args = MakeCredentialArgsBuilder::new(rp_id, &challenge)
            .user_entity(&user_entity)
            .without_pin_and_uv()
            .build();

        let attestation = self
            .inner
            .make_credential_with_args(&args)
            .map_err(|e| format!("makeCredential failed: {e}"))?;

        let verify_result = verifier::verify_attestation(rp_id, &challenge, &attestation);
        if !verify_result.is_success {
            return Err("local attestation verification failed".to_string());
        }

        let attestation_object = rebuild_attestation_cbor(
            &attestation.fmt,
            &attestation.auth_data,
            attestation.attstmt_alg,
            &attestation.attstmt_sig,
        );

        Ok(EnrollmentOutcome {
            credential_id: verify_result.credential_id,
            attestation_object,
            client_data_hash: challenge.to_vec(),
        })
    }

    /// Authentication ceremony with User Verification. `pin` MUST be
    /// `Some` for the resulting assertion to carry the UV flag the
    /// server requires for `admin_vouch`/`admin_revoke_vouch`; `None`
    /// only makes sense against an authenticator with no PIN capability
    /// at all (`has_pin_configured` returned `Ok(false)` with no
    /// `clientPin` option present), where the server will simply reject
    /// the resulting assertion — a real hardware limitation, not a bug
    /// in this tool.
    pub fn get_assertion(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        challenge_b64url: &str,
        pin: Option<&str>,
    ) -> Result<AssertionOutcome, String> {
        // Must match `expected_origin = format!("https://{rp_id}")` and
        // the exact field order in `verify_assertion_common`
        // (dds-node/src/service.rs) byte for byte — this JSON's SHA-256
        // is what the authenticator ultimately signs over.
        let client_data_json =
            format!(r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{rp_id}"}}"#);
        let cdj_bytes = client_data_json.as_bytes();
        let client_data_hash = Sha256::digest(cdj_bytes).to_vec();

        let mut builder = GetAssertionArgsBuilder::new(rp_id, cdj_bytes).credential_id(credential_id);
        builder = match pin {
            Some(p) => builder.pin(p),
            None => builder.without_pin_and_uv(),
        };
        let args = builder.build();

        let assertions = self
            .inner
            .get_assertion_with_args(&args)
            .map_err(|e| format!("getAssertion failed: {e}"))?;
        let assertion = assertions
            .into_iter()
            .next()
            .ok_or_else(|| "getAssertion returned no assertions".to_string())?;

        Ok(AssertionOutcome {
            authenticator_data: assertion.auth_data,
            signature: assertion.signature,
            client_data_hash,
        })
    }
}

/// Rebuild a CBOR attestation object (`{fmt, attStmt, authData}`) from
/// the parsed `Attestation` struct — verbatim from `dds-fido2-test`,
/// which this server-verification path is already proven against.
fn rebuild_attestation_cbor(
    fmt: &str,
    auth_data: &[u8],
    attstmt_alg: i32,
    attstmt_sig: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa3); // map(3)

    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, fmt);

    cbor_text(&mut out, "attStmt");
    if fmt == "none" || attstmt_sig.is_empty() {
        out.push(0xa0); // empty map
    } else {
        out.push(0xa2); // map(2): alg + sig
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, attstmt_alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, attstmt_sig);
    }

    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);

    out
}

fn cbor_text(out: &mut Vec<u8>, s: &str) {
    let len = s.len();
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len < 256 {
        out.push(0x78);
        out.push(len as u8);
    } else {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(s.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let len = b.len();
    if len < 24 {
        out.push(0x40 | len as u8);
    } else if len < 256 {
        out.push(0x58);
        out.push(len as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(b);
}

fn cbor_int(out: &mut Vec<u8>, val: i64) {
    if val >= 0 {
        let v = val as u64;
        if v < 24 {
            out.push(v as u8);
        } else if v < 256 {
            out.push(0x18);
            out.push(v as u8);
        } else {
            out.push(0x19);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    } else {
        let v = (-1 - val) as u64;
        if v < 24 {
            out.push(0x20 | v as u8);
        } else if v < 256 {
            out.push(0x38);
            out.push(v as u8);
        } else {
            out.push(0x39);
            out.extend_from_slice(&(v as u16).to_be_bytes());
        }
    }
}
