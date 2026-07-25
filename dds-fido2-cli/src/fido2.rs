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
    fidokey::{
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
        make_credential::make_credential_params::Extension as MakeCredentialExtension,
    },
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

/// How (or whether) this authenticator can achieve **User Verification**.
///
/// The server requires UV for `admin_vouch` / `admin_revoke_vouch`
/// (`service.rs`, AUDIT-2026-06-12 R2), and CTAP2 offers two routes to it.
/// Reading only `clientPin` gets biometric keys wrong: e.g. a Crayonic
/// KeyVault reports `uv = true` + `bioEnroll = true` with `clientPin`
/// **absent** — it has no PIN at all and verifies on-device instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvCapability {
    /// `options.uv == true` — the authenticator verifies the user itself
    /// (fingerprint / on-device). Request `uv: true`; no PIN is involved.
    /// Preferred when offered, since it needs no secret from us.
    BuiltIn,
    /// `clientPin` present and `true` — a PIN is set; UV via the PIN
    /// protocol.
    Pin,
    /// `clientPin` present and `false` — the authenticator supports a PIN
    /// but none has been set yet, and it offers no built-in UV.
    PinNotSet,
    /// Neither route available — this authenticator cannot reach UV, so
    /// vouch ceremonies will be rejected server-side.
    Unavailable,
}

/// Which UV route to actually exercise for one ceremony.
///
/// Maps onto the `ctap-hid-fido2` builders, whose defaults are easy to get
/// wrong: a fresh builder already carries `uv: Some(true)`, and **both**
/// `.pin()` and `.without_pin_and_uv()` reset it to `None`. So the
/// built-in-UV route is expressed by calling *neither*.
pub enum UvMethod<'a> {
    /// Leave the builder's `uv: Some(true)` in place.
    BuiltIn,
    /// PIN-protocol UV.
    Pin(&'a str),
    /// Explicitly no UV (`without_pin_and_uv`). Registration-only; a
    /// vouch assertion made this way is rejected by the server.
    None,
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

    /// Determine how this authenticator can achieve User Verification, by
    /// reading `authenticatorGetInfo`'s `options` map (no touch required).
    ///
    /// `uv == true` is checked **first**: an authenticator that verifies
    /// on-device (biometric) needs no PIN from us, and some such keys do
    /// not implement `clientPin` at all. Only if built-in UV is absent do
    /// we fall back to interpreting `clientPin`.
    pub fn uv_capability(&self) -> Result<UvCapability, String> {
        let info = self
            .inner
            .get_info()
            .map_err(|e| format!("GetInfo failed: {e}"))?;
        let builtin_uv = info.options.iter().any(|(k, v)| k == "uv" && *v);
        if builtin_uv {
            return Ok(UvCapability::BuiltIn);
        }
        Ok(match info.options.iter().find(|(k, _)| k == "clientPin") {
            Some((_, true)) => UvCapability::Pin,
            Some((_, false)) => UvCapability::PinNotSet,
            None => UvCapability::Unavailable,
        })
    }

    /// Set a PIN on an authenticator that doesn't have one yet. Without
    /// this, such a key could never produce a UV-capable assertion,
    /// permanently blocking `vouch`/`revoke-vouch` for that admin. Only
    /// valid when `uv_capability()` returned `PinNotSet` — calling this on
    /// a key that already has a PIN set fails; use `change_pin` instead
    /// (not exposed here — out of scope, changing an existing PIN isn't
    /// part of any ceremony this tool drives). Not needed at all on a
    /// `BuiltIn` (biometric) authenticator.
    pub fn set_new_pin(&self, pin: &str) -> Result<(), String> {
        self.inner
            .set_new_pin(pin)
            .map_err(|e| format!("failed to set a new PIN on the authenticator: {e}"))
    }

    /// Registration ceremony. The server does not gate
    /// `enroll_user`/`admin_setup` on UV, so `uv` may be
    /// [`UvMethod::None`]; pass a real method on a UV-capable key so the
    /// resulting credential is registered as user-verified (this is what
    /// Windows' admin flow does with `requireUserVerification=true`).
    ///
    /// `request_hmac_secret` mirrors the Windows enrollment flow's
    /// `hmacSecret` argument (`platform/windows/native/DdsTrayAgent/
    /// EnrollmentFlow.cpp:372` — "must be enabled at create time"):
    ///
    /// - **`true` for people who will log in to a machine.** The CTAP2
    ///   `hmac-secret` extension makes the authenticator derive a
    ///   per-credential `CredRandom` *at registration*, and the Windows
    ///   logon path uses the assertion-time HMAC output as the raw
    ///   AES-256-GCM key for the credential vault
    ///   (`DdsAuthBridge/CredentialVault.cpp` — the 32-byte output is
    ///   the key, no KDF). It cannot be retrofitted onto an existing
    ///   credential: without it the Auth Bridge hard-rejects the logon
    ///   with "Authenticator did not return hmac-secret output"
    ///   (`DdsAuthBridgeMain.cpp:1688`), *after* DDS-level
    ///   authentication already succeeded — so the failure looks like a
    ///   Windows bug rather than a registration mistake. Requesting it
    ///   here is what lets a key registered on macOS complete a
    ///   first-logon account claim on a Windows node.
    /// - **`false` for admin credentials.** Matches
    ///   `DdsTrayAgent/AdminFlow.cpp:186` (`false /*no hmac-secret*/`):
    ///   admins vouch, they never unseal a vault.
    pub fn make_credential(
        &self,
        rp_id: &str,
        user_id: &[u8],
        user_name: &str,
        display_name: &str,
        request_hmac_secret: bool,
        uv: UvMethod<'_>,
    ) -> Result<EnrollmentOutcome, String> {
        let challenge = verifier::create_challenge();
        let user_entity =
            PublicKeyCredentialUserEntity::new(Some(user_id), Some(user_name), Some(display_name));
        let mut builder =
            MakeCredentialArgsBuilder::new(rp_id, &challenge).user_entity(&user_entity);
        // The builder starts at `uv: Some(true)`; BuiltIn means "leave it".
        builder = match uv {
            UvMethod::BuiltIn => builder,
            UvMethod::Pin(p) => builder.pin(p),
            UvMethod::None => builder.without_pin_and_uv(),
        };
        if request_hmac_secret {
            // Encodes as `{"hmac-secret": true}` in the CTAP2 extensions
            // map. Must be `Some(_)` — the crate unwraps it.
            builder = builder.extensions(&[MakeCredentialExtension::HmacSecret(Some(true))]);
        }
        let args = builder.build();

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
            &attestation.attstmt_x5c,
        );

        Ok(EnrollmentOutcome {
            credential_id: verify_result.credential_id,
            attestation_object,
            client_data_hash: challenge.to_vec(),
        })
    }

    /// Authentication ceremony. `uv` must be [`UvMethod::BuiltIn`] or
    /// [`UvMethod::Pin`] for the assertion to carry the UV flag that
    /// `admin_vouch`/`admin_revoke_vouch` require; [`UvMethod::None`]
    /// only makes sense on an authenticator that reports neither route
    /// ([`UvCapability::Unavailable`]), where the server will reject the
    /// result — a real hardware limitation, not a bug in this tool.
    pub fn get_assertion(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        challenge_b64url: &str,
        uv: UvMethod<'_>,
    ) -> Result<AssertionOutcome, String> {
        // Must match `expected_origin = format!("https://{rp_id}")` and
        // the exact field order in `verify_assertion_common`
        // (dds-node/src/service.rs) byte for byte — this JSON's SHA-256
        // is what the authenticator ultimately signs over.
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"https://{rp_id}"}}"#
        );
        let cdj_bytes = client_data_json.as_bytes();
        let client_data_hash = Sha256::digest(cdj_bytes).to_vec();

        let mut builder =
            GetAssertionArgsBuilder::new(rp_id, cdj_bytes).credential_id(credential_id);
        // The builder starts at `uv: Some(true)`; BuiltIn means "leave it"
        // so the authenticator performs UV itself (fingerprint/on-device).
        builder = match uv {
            UvMethod::BuiltIn => builder,
            UvMethod::Pin(p) => builder.pin(p),
            UvMethod::None => builder.without_pin_and_uv(),
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
/// the parsed `Attestation` struct, so it can be posted to the node.
///
/// **`x5c` must be carried through when the authenticator supplies it.**
/// `packed` attestation has two sub-modes and the server picks between
/// them by presence of `x5c` (`dds-domain/src/fido2.rs`, `verify_packed`):
/// with a chain it verifies `sig` against the **leaf certificate's**
/// public key; without one it treats the statement as self-attestation
/// and verifies against the *credential* key. Dropping the chain
/// therefore doesn't merely lose metadata — it sends the server down the
/// wrong branch, and a perfectly valid full attestation is rejected as
/// `bad attestation signature` (surfacing to the client as HTTP 401
/// `auth_failed`). Any authenticator doing full attestation — e.g. a
/// Crayonic KeyVault — hits this.
///
/// The server's parser matches map keys by name, so key order is free.
fn rebuild_attestation_cbor(
    fmt: &str,
    auth_data: &[u8],
    attstmt_alg: i32,
    attstmt_sig: &[u8],
    attstmt_x5c: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa3); // map(3): fmt, attStmt, authData

    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, fmt);

    cbor_text(&mut out, "attStmt");
    if fmt == "none" || attstmt_sig.is_empty() {
        out.push(0xa0); // empty map
    } else {
        if attstmt_x5c.is_empty() {
            out.push(0xa2); // map(2): alg, sig  (self-attestation)
        } else {
            out.push(0xa3); // map(3): alg, sig, x5c  (full attestation)
        }
        cbor_text(&mut out, "alg");
        cbor_int(&mut out, attstmt_alg as i64);
        cbor_text(&mut out, "sig");
        cbor_bytes(&mut out, attstmt_sig);
        if !attstmt_x5c.is_empty() {
            cbor_text(&mut out, "x5c");
            cbor_array_header(&mut out, attstmt_x5c.len());
            for cert in attstmt_x5c {
                cbor_bytes(&mut out, cert);
            }
        }
    }

    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);

    out
}

/// CBOR array header (major type 4). Certificate chains are short, but
/// individual certs are not — the element encoder handles their length.
fn cbor_array_header(out: &mut Vec<u8>, len: usize) {
    if len < 24 {
        out.push(0x80 | len as u8);
    } else if len < 256 {
        out.push(0x98);
        out.push(len as u8);
    } else {
        out.push(0x99);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
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

#[cfg(test)]
mod tests {
    //! The attestation object is hand-rolled CBOR, so these decode it
    //! back with a real CBOR reader rather than trusting the byte
    //! arithmetic by eye. The `x5c` case is a regression guard: dropping
    //! that field made the node verify a full attestation against the
    //! credential key instead of the leaf cert, rejecting valid keys with
    //! "bad attestation signature" (HTTP 401 `auth_failed`).
    use super::*;
    use ciborium::value::Value;

    fn decode(bytes: &[u8]) -> Value {
        ciborium::de::from_reader(bytes).expect("rebuilt attestation must be valid CBOR")
    }

    fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
        v.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, val)| val)
    }

    #[test]
    fn packed_with_x5c_preserves_the_certificate_chain() {
        let leaf = vec![0xAAu8; 300]; // cert-sized: exercises the 16-bit length path
        let intermediate = vec![0xBBu8; 20]; // and the short path
        let obj = rebuild_attestation_cbor(
            "packed",
            &[0x01, 0x02, 0x03],
            -7,
            &[0x99; 64],
            &[leaf.clone(), intermediate.clone()],
        );

        let v = decode(&obj);
        assert_eq!(get(&v, "fmt").unwrap().as_text(), Some("packed"));

        let att = get(&v, "attStmt").expect("attStmt present");
        assert_eq!(
            att.as_map().unwrap().len(),
            3,
            "attStmt must carry alg, sig AND x5c"
        );
        assert_eq!(
            get(att, "alg").unwrap().as_integer().unwrap(),
            (-7i64).into()
        );
        assert_eq!(get(att, "sig").unwrap().as_bytes().unwrap().len(), 64);

        let x5c = get(att, "x5c").expect("x5c must survive the rebuild");
        let arr = x5c.as_array().expect("x5c is an array");
        assert_eq!(arr.len(), 2, "both chain elements present, in order");
        assert_eq!(arr[0].as_bytes().unwrap(), &leaf);
        assert_eq!(arr[1].as_bytes().unwrap(), &intermediate);
    }

    #[test]
    fn packed_self_attestation_omits_x5c() {
        // No chain supplied => self-attestation sub-mode; emitting an
        // empty x5c array would flip the server to the leaf-cert branch
        // and fail, so the key must be absent entirely.
        let obj = rebuild_attestation_cbor("packed", &[0x01], -7, &[0x42; 64], &[]);
        let v = decode(&obj);
        let att = get(&v, "attStmt").unwrap();
        assert_eq!(att.as_map().unwrap().len(), 2);
        assert!(get(att, "x5c").is_none(), "must not emit an empty x5c");
    }

    #[test]
    fn fmt_none_has_empty_attstmt() {
        let obj = rebuild_attestation_cbor("none", &[0x01], -7, &[], &[]);
        let v = decode(&obj);
        assert_eq!(get(&v, "fmt").unwrap().as_text(), Some("none"));
        assert!(get(&v, "attStmt").unwrap().as_map().unwrap().is_empty());
    }

    #[test]
    fn auth_data_round_trips_verbatim() {
        // authData carries the credential public key and the UV flag the
        // server checks — any corruption here breaks enrollment silently.
        let auth: Vec<u8> = (0..=255u8).cycle().take(500).collect();
        let obj = rebuild_attestation_cbor("packed", &auth, -7, &[0x11; 64], &[]);
        let v = decode(&obj);
        assert_eq!(get(&v, "authData").unwrap().as_bytes().unwrap(), &auth);
    }
}
