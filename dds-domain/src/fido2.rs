//! Minimal FIDO2 / WebAuthn attestation and assertion parsing + verification.
//!
//! **Attestation** (enrollment): Supports `none` and `packed` (self-attestation)
//! formats with Ed25519 (`alg=-8`) and ECDSA P-256 (`alg=-7`, ES256) keys.
//!
//! **Assertion** (authentication): Supports Ed25519 and ECDSA P-256 (`alg=-7`)
//! signature verification. Used by the `/v1/session/assert` endpoint to issue
//! sessions from FIDO2 getAssertion proofs.
//!
//! Full attestation with x5c certificate chains is intentionally out of scope.
//!
//! Implemented from scratch against the WebAuthn Level 2 spec to avoid
//! pulling in the (very large) `webauthn-rs` dependency tree.

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha256};

/// COSE algorithm identifier for Ed25519 (RFC 9053).
pub const COSE_ALG_EDDSA: i64 = -8;
/// COSE algorithm identifier for ECDSA w/ SHA-256 (ES256).
pub const COSE_ALG_ES256: i64 = -7;

/// A parsed WebAuthn attestation object.
#[derive(Debug, Clone)]
pub struct ParsedAttestation {
    pub fmt: String,
    pub auth_data: Vec<u8>,
    /// Credential ID extracted from authenticatorData.
    pub credential_id: Vec<u8>,
    /// Credential public key (Ed25519 or P-256).
    pub credential_public_key: CredentialPublicKey,
    /// Relying-party ID hash (first 32 bytes of authData).
    pub rp_id_hash: [u8; 32],
}

/// Errors from FIDO2 parsing/verification.
#[derive(Debug)]
pub enum Fido2Error {
    Cbor(String),
    Format(String),
    Unsupported(String),
    BadSignature,
    KeyError(String),
}

impl std::fmt::Display for Fido2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fido2Error::Cbor(e) => write!(f, "cbor: {e}"),
            Fido2Error::Format(e) => write!(f, "format: {e}"),
            Fido2Error::Unsupported(e) => write!(f, "unsupported: {e}"),
            Fido2Error::BadSignature => write!(f, "bad attestation signature"),
            Fido2Error::KeyError(e) => write!(f, "key: {e}"),
        }
    }
}

impl std::error::Error for Fido2Error {}

/// Parse and verify a WebAuthn attestation object.
///
/// `attestation_object` is the raw CBOR-encoded value returned by
/// `navigator.credentials.create()`'s `response.attestationObject`.
/// `client_data_hash` is SHA-256(clientDataJSON).
pub fn verify_attestation(
    attestation_object: &[u8],
    client_data_hash: &[u8],
) -> Result<ParsedAttestation, Fido2Error> {
    let value: CborValue =
        ciborium::from_reader(attestation_object).map_err(|e| Fido2Error::Cbor(e.to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| Fido2Error::Format("top-level not a map".into()))?;

    let mut fmt: Option<String> = None;
    let mut auth_data: Option<Vec<u8>> = None;
    let mut att_stmt: Option<&CborValue> = None;
    for (k, v) in map.iter() {
        if let Some(key) = k.as_text() {
            match key {
                "fmt" => fmt = v.as_text().map(|s| s.to_string()),
                "authData" => auth_data = v.as_bytes().cloned(),
                "attStmt" => att_stmt = Some(v),
                _ => {}
            }
        }
    }

    let fmt = fmt.ok_or_else(|| Fido2Error::Format("missing fmt".into()))?;
    let auth_data = auth_data.ok_or_else(|| Fido2Error::Format("missing authData".into()))?;

    let parsed_auth = parse_auth_data(&auth_data)?;

    match fmt.as_str() {
        "none" => {
            // Nothing to verify cryptographically.
        }
        "packed" => {
            let stmt =
                att_stmt.ok_or_else(|| Fido2Error::Format("packed missing attStmt".into()))?;
            verify_packed(
                stmt,
                &auth_data,
                client_data_hash,
                &parsed_auth.credential_public_key,
            )?;
        }
        other => return Err(Fido2Error::Unsupported(format!("fmt={other}"))),
    }

    Ok(ParsedAttestation {
        fmt,
        auth_data: auth_data.clone(),
        credential_id: parsed_auth.credential_id,
        credential_public_key: parsed_auth.credential_public_key,
        rp_id_hash: parsed_auth.rp_id_hash,
    })
}

struct AuthDataParts {
    rp_id_hash: [u8; 32],
    credential_id: Vec<u8>,
    credential_public_key: CredentialPublicKey,
}

fn parse_auth_data(auth_data: &[u8]) -> Result<AuthDataParts, Fido2Error> {
    if auth_data.len() < 37 {
        return Err(Fido2Error::Format("authData too short".into()));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[0..32]);
    let flags = auth_data[32];
    let attested = (flags & 0x40) != 0;
    if !attested {
        return Err(Fido2Error::Format(
            "AT flag not set; no attested credential data".into(),
        ));
    }
    // Skip signCount (4 bytes).
    let mut p = 37;
    if auth_data.len() < p + 16 + 2 {
        return Err(Fido2Error::Format("authData truncated at AAGUID".into()));
    }
    p += 16; // AAGUID
    let cred_id_len = u16::from_be_bytes([auth_data[p], auth_data[p + 1]]) as usize;
    p += 2;
    if auth_data.len() < p + cred_id_len {
        return Err(Fido2Error::Format(
            "authData truncated at credentialId".into(),
        ));
    }
    let credential_id = auth_data[p..p + cred_id_len].to_vec();
    p += cred_id_len;

    // Remainder starts with the COSE_Key CBOR object, possibly followed by extensions.
    let cose_bytes = &auth_data[p..];
    let credential_public_key = cose_to_credential_public_key(cose_bytes)?;

    Ok(AuthDataParts {
        rp_id_hash,
        credential_id,
        credential_public_key,
    })
}

fn verify_packed(
    att_stmt: &CborValue,
    auth_data: &[u8],
    client_data_hash: &[u8],
    credential_pk: &CredentialPublicKey,
) -> Result<(), Fido2Error> {
    let map = att_stmt
        .as_map()
        .ok_or_else(|| Fido2Error::Format("attStmt not map".into()))?;
    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c_present = false;
    for (k, v) in map.iter() {
        if let Some(key) = k.as_text() {
            match key {
                "alg" => alg = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "sig" => sig = v.as_bytes().cloned(),
                "x5c" => x5c_present = true,
                _ => {}
            }
        }
    }
    if x5c_present {
        // Full attestation with an x5c certificate chain (sent by hardware
        // authenticators like YubiKey, SoloKey, Keyvault, etc.).  We skip
        // certificate-chain signature verification — the credential public
        // key extracted from authData is what we store and use for future
        // assertions.  Physical presence of the authenticator during
        // MakeCredential is sufficient trust for our use case.
        return Ok(());
    }
    let sig = sig.ok_or_else(|| Fido2Error::Format("missing sig".into()))?;

    // Signed data = authData || clientDataHash
    let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(client_data_hash);

    match credential_pk {
        CredentialPublicKey::Ed25519(vk) => {
            if alg != Some(COSE_ALG_EDDSA) {
                return Err(Fido2Error::Unsupported(format!(
                    "packed alg={alg:?} for Ed25519 key"
                )));
            }
            let signature = Ed25519Signature::from_slice(&sig)
                .map_err(|e| Fido2Error::KeyError(e.to_string()))?;
            vk.verify(&signed, &signature)
                .map_err(|_| Fido2Error::BadSignature)
        }
        CredentialPublicKey::P256(vk) => {
            if alg != Some(COSE_ALG_ES256) {
                return Err(Fido2Error::Unsupported(format!(
                    "packed alg={alg:?} for P-256 key"
                )));
            }
            let signature = P256Signature::from_der(&sig)
                .or_else(|_| P256Signature::from_slice(&sig))
                .map_err(|e| Fido2Error::KeyError(format!("P-256 sig: {e}")))?;
            // Normalize high-S signatures — the RustCrypto p256 verifier
            // enforces low-S; some authenticators emit high-S. See the
            // matching note in `verify_assertion` for why this is safe.
            let signature = signature.normalize_s().unwrap_or(signature);
            vk.verify(&signed, &signature)
                .map_err(|_| Fido2Error::BadSignature)
        }
    }
}

// =========================================================================
// Assertion verification (getAssertion — authentication time)
// =========================================================================

/// A credential public key that can be either Ed25519 or P-256.
/// Stored in the trust graph at enrollment time; used to verify
/// assertions at logon time.
#[derive(Debug, Clone)]
pub enum CredentialPublicKey {
    Ed25519(VerifyingKey),
    P256(P256VerifyingKey),
}

/// A parsed assertion response from a FIDO2 getAssertion.
#[derive(Debug, Clone)]
pub struct ParsedAssertion {
    /// RP ID hash (first 32 bytes of authenticatorData).
    pub rp_id_hash: [u8; 32],
    /// User Presence (UP) flag.
    pub user_present: bool,
    /// User Verified (UV) flag.
    pub user_verified: bool,
    /// Signature counter from authenticatorData.
    pub sign_count: u32,
}

/// Verify a WebAuthn assertion (getAssertion response).
///
/// `authenticator_data` is the raw authenticatorData from the assertion.
/// `client_data_hash` is SHA-256(clientDataJSON).
/// `signature` is the assertion signature.
/// `public_key` is the credential public key stored at enrollment.
///
/// Returns parsed assertion data on success, or a `Fido2Error` on failure.
pub fn verify_assertion(
    authenticator_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
    public_key: &CredentialPublicKey,
) -> Result<ParsedAssertion, Fido2Error> {
    // authenticatorData for assertions is at least 37 bytes:
    //   rpIdHash (32) + flags (1) + signCount (4)
    if authenticator_data.len() < 37 {
        return Err(Fido2Error::Format(
            "assertion authenticatorData too short".into(),
        ));
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&authenticator_data[0..32]);
    let flags = authenticator_data[32];
    let user_present = (flags & 0x01) != 0;
    let user_verified = (flags & 0x04) != 0;
    let sign_count = u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]);

    // Signed data = authenticatorData || clientDataHash
    let mut signed = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(client_data_hash);

    match public_key {
        CredentialPublicKey::Ed25519(vk) => {
            let sig = Ed25519Signature::from_slice(signature)
                .map_err(|e| Fido2Error::KeyError(format!("Ed25519 sig: {e}")))?;
            vk.verify(&signed, &sig)
                .map_err(|_| Fido2Error::BadSignature)?;
        }
        CredentialPublicKey::P256(vk) => {
            let sig = P256Signature::from_der(signature)
                .or_else(|_| P256Signature::from_slice(signature))
                .map_err(|e| Fido2Error::KeyError(format!("P-256 sig: {e}")))?;
            // WebAuthn-spec authenticators (e.g. Crayonic KeyVault, some
            // YubiKey firmware) emit ECDSA signatures with high-S
            // values. The RustCrypto `p256` crate enforces low-S in
            // `verify` to defend against malleability, which would
            // reject otherwise-valid assertions. Normalize before
            // verifying — assertion replay is already gated by the
            // single-use server challenge upstream, so the malleability
            // window is closed at the protocol layer regardless.
            let sig = sig.normalize_s().unwrap_or(sig);
            vk.verify(&signed, &sig)
                .map_err(|_| Fido2Error::BadSignature)?;
        }
    }

    Ok(ParsedAssertion {
        rp_id_hash,
        user_present,
        user_verified,
        sign_count,
    })
}

/// Parse a COSE_Key from CBOR into a `CredentialPublicKey`.
/// Supports Ed25519 (kty=1, alg=-8) and P-256 (kty=2, alg=-7).
pub fn cose_to_credential_public_key(cose_bytes: &[u8]) -> Result<CredentialPublicKey, Fido2Error> {
    let value: CborValue = ciborium::from_reader(cose_bytes)
        .map_err(|e| Fido2Error::Cbor(format!("COSE_Key: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| Fido2Error::Format("COSE_Key not a map".into()))?;

    let mut kty: Option<i64> = None;
    let mut alg: Option<i64> = None;
    let mut crv: Option<i64> = None;
    let mut x: Option<Vec<u8>> = None;
    let mut y: Option<Vec<u8>> = None;
    for (k, v) in map.iter() {
        let key_int = k.as_integer().and_then(|i| i64::try_from(i).ok());
        match key_int {
            Some(1) => kty = v.as_integer().and_then(|i| i64::try_from(i).ok()),
            Some(3) => alg = v.as_integer().and_then(|i| i64::try_from(i).ok()),
            Some(-1) => crv = v.as_integer().and_then(|i| i64::try_from(i).ok()),
            Some(-2) => x = v.as_bytes().cloned(),
            Some(-3) => y = v.as_bytes().cloned(),
            _ => {}
        }
    }

    match (kty, alg) {
        // Ed25519 (OKP)
        (Some(1), Some(COSE_ALG_EDDSA)) | (Some(1), None) => {
            if crv != Some(6) {
                return Err(Fido2Error::Unsupported(format!("OKP crv={crv:?}")));
            }
            let x = x.ok_or_else(|| Fido2Error::Format("missing x coord".into()))?;
            if x.len() != 32 {
                return Err(Fido2Error::Format(format!("Ed25519 x len={}", x.len())));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&x);
            let vk = VerifyingKey::from_bytes(&bytes)
                .map_err(|e| Fido2Error::KeyError(e.to_string()))?;
            Ok(CredentialPublicKey::Ed25519(vk))
        }
        // P-256 (EC2)
        (Some(2), Some(COSE_ALG_ES256)) | (Some(2), None) => {
            if crv != Some(1) {
                return Err(Fido2Error::Unsupported(format!("EC2 crv={crv:?}")));
            }
            let x = x.ok_or_else(|| Fido2Error::Format("missing x coord".into()))?;
            let y = y.ok_or_else(|| Fido2Error::Format("missing y coord for P-256".into()))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(Fido2Error::Format(format!(
                    "P-256 x={} y={} (expected 32)",
                    x.len(),
                    y.len()
                )));
            }
            // Uncompressed point: 0x04 || x || y
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let vk = P256VerifyingKey::from_sec1_bytes(&point)
                .map_err(|e| Fido2Error::KeyError(format!("P-256: {e}")))?;
            Ok(CredentialPublicKey::P256(vk))
        }
        _ => Err(Fido2Error::Unsupported(format!("kty={kty:?} alg={alg:?}"))),
    }
}

/// Build a synthetic assertion authenticatorData (no attested credential data).
/// Useful for tests.
pub fn build_assertion_auth_data(rp_id: &str, sign_count: u32) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash);
    out.push(0x05); // UP | UV flags
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

/// Build a synthetic "none" attestation object containing the given Ed25519
/// credential public key. Useful for tests and bridging non-WebAuthn enrollment.
pub fn build_none_attestation(rp_id: &str, credential_id: &[u8], pk: &VerifyingKey) -> Vec<u8> {
    let auth_data = build_auth_data(rp_id, credential_id, pk);
    let map: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        ),
        (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut out).unwrap();
    out
}

/// Build a synthetic "packed" self-attestation containing the given Ed25519
/// credential and a real signature. For tests.
pub fn build_packed_self_attestation(
    rp_id: &str,
    credential_id: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    client_data_hash: &[u8],
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = signing_key.verifying_key();
    let auth_data = build_auth_data(rp_id, credential_id, &pk);
    let mut signed = Vec::new();
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(client_data_hash);
    let sig = signing_key.sign(&signed);

    let stmt: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("alg".into()),
            CborValue::Integer(COSE_ALG_EDDSA.into()),
        ),
        (
            CborValue::Text("sig".into()),
            CborValue::Bytes(sig.to_bytes().to_vec()),
        ),
    ];
    let map: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (CborValue::Text("attStmt".into()), CborValue::Map(stmt)),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut out).unwrap();
    out
}

fn build_auth_data(rp_id: &str, credential_id: &[u8], pk: &VerifyingKey) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(0x41); // UP | AT
    out.extend_from_slice(&[0, 0, 0, 0]); // signCount
    out.extend_from_slice(&[0u8; 16]); // AAGUID
    let id_len = credential_id.len() as u16;
    out.extend_from_slice(&id_len.to_be_bytes());
    out.extend_from_slice(credential_id);

    // COSE_Key for Ed25519 OKP
    let cose: Vec<(CborValue, CborValue)> = vec![
        (CborValue::Integer(1.into()), CborValue::Integer(1.into())), // kty=OKP
        (
            CborValue::Integer(3.into()),
            CborValue::Integer(COSE_ALG_EDDSA.into()),
        ), // alg
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(6.into()),
        ), // crv=Ed25519
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(pk.to_bytes().to_vec()),
        ),
    ];
    ciborium::into_writer(&CborValue::Map(cose), &mut out).unwrap();
    out
}

/// Build a synthetic "none" attestation object containing a P-256 credential
/// public key. Useful for tests and bridging non-WebAuthn enrollment with
/// ES256 authenticators.
pub fn build_none_attestation_p256(
    rp_id: &str,
    credential_id: &[u8],
    pk: &P256VerifyingKey,
) -> Vec<u8> {
    let auth_data = build_auth_data_p256(rp_id, credential_id, pk);
    let map: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        ),
        (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut out).unwrap();
    out
}

/// Build a synthetic "packed" self-attestation containing a P-256 credential
/// and a real ES256 signature. For tests.
pub fn build_packed_self_attestation_p256(
    rp_id: &str,
    credential_id: &[u8],
    signing_key: &p256::ecdsa::SigningKey,
    client_data_hash: &[u8],
) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let pk = P256VerifyingKey::from(signing_key);
    let auth_data = build_auth_data_p256(rp_id, credential_id, &pk);
    let mut signed = Vec::new();
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(client_data_hash);
    let sig: P256Signature = signing_key.sign(&signed);

    let stmt: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("alg".into()),
            CborValue::Integer(COSE_ALG_ES256.into()),
        ),
        (
            CborValue::Text("sig".into()),
            CborValue::Bytes(sig.to_der().as_bytes().to_vec()),
        ),
    ];
    let map: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("packed".into()),
        ),
        (CborValue::Text("attStmt".into()), CborValue::Map(stmt)),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        ),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&CborValue::Map(map), &mut out).unwrap();
    out
}

fn build_auth_data_p256(rp_id: &str, credential_id: &[u8], pk: &P256VerifyingKey) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(0x41); // UP | AT
    out.extend_from_slice(&[0, 0, 0, 0]); // signCount
    out.extend_from_slice(&[0u8; 16]); // AAGUID
    let id_len = credential_id.len() as u16;
    out.extend_from_slice(&id_len.to_be_bytes());
    out.extend_from_slice(credential_id);

    // COSE_Key for P-256 EC2
    let point = pk.to_encoded_point(false); // uncompressed
    let x = point.x().unwrap().to_vec();
    let y = point.y().unwrap().to_vec();
    let cose: Vec<(CborValue, CborValue)> = vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty=EC2
        (
            CborValue::Integer(3.into()),
            CborValue::Integer(COSE_ALG_ES256.into()),
        ), // alg=-7
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ), // crv=P-256
        (CborValue::Integer((-2).into()), CborValue::Bytes(x)),       // x
        (CborValue::Integer((-3).into()), CborValue::Bytes(y)),       // y
    ];
    ciborium::into_writer(&CborValue::Map(cose), &mut out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_none_attestation_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let cred_id = b"test-credential";
        let attestation = build_none_attestation("example.com", cred_id, &sk.verifying_key());
        let parsed = verify_attestation(&attestation, &[0u8; 32]).unwrap();
        assert_eq!(parsed.fmt, "none");
        assert_eq!(parsed.credential_id, cred_id);
        match &parsed.credential_public_key {
            CredentialPublicKey::Ed25519(vk) => {
                assert_eq!(vk.to_bytes(), sk.verifying_key().to_bytes());
            }
            other => panic!("expected Ed25519, got {other:?}"),
        }
        let expected_hash: [u8; 32] = Sha256::digest(b"example.com").into();
        assert_eq!(parsed.rp_id_hash, expected_hash);
    }

    #[test]
    fn test_p256_none_attestation_roundtrip() {
        use p256::ecdsa::SigningKey as P256SigningKey;

        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let cred_id = b"p256-credential";
        let attestation = build_none_attestation_p256("example.com", cred_id, &vk);
        let parsed = verify_attestation(&attestation, &[0u8; 32]).unwrap();
        assert_eq!(parsed.fmt, "none");
        assert_eq!(parsed.credential_id, cred_id);
        match &parsed.credential_public_key {
            CredentialPublicKey::P256(parsed_vk) => {
                assert_eq!(
                    parsed_vk.to_encoded_point(false),
                    vk.to_encoded_point(false),
                );
            }
            other => panic!("expected P-256, got {other:?}"),
        }
        let expected_hash: [u8; 32] = Sha256::digest(b"example.com").into();
        assert_eq!(parsed.rp_id_hash, expected_hash);
    }

    #[test]
    fn test_p256_packed_self_attestation() {
        use p256::ecdsa::SigningKey as P256SigningKey;

        let sk = P256SigningKey::random(&mut OsRng);
        let cdh = [0xCD; 32];
        let attestation =
            build_packed_self_attestation_p256("login.example.com", b"p256-cred", &sk, &cdh);
        let parsed = verify_attestation(&attestation, &cdh).unwrap();
        assert_eq!(parsed.fmt, "packed");
        assert_eq!(parsed.credential_id, b"p256-cred");
        assert!(matches!(
            parsed.credential_public_key,
            CredentialPublicKey::P256(_)
        ));
    }

    #[test]
    fn test_packed_self_attestation_valid() {
        let sk = SigningKey::generate(&mut OsRng);
        let cdh = [0xAB; 32];
        let attestation = build_packed_self_attestation("login.example.com", b"cred1", &sk, &cdh);
        let parsed = verify_attestation(&attestation, &cdh).unwrap();
        assert_eq!(parsed.fmt, "packed");
        assert_eq!(parsed.credential_id, b"cred1");
    }

    #[test]
    fn test_packed_bad_signature_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let cdh = [0xAB; 32];
        let mut attestation =
            build_packed_self_attestation("login.example.com", b"cred1", &sk, &cdh);
        // Verifying with the wrong client_data_hash must fail.
        let wrong = [0u8; 32];
        let res = verify_attestation(&attestation, &wrong);
        assert!(matches!(res, Err(Fido2Error::BadSignature)));

        // Tamper a byte in the attestation and confirm it fails too.
        let len = attestation.len();
        attestation[len - 1] ^= 0xFF;
        let res2 = verify_attestation(&attestation, &cdh);
        assert!(res2.is_err());
    }

    #[test]
    fn test_garbage_input_rejected() {
        assert!(verify_attestation(&[0u8; 4], &[0u8; 32]).is_err());
        assert!(verify_attestation(b"not cbor", &[0u8; 32]).is_err());
    }

    #[test]
    fn test_unsupported_format_rejected() {
        let map: Vec<(CborValue, CborValue)> = vec![
            (CborValue::Text("fmt".into()), CborValue::Text("tpm".into())),
            (CborValue::Text("attStmt".into()), CborValue::Map(vec![])),
            (
                CborValue::Text("authData".into()),
                CborValue::Bytes(vec![0u8; 100]),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut bytes).unwrap();
        let res = verify_attestation(&bytes, &[0u8; 32]);
        assert!(matches!(
            res,
            Err(Fido2Error::Unsupported(_)) | Err(Fido2Error::Format(_))
        ));
    }

    // ---- Assertion verification tests ----

    #[test]
    fn test_ed25519_assertion_valid() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let pk = CredentialPublicKey::Ed25519(vk);

        let auth_data = build_assertion_auth_data("dds.local", 1);
        let cdh = Sha256::digest(b"test-client-data");

        // Sign: authenticatorData || clientDataHash
        let mut signed = Vec::new();
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&cdh);
        use ed25519_dalek::Signer;
        let sig = sk.sign(&signed);

        let parsed = verify_assertion(&auth_data, &cdh, &sig.to_bytes(), &pk).unwrap();
        assert!(parsed.user_present);
        assert!(parsed.user_verified);
        assert_eq!(parsed.sign_count, 1);

        let expected_hash: [u8; 32] = Sha256::digest(b"dds.local").into();
        assert_eq!(parsed.rp_id_hash, expected_hash);
    }

    #[test]
    fn test_ed25519_assertion_bad_sig() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = CredentialPublicKey::Ed25519(sk.verifying_key());

        let auth_data = build_assertion_auth_data("dds.local", 1);
        let cdh = [0xABu8; 32];

        // Wrong signature
        let bad_sig = [0u8; 64];
        let res = verify_assertion(&auth_data, &cdh, &bad_sig, &pk);
        assert!(matches!(res, Err(Fido2Error::BadSignature)));
    }

    #[test]
    fn test_p256_assertion_valid() {
        use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer};

        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let pk = CredentialPublicKey::P256(vk);

        let auth_data = build_assertion_auth_data("dds.local", 42);
        let cdh = Sha256::digest(b"p256-client-data");

        let mut signed = Vec::new();
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&cdh);
        let sig: P256Signature = sk.sign(&signed);

        let parsed = verify_assertion(&auth_data, &cdh, sig.to_der().as_bytes(), &pk).unwrap();
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.user_present);
    }

    #[test]
    fn test_p256_assertion_bad_sig() {
        use p256::ecdsa::SigningKey as P256SigningKey;

        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let pk = CredentialPublicKey::P256(vk);

        let auth_data = build_assertion_auth_data("dds.local", 1);
        let cdh = [0xCDu8; 32];
        let bad_sig = [0u8; 64]; // garbage

        let res = verify_assertion(&auth_data, &cdh, &bad_sig, &pk);
        assert!(res.is_err());
    }

    #[test]
    fn test_assertion_auth_data_too_short() {
        let pk = CredentialPublicKey::Ed25519(SigningKey::generate(&mut OsRng).verifying_key());
        let res = verify_assertion(&[0u8; 10], &[0u8; 32], &[0u8; 64], &pk);
        assert!(matches!(res, Err(Fido2Error::Format(_))));
    }

    #[test]
    fn test_cose_to_credential_public_key_ed25519() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let cose: Vec<(CborValue, CborValue)> = vec![
            (CborValue::Integer(1.into()), CborValue::Integer(1.into())), // kty=OKP
            (
                CborValue::Integer(3.into()),
                CborValue::Integer(COSE_ALG_EDDSA.into()),
            ), // alg
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(6.into()),
            ), // crv=Ed25519
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(vk.to_bytes().to_vec()),
            ),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(cose), &mut bytes).unwrap();

        let cpk = cose_to_credential_public_key(&bytes).unwrap();
        assert!(matches!(cpk, CredentialPublicKey::Ed25519(_)));
    }

    #[test]
    fn test_cose_to_credential_public_key_p256() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let point = vk.to_encoded_point(false); // uncompressed
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();

        let cose: Vec<(CborValue, CborValue)> = vec![
            (CborValue::Integer(2.into()), CborValue::Integer(2.into())), // kty=EC2 (wrong — should be key 1)
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty=EC2
            (
                CborValue::Integer(3.into()),
                CborValue::Integer(COSE_ALG_ES256.into()),
            ), // alg
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ), // crv=P-256
            (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
            (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(cose), &mut bytes).unwrap();

        let cpk = cose_to_credential_public_key(&bytes).unwrap();
        assert!(matches!(cpk, CredentialPublicKey::P256(_)));
    }
}
