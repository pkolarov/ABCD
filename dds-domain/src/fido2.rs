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

/// Maximum credential ID length per CTAP2.1 §6.1 (`MAX_CREDENTIAL_ID_LENGTH`).
/// WebAuthn §4 also recommends Relying Parties ignore credential IDs >= 1024 bytes.
/// Closes Claude_sec_review.md I-8: prevents a malformed authData from
/// declaring a multi-kilobyte credential id and forcing a large allocation.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

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
    /// Authenticator Attestation GUID, bytes 37..53 of authData. All-zero
    /// for `fmt = "none"` and self-attested platform authenticators.
    /// Phase 1 of `docs/fido2-attestation-allowlist.md` — the dds-node
    /// service rejects enrollment when a non-empty
    /// `fido2_allowed_aaguids` list is configured and this value is
    /// not in it.
    pub aaguid: [u8; 16],
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
///
/// **A-1 step-1 (security review, 2026-04-25)**: `fmt = "none"`
/// (no attestation at all) is gated behind
/// `allow_unattested_credentials`. The default deployment posture
/// (set by [`crate::Service`] / [`DomainConfig`]) is `false`, so a
/// caller that hands in an attestation object with `fmt = "none"`
/// is rejected with [`Fido2Error::Unsupported`]. Set the parameter
/// to `true` only on dev/test paths or when the operator has
/// explicitly opted in via configuration. Packed attestation
/// (whether self-attested with no `x5c` or full with an `x5c`
/// chain) is verified regardless of the flag.
///
/// Re-parse callers (e.g. assertion-time sanity checks where the
/// attestation was already trusted at original enrollment) should
/// pass `allow_unattested_credentials = true` so the re-parse does
/// not regress on previously-stored credentials.
pub fn verify_attestation(
    attestation_object: &[u8],
    client_data_hash: &[u8],
    allow_unattested_credentials: bool,
) -> Result<ParsedAttestation, Fido2Error> {
    // Bounded depth: attestation_object is supplied by an arbitrary
    // local HTTP API caller. Security review I-6.
    let value: CborValue = dds_core::cbor_bounded::from_reader(attestation_object)
        .map_err(|e| Fido2Error::Cbor(e.to_string()))?;
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
            // **A-1 step-1**: refuse `fmt = "none"` unless the caller
            // has explicitly opted in. Callers that accept it should
            // log the decision at WARN — `dds-domain` stays
            // `tracing`-free, so the WARN happens on the caller side
            // (see `Service::enroll_user` etc.).
            if !allow_unattested_credentials {
                return Err(Fido2Error::Unsupported(
                    "fmt=none rejected: no attestation provided and \
                     allow_unattested_credentials is false (A-1)"
                        .into(),
                ));
            }
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
        aaguid: parsed_auth.aaguid,
    })
}

struct AuthDataParts {
    rp_id_hash: [u8; 32],
    credential_id: Vec<u8>,
    credential_public_key: CredentialPublicKey,
    aaguid: [u8; 16],
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
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&auth_data[p..p + 16]);
    p += 16; // AAGUID
    let cred_id_len = u16::from_be_bytes([auth_data[p], auth_data[p + 1]]) as usize;
    p += 2;
    // I-8: enforce CTAP2.1 §6.1 MAX_CREDENTIAL_ID_LENGTH (1023). Without
    // this, a peer-supplied authData could declare a 64 KiB credential id
    // and force a large allocation in `to_vec` below.
    if cred_id_len > MAX_CREDENTIAL_ID_LEN {
        return Err(Fido2Error::Format(format!(
            "credentialId length {cred_id_len} exceeds MAX_CREDENTIAL_ID_LEN ({MAX_CREDENTIAL_ID_LEN})"
        )));
    }
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
        aaguid,
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
    let mut x5c: Option<Vec<Vec<u8>>> = None;
    for (k, v) in map.iter() {
        if let Some(key) = k.as_text() {
            match key {
                "alg" => alg = v.as_integer().and_then(|i| i64::try_from(i).ok()),
                "sig" => sig = v.as_bytes().cloned(),
                "x5c" => {
                    let arr = v
                        .as_array()
                        .ok_or_else(|| Fido2Error::Format("x5c not array".into()))?;
                    let mut certs = Vec::with_capacity(arr.len());
                    for cert in arr {
                        let bytes = cert
                            .as_bytes()
                            .ok_or_else(|| Fido2Error::Format("x5c element not bytes".into()))?;
                        certs.push(bytes.clone());
                    }
                    x5c = Some(certs);
                }
                _ => {}
            }
        }
    }
    let sig = sig.ok_or_else(|| Fido2Error::Format("missing sig".into()))?;

    // Signed data = authData || clientDataHash. Same input regardless
    // of the packed sub-mode (self-attestation vs full attestation
    // with x5c).
    let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    signed.extend_from_slice(auth_data);
    signed.extend_from_slice(client_data_hash);

    // **A-1 step-2 (security review, 2026-04-25)**: verify the
    // attestation signature regardless of whether the statement
    // carries an `x5c` chain. Pre-A-1 this branch returned `Ok(())`
    // unconditionally when `x5c` was present, which let any local
    // process forge a packed attestation by attaching arbitrary cert
    // bytes. We now extract the leaf cert's SubjectPublicKeyInfo and
    // verify the `sig` field under that pubkey. Chain validation
    // against a trust-anchor list remains deferred to M-13 (FIDO MDS
    // integration); presence-without-validation of a plausible cert
    // is still strictly stronger than the previous "trust on sight"
    // posture, because the attacker now has to produce a signature
    // matching the leaf pubkey on a CDH the server controls.
    if let Some(x5c) = x5c {
        let leaf = x5c
            .first()
            .ok_or_else(|| Fido2Error::Format("x5c empty".into()))?;
        let leaf_pk = leaf_public_key_from_der(leaf, alg)?;
        return verify_attestation_sig(&leaf_pk, alg, &sig, &signed);
    }

    // Self-attestation (no x5c): the signature is verified under the
    // **credential** pubkey from authData. WebAuthn §8.2.1 requires
    // `attStmt.alg` to match the credential pubkey's algorithm.
    let credential_attest_pk = match credential_pk {
        CredentialPublicKey::Ed25519(vk) => AttestationPublicKey::Ed25519(*vk),
        CredentialPublicKey::P256(vk) => AttestationPublicKey::P256(*vk),
    };
    verify_attestation_sig(&credential_attest_pk, alg, &sig, &signed)
}

/// Public key recovered from an attestation source (the credential
/// pubkey for self-attestation, or the leaf cert pubkey for `x5c`).
/// Distinct from [`CredentialPublicKey`] only so the call site cannot
/// confuse "key signing the attestation" with "key signing future
/// assertions."
enum AttestationPublicKey {
    Ed25519(VerifyingKey),
    P256(P256VerifyingKey),
}

/// Verify `attStmt.sig` over the WebAuthn signed-input
/// (`authData || clientDataHash`) under the attestation pubkey,
/// enforcing the WebAuthn requirement that `alg` matches the key
/// type.
fn verify_attestation_sig(
    pk: &AttestationPublicKey,
    alg: Option<i64>,
    sig: &[u8],
    signed: &[u8],
) -> Result<(), Fido2Error> {
    match pk {
        AttestationPublicKey::Ed25519(vk) => {
            if alg != Some(COSE_ALG_EDDSA) {
                return Err(Fido2Error::Unsupported(format!(
                    "packed alg={alg:?} for Ed25519 key"
                )));
            }
            let signature = Ed25519Signature::from_slice(sig)
                .map_err(|e| Fido2Error::KeyError(e.to_string()))?;
            vk.verify(signed, &signature)
                .map_err(|_| Fido2Error::BadSignature)
        }
        AttestationPublicKey::P256(vk) => {
            if alg != Some(COSE_ALG_ES256) {
                return Err(Fido2Error::Unsupported(format!(
                    "packed alg={alg:?} for P-256 key"
                )));
            }
            let signature = P256Signature::from_der(sig)
                .or_else(|_| P256Signature::from_slice(sig))
                .map_err(|e| Fido2Error::KeyError(format!("P-256 sig: {e}")))?;
            // Normalize high-S signatures — see the matching note in
            // `verify_assertion`.
            let signature = signature.normalize_s().unwrap_or(signature);
            vk.verify(signed, &signature)
                .map_err(|_| Fido2Error::BadSignature)
        }
    }
}

/// Extract the SubjectPublicKey from a DER-encoded X.509 certificate
/// and return it as an [`AttestationPublicKey`]. Used to verify the
/// `attStmt.sig` field of a packed-with-`x5c` attestation under the
/// leaf attestation cert's public key (A-1 step-2).
///
/// `expected_alg` is the COSE alg from `attStmt.alg`. We use it to
/// pick which key shape to extract; the SPKI's algorithm OID is
/// double-checked against it so an attacker cannot ship a cert under
/// one algorithm and a `sig` under another.
fn leaf_public_key_from_der(
    cert_der: &[u8],
    expected_alg: Option<i64>,
) -> Result<AttestationPublicKey, Fido2Error> {
    use x509_parser::oid_registry;
    use x509_parser::prelude::FromDer;

    let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| Fido2Error::Format(format!("x5c[0] not a valid X.509 cert: {e}")))?;
    if !rest.is_empty() {
        return Err(Fido2Error::Format(
            "x5c[0] has trailing bytes after cert".into(),
        ));
    }

    let spki = &cert.tbs_certificate.subject_pki;
    let raw = spki.subject_public_key.data.as_ref();
    let oid = &spki.algorithm.algorithm;

    // P-256 leaf: OID is id-ecPublicKey (1.2.840.10045.2.1) and the
    // curve parameter is prime256v1 (1.2.840.10045.3.1.7). The raw
    // bytes are an uncompressed SEC1 point (0x04 || x || y, 65 bytes).
    if *oid == oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        if expected_alg != Some(COSE_ALG_ES256) {
            return Err(Fido2Error::Unsupported(format!(
                "x5c leaf is EC but attStmt.alg={expected_alg:?} (expected -7 / ES256)"
            )));
        }
        let vk = P256VerifyingKey::from_sec1_bytes(raw)
            .map_err(|e| Fido2Error::KeyError(format!("x5c P-256: {e}")))?;
        return Ok(AttestationPublicKey::P256(vk));
    }

    // Ed25519 leaf: OID is id-Ed25519 (1.3.101.112). The raw bytes
    // are the 32-byte public key.
    if *oid == oid_registry::OID_SIG_ED25519 {
        if expected_alg != Some(COSE_ALG_EDDSA) {
            return Err(Fido2Error::Unsupported(format!(
                "x5c leaf is Ed25519 but attStmt.alg={expected_alg:?} (expected -8 / EdDSA)"
            )));
        }
        if raw.len() != 32 {
            return Err(Fido2Error::Format(format!(
                "x5c leaf Ed25519 SPKI len={} expected 32",
                raw.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        let vk = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| Fido2Error::KeyError(format!("x5c Ed25519: {e}")))?;
        return Ok(AttestationPublicKey::Ed25519(vk));
    }

    Err(Fido2Error::Unsupported(format!(
        "x5c leaf algorithm OID {oid} not supported (only ES256 / EdDSA)"
    )))
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
    // Bounded depth: cose_bytes flow in from authData which is
    // attacker-controlled at the enrollment boundary. Security
    // review I-6.
    let value: CborValue = dds_core::cbor_bounded::from_reader(cose_bytes)
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

    // I-10 (Claude_sec_review.md): RFC 9052 §7.1 lists `alg` (label 3) as
    // a defined COSE_Key parameter and §3.1 mandates it for keys used in
    // signature verification. Real authenticators always emit it; refusing
    // a missing alg removes the prior fallback that picked an algorithm
    // from `kty` alone.
    let alg = alg.ok_or_else(|| {
        Fido2Error::Format("COSE_Key missing required alg parameter (RFC 9052 §3.1)".into())
    })?;

    match (kty, alg) {
        // Ed25519 (OKP)
        (Some(1), COSE_ALG_EDDSA) => {
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
        (Some(2), COSE_ALG_ES256) => {
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
    build_none_attestation_with_aaguid(rp_id, credential_id, pk, &[0u8; 16])
}

/// Same as `build_none_attestation` but with an explicit AAGUID embedded
/// in the authenticator data. Useful for tests covering the
/// `fido2_allowed_aaguids` allow-list.
pub fn build_none_attestation_with_aaguid(
    rp_id: &str,
    credential_id: &[u8],
    pk: &VerifyingKey,
    aaguid: &[u8; 16],
) -> Vec<u8> {
    let auth_data = build_auth_data_with_aaguid(rp_id, credential_id, pk, aaguid);
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
    build_packed_self_attestation_with_aaguid(
        rp_id,
        credential_id,
        signing_key,
        client_data_hash,
        &[0u8; 16],
    )
}

/// Same as `build_packed_self_attestation` but with an explicit AAGUID
/// embedded in the authenticator data. Useful for tests covering the
/// `fido2_allowed_aaguids` allow-list.
pub fn build_packed_self_attestation_with_aaguid(
    rp_id: &str,
    credential_id: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    client_data_hash: &[u8],
    aaguid: &[u8; 16],
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let pk = signing_key.verifying_key();
    let auth_data = build_auth_data_with_aaguid(rp_id, credential_id, &pk, aaguid);
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

fn build_auth_data_with_aaguid(
    rp_id: &str,
    credential_id: &[u8],
    pk: &VerifyingKey,
    aaguid: &[u8; 16],
) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(0x41); // UP | AT
    out.extend_from_slice(&[0, 0, 0, 0]); // signCount
    out.extend_from_slice(aaguid); // AAGUID
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

    /// **A-1 step-2** test helper: build a synthetic packed-with-x5c
    /// attestation. The credential pubkey lives in `authData`; the
    /// **attestation** key (separate, owned by `attestation_sk`) signs
    /// `authData || cdh`. The leaf cert is a self-signed P-256 cert
    /// generated by `rcgen` carrying the attestation pubkey in its
    /// SubjectPublicKeyInfo. Mirrors the shape that real authenticators
    /// (YubiKey / SoloKey / Crayonic) emit.
    fn build_packed_x5c_attestation_p256(
        rp_id: &str,
        credential_id: &[u8],
        credential_signing_key: &p256::ecdsa::SigningKey,
        client_data_hash: &[u8],
    ) -> (Vec<u8>, p256::ecdsa::SigningKey) {
        use p256::ecdsa::signature::Signer;
        // 1. Self-signed leaf attestation cert (rcgen).
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["dds-test".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();

        // 2. The attestation private key (matching the leaf cert's
        // SPKI). rcgen lets us export PKCS8 DER, which we re-import
        // through `p256` so we can sign with it. (PEM would need both
        // `pkcs8` AND `pem` features on `p256`; DER needs only the
        // first, which we already enable in dev-deps.)
        let key_der = key_pair.serialize_der();
        let attestation_sk = {
            use p256::pkcs8::DecodePrivateKey;
            p256::ecdsa::SigningKey::from_pkcs8_der(&key_der).unwrap()
        };

        // 3. Build authData carrying the *credential* pubkey (separate
        //    from the attestation key — this models the WebAuthn
        //    distinction).
        let credential_vk = P256VerifyingKey::from(credential_signing_key);
        let auth_data = build_auth_data_p256(rp_id, credential_id, &credential_vk);

        // 4. Sign authData || cdh under the attestation key. This is
        //    what real packed-with-x5c emits.
        let mut signed = Vec::new();
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(client_data_hash);
        let sig: P256Signature = attestation_sk.sign(&signed);

        let stmt: Vec<(CborValue, CborValue)> = vec![
            (
                CborValue::Text("alg".into()),
                CborValue::Integer(COSE_ALG_ES256.into()),
            ),
            (
                CborValue::Text("sig".into()),
                CborValue::Bytes(sig.to_der().as_bytes().to_vec()),
            ),
            (
                CborValue::Text("x5c".into()),
                CborValue::Array(vec![CborValue::Bytes(cert_der)]),
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
        (out, attestation_sk)
    }

    /// **A-1 step-2**: positive — packed attestation with a valid
    /// `x5c` leaf signature is accepted. The leaf cert is synthesized
    /// at test time; the attestation pubkey is distinct from the
    /// credential pubkey, mirroring the WebAuthn shape.
    #[test]
    fn test_packed_x5c_p256_valid() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        let cred_sk = P256SigningKey::random(&mut OsRng);
        let cdh = [0xCD; 32];
        let (attestation, _att_sk) =
            build_packed_x5c_attestation_p256("login.example.com", b"hw-cred", &cred_sk, &cdh);
        let parsed = verify_attestation(&attestation, &cdh, false).unwrap();
        assert_eq!(parsed.fmt, "packed");
        assert_eq!(parsed.credential_id, b"hw-cred");
        // The persisted credential pubkey is the credential's, not the
        // attestation cert's.
        match &parsed.credential_public_key {
            CredentialPublicKey::P256(vk) => {
                let expected = P256VerifyingKey::from(&cred_sk);
                assert_eq!(vk.to_encoded_point(false), expected.to_encoded_point(false));
            }
            other => panic!("expected P-256 credential, got {other:?}"),
        }
    }

    /// **A-1 step-2**: negative — packed attestation whose `x5c[0]`
    /// is not a valid X.509 cert is rejected with `Format`. (Pre-A-1
    /// step-2 this would have returned `Ok(())`.)
    #[test]
    fn test_packed_x5c_garbage_cert_rejected() {
        let stmt: Vec<(CborValue, CborValue)> = vec![
            (
                CborValue::Text("alg".into()),
                CborValue::Integer(COSE_ALG_ES256.into()),
            ),
            (
                CborValue::Text("sig".into()),
                CborValue::Bytes(vec![0u8; 64]),
            ),
            (
                CborValue::Text("x5c".into()),
                CborValue::Array(vec![CborValue::Bytes(b"definitely not DER".to_vec())]),
            ),
        ];
        // Build minimal authData with a P-256 credential pubkey so the
        // parser gets past parse_auth_data and into verify_packed.
        use p256::ecdsa::SigningKey as P256SigningKey;
        let cred_vk = P256VerifyingKey::from(&P256SigningKey::random(&mut OsRng));
        let auth_data = build_auth_data_p256("login.example.com", b"hw-cred", &cred_vk);
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
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut bytes).unwrap();
        let res = verify_attestation(&bytes, &[0u8; 32], false);
        match res {
            Err(Fido2Error::Format(msg)) => {
                assert!(msg.contains("x5c"), "unexpected message: {msg}");
            }
            other => panic!("expected Format(x5c…), got {other:?}"),
        }
    }

    /// **A-1 step-2**: negative — packed attestation with a valid leaf
    /// cert but a `sig` signed under a *different* key is rejected
    /// with `BadSignature`. This is the attack the pre-A-1 code
    /// allowed: drop in any cert, sign with anything, get accepted.
    #[test]
    fn test_packed_x5c_sig_under_wrong_key_rejected() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        use p256::ecdsa::signature::Signer;

        // Synthesize a leaf cert under attestation_sk_a, but sign the
        // attestation with attestation_sk_b. The cert says A; the sig
        // matches B. Must reject.
        let key_pair_a = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["dds-test".to_string()]).unwrap();
        let cert_a = params.self_signed(&key_pair_a).unwrap();

        let attestation_sk_b = P256SigningKey::random(&mut OsRng);

        let cred_sk = P256SigningKey::random(&mut OsRng);
        let cred_vk = P256VerifyingKey::from(&cred_sk);
        let auth_data = build_auth_data_p256("login.example.com", b"hw-cred", &cred_vk);
        let cdh = [0xAA; 32];

        let mut signed = Vec::new();
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(&cdh);
        let sig: P256Signature = attestation_sk_b.sign(&signed);

        let stmt: Vec<(CborValue, CborValue)> = vec![
            (
                CborValue::Text("alg".into()),
                CborValue::Integer(COSE_ALG_ES256.into()),
            ),
            (
                CborValue::Text("sig".into()),
                CborValue::Bytes(sig.to_der().as_bytes().to_vec()),
            ),
            (
                CborValue::Text("x5c".into()),
                CborValue::Array(vec![CborValue::Bytes(cert_a.der().to_vec())]),
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
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut bytes).unwrap();
        let res = verify_attestation(&bytes, &cdh, false);
        assert!(matches!(res, Err(Fido2Error::BadSignature)));
    }

    /// **A-1 step-2**: defense-in-depth — `attStmt.alg` claiming Ed25519
    /// while the `x5c` leaf carries a P-256 SPKI is rejected. Prevents
    /// a downgrade where an attacker presents a real EC cert but
    /// claims a different algorithm to skip `from_sec1_bytes` parsing.
    #[test]
    fn test_packed_x5c_alg_mismatch_rejected() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["dds-test".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cred_sk = P256SigningKey::random(&mut OsRng);
        let cred_vk = P256VerifyingKey::from(&cred_sk);
        let auth_data = build_auth_data_p256("login.example.com", b"hw-cred", &cred_vk);
        let cdh = [0xAA; 32];

        let stmt: Vec<(CborValue, CborValue)> = vec![
            (
                CborValue::Text("alg".into()),
                CborValue::Integer(COSE_ALG_EDDSA.into()), // wrong on purpose
            ),
            (
                CborValue::Text("sig".into()),
                CborValue::Bytes(vec![0u8; 64]),
            ),
            (
                CborValue::Text("x5c".into()),
                CborValue::Array(vec![CborValue::Bytes(cert.der().to_vec())]),
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
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(map), &mut bytes).unwrap();
        let res = verify_attestation(&bytes, &cdh, false);
        assert!(matches!(res, Err(Fido2Error::Unsupported(_))));
    }

    #[test]
    fn test_none_attestation_roundtrip_when_allowed() {
        let sk = SigningKey::generate(&mut OsRng);
        let cred_id = b"test-credential";
        let attestation = build_none_attestation("example.com", cred_id, &sk.verifying_key());
        // A-1 step-1: caller must opt in to fmt=none.
        let parsed = verify_attestation(&attestation, &[0u8; 32], true).unwrap();
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
    fn test_p256_none_attestation_roundtrip_when_allowed() {
        use p256::ecdsa::SigningKey as P256SigningKey;

        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let cred_id = b"p256-credential";
        let attestation = build_none_attestation_p256("example.com", cred_id, &vk);
        let parsed = verify_attestation(&attestation, &[0u8; 32], true).unwrap();
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

    /// **A-1 step-1**: `fmt = "none"` is rejected when the caller has not
    /// opted into unattested credentials.
    #[test]
    fn test_none_attestation_rejected_by_default() {
        let sk = SigningKey::generate(&mut OsRng);
        let attestation = build_none_attestation("example.com", b"cred", &sk.verifying_key());
        let res = verify_attestation(&attestation, &[0u8; 32], false);
        match res {
            Err(Fido2Error::Unsupported(msg)) => {
                assert!(msg.contains("fmt=none"), "unexpected message: {msg}");
                assert!(msg.contains("A-1"), "missing remediation tag: {msg}");
            }
            other => panic!("expected Unsupported(fmt=none), got {other:?}"),
        }
    }

    /// **A-1 step-1**: P-256 variant of the gate.
    #[test]
    fn test_p256_none_attestation_rejected_by_default() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let attestation = build_none_attestation_p256("example.com", b"p", &vk);
        let res = verify_attestation(&attestation, &[0u8; 32], false);
        assert!(matches!(res, Err(Fido2Error::Unsupported(_))));
    }

    /// **A-1 step-1**: packed self-attestation is unaffected by the
    /// `allow_unattested_credentials` flag — it still verifies the
    /// signature regardless.
    #[test]
    fn test_packed_unaffected_by_unattested_flag() {
        let sk = SigningKey::generate(&mut OsRng);
        let cdh = [0xAB; 32];
        let attestation = build_packed_self_attestation("login.example.com", b"cred1", &sk, &cdh);
        // Both flag values must accept a valid packed attestation.
        for allow in [false, true] {
            let parsed = verify_attestation(&attestation, &cdh, allow).unwrap();
            assert_eq!(parsed.fmt, "packed");
            assert_eq!(parsed.credential_id, b"cred1");
        }
    }

    #[test]
    fn test_p256_packed_self_attestation() {
        use p256::ecdsa::SigningKey as P256SigningKey;

        let sk = P256SigningKey::random(&mut OsRng);
        let cdh = [0xCD; 32];
        let attestation =
            build_packed_self_attestation_p256("login.example.com", b"p256-cred", &sk, &cdh);
        // packed verification is unaffected by the unattested flag —
        // pass `false` (the default) to confirm.
        let parsed = verify_attestation(&attestation, &cdh, false).unwrap();
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
        let parsed = verify_attestation(&attestation, &cdh, false).unwrap();
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
        let res = verify_attestation(&attestation, &wrong, false);
        assert!(matches!(res, Err(Fido2Error::BadSignature)));

        // Tamper a byte in the attestation and confirm it fails too.
        let len = attestation.len();
        attestation[len - 1] ^= 0xFF;
        let res2 = verify_attestation(&attestation, &cdh, false);
        assert!(res2.is_err());
    }

    #[test]
    fn test_garbage_input_rejected() {
        assert!(verify_attestation(&[0u8; 4], &[0u8; 32], true).is_err());
        assert!(verify_attestation(b"not cbor", &[0u8; 32], true).is_err());
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
        let res = verify_attestation(&bytes, &[0u8; 32], true);
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

    /// I-8 (Claude_sec_review.md): a malformed authData claiming a
    /// `cred_id_len` over `MAX_CREDENTIAL_ID_LEN` (1023) must be rejected
    /// before any allocation happens. Build a buffer that's just large
    /// enough to satisfy the truncation check (so the only thing that
    /// trips is the length cap) and confirm the parser refuses it.
    #[test]
    fn i8_parse_auth_data_rejects_oversized_credential_id() {
        let rp_id_hash = Sha256::digest(b"dds.local");
        let oversized = (MAX_CREDENTIAL_ID_LEN + 1) as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&rp_id_hash); // 32
        buf.push(0x41); // flags UP|AT
        buf.extend_from_slice(&[0, 0, 0, 0]); // signCount
        buf.extend_from_slice(&[0u8; 16]); // AAGUID
        buf.extend_from_slice(&oversized.to_be_bytes());
        // Pad to satisfy the truncation precheck — the length cap should
        // fire before the truncation check anyway, but we want to prove
        // the cap is the rejection reason rather than incidental short-input.
        buf.resize(buf.len() + oversized as usize + 64, 0);

        let res = parse_auth_data(&buf);
        match res {
            Err(Fido2Error::Format(msg)) => {
                assert!(
                    msg.contains("MAX_CREDENTIAL_ID_LEN") || msg.contains("exceeds"),
                    "unexpected error message: {msg}"
                );
            }
            Err(other) => panic!("expected Format error, got {other:?}"),
            Ok(_) => panic!("oversized cred_id_len should be rejected"),
        }
    }

    /// I-8 boundary: exactly `MAX_CREDENTIAL_ID_LEN` bytes must still
    /// parse (only `> MAX` is rejected, matching the CTAP2.1 wording).
    /// We don't need a valid COSE_Key here — we use a 0-byte cred_id +
    /// real COSE in the existing roundtrip tests for that — this test
    /// just verifies the cap boundary is `>`, not `>=`.
    #[test]
    fn i8_parse_auth_data_accepts_max_credential_id_length() {
        let rp_id_hash = Sha256::digest(b"dds.local");
        let at_max = MAX_CREDENTIAL_ID_LEN as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&rp_id_hash);
        buf.push(0x41);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&at_max.to_be_bytes());
        buf.extend_from_slice(&vec![0u8; at_max as usize]);
        // Followed by garbage where COSE_Key would normally live; the
        // parser should fail later (in cose_to_credential_public_key)
        // rather than at the length check we're exercising.
        buf.extend_from_slice(&[0xFFu8; 8]);
        let res = parse_auth_data(&buf);
        // Either Cbor or Format from the COSE step is fine — what matters
        // is we got past the length cap.
        match res {
            Err(Fido2Error::Cbor(_)) | Err(Fido2Error::Format(_)) => {}
            Err(other) => panic!("expected Cbor/Format from COSE step, got {other:?}"),
            Ok(_) => panic!("garbage COSE should not parse"),
        }
    }

    /// I-10 (Claude_sec_review.md): a COSE_Key without `alg` is now
    /// rejected. RFC 9052 §3.1 mandates the parameter for keys used in
    /// signature verification, and real FIDO2 authenticators always
    /// emit it. The previous behaviour fell back to inferring the
    /// algorithm from `kty` alone, which left a small mismatch surface.
    #[test]
    fn i10_cose_to_credential_public_key_rejects_missing_alg() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        // Same as test_cose_to_credential_public_key_ed25519, but without label 3 (alg).
        let cose: Vec<(CborValue, CborValue)> = vec![
            (CborValue::Integer(1.into()), CborValue::Integer(1.into())), // kty=OKP
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

        let res = cose_to_credential_public_key(&bytes);
        match res {
            Err(Fido2Error::Format(msg)) => {
                assert!(
                    msg.contains("alg"),
                    "expected error mentioning alg, got: {msg}"
                );
            }
            other => panic!("expected Format error, got {other:?}"),
        }
    }

    /// I-10: an EC2 (P-256) COSE_Key without `alg` is rejected on the
    /// same RFC 9052 §3.1 ground.
    #[test]
    fn i10_cose_to_credential_public_key_rejects_missing_alg_p256() {
        use p256::ecdsa::SigningKey as P256SigningKey;
        let sk = P256SigningKey::random(&mut OsRng);
        let vk = P256VerifyingKey::from(&sk);
        let point = vk.to_encoded_point(false);
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();

        let cose: Vec<(CborValue, CborValue)> = vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())), // kty=EC2
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ), // crv=P-256
            (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
            (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
        ];
        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(cose), &mut bytes).unwrap();

        let res = cose_to_credential_public_key(&bytes);
        match res {
            Err(Fido2Error::Format(msg)) => {
                assert!(
                    msg.contains("alg"),
                    "expected error mentioning alg, got: {msg}"
                );
            }
            other => panic!("expected Format error, got {other:?}"),
        }
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

    /// **I-6 (security review)**. `verify_attestation` reads
    /// caller-supplied bytes (every `/v1/enroll/*` and re-parse on
    /// session assert routes through it). A depth-bomb
    /// attestation_object must be rejected at decode rather than
    /// driving ciborium's recursive deserializer toward stack
    /// exhaustion.
    #[test]
    fn i6_verify_attestation_refuses_depth_bomb() {
        let mut bytes = vec![0x81u8; 2048]; // 2048 × array(1)
        bytes.push(0x00);
        let res = verify_attestation(&bytes, &[0u8; 32], false);
        assert!(matches!(res, Err(Fido2Error::Cbor(_))));
    }

    /// **I-6 (security review)**. `cose_to_credential_public_key`
    /// is reachable directly from `parse_auth_data` →
    /// attacker-controlled `authData`. Same depth-bomb posture as
    /// the outer `verify_attestation` entry point.
    #[test]
    fn i6_cose_to_credential_public_key_refuses_depth_bomb() {
        let mut bytes = vec![0x81u8; 2048];
        bytes.push(0x00);
        let res = cose_to_credential_public_key(&bytes);
        assert!(matches!(res, Err(Fido2Error::Cbor(_))));
    }

    /// Phase 1 of `docs/fido2-attestation-allowlist.md` requires the
    /// 16-byte AAGUID to round-trip from authData into
    /// `ParsedAttestation` so the dds-node service can match it
    /// against the configured allow-list. The default test builders
    /// emit all-zero AAGUID, which is a real-world value (FIDO2
    /// platform authenticators that reveal nothing) — the allow-list
    /// machinery must therefore distinguish the zero AAGUID from
    /// "unknown" (the comparison is a plain set membership).
    #[test]
    fn aaguid_extracted_into_parsed_attestation_zero() {
        let sk = SigningKey::generate(&mut OsRng);
        let cdh = [0u8; 32];
        let attestation = build_packed_self_attestation("login.example.com", b"cred1", &sk, &cdh);
        let parsed = verify_attestation(&attestation, &cdh, false).unwrap();
        assert_eq!(parsed.aaguid, [0u8; 16]);
    }

    #[test]
    fn aaguid_extracted_into_parsed_attestation_non_zero() {
        let sk = SigningKey::generate(&mut OsRng);
        let cdh = [0u8; 32];
        // Canonical YubiKey 5 NFC AAGUID per FIDO MDS metadata.
        let aaguid: [u8; 16] = [
            0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9,
            0x20, 0x2a,
        ];
        let attestation = build_packed_self_attestation_with_aaguid(
            "login.example.com",
            b"cred1",
            &sk,
            &cdh,
            &aaguid,
        );
        let parsed = verify_attestation(&attestation, &cdh, false).unwrap();
        assert_eq!(parsed.aaguid, aaguid);
    }

    #[test]
    fn aaguid_extracted_from_fmt_none() {
        let sk = SigningKey::generate(&mut OsRng);
        let aaguid: [u8; 16] = [
            0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97,
            0x07, 0x2a,
        ];
        let attestation = build_none_attestation_with_aaguid(
            "example.com",
            b"cred",
            &sk.verifying_key(),
            &aaguid,
        );
        // fmt=none requires opt-in to verify_attestation; the AAGUID
        // is still surfaced so the service-side allow-list runs.
        let parsed = verify_attestation(&attestation, &[0u8; 32], true).unwrap();
        assert_eq!(parsed.fmt, "none");
        assert_eq!(parsed.aaguid, aaguid);
    }
}
