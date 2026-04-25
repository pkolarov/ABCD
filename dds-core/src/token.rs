//! Token parsing, validation, and signature verification.
//!
//! Handles Vouchsafe token types:
//! - Attestation (`vch:attest`) — identity declarations, policy assignments
//! - Vouch (`vch:vouch`) — group membership, delegation
//! - Revocation (`vch:revoke`) — membership removal
//! - Burn (`vch:burn`) — permanent identity retirement

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cbor_canonical::encode_token_payload;
use crate::crypto::{PublicKeyBundle, SignatureBundle};
use crate::identity::VouchsafeId;

/// **M-1 (security review)** — wire-envelope version selector.
///
/// `v = 1` (or absent when decoding legacy blobs) means the signed
/// bytes are whatever `ciborium::into_writer(payload)` produced —
/// non-canonical, signer-dependent ordering. Kept for reading
/// existing on-disk tokens and network traffic from pre-v2 peers;
/// new signers never emit v1.
///
/// `v = 2` means the signed bytes are the canonical CBOR encoding
/// from [`crate::cbor_canonical::encode_token_payload`], prefixed
/// with the domain tag [`TOKEN_V2_DOMAIN_TAG`] during the signing
/// operation (so v1 and v2 signatures cannot be mistaken for each
/// other even if the canonical bytes happened to match the
/// non-canonical v1 bytes — they never do in practice, but the
/// domain tag makes the distinction cryptographic).
pub const TOKEN_WIRE_V1: u8 = 1;
pub const TOKEN_WIRE_V2: u8 = 2;

/// Domain-separation prefix mixed into every v2 signature input.
/// Null-terminated so a longer tag can never be confused with a
/// shorter one via length-extension semantics.
pub const TOKEN_V2_DOMAIN_TAG: &[u8] = b"dds-token-v2\x00";

/// `serde(default)` fallback for the wire version field — absent
/// means "a pre-v2 sender", which decodes as v1.
fn default_wire_version() -> u8 {
    TOKEN_WIRE_V1
}

/// Canonical purpose strings for vouches that grant a publishing
/// capability. C-3 from the security review: only attestations whose
/// issuer chains to a trusted root via a vouch carrying one of these
/// purposes may publish the corresponding document type. The constants
/// live here so that producers (admin tooling) and consumers
/// (`list_applicable_*` filters in `dds-node`) cannot drift.
pub mod purpose {
    /// Authorized to publish `WindowsPolicyDocument` attestations.
    pub const POLICY_PUBLISHER_WINDOWS: &str = "dds:policy-publisher-windows";
    /// Authorized to publish `MacOsPolicyDocument` attestations.
    pub const POLICY_PUBLISHER_MACOS: &str = "dds:policy-publisher-macos";
    /// Authorized to publish `SoftwareAssignment` attestations.
    pub const SOFTWARE_PUBLISHER: &str = "dds:software-publisher";

    /// Special purpose: the subject of a vouch with this purpose is
    /// being promoted to a trusted-root admin. `admin_vouch` enforces
    /// that only the bootstrap admin (or an admin holding
    /// `dds:admin-vouch:dds:admin`) may issue such a vouch, and on
    /// success the subject is added to `trusted_roots` and persisted
    /// to config so the promotion survives restart. H-8 in the
    /// security review.
    pub const ADMIN: &str = "dds:admin";

    /// Special purpose: the subject of a vouch with this purpose has
    /// had its self-attested device scope (tags / org_unit) confirmed
    /// by the voucher. With `NodeConfig::enforce_device_scope_vouch`
    /// enabled, only scope facts from devices carrying such a vouch
    /// are honored when evaluating `PolicyScope.device_tags` /
    /// `PolicyScope.org_units`. Closes M-7 in the security review.
    pub const DEVICE_SCOPE: &str = "dds:device-scope";
}

/// The type of a Vouchsafe token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    /// Self-issued identity declaration or policy assignment.
    #[serde(rename = "vch:attest")]
    Attest,
    /// Vouch for another identity's claim (group membership, delegation).
    #[serde(rename = "vch:vouch")]
    Vouch,
    /// Revoke a previously issued vouch.
    #[serde(rename = "vch:revoke")]
    Revoke,
    /// Permanently retire an identity.
    #[serde(rename = "vch:burn")]
    Burn,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenKind::Attest => write!(f, "vch:attest"),
            TokenKind::Vouch => write!(f, "vch:vouch"),
            TokenKind::Revoke => write!(f, "vch:revoke"),
            TokenKind::Burn => write!(f, "vch:burn"),
        }
    }
}

/// The payload of a Vouchsafe token (unsigned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Issuer identity URN.
    pub iss: String,
    /// Issuer's public key bundle (scheme-aware: Ed25519 or hybrid).
    pub iss_key: PublicKeyBundle,
    /// Unique token identifier.
    pub jti: String,
    /// Subject identifier (what this token is about).
    pub sub: String,
    /// Token type.
    pub kind: TokenKind,
    /// Purpose string (scoping: group name, OU, policy, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// For vouches: the issuer URN of the vouched token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vch_iss: Option<String>,
    /// For vouches: SHA-256 hash of the vouched token's payload bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vch_sum: Option<String>,
    /// For revocations: the JTI of the revoked token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes: Option<String>,
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiration timestamp (Unix seconds). None for revocations and burns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,

    // ---- Opaque extension body ----
    // Domain-specific data rides inside the signed envelope.
    // Core never interprets these; dds-domain provides typed wrappers.
    /// Body type URI (e.g. "dds:user-auth-attestation", "dds:device-join").
    /// When present, `body_cbor` must also be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_type: Option<String>,
    /// CBOR-encoded domain-specific payload (signed along with all other fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_cbor: Option<Vec<u8>>,
}

/// A signed Vouchsafe token: payload + signature (scheme-aware).
#[derive(Debug, Clone)]
pub struct Token {
    pub payload: TokenPayload,
    /// CBOR-encoded payload bytes. For v1 these are whatever
    /// `ciborium::into_writer` produced at signing time; for v2
    /// they are the canonical-CBOR bytes returned by
    /// [`crate::cbor_canonical::encode_token_payload`] and are
    /// also exactly the input the signer used for
    /// `sign(domain_tag || payload_bytes)`.
    payload_bytes: Vec<u8>,
    /// Signature over the domain-separated payload bytes (v2) or
    /// directly over `payload_bytes` (v1).
    signature: SignatureBundle,
    /// Wire version this token was signed with / decoded as.
    /// Re-emitted verbatim on `to_cbor`.
    wire_version: u8,
}

impl Token {
    /// Create and sign a token at wire version v2 (canonical CBOR +
    /// domain-separated signature input). This is the default for
    /// new signers.
    ///
    /// `sign_fn` receives the **domain-separated** bytes
    /// (`TOKEN_V2_DOMAIN_TAG || canonical_cbor(payload)`) and
    /// returns a `SignatureBundle`. The stored `payload_bytes` are
    /// the canonical CBOR bytes alone — verifiers recompute the
    /// domain-separated input on the fly.
    pub fn create<F>(payload: TokenPayload, sign_fn: F) -> Result<Self, TokenError>
    where
        F: FnOnce(&[u8]) -> SignatureBundle,
    {
        Self::create_with_version(payload, TOKEN_WIRE_V2, sign_fn)
    }

    /// Create and sign at a specific wire version. `v = 1` reproduces
    /// the pre-v2 behaviour (used only to pin test vectors against
    /// historical bytes); `v = 2` is the default every production
    /// caller should use via [`Token::create`].
    pub fn create_with_version<F>(
        payload: TokenPayload,
        wire_version: u8,
        sign_fn: F,
    ) -> Result<Self, TokenError>
    where
        F: FnOnce(&[u8]) -> SignatureBundle,
    {
        // Shape validation: the same invariants are also enforced on
        // ingest (`Token::validate_shape`) so that an inbound token
        // missing kind-specific fields cannot bypass these checks
        // when it was signed by a foreign producer that didn't run
        // through `create_with_version`. **B-2 (security review).**
        validate_shape(&payload)?;

        let (payload_bytes, signed_input) = match wire_version {
            TOKEN_WIRE_V1 => {
                let bytes = cbor_encode(&payload)?;
                let signed = bytes.clone();
                (bytes, signed)
            }
            TOKEN_WIRE_V2 => {
                let bytes = encode_token_payload(&payload);
                let mut signed = Vec::with_capacity(TOKEN_V2_DOMAIN_TAG.len() + bytes.len());
                signed.extend_from_slice(TOKEN_V2_DOMAIN_TAG);
                signed.extend_from_slice(&bytes);
                (bytes, signed)
            }
            other => return Err(TokenError::UnsupportedWireVersion(other)),
        };

        let signature = sign_fn(&signed_input);

        Ok(Self {
            payload,
            payload_bytes,
            signature,
            wire_version,
        })
    }

    /// Convenience: create and sign with an Ed25519 signing key at
    /// the default v2 wire version.
    pub fn sign(
        payload: TokenPayload,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, TokenError> {
        let classical = crate::crypto::Ed25519Only::from_bytes(&signing_key.to_bytes());
        Self::create(payload, |msg| classical.sign(msg))
    }

    /// Explicitly sign at v1 — only for tests pinning historical
    /// bytes and for tooling that needs to round-trip pre-v2 state.
    #[doc(hidden)]
    pub fn sign_v1(
        payload: TokenPayload,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, TokenError> {
        let classical = crate::crypto::Ed25519Only::from_bytes(&signing_key.to_bytes());
        Self::create_with_version(payload, TOKEN_WIRE_V1, |msg| classical.sign(msg))
    }

    /// The wire version this token was signed with / decoded as.
    pub fn wire_version(&self) -> u8 {
        self.wire_version
    }

    /// Verify the token's signature against the embedded issuer
    /// public key. v2 tokens are additionally verified to be
    /// byte-identical to the canonical re-encoding of the decoded
    /// payload — a non-canonical wire is rejected as
    /// [`TokenError::NonCanonicalPayload`], closing M-1's signature
    /// malleability.
    ///
    /// Dispatch picks the right hybrid / triple-hybrid verifier
    /// based on the envelope version: v=1 tokens use the legacy
    /// pre-M-2 verifiers (no scheme-specific domain prefixes) so
    /// persisted v=1 hybrid tokens keep verifying; v=2 tokens go
    /// through the domain-separated M-2 verifiers. For single-
    /// scheme signatures the distinction is immaterial — classical
    /// verify is identical under both versions.
    pub fn verify_signature(&self) -> Result<(), TokenError> {
        let (signed_input, result): (alloc::borrow::Cow<'_, [u8]>, _) = match self.wire_version {
            TOKEN_WIRE_V1 => {
                let input = alloc::borrow::Cow::Borrowed(self.payload_bytes.as_slice());
                let r = crate::crypto::verify_v1(
                    &self.payload.iss_key,
                    &input,
                    &self.signature,
                );
                (input, r)
            }
            TOKEN_WIRE_V2 => {
                // Re-canonicalise and compare. An attacker submitting
                // non-canonical bytes paired with a signature valid
                // over those bytes is rejected here.
                let recanon = encode_token_payload(&self.payload);
                if recanon != self.payload_bytes {
                    return Err(TokenError::NonCanonicalPayload);
                }
                let mut signed =
                    Vec::with_capacity(TOKEN_V2_DOMAIN_TAG.len() + self.payload_bytes.len());
                signed.extend_from_slice(TOKEN_V2_DOMAIN_TAG);
                signed.extend_from_slice(&self.payload_bytes);
                let input = alloc::borrow::Cow::Owned(signed);
                let r = crate::crypto::verify(&self.payload.iss_key, &input, &self.signature);
                (input, r)
            }
            other => return Err(TokenError::UnsupportedWireVersion(other)),
        };
        // `signed_input` is kept alive in-scope so the Cow stays valid
        // across the verify call above.
        let _ = signed_input;
        result.map_err(|_| TokenError::InvalidSignature)
    }

    /// Verify that the issuer URN is cryptographically bound to the issuer key.
    pub fn verify_issuer_binding(&self) -> Result<(), TokenError> {
        let id =
            VouchsafeId::from_urn(&self.payload.iss).map_err(|_| TokenError::InvalidIssuerUrn)?;
        if !id.verify_binding_bundle(&self.payload.iss_key) {
            return Err(TokenError::IssuerKeyMismatch);
        }
        Ok(())
    }

    /// Full validation: shape + signature + issuer binding + expiry.
    ///
    /// **B-2 (security review):** the shape check matches the
    /// invariants enforced by [`Token::create_with_version`] so an
    /// inbound, signed token whose kind-specific fields are missing
    /// (e.g. a `Vouch` without `vch_iss` / `vch_sum`, a `Revoke`
    /// without `revokes`, or a `Revoke` / `Burn` carrying `exp`) is
    /// rejected the same way it would be at construction time. The
    /// trust graph also calls [`Token::validate_shape`] on ingest;
    /// this method exists for callers that already hold a `Token`
    /// and want a single full-validation entry point.
    pub fn validate(&self) -> Result<(), TokenError> {
        self.validate_shape()?;
        self.verify_signature()?;
        self.verify_issuer_binding()?;

        #[cfg(feature = "std")]
        if let Some(exp) = self.payload.exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| TokenError::ClockError)?
                .as_secs();
            if now > exp {
                return Err(TokenError::Expired(self.payload.jti.clone()));
            }
        }

        Ok(())
    }

    /// Enforce the shape invariants in [`validate_shape`] against
    /// `self.payload`. Returns the same errors as the construction
    /// path so callers can surface them uniformly.
    pub fn validate_shape(&self) -> Result<(), TokenError> {
        validate_shape(&self.payload)
    }

    /// Compute the SHA-256 hash of this token's payload bytes (for use as `vch_sum`).
    pub fn payload_hash(&self) -> String {
        let digest = Sha256::digest(&self.payload_bytes);
        hex_encode(&digest)
    }

    /// Serialize the full token (payload + signature) to CBOR bytes.
    ///
    /// The envelope carries the `v` field starting at v2; older
    /// consumers that decode via a struct without `v` still parse it
    /// because ciborium tolerates unknown map keys.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TokenError> {
        let wire = TokenWire {
            v: self.wire_version,
            payload: self.payload_bytes.clone(),
            signature: cbor_encode(&self.signature)?,
        };
        cbor_encode(&wire)
    }

    /// Deserialize a token from CBOR bytes. Envelope `v` missing or
    /// `1` is decoded as v1 legacy; `2` is canonical-CBOR v2.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TokenError> {
        let wire: TokenWire = cbor_decode(bytes)?;
        let payload: TokenPayload = cbor_decode(&wire.payload)?;
        let signature: SignatureBundle = cbor_decode(&wire.signature)?;
        if !matches!(wire.v, TOKEN_WIRE_V1 | TOKEN_WIRE_V2) {
            return Err(TokenError::UnsupportedWireVersion(wire.v));
        }
        Ok(Self {
            payload,
            payload_bytes: wire.payload,
            signature,
            wire_version: wire.v,
        })
    }

    /// Get the signature bundle.
    pub fn signature(&self) -> &SignatureBundle {
        &self.signature
    }
}

/// Wire format for serializing a signed token.
#[derive(Serialize, Deserialize)]
struct TokenWire {
    /// Envelope version selector (M-1). Absent in pre-v2 encodings;
    /// decodes as [`TOKEN_WIRE_V1`] via `serde(default)`.
    #[serde(default = "default_wire_version")]
    v: u8,
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    /// CBOR-encoded SignatureBundle (variable size: classical ~70B, hybrid ~3.4KB).
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

/// Helper: CBOR encode.
/// **B-2 (security review).** Shared structural validator: enforced
/// on construction (`Token::create_with_version`) and on ingest
/// (`Token::validate` / `Token::validate_shape`, called by
/// `TrustGraph::add_token`). Without this, a foreign signer that
/// emits a CBOR-correct, signature-valid token without
/// `vch_iss` / `vch_sum` (for a vouch) or without `revokes` (for a
/// revoke) was accepted by the verifier path even though local
/// construction always rejected it.
fn validate_shape(payload: &TokenPayload) -> Result<(), TokenError> {
    if matches!(payload.kind, TokenKind::Revoke | TokenKind::Burn) && payload.exp.is_some() {
        return Err(TokenError::RevocationMustNotExpire);
    }
    if payload.kind == TokenKind::Vouch
        && (payload.vch_iss.is_none() || payload.vch_sum.is_none())
    {
        return Err(TokenError::VouchMissingFields);
    }
    if payload.kind == TokenKind::Revoke && payload.revokes.is_none() {
        return Err(TokenError::RevokeMissingTarget);
    }
    Ok(())
}

fn cbor_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, TokenError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| TokenError::SerializationError)?;
    Ok(buf)
}

/// Helper: CBOR decode.
fn cbor_decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, TokenError> {
    ciborium::from_reader(bytes).map_err(|_| TokenError::DeserializationError)
}

/// Helper: hex encode bytes to lowercase string.
fn hex_encode(bytes: &[u8]) -> String {
    use alloc::format;
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Errors that can occur during token operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidSignature,
    InvalidPublicKey,
    InvalidIssuerUrn,
    IssuerKeyMismatch,
    RevocationMustNotExpire,
    VouchMissingFields,
    RevokeMissingTarget,
    SerializationError,
    DeserializationError,
    Expired(alloc::string::String),
    ClockError,
    /// **M-1**: the envelope announces a wire version the verifier
    /// doesn't speak. Distinct from a corrupt envelope so the caller
    /// can surface upgrade guidance.
    UnsupportedWireVersion(u8),
    /// **M-1**: a v2 token arrived whose payload bytes do not equal
    /// the canonical CBOR re-encoding of the decoded payload.
    /// An attacker reaching this branch is trying to exploit the
    /// non-canonical-signature path that motivated v2.
    NonCanonicalPayload,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidSignature => write!(f, "invalid Ed25519 signature"),
            TokenError::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            TokenError::InvalidIssuerUrn => write!(f, "invalid issuer URN"),
            TokenError::IssuerKeyMismatch => write!(f, "issuer URN does not match public key"),
            TokenError::RevocationMustNotExpire => {
                write!(f, "revocation/burn tokens must not have exp")
            }
            TokenError::VouchMissingFields => {
                write!(f, "vouch tokens must have vch_iss and vch_sum")
            }
            TokenError::RevokeMissingTarget => {
                write!(f, "revoke tokens must have revokes field")
            }
            TokenError::SerializationError => write!(f, "CBOR serialization failed"),
            TokenError::DeserializationError => write!(f, "CBOR deserialization failed"),
            TokenError::Expired(jti) => write!(f, "token {} is expired", jti),
            TokenError::ClockError => write!(f, "system clock unavailable"),
            TokenError::UnsupportedWireVersion(v) => {
                write!(f, "unsupported token wire version: {v}")
            }
            TokenError::NonCanonicalPayload => {
                write!(f, "v2 token payload is not canonical CBOR")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand::rngs::OsRng;

    fn make_attest_payload(ident: &Identity) -> TokenPayload {
        TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: String::from("test-jti-1"),
            sub: String::from("test-sub-1"),
            kind: TokenKind::Attest,
            purpose: Some(String::from("dds:directory-entry")),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714605000,
            exp: Some(4102444800), // 2100-01-01
            body_type: None,
            body_cbor: None,
        }
    }

    #[test]
    fn test_sign_and_verify_attest() {
        let ident = Identity::generate("alice", &mut OsRng);
        let payload = make_attest_payload(&ident);
        let token = Token::sign(payload, &ident.signing_key).unwrap();
        assert!(token.verify_signature().is_ok());
        assert!(token.verify_issuer_binding().is_ok());
        assert!(token.validate().is_ok());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let alice = Identity::generate("alice", &mut OsRng);
        let bob = Identity::generate("bob", &mut OsRng);

        // Sign with alice's key but put bob's key in the payload
        let mut payload = make_attest_payload(&alice);
        payload.iss_key = bob.public_key.clone();

        // This will sign with alice's key but the payload says bob's key
        let token = Token::sign(payload, &alice.signing_key).unwrap();
        // Verification will fail because signature was made with alice but key says bob
        assert_eq!(token.verify_signature(), Err(TokenError::InvalidSignature));
    }

    #[test]
    fn test_issuer_key_mismatch() {
        let alice = Identity::generate("alice", &mut OsRng);
        let bob = Identity::generate("bob", &mut OsRng);

        // Use alice's URN but bob's key
        let mut payload = make_attest_payload(&alice);
        payload.iss_key = bob.public_key.clone();
        // Sign with bob so signature is valid against bob's key
        let token = Token::sign(payload, &bob.signing_key).unwrap();
        // Signature valid, but issuer URN doesn't match the key
        assert!(token.verify_signature().is_ok());
        assert_eq!(
            token.verify_issuer_binding(),
            Err(TokenError::IssuerKeyMismatch)
        );
    }

    #[test]
    fn test_cbor_roundtrip() {
        let ident = Identity::generate("alice", &mut OsRng);
        let payload = make_attest_payload(&ident);
        let token = Token::sign(payload, &ident.signing_key).unwrap();

        let cbor = token.to_cbor().unwrap();
        let restored = Token::from_cbor(&cbor).unwrap();

        assert_eq!(restored.payload, token.payload);
        assert!(restored.validate().is_ok());
    }

    #[test]
    fn test_vouch_token() {
        let admin = Identity::generate("admin", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        // First create the user's attest token
        let user_payload = make_attest_payload(&user);
        let user_token = Token::sign(user_payload, &user.signing_key).unwrap();

        // Admin vouches for user
        let vouch_payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: String::from("vouch-jti-1"),
            sub: String::from("test-sub-1"),
            kind: TokenKind::Vouch,
            purpose: Some(String::from("dds:group:backend-devs")),
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(user_token.payload_hash()),
            revokes: None,
            iat: 1714606000,
            exp: Some(4102444800), // 2100-01-01
            body_type: None,
            body_cbor: None,
        };

        let vouch = Token::sign(vouch_payload, &admin.signing_key).unwrap();
        assert!(vouch.validate().is_ok());
        assert_eq!(vouch.payload.kind, TokenKind::Vouch);
    }

    #[test]
    fn test_vouch_missing_fields() {
        let admin = Identity::generate("admin", &mut OsRng);
        let payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: String::from("vouch-jti"),
            sub: String::from("sub"),
            kind: TokenKind::Vouch,
            purpose: None,
            vch_iss: None, // missing
            vch_sum: None, // missing
            revokes: None,
            iat: 1714606000,
            exp: Some(4102444800), // 2100-01-01
            body_type: None,
            body_cbor: None,
        };
        let err = Token::sign(payload, &admin.signing_key).unwrap_err();
        assert_eq!(err, TokenError::VouchMissingFields);
    }

    #[test]
    fn test_revocation_token() {
        let admin = Identity::generate("admin", &mut OsRng);
        let user = Identity::generate("user", &mut OsRng);

        let revoke_payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: String::from("revoke-jti"),
            sub: String::from("user-sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(String::from("deadbeef")),
            revokes: Some(String::from("vouch-jti-1")),
            iat: 1714608000,
            exp: None, // Revocations must not expire
            body_type: None,
            body_cbor: None,
        };

        let token = Token::sign(revoke_payload, &admin.signing_key).unwrap();
        assert!(token.validate().is_ok());
        assert_eq!(token.payload.kind, TokenKind::Revoke);
    }

    #[test]
    fn test_revocation_with_exp_fails() {
        let admin = Identity::generate("admin", &mut OsRng);

        let payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: String::from("revoke-jti"),
            sub: String::from("sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(String::from("target-jti")),
            iat: 1714608000,
            exp: Some(9999999999), // not allowed
            body_type: None,
            body_cbor: None,
        };
        let err = Token::sign(payload, &admin.signing_key).unwrap_err();
        assert_eq!(err, TokenError::RevocationMustNotExpire);
    }

    #[test]
    fn test_revoke_missing_target() {
        let admin = Identity::generate("admin", &mut OsRng);

        let payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.public_key.clone(),
            jti: String::from("revoke-jti"),
            sub: String::from("sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None, // missing
            iat: 1714608000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        let err = Token::sign(payload, &admin.signing_key).unwrap_err();
        assert_eq!(err, TokenError::RevokeMissingTarget);
    }

    #[test]
    fn test_burn_token() {
        let user = Identity::generate("user", &mut OsRng);

        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: String::from("burn-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Burn,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714608000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };

        let token = Token::sign(payload, &user.signing_key).unwrap();
        assert!(token.validate().is_ok());
        assert_eq!(token.payload.kind, TokenKind::Burn);
    }

    #[test]
    fn test_validate_rejects_expired_token() {
        let user = Identity::generate("user", &mut OsRng);
        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: String::from("expired-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(1), // epoch second 1 — long past
            body_type: None,
            body_cbor: None,
        };
        let token = Token::sign(payload, &user.signing_key).unwrap();
        let err = token.validate().unwrap_err();
        assert!(matches!(err, TokenError::Expired(_)));
    }

    #[test]
    fn test_clock_error_variant() {
        // Verify ClockError is a distinct variant with the expected display string.
        let err = TokenError::ClockError;
        assert_eq!(err.to_string(), "system clock unavailable");
        // Ensure it does not match other variants.
        assert!(!matches!(err, TokenError::Expired(_)));
        assert!(!matches!(err, TokenError::InvalidSignature));
    }

    #[test]
    fn test_validate_accepts_future_expiry() {
        let user = Identity::generate("user", &mut OsRng);
        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: String::from("future-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: Some(4102444800), // 2100-01-01
            body_type: None,
            body_cbor: None,
        };
        let token = Token::sign(payload, &user.signing_key).unwrap();
        assert!(token.validate().is_ok());
    }

    #[test]
    fn test_validate_accepts_no_expiry() {
        let user = Identity::generate("user", &mut OsRng);
        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: String::from("no-exp-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1000,
            exp: None,
            body_type: None,
            body_cbor: None,
        };
        let token = Token::sign(payload, &user.signing_key).unwrap();
        assert!(token.validate().is_ok());
    }

    #[test]
    fn test_burn_with_exp_fails() {
        let user = Identity::generate("user", &mut OsRng);
        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.public_key.clone(),
            jti: String::from("burn-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Burn,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714608000,
            exp: Some(9999999999),
            body_type: None,
            body_cbor: None,
        };
        let err = Token::sign(payload, &user.signing_key).unwrap_err();
        assert_eq!(err, TokenError::RevocationMustNotExpire);
    }

    #[test]
    fn test_payload_hash_deterministic() {
        let ident = Identity::generate("alice", &mut OsRng);
        let payload = make_attest_payload(&ident);
        let token = Token::sign(payload, &ident.signing_key).unwrap();
        let h1 = token.payload_hash();
        let h2 = token.payload_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn test_token_kind_display() {
        assert_eq!(format!("{}", TokenKind::Attest), "vch:attest");
        assert_eq!(format!("{}", TokenKind::Vouch), "vch:vouch");
        assert_eq!(format!("{}", TokenKind::Revoke), "vch:revoke");
        assert_eq!(format!("{}", TokenKind::Burn), "vch:burn");
    }

    #[test]
    fn test_deserialize_corrupted_cbor() {
        let result = Token::from_cbor(&[0xff, 0xfe, 0x00]);
        let err = result.unwrap_err();
        assert_eq!(err, TokenError::DeserializationError);
    }

    #[test]
    fn test_token_error_display() {
        assert!(!format!("{}", TokenError::InvalidSignature).is_empty());
        assert!(!format!("{}", TokenError::InvalidPublicKey).is_empty());
        assert!(!format!("{}", TokenError::IssuerKeyMismatch).is_empty());
        assert!(!format!("{}", TokenError::RevocationMustNotExpire).is_empty());
        assert!(!format!("{}", TokenError::VouchMissingFields).is_empty());
        assert!(!format!("{}", TokenError::RevokeMissingTarget).is_empty());
        assert!(!format!("{}", TokenError::SerializationError).is_empty());
        assert!(!format!("{}", TokenError::DeserializationError).is_empty());
        assert!(!format!("{}", TokenError::InvalidIssuerUrn).is_empty());
        assert!(!format!("{}", TokenError::UnsupportedWireVersion(42)).is_empty());
        assert!(!format!("{}", TokenError::NonCanonicalPayload).is_empty());
    }

    // ---------- M-1: v2 canonical-CBOR signing tests ----------

    #[test]
    fn default_sign_produces_v2_envelope() {
        let ident = Identity::generate("alice", &mut OsRng);
        let token = Token::sign(make_attest_payload(&ident), &ident.signing_key).unwrap();
        assert_eq!(token.wire_version(), TOKEN_WIRE_V2);
        assert!(token.verify_signature().is_ok());
    }

    #[test]
    fn v2_payload_bytes_are_canonical() {
        let ident = Identity::generate("alice", &mut OsRng);
        let token = Token::sign(make_attest_payload(&ident), &ident.signing_key).unwrap();
        let recanon = crate::cbor_canonical::encode_token_payload(&token.payload);
        assert_eq!(token.payload_bytes, recanon);
    }

    /// v1 signing remains available so tests that pin pre-v2 bytes
    /// still pass, and so operators with legacy state can mint
    /// matching tokens for debugging.
    #[test]
    fn v1_sign_and_verify_still_works() {
        let ident = Identity::generate("alice", &mut OsRng);
        let token = Token::sign_v1(make_attest_payload(&ident), &ident.signing_key).unwrap();
        assert_eq!(token.wire_version(), TOKEN_WIRE_V1);
        assert!(token.verify_signature().is_ok());
    }

    /// A v2 signature must not verify when interpreted as v1
    /// (different signed bytes due to the domain tag), and vice versa.
    #[test]
    fn v1_and_v2_signatures_are_not_interchangeable() {
        let ident = Identity::generate("alice", &mut OsRng);
        let payload = make_attest_payload(&ident);

        let v2 = Token::sign(payload.clone(), &ident.signing_key).unwrap();
        // Build a hand-rolled v1 token that reuses v2's signature —
        // must fail verification.
        let forged = Token {
            payload: v2.payload.clone(),
            payload_bytes: cbor_encode(&v2.payload).unwrap(),
            signature: v2.signature().clone(),
            wire_version: TOKEN_WIRE_V1,
        };
        assert_eq!(
            forged.verify_signature(),
            Err(TokenError::InvalidSignature)
        );

        // Same story the other way: v1 signature in a v2 envelope
        // flags non-canonical payload (or signature invalid) once
        // we recanonicalise.
        let v1 = Token::sign_v1(payload, &ident.signing_key).unwrap();
        let forged = Token {
            payload: v1.payload.clone(),
            payload_bytes: v1.payload_bytes.clone(),
            signature: v1.signature().clone(),
            wire_version: TOKEN_WIRE_V2,
        };
        // The wire bytes came from ciborium (v1 path), not the
        // canonical encoder, so recanonicalisation catches it first.
        assert_eq!(
            forged.verify_signature(),
            Err(TokenError::NonCanonicalPayload)
        );
    }

    /// v2 verifier rejects a token whose payload bytes aren't the
    /// canonical re-encoding of the decoded payload. Attack surface:
    /// attacker crafts wire bytes that decode into a valid payload
    /// but whose order/encoding differs from canonical.
    #[test]
    fn v2_rejects_non_canonical_payload_bytes() {
        let ident = Identity::generate("alice", &mut OsRng);
        let payload = make_attest_payload(&ident);
        // Correctly-signed v2 token, then corrupt payload_bytes to a
        // non-canonical ciborium encoding.
        let mut token = Token::sign(payload.clone(), &ident.signing_key).unwrap();
        token.payload_bytes = cbor_encode(&payload).unwrap();
        assert_eq!(
            token.verify_signature(),
            Err(TokenError::NonCanonicalPayload)
        );
    }

    #[test]
    fn v2_cbor_roundtrip_preserves_wire_version() {
        let ident = Identity::generate("alice", &mut OsRng);
        let token = Token::sign(make_attest_payload(&ident), &ident.signing_key).unwrap();
        let cbor = token.to_cbor().unwrap();
        let restored = Token::from_cbor(&cbor).unwrap();
        assert_eq!(restored.wire_version(), TOKEN_WIRE_V2);
        assert!(restored.verify_signature().is_ok());
    }

    #[test]
    fn v1_cbor_roundtrip_decoded_as_v1_when_v_absent() {
        // Envelope without the `v` field must decode as v1 (legacy
        // pre-M-1 state on disk).
        let ident = Identity::generate("alice", &mut OsRng);
        let token = Token::sign_v1(make_attest_payload(&ident), &ident.signing_key).unwrap();
        // Re-encode the legacy envelope by hand (no `v` field).
        let sig_bytes = cbor_encode(token.signature()).unwrap();
        #[derive(serde::Serialize)]
        struct LegacyWire<'a> {
            #[serde(with = "serde_bytes")]
            payload: &'a [u8],
            #[serde(with = "serde_bytes")]
            signature: &'a [u8],
        }
        let wire = LegacyWire {
            payload: &token.payload_bytes,
            signature: &sig_bytes,
        };
        let mut envelope = Vec::new();
        ciborium::into_writer(&wire, &mut envelope).unwrap();
        let restored = Token::from_cbor(&envelope).unwrap();
        assert_eq!(restored.wire_version(), TOKEN_WIRE_V1);
        assert!(restored.verify_signature().is_ok());
    }

    /// **Review regression** — legacy v=1 hybrid tokens must still
    /// verify after M-2 lands. The dispatch in `Token::verify_signature`
    /// routes v=1 envelopes through `crypto::verify_v1` which in turn
    /// calls `hybrid::verify_hybrid_v1` (no scheme prefixes). Without
    /// this path, `allow_legacy_v1_tokens = true` would only get
    /// legacy hybrid tokens past the ingest filter; validation would
    /// still reject them because the v2 verifier expects
    /// scheme-prefixed signed bytes that a pre-M-2 signer never
    /// produced.
    #[cfg(feature = "pq")]
    #[test]
    fn v1_hybrid_token_still_verifies_after_m2() {
        let root = Identity::generate_hybrid("pq-root", &mut OsRng);
        let payload = TokenPayload {
            iss: root.id.to_urn(),
            iss_key: root.public_key.clone(),
            jti: "legacy-hybrid".into(),
            sub: root.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1_000,
            exp: Some(4_102_444_800),
            body_type: None,
            body_cbor: None,
        };
        // Build a v=1 hybrid token using the legacy (pre-M-2) sign
        // path. This mirrors what's already on disk on any node that
        // ran a pre-v2 release.
        let token = Token::create_with_version(payload, TOKEN_WIRE_V1, |msg| {
            root.hybrid_key.sign_v1(msg)
        })
        .unwrap();
        assert_eq!(token.wire_version(), TOKEN_WIRE_V1);
        assert!(
            token.verify_signature().is_ok(),
            "legacy v=1 hybrid token must verify via verify_hybrid_v1"
        );

        // And crucially: a v=1 envelope carrying a v=2 (prefixed)
        // hybrid signature must STILL fail, since v=1 dispatch goes
        // through the unprefixed verifier.
        let v2_sig = root.hybrid_key.sign_v2(&token.payload_bytes);
        let forged = Token {
            payload: token.payload.clone(),
            payload_bytes: token.payload_bytes.clone(),
            signature: v2_sig,
            wire_version: TOKEN_WIRE_V1,
        };
        assert_eq!(
            forged.verify_signature(),
            Err(TokenError::InvalidSignature)
        );
    }

    #[test]
    fn unsupported_wire_version_rejected() {
        // Manually build an envelope with v = 99.
        let ident = Identity::generate("alice", &mut OsRng);
        let token = Token::sign(make_attest_payload(&ident), &ident.signing_key).unwrap();
        let sig_bytes = cbor_encode(token.signature()).unwrap();
        let wire = TokenWire {
            v: 99,
            payload: token.payload_bytes.clone(),
            signature: sig_bytes,
        };
        let mut env = Vec::new();
        ciborium::into_writer(&wire, &mut env).unwrap();
        match Token::from_cbor(&env) {
            Err(TokenError::UnsupportedWireVersion(99)) => {}
            other => panic!("expected UnsupportedWireVersion(99), got {other:?}"),
        }
    }
}
