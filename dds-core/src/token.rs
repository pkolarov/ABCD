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

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::VouchsafeId;

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
    /// Issuer's Ed25519 public key (32 bytes).
    #[serde(with = "serde_bytes_array")]
    pub iss_key: [u8; 32],
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
}

/// A signed Vouchsafe token: payload + Ed25519 signature.
#[derive(Debug, Clone)]
pub struct Token {
    pub payload: TokenPayload,
    /// CBOR-encoded payload bytes (the signed data).
    payload_bytes: Vec<u8>,
    /// Ed25519 signature over `payload_bytes`.
    signature: Signature,
}

impl Token {
    /// Create and sign a token from a payload and signing key.
    pub fn sign(payload: TokenPayload, signing_key: &SigningKey) -> Result<Self, TokenError> {
        // Validate: revocations and burns MUST NOT have exp
        if matches!(payload.kind, TokenKind::Revoke | TokenKind::Burn) && payload.exp.is_some() {
            return Err(TokenError::RevocationMustNotExpire);
        }
        // Validate: vouches MUST have vch_iss and vch_sum
        if payload.kind == TokenKind::Vouch
            && (payload.vch_iss.is_none() || payload.vch_sum.is_none())
        {
            return Err(TokenError::VouchMissingFields);
        }
        // Validate: revocations MUST have revokes
        if payload.kind == TokenKind::Revoke && payload.revokes.is_none() {
            return Err(TokenError::RevokeMissingTarget);
        }

        let payload_bytes = cbor_encode(&payload)?;
        let signature = signing_key.sign(&payload_bytes);

        Ok(Self {
            payload,
            payload_bytes,
            signature,
        })
    }

    /// Verify the token's signature against the embedded issuer public key.
    pub fn verify_signature(&self) -> Result<(), TokenError> {
        let verifying_key = VerifyingKey::from_bytes(&self.payload.iss_key)
            .map_err(|_| TokenError::InvalidPublicKey)?;
        verifying_key
            .verify(&self.payload_bytes, &self.signature)
            .map_err(|_| TokenError::InvalidSignature)
    }

    /// Verify that the issuer URN is cryptographically bound to the issuer key.
    pub fn verify_issuer_binding(&self) -> Result<(), TokenError> {
        let id = VouchsafeId::from_urn(&self.payload.iss)
            .map_err(|_| TokenError::InvalidIssuerUrn)?;
        let verifying_key = VerifyingKey::from_bytes(&self.payload.iss_key)
            .map_err(|_| TokenError::InvalidPublicKey)?;
        if !id.verify_binding(&verifying_key) {
            return Err(TokenError::IssuerKeyMismatch);
        }
        Ok(())
    }

    /// Full validation: signature + issuer binding.
    pub fn validate(&self) -> Result<(), TokenError> {
        self.verify_signature()?;
        self.verify_issuer_binding()?;
        Ok(())
    }

    /// Compute the SHA-256 hash of this token's payload bytes (for use as `vch_sum`).
    pub fn payload_hash(&self) -> String {
        let digest = Sha256::digest(&self.payload_bytes);
        hex_encode(&digest)
    }

    /// Serialize the full token (payload + signature) to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, TokenError> {
        let wire = TokenWire {
            payload: self.payload_bytes.clone(),
            signature: self.signature.to_bytes(),
        };
        cbor_encode(&wire)
    }

    /// Deserialize a token from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, TokenError> {
        let wire: TokenWire = cbor_decode(bytes)?;
        let payload: TokenPayload = cbor_decode(&wire.payload)?;
        let signature =
            Signature::from_bytes(&wire.signature);

        Ok(Self {
            payload,
            payload_bytes: wire.payload,
            signature,
        })
    }

    /// Get the signature.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Wire format for serializing a signed token.
#[derive(Serialize, Deserialize)]
struct TokenWire {
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    #[serde(with = "serde_bytes_64")]
    signature: [u8; 64],
}

/// Serde helper for fixed-size [u8; 32] as bytes.
mod serde_bytes_array {
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v: Vec<u8> = <serde_bytes::ByteBuf as Deserialize>::deserialize(d)?.into_vec();
        v.as_slice().try_into().map_err(serde::de::Error::custom)
    }
}

/// Helper: CBOR encode.
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
        }
    }
}

/// Serde helper for fixed-size [u8; 64] as bytes.
mod serde_bytes_64 {
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(bytes.as_slice()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = <serde_bytes::ByteBuf as Deserialize>::deserialize(d)?.into_vec();
        v.as_slice().try_into().map_err(serde::de::Error::custom)
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
            iss_key: ident.verifying_key().to_bytes(),
            jti: String::from("test-jti-1"),
            sub: String::from("test-sub-1"),
            kind: TokenKind::Attest,
            purpose: Some(String::from("dds:directory-entry")),
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714605000,
            exp: Some(1746141000),
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
        payload.iss_key = bob.verifying_key().to_bytes();

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
        payload.iss_key = bob.verifying_key().to_bytes();
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
            iss_key: admin.verifying_key().to_bytes(),
            jti: String::from("vouch-jti-1"),
            sub: String::from("test-sub-1"),
            kind: TokenKind::Vouch,
            purpose: Some(String::from("dds:group:backend-devs")),
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(user_token.payload_hash()),
            revokes: None,
            iat: 1714606000,
            exp: Some(1746142000),
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
            iss_key: admin.verifying_key().to_bytes(),
            jti: String::from("vouch-jti"),
            sub: String::from("sub"),
            kind: TokenKind::Vouch,
            purpose: None,
            vch_iss: None, // missing
            vch_sum: None, // missing
            revokes: None,
            iat: 1714606000,
            exp: Some(1746142000),
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
            iss_key: admin.verifying_key().to_bytes(),
            jti: String::from("revoke-jti"),
            sub: String::from("user-sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: Some(user.id.to_urn()),
            vch_sum: Some(String::from("deadbeef")),
            revokes: Some(String::from("vouch-jti-1")),
            iat: 1714608000,
            exp: None, // Revocations must not expire
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
            iss_key: admin.verifying_key().to_bytes(),
            jti: String::from("revoke-jti"),
            sub: String::from("sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: Some(String::from("target-jti")),
            iat: 1714608000,
            exp: Some(9999999999), // not allowed
        };
        let err = Token::sign(payload, &admin.signing_key).unwrap_err();
        assert_eq!(err, TokenError::RevocationMustNotExpire);
    }

    #[test]
    fn test_revoke_missing_target() {
        let admin = Identity::generate("admin", &mut OsRng);

        let payload = TokenPayload {
            iss: admin.id.to_urn(),
            iss_key: admin.verifying_key().to_bytes(),
            jti: String::from("revoke-jti"),
            sub: String::from("sub"),
            kind: TokenKind::Revoke,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None, // missing
            iat: 1714608000,
            exp: None,
        };
        let err = Token::sign(payload, &admin.signing_key).unwrap_err();
        assert_eq!(err, TokenError::RevokeMissingTarget);
    }

    #[test]
    fn test_burn_token() {
        let user = Identity::generate("user", &mut OsRng);

        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.verifying_key().to_bytes(),
            jti: String::from("burn-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Burn,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714608000,
            exp: None,
        };

        let token = Token::sign(payload, &user.signing_key).unwrap();
        assert!(token.validate().is_ok());
        assert_eq!(token.payload.kind, TokenKind::Burn);
    }

    #[test]
    fn test_burn_with_exp_fails() {
        let user = Identity::generate("user", &mut OsRng);
        let payload = TokenPayload {
            iss: user.id.to_urn(),
            iss_key: user.verifying_key().to_bytes(),
            jti: String::from("burn-jti"),
            sub: user.id.to_urn(),
            kind: TokenKind::Burn,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 1714608000,
            exp: Some(9999999999),
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
    }
}
