//! Domain identity for DDS — Stage 1 (software domain key).
//!
//! A "domain" is a cryptographic realm that DDS nodes belong to. Two
//! mechanisms keep domains separate and admission-controlled:
//!
//! 1. **Protocol isolation** — the domain id is baked into libp2p protocol
//!    strings (`/dds/kad/1.0.0/<domain-tag>` etc), so nodes from different
//!    domains cannot complete a libp2p handshake.
//! 2. **Admission certificates** — within a domain, only nodes holding an
//!    [`AdmissionCert`] signed by the domain key are valid. The cert is
//!    verified at node startup against the public domain key in config.
//!
//! ## Concepts
//!
//! - [`DomainKey`] — Ed25519 keypair that *is* the domain. Created on the
//!   first node ("genesis") and used to sign admission certs for siblings.
//!   In Stage 2 this will move to a FIDO2 authenticator (the
//!   [`DomainSigner`] trait is the seam).
//! - [`DomainId`] — `sha256(pubkey)`, displayed as `dds-dom:<base32>`.
//! - [`Domain`] — public information (name, id, pubkey) safe to share with
//!   sibling nodes.
//! - [`AdmissionCert`] — signed statement "this peer id is admitted to this
//!   domain", verifiable by anyone with the [`Domain`] pubkey.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN_ID_PREFIX: &str = "dds-dom:";
const B32: base32::Alphabet = base32::Alphabet::Rfc4648Lower { padding: false };

/// Hex helpers (avoid pulling in another crate).
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, DomainError> {
    if !s.len().is_multiple_of(2) {
        return Err(DomainError::Parse("hex length must be even".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, DomainError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DomainError::Parse(format!("invalid hex digit: {c:#x}"))),
    }
}

/// 32-byte cryptographic identifier for a domain (`sha256(pubkey)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainId(pub [u8; 32]);

impl DomainId {
    /// Derive the id from the raw Ed25519 public key bytes.
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(pubkey);
        let out = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        Self(bytes)
    }

    /// Parse from `dds-dom:<base32>` form.
    pub fn parse(s: &str) -> Result<Self, DomainError> {
        let body = s
            .strip_prefix(DOMAIN_ID_PREFIX)
            .ok_or_else(|| DomainError::Parse(format!("missing '{DOMAIN_ID_PREFIX}' prefix")))?;
        let bytes =
            base32::decode(B32, body).ok_or_else(|| DomainError::Parse("invalid base32".into()))?;
        if bytes.len() != 32 {
            return Err(DomainError::Parse(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        Ok(Self(a))
    }

    /// Bare base32 form (no `dds-dom:` prefix), suitable for embedding in
    /// libp2p protocol strings where the prefix would be noise.
    pub fn protocol_tag(&self) -> String {
        base32::encode(B32, &self.0)
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{DOMAIN_ID_PREFIX}{}", base32::encode(B32, &self.0))
    }
}

/// Public information about a domain. Safe to share with sibling nodes;
/// contains no secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub id: DomainId,
    pub pubkey: [u8; 32],
}

impl Domain {
    /// Verify that the stored `pubkey` actually hashes to the stored `id`.
    /// Should be called after loading a `Domain` from any untrusted source.
    pub fn verify_self_consistent(&self) -> Result<(), DomainError> {
        let derived = DomainId::from_pubkey(&self.pubkey);
        if derived == self.id {
            Ok(())
        } else {
            Err(DomainError::Mismatch(
                "domain pubkey does not hash to id".into(),
            ))
        }
    }

    /// Construct an `ed25519_dalek::VerifyingKey` from the stored pubkey.
    pub fn verifying_key(&self) -> Result<VerifyingKey, DomainError> {
        VerifyingKey::from_bytes(&self.pubkey).map_err(|e| DomainError::Crypto(e.to_string()))
    }
}

/// Trait for "something that can sign on behalf of a domain". In Stage 1
/// the only impl is [`DomainKey`] (software). In Stage 2 a hardware
/// `Fido2DomainSigner` will implement this without any other code change.
pub trait DomainSigner {
    fn domain(&self) -> Domain;
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DomainError>;
}

/// Software domain key — holds the Ed25519 secret in process memory.
/// Stage 1 implementation; superseded by FIDO2-backed signer in Stage 2.
pub struct DomainKey {
    pub name: String,
    pub signing_key: SigningKey,
}

impl DomainKey {
    pub fn generate<R: CryptoRng + RngCore>(name: &str, rng: &mut R) -> Self {
        Self {
            name: name.to_string(),
            signing_key: SigningKey::generate(rng),
        }
    }

    pub fn from_secret_bytes(name: &str, secret: [u8; 32]) -> Self {
        Self {
            name: name.to_string(),
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn id(&self) -> DomainId {
        DomainId::from_pubkey(&self.pubkey())
    }

    /// Build the public [`Domain`] descriptor for this key.
    pub fn domain(&self) -> Domain {
        Domain {
            name: self.name.clone(),
            id: self.id(),
            pubkey: self.pubkey(),
        }
    }

    /// Issue an admission cert for a node identified by `peer_id` (the
    /// stringified libp2p PeerId of the sibling node).
    pub fn issue_admission(
        &self,
        peer_id: String,
        issued_at: u64,
        expires_at: Option<u64>,
    ) -> AdmissionCert {
        let body = AdmissionBody {
            domain_id: self.id(),
            peer_id,
            issued_at,
            expires_at,
        };
        let payload = body.to_signing_bytes();
        let sig = self.signing_key.sign(&payload);
        AdmissionCert {
            body,
            signature: sig.to_bytes().to_vec(),
        }
    }
}

impl DomainSigner for DomainKey {
    fn domain(&self) -> Domain {
        DomainKey::domain(self)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DomainError> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

/// The signed body of an admission certificate. Field order is fixed; the
/// CBOR encoding of this struct is what gets signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionBody {
    pub domain_id: DomainId,
    pub peer_id: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}

impl AdmissionBody {
    fn to_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("cbor encode admission body");
        buf
    }
}

/// An admission certificate: the domain key signs the assertion that a
/// given libp2p peer id is allowed to participate in the domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionCert {
    pub body: AdmissionBody,
    pub signature: Vec<u8>, // 64 bytes
}

impl AdmissionCert {
    pub fn to_cbor(&self) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| DomainError::Serialize(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DomainError> {
        ciborium::from_reader(bytes).map_err(|e| DomainError::Deserialize(e.to_string()))
    }

    /// Verify the signature against `domain_pubkey` and confirm the cert
    /// applies to `expected_peer_id` in `expected_domain_id`, and is not
    /// expired at `now` (UNIX seconds since the epoch).
    pub fn verify(
        &self,
        domain_pubkey: &[u8; 32],
        expected_domain_id: &DomainId,
        expected_peer_id: &str,
        now: u64,
    ) -> Result<(), DomainError> {
        if &self.body.domain_id != expected_domain_id {
            return Err(DomainError::Mismatch("domain_id mismatch".into()));
        }
        if self.body.peer_id != expected_peer_id {
            return Err(DomainError::Mismatch("peer_id mismatch".into()));
        }
        if let Some(exp) = self.body.expires_at
            && now > exp
        {
            return Err(DomainError::Expired);
        }
        if self.signature.len() != 64 {
            return Err(DomainError::Signature(format!(
                "expected 64-byte signature, got {}",
                self.signature.len()
            )));
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        let vk = VerifyingKey::from_bytes(domain_pubkey)
            .map_err(|e| DomainError::Crypto(e.to_string()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let payload = self.body.to_signing_bytes();
        vk.verify(&payload, &sig)
            .map_err(|e| DomainError::Signature(e.to_string()))?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum DomainError {
    Parse(String),
    Mismatch(String),
    Crypto(String),
    Signature(String),
    Serialize(String),
    Deserialize(String),
    Expired,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::Parse(e) => write!(f, "parse: {e}"),
            DomainError::Mismatch(e) => write!(f, "mismatch: {e}"),
            DomainError::Crypto(e) => write!(f, "crypto: {e}"),
            DomainError::Signature(e) => write!(f, "signature: {e}"),
            DomainError::Serialize(e) => write!(f, "serialize: {e}"),
            DomainError::Deserialize(e) => write!(f, "deserialize: {e}"),
            DomainError::Expired => write!(f, "admission cert expired"),
        }
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn domain_id_roundtrip() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let id = key.id();
        let s = id.to_string();
        assert!(s.starts_with("dds-dom:"));
        let parsed = DomainId::parse(&s).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn domain_id_derived_from_pubkey() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let domain = key.domain();
        domain.verify_self_consistent().unwrap();
    }

    #[test]
    fn domain_id_parse_rejects_bad_prefix() {
        assert!(DomainId::parse("acme:abc").is_err());
    }

    #[test]
    fn domain_id_parse_rejects_short() {
        assert!(DomainId::parse("dds-dom:abc").is_err());
    }

    #[test]
    fn admission_cert_sign_and_verify() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let domain = key.domain();
        let cert = key.issue_admission("12D3KooWPeerIdExample".into(), 1000, Some(2000));
        cert.verify(&domain.pubkey, &domain.id, "12D3KooWPeerIdExample", 1500)
            .unwrap();
    }

    #[test]
    fn admission_cert_rejects_wrong_peer() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let domain = key.domain();
        let cert = key.issue_admission("peer-A".into(), 0, None);
        assert!(matches!(
            cert.verify(&domain.pubkey, &domain.id, "peer-B", 0),
            Err(DomainError::Mismatch(_))
        ));
    }

    #[test]
    fn admission_cert_rejects_wrong_domain() {
        let key_a = DomainKey::generate("acme.com", &mut OsRng);
        let key_b = DomainKey::generate("globex.com", &mut OsRng);
        let cert = key_a.issue_admission("peer".into(), 0, None);
        let other = key_b.domain();
        assert!(cert.verify(&other.pubkey, &other.id, "peer", 0).is_err());
    }

    #[test]
    fn admission_cert_rejects_expired() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let d = key.domain();
        let cert = key.issue_admission("peer".into(), 0, Some(100));
        assert!(matches!(
            cert.verify(&d.pubkey, &d.id, "peer", 200),
            Err(DomainError::Expired)
        ));
    }

    #[test]
    fn admission_cert_rejects_tampered_signature() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let d = key.domain();
        let mut cert = key.issue_admission("peer".into(), 0, None);
        cert.signature[0] ^= 0xff;
        assert!(matches!(
            cert.verify(&d.pubkey, &d.id, "peer", 0),
            Err(DomainError::Signature(_))
        ));
    }

    #[test]
    fn admission_cert_cbor_roundtrip() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let cert = key.issue_admission("peer".into(), 0, Some(100));
        let bytes = cert.to_cbor().unwrap();
        let decoded = AdmissionCert::from_cbor(&bytes).unwrap();
        let d = key.domain();
        decoded.verify(&d.pubkey, &d.id, "peer", 50).unwrap();
    }

    #[test]
    fn protocol_tag_is_stable_for_same_key() {
        let bytes = [42u8; 32];
        let key = DomainKey::from_secret_bytes("acme.com", bytes);
        let id = key.id();
        let tag1 = id.protocol_tag();
        let tag2 = id.protocol_tag();
        assert_eq!(tag1, tag2);
        assert!(!tag1.contains("dds-dom:"));
    }

    #[test]
    fn different_domains_have_different_protocol_tags() {
        let a = DomainKey::generate("acme.com", &mut OsRng);
        let b = DomainKey::generate("globex.com", &mut OsRng);
        assert_ne!(a.id().protocol_tag(), b.id().protocol_tag());
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let s = to_hex(&bytes);
        assert_eq!(s, "deadbeef00ff");
        assert_eq!(from_hex(&s).unwrap(), bytes);
    }
}
