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
#[cfg(feature = "pq")]
use pqcrypto_mldsa::mldsa65;
#[cfg(feature = "pq")]
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN_ID_PREFIX: &str = "dds-dom:";
const B32: base32::Alphabet = base32::Alphabet::Rfc4648Lower { padding: false };

/// **Z-1 Phase A** — domain separator for the ML-DSA-65 component of a
/// v2-hybrid admission cert. Distinct from the revocation prefix so a
/// signature over an admission body cannot be replayed as a signature
/// over a revocation body. Null-terminated so a longer tag cannot be
/// confused with a shorter one (mirrors the M-2 pattern in
/// `dds_core::crypto::hybrid`).
#[cfg(feature = "pq")]
pub(crate) const ADMISSION_PQ_PREFIX_V2: &[u8] = b"dds-admission-v2/mldsa65\x00";
/// **Z-1 Phase A** — sibling separator for the ML-DSA-65 component of a
/// v2-hybrid admission revocation.
#[cfg(feature = "pq")]
pub(crate) const REVOCATION_PQ_PREFIX_V2: &[u8] = b"dds-revocation-v2/mldsa65\x00";

/// ML-DSA-65 (FIPS 204) public key length, in bytes.
#[cfg(feature = "pq")]
pub const MLDSA65_PK_LEN: usize = 1952;
/// ML-DSA-65 detached-signature length, in bytes.
#[cfg(feature = "pq")]
pub const MLDSA65_SIG_LEN: usize = 3309;

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
///
/// **Z-1 Phase A**: an optional `pq_pubkey` (ML-DSA-65, 1,952 bytes)
/// upgrades the domain to v2-hybrid. Once present, all admission certs
/// and admission revocations must carry a v2 PQ signature; a v1
/// (Ed25519-only) cert is rejected. Absent ⇒ legacy Ed25519-only domain
/// (the v1 default — preserves existing on-disk and on-wire formats).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub id: DomainId,
    pub pubkey: [u8; 32],
    /// **Z-1 Phase A** — ML-DSA-65 public key (1,952 bytes) when the
    /// domain has been rotated to v2-hybrid. `#[serde(default)]` +
    /// `skip_serializing_if = "Option::is_none"` keeps legacy v1
    /// encodings byte-identical so old peers still deserialize cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_pubkey: Option<Vec<u8>>,
}

impl Domain {
    /// Verify that the stored `pubkey` actually hashes to the stored `id`,
    /// and that any `pq_pubkey` has the correct length for ML-DSA-65.
    /// Should be called after loading a `Domain` from any untrusted source.
    pub fn verify_self_consistent(&self) -> Result<(), DomainError> {
        let derived = DomainId::from_pubkey(&self.pubkey);
        if derived != self.id {
            return Err(DomainError::Mismatch(
                "domain pubkey does not hash to id".into(),
            ));
        }
        #[cfg(feature = "pq")]
        if let Some(pq) = &self.pq_pubkey
            && pq.len() != MLDSA65_PK_LEN
        {
            return Err(DomainError::Mismatch(format!(
                "pq_pubkey: expected {MLDSA65_PK_LEN} bytes, got {}",
                pq.len()
            )));
        }
        Ok(())
    }

    /// Construct an `ed25519_dalek::VerifyingKey` from the stored pubkey.
    pub fn verifying_key(&self) -> Result<VerifyingKey, DomainError> {
        VerifyingKey::from_bytes(&self.pubkey).map_err(|e| DomainError::Crypto(e.to_string()))
    }

    /// **Z-1 Phase A** — true if this domain has been rotated to v2
    /// (i.e., requires hybrid PQ signatures on every admission artifact).
    pub fn is_hybrid(&self) -> bool {
        self.pq_pubkey.is_some()
    }
}

/// Trait for "something that can sign on behalf of a domain". In Stage 1
/// the only impl is [`DomainKey`] (software). In Stage 2 a hardware
/// `Fido2DomainSigner` will implement this without any other code change.
pub trait DomainSigner {
    fn domain(&self) -> Domain;
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DomainError>;
}

/// **Z-1 Phase A** — ML-DSA-65 (FIPS 204) keypair owned by a hybrid
/// [`DomainKey`]. Wraps the raw `pqcrypto-mldsa` types so callers
/// don't need a direct dep on the underlying crate, and so the
/// secret-key bytes can be exported/imported for on-disk persistence.
#[cfg(feature = "pq")]
pub struct DomainPqKey {
    secret_key: mldsa65::SecretKey,
    public_key: mldsa65::PublicKey,
}

#[cfg(feature = "pq")]
impl DomainPqKey {
    /// Generate a fresh ML-DSA-65 keypair. (`pqcrypto-mldsa` uses its
    /// own internal RNG — no `rng` parameter exposed.)
    pub fn generate() -> Self {
        let (public_key, secret_key) = mldsa65::keypair();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Reconstruct from raw secret-key bytes (for loading a persisted
    /// hybrid domain key from disk). Recomputes the matching public key
    /// from the secret material via a one-shot self-test sign so a
    /// corrupt secret blob is rejected at load time rather than the
    /// first signing attempt.
    pub fn from_secret_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self, DomainError> {
        let secret_key = mldsa65::SecretKey::from_bytes(sk_bytes)
            .map_err(|e| DomainError::Crypto(format!("ml-dsa-65 secret: {e}")))?;
        let public_key = mldsa65::PublicKey::from_bytes(pk_bytes)
            .map_err(|e| DomainError::Crypto(format!("ml-dsa-65 public: {e}")))?;
        // Cheap self-test: sign a fixed sentinel and verify with the
        // claimed public key. Catches the "secret + foreign public"
        // mismatch at load time.
        let probe = b"dds-pq-self-test\x00";
        let sig = mldsa65::detached_sign(probe, &secret_key);
        mldsa65::verify_detached_signature(&sig, probe, &public_key)
            .map_err(|_| DomainError::Crypto("ml-dsa-65 secret/public mismatch".into()))?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Raw ML-DSA-65 public-key bytes (1,952 bytes, [`MLDSA65_PK_LEN`]).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    /// Raw ML-DSA-65 secret-key bytes (for on-disk persistence —
    /// callers must protect these at the same level as the Ed25519
    /// secret).
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_bytes().to_vec()
    }

    /// Sign a message with this PQ key, returning the raw 3,309-byte
    /// detached signature ([`MLDSA65_SIG_LEN`]).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        mldsa65::detached_sign(message, &self.secret_key)
            .as_bytes()
            .to_vec()
    }
}

/// Software domain key — holds the Ed25519 secret in process memory.
/// Stage 1 implementation; superseded by FIDO2-backed signer in Stage 2.
///
/// **Z-1 Phase A**: an optional `pq` half (`DomainPqKey`) upgrades the
/// key to v2-hybrid. When present, `issue_admission` and
/// `revoke_admission` co-sign with ML-DSA-65 and the resulting cert /
/// revocation carries a `pq_signature`. Construct via
/// [`Self::generate_hybrid`] for new v2 domains; the legacy
/// [`Self::generate`] / [`Self::from_secret_bytes`] paths produce a
/// v1 (Ed25519-only) key with `pq = None`.
pub struct DomainKey {
    pub name: String,
    pub signing_key: SigningKey,
    /// **Z-1 Phase A** — ML-DSA-65 half of a hybrid domain key.
    /// `None` for legacy Ed25519-only domains.
    #[cfg(feature = "pq")]
    pub pq: Option<DomainPqKey>,
}

impl DomainKey {
    pub fn generate<R: CryptoRng + RngCore>(name: &str, rng: &mut R) -> Self {
        Self {
            name: name.to_string(),
            signing_key: SigningKey::generate(rng),
            #[cfg(feature = "pq")]
            pq: None,
        }
    }

    /// **Z-1 Phase A** — generate a v2-hybrid domain key (Ed25519 +
    /// ML-DSA-65). The Ed25519 half still defines the [`DomainId`]
    /// (`sha256(ed_pubkey)`) so a fleet that rotates from v1 to v2
    /// keeps the same DomainId — only `Domain.pq_pubkey` becomes
    /// populated, and admission certs grow a `pq_signature` field.
    #[cfg(feature = "pq")]
    pub fn generate_hybrid<R: CryptoRng + RngCore>(name: &str, rng: &mut R) -> Self {
        Self {
            name: name.to_string(),
            signing_key: SigningKey::generate(rng),
            pq: Some(DomainPqKey::generate()),
        }
    }

    pub fn from_secret_bytes(name: &str, secret: [u8; 32]) -> Self {
        Self {
            name: name.to_string(),
            signing_key: SigningKey::from_bytes(&secret),
            #[cfg(feature = "pq")]
            pq: None,
        }
    }

    /// **Z-1 Phase A** — reconstruct a hybrid domain key from raw
    /// Ed25519 secret bytes plus the ML-DSA-65 secret/public key
    /// bytes. Used by the v2 on-disk format in
    /// `dds-node::domain_store`.
    #[cfg(feature = "pq")]
    pub fn from_secret_bytes_hybrid(
        name: &str,
        ed_secret: [u8; 32],
        pq_secret: &[u8],
        pq_public: &[u8],
    ) -> Result<Self, DomainError> {
        Ok(Self {
            name: name.to_string(),
            signing_key: SigningKey::from_bytes(&ed_secret),
            pq: Some(DomainPqKey::from_secret_bytes(pq_secret, pq_public)?),
        })
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// **Z-1 Phase A** — raw ML-DSA-65 public-key bytes if this is a
    /// hybrid key, `None` otherwise.
    #[cfg(feature = "pq")]
    pub fn pq_pubkey_bytes(&self) -> Option<Vec<u8>> {
        self.pq.as_ref().map(|p| p.public_key_bytes())
    }

    /// **Z-1 Phase A** — true if this key carries an ML-DSA-65 half.
    pub fn is_hybrid(&self) -> bool {
        #[cfg(feature = "pq")]
        {
            self.pq.is_some()
        }
        #[cfg(not(feature = "pq"))]
        {
            false
        }
    }

    pub fn id(&self) -> DomainId {
        DomainId::from_pubkey(&self.pubkey())
    }

    /// Build the public [`Domain`] descriptor for this key. When the
    /// key is v2-hybrid, the resulting `Domain.pq_pubkey` is `Some`
    /// and downstream verifiers will require a `pq_signature` on every
    /// admission artifact for this domain.
    pub fn domain(&self) -> Domain {
        Domain {
            name: self.name.clone(),
            id: self.id(),
            pubkey: self.pubkey(),
            #[cfg(feature = "pq")]
            pq_pubkey: self.pq.as_ref().map(|p| p.public_key_bytes()),
            #[cfg(not(feature = "pq"))]
            pq_pubkey: None,
        }
    }

    /// Issue an admission cert for a node identified by `peer_id` (the
    /// stringified libp2p PeerId of the sibling node).
    ///
    /// **Z-1 Phase A**: if this key is v2-hybrid, the returned cert
    /// also carries a `pq_signature` (ML-DSA-65 over
    /// [`ADMISSION_PQ_PREFIX_V2`] || body_bytes). The Ed25519
    /// component continues to sign raw body bytes so a v1 verifier
    /// can still validate the cert (defence in depth: both signatures
    /// must verify under a v2 verifier; only the Ed25519 sig is
    /// checked under a v1 verifier).
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
        #[cfg(feature = "pq")]
        let pq_signature = self.pq.as_ref().map(|pq| {
            let mut prefixed = Vec::with_capacity(ADMISSION_PQ_PREFIX_V2.len() + payload.len());
            prefixed.extend_from_slice(ADMISSION_PQ_PREFIX_V2);
            prefixed.extend_from_slice(&payload);
            pq.sign(&prefixed)
        });
        #[cfg(not(feature = "pq"))]
        let pq_signature: Option<Vec<u8>> = None;
        AdmissionCert {
            body,
            signature: sig.to_bytes().to_vec(),
            pq_signature,
        }
    }

    /// Issue an admission revocation for a peer id. Once a node loads
    /// this revocation, it will refuse to admit `peer_id` during the
    /// H-12 handshake regardless of what cert that peer presents.
    /// Revocations are permanent — there is no un-revoke. To re-admit
    /// the peer, generate a new libp2p keypair on the target machine
    /// and issue a fresh admission cert for the new PeerId.
    ///
    /// **Z-1 Phase A**: if this key is v2-hybrid, the returned
    /// revocation also carries a `pq_signature` (ML-DSA-65 over
    /// [`REVOCATION_PQ_PREFIX_V2`] || body_bytes).
    pub fn revoke_admission(
        &self,
        peer_id: String,
        revoked_at: u64,
        reason: Option<String>,
    ) -> AdmissionRevocation {
        let body = RevocationBody {
            domain_id: self.id(),
            peer_id,
            revoked_at,
            reason,
        };
        let payload = body.to_signing_bytes();
        let sig = self.signing_key.sign(&payload);
        #[cfg(feature = "pq")]
        let pq_signature = self.pq.as_ref().map(|pq| {
            let mut prefixed = Vec::with_capacity(REVOCATION_PQ_PREFIX_V2.len() + payload.len());
            prefixed.extend_from_slice(REVOCATION_PQ_PREFIX_V2);
            prefixed.extend_from_slice(&payload);
            pq.sign(&prefixed)
        });
        #[cfg(not(feature = "pq"))]
        let pq_signature: Option<Vec<u8>> = None;
        AdmissionRevocation {
            body,
            signature: sig.to_bytes().to_vec(),
            pq_signature,
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
///
/// **Z-1 Phase A** — when issued by a v2-hybrid [`DomainKey`], the
/// optional `pq_signature` carries an ML-DSA-65 sig over
/// [`ADMISSION_PQ_PREFIX_V2`] || body_bytes. A v2 verifier
/// ([`Self::verify_with_domain`]) requires this signature when the
/// target [`Domain`] has a `pq_pubkey`; legacy v1 nodes ignore the
/// field and continue to verify Ed25519 only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionCert {
    pub body: AdmissionBody,
    pub signature: Vec<u8>, // 64 bytes Ed25519
    /// **Z-1 Phase A** — ML-DSA-65 signature (3,309 bytes) over
    /// `ADMISSION_PQ_PREFIX_V2 || body.to_signing_bytes()`. Absent on
    /// v1 certs; required by [`Self::verify_with_domain`] when the
    /// domain has a `pq_pubkey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<Vec<u8>>,
}

impl AdmissionCert {
    pub fn to_cbor(&self) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| DomainError::Serialize(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DomainError> {
        // Bounded depth: peer-supplied via H-12 handshake. Security
        // review I-6.
        dds_core::cbor_bounded::from_reader(bytes)
            .map_err(|e| DomainError::Deserialize(e.to_string()))
    }

    /// Verify the Ed25519 signature against `domain_pubkey` and confirm
    /// the cert applies to `expected_peer_id` in `expected_domain_id`,
    /// and is not expired at `now` (UNIX seconds since the epoch).
    ///
    /// **v1 / Ed25519-only verification.** This method does *not*
    /// inspect [`Self::pq_signature`]; callers in a v2-hybrid domain
    /// must use [`Self::verify_with_domain`] to enforce the PQ
    /// component. Kept for backward compat with callers that hold raw
    /// pubkey bytes (and for tests).
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

    /// **Z-1 Phase A** — verify against a full [`Domain`], enforcing
    /// the v2 PQ signature when the domain is hybrid.
    ///
    /// Behaviour:
    /// - Always verifies the body invariants (domain_id, peer_id,
    ///   expiry) and the Ed25519 signature.
    /// - If `domain.pq_pubkey` is `Some`, also requires
    ///   `self.pq_signature` to be `Some` and verifies it as ML-DSA-65
    ///   over `ADMISSION_PQ_PREFIX_V2 || body_bytes`. Missing or
    ///   malformed PQ signature ⇒ `DomainError::Signature`.
    /// - If `domain.pq_pubkey` is `None`, accepts the cert with or
    ///   without `pq_signature` (legacy v1 verification).
    pub fn verify_with_domain(
        &self,
        domain: &Domain,
        expected_peer_id: &str,
        now: u64,
    ) -> Result<(), DomainError> {
        // Step 1: Ed25519 + body invariants (existing v1 path).
        self.verify(&domain.pubkey, &domain.id, expected_peer_id, now)?;

        // Step 2: enforce the PQ component when the domain requires it.
        #[cfg(feature = "pq")]
        if let Some(pq_pk) = &domain.pq_pubkey {
            let pq_sig = self.pq_signature.as_ref().ok_or_else(|| {
                DomainError::Signature(
                    "v2 hybrid domain requires pq_signature on admission cert".into(),
                )
            })?;
            verify_pq_admission_signature(pq_pk, &self.body.to_signing_bytes(), pq_sig)?;
        }
        #[cfg(not(feature = "pq"))]
        if domain.pq_pubkey.is_some() {
            return Err(DomainError::Crypto(
                "domain advertises pq_pubkey but binary built without `pq` feature".into(),
            ));
        }
        Ok(())
    }
}

/// **Z-1 Phase A** — verify an ML-DSA-65 signature over
/// `ADMISSION_PQ_PREFIX_V2 || body_bytes` against `pq_pubkey` (raw
/// 1,952-byte ML-DSA-65 public key).
#[cfg(feature = "pq")]
fn verify_pq_admission_signature(
    pq_pubkey: &[u8],
    body_bytes: &[u8],
    pq_signature: &[u8],
) -> Result<(), DomainError> {
    if pq_pubkey.len() != MLDSA65_PK_LEN {
        return Err(DomainError::Crypto(format!(
            "pq_pubkey: expected {MLDSA65_PK_LEN} bytes, got {}",
            pq_pubkey.len()
        )));
    }
    if pq_signature.len() != MLDSA65_SIG_LEN {
        return Err(DomainError::Signature(format!(
            "pq_signature: expected {MLDSA65_SIG_LEN} bytes, got {}",
            pq_signature.len()
        )));
    }
    let pk = mldsa65::PublicKey::from_bytes(pq_pubkey)
        .map_err(|e| DomainError::Crypto(format!("ml-dsa-65 pk: {e}")))?;
    let sig = mldsa65::DetachedSignature::from_bytes(pq_signature)
        .map_err(|e| DomainError::Signature(format!("ml-dsa-65 sig: {e}")))?;
    let mut prefixed = Vec::with_capacity(ADMISSION_PQ_PREFIX_V2.len() + body_bytes.len());
    prefixed.extend_from_slice(ADMISSION_PQ_PREFIX_V2);
    prefixed.extend_from_slice(body_bytes);
    mldsa65::verify_detached_signature(&sig, &prefixed, &pk)
        .map_err(|e| DomainError::Signature(format!("ml-dsa-65 verify: {e}")))
}

/// Signed body of an admission revocation. Mirrors [`AdmissionBody`] in
/// shape so peers can verify revocations against the same domain pubkey
/// they already trust for admissions. Field order is fixed; the CBOR
/// encoding of this struct is what gets signed.
///
/// `peer_id` is the libp2p PeerId string of the node whose admission is
/// being revoked. `revoked_at` is UNIX-seconds at issuance (used by
/// recipients to detect rebroadcast staleness, not to expire the
/// revocation itself — once revoked, a peer stays revoked).
///
/// **Threat-model §1 — admission cert revocation list (open item #4).**
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationBody {
    pub domain_id: DomainId,
    pub peer_id: String,
    pub revoked_at: u64,
    pub reason: Option<String>,
}

impl RevocationBody {
    fn to_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("cbor encode revocation body");
        buf
    }
}

/// Domain-signed statement that a previously-admitted peer id is no
/// longer welcome in the domain. Verified against the domain pubkey;
/// peers check the local revocation list during the H-12 admission
/// handshake and refuse to admit a peer whose id appears here.
///
/// **Z-1 Phase A** — when issued by a v2-hybrid [`DomainKey`], the
/// optional `pq_signature` carries an ML-DSA-65 sig over
/// [`REVOCATION_PQ_PREFIX_V2`] || body_bytes. A v2 verifier
/// ([`Self::verify_with_domain`]) requires this signature when the
/// target [`Domain`] has a `pq_pubkey`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionRevocation {
    pub body: RevocationBody,
    pub signature: Vec<u8>, // 64 bytes Ed25519
    /// **Z-1 Phase A** — ML-DSA-65 signature (3,309 bytes) over
    /// `REVOCATION_PQ_PREFIX_V2 || body.to_signing_bytes()`. Absent on
    /// v1 revocations; required by [`Self::verify_with_domain`] when
    /// the domain has a `pq_pubkey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<Vec<u8>>,
}

impl AdmissionRevocation {
    pub fn to_cbor(&self) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| DomainError::Serialize(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DomainError> {
        // Bounded depth: peer-supplied via H-12 handshake piggy-back
        // and via `dds-node import-revocation`. Security review I-6.
        dds_core::cbor_bounded::from_reader(bytes)
            .map_err(|e| DomainError::Deserialize(e.to_string()))
    }

    /// Verify the Ed25519 signature against `domain_pubkey` and confirm
    /// the revocation applies to `expected_domain_id`. Unlike
    /// [`AdmissionCert::verify`], there is no `expected_peer_id` argument
    /// — callers iterate the revocation list and match on
    /// `body.peer_id` themselves.
    ///
    /// **v1 / Ed25519-only verification.** Does *not* inspect
    /// [`Self::pq_signature`]; v2 callers should use
    /// [`Self::verify_with_domain`].
    pub fn verify(
        &self,
        domain_pubkey: &[u8; 32],
        expected_domain_id: &DomainId,
    ) -> Result<(), DomainError> {
        if &self.body.domain_id != expected_domain_id {
            return Err(DomainError::Mismatch("domain_id mismatch".into()));
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

    /// **Z-1 Phase A** — verify against a full [`Domain`], enforcing
    /// the v2 PQ signature when the domain is hybrid. Same shape as
    /// [`AdmissionCert::verify_with_domain`] but uses the revocation
    /// PQ prefix.
    pub fn verify_with_domain(&self, domain: &Domain) -> Result<(), DomainError> {
        self.verify(&domain.pubkey, &domain.id)?;
        #[cfg(feature = "pq")]
        if let Some(pq_pk) = &domain.pq_pubkey {
            let pq_sig = self.pq_signature.as_ref().ok_or_else(|| {
                DomainError::Signature(
                    "v2 hybrid domain requires pq_signature on admission revocation".into(),
                )
            })?;
            verify_pq_revocation_signature(pq_pk, &self.body.to_signing_bytes(), pq_sig)?;
        }
        #[cfg(not(feature = "pq"))]
        if domain.pq_pubkey.is_some() {
            return Err(DomainError::Crypto(
                "domain advertises pq_pubkey but binary built without `pq` feature".into(),
            ));
        }
        Ok(())
    }
}

/// **Z-1 Phase A** — verify an ML-DSA-65 signature over
/// `REVOCATION_PQ_PREFIX_V2 || body_bytes` against `pq_pubkey`.
#[cfg(feature = "pq")]
fn verify_pq_revocation_signature(
    pq_pubkey: &[u8],
    body_bytes: &[u8],
    pq_signature: &[u8],
) -> Result<(), DomainError> {
    if pq_pubkey.len() != MLDSA65_PK_LEN {
        return Err(DomainError::Crypto(format!(
            "pq_pubkey: expected {MLDSA65_PK_LEN} bytes, got {}",
            pq_pubkey.len()
        )));
    }
    if pq_signature.len() != MLDSA65_SIG_LEN {
        return Err(DomainError::Signature(format!(
            "pq_signature: expected {MLDSA65_SIG_LEN} bytes, got {}",
            pq_signature.len()
        )));
    }
    let pk = mldsa65::PublicKey::from_bytes(pq_pubkey)
        .map_err(|e| DomainError::Crypto(format!("ml-dsa-65 pk: {e}")))?;
    let sig = mldsa65::DetachedSignature::from_bytes(pq_signature)
        .map_err(|e| DomainError::Signature(format!("ml-dsa-65 sig: {e}")))?;
    let mut prefixed = Vec::with_capacity(REVOCATION_PQ_PREFIX_V2.len() + body_bytes.len());
    prefixed.extend_from_slice(REVOCATION_PQ_PREFIX_V2);
    prefixed.extend_from_slice(body_bytes);
    mldsa65::verify_detached_signature(&sig, &prefixed, &pk)
        .map_err(|e| DomainError::Signature(format!("ml-dsa-65 verify: {e}")))
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

    #[test]
    fn admission_revocation_sign_and_verify() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let d = key.domain();
        let rev = key.revoke_admission(
            "12D3KooWPeerIdExample".into(),
            1_700_000_000,
            Some("key compromise".into()),
        );
        rev.verify(&d.pubkey, &d.id).unwrap();
        assert_eq!(rev.body.peer_id, "12D3KooWPeerIdExample");
        assert_eq!(rev.body.reason.as_deref(), Some("key compromise"));
    }

    #[test]
    fn admission_revocation_rejects_wrong_domain() {
        let a = DomainKey::generate("acme.com", &mut OsRng);
        let b = DomainKey::generate("globex.com", &mut OsRng);
        let rev = a.revoke_admission("peer".into(), 0, None);
        let other = b.domain();
        assert!(rev.verify(&other.pubkey, &other.id).is_err());
    }

    #[test]
    fn admission_revocation_rejects_tampered_signature() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let d = key.domain();
        let mut rev = key.revoke_admission("peer".into(), 0, None);
        rev.signature[0] ^= 0xff;
        assert!(matches!(
            rev.verify(&d.pubkey, &d.id),
            Err(DomainError::Signature(_))
        ));
    }

    #[test]
    fn admission_revocation_rejects_tampered_body() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let d = key.domain();
        let mut rev = key.revoke_admission("peer-A".into(), 0, None);
        // Forge a different peer id while keeping the original signature.
        rev.body.peer_id = "peer-B".into();
        assert!(matches!(
            rev.verify(&d.pubkey, &d.id),
            Err(DomainError::Signature(_))
        ));
    }

    #[test]
    fn admission_revocation_cbor_roundtrip() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let rev = key.revoke_admission("peer".into(), 1234, Some("decommissioned".into()));
        let bytes = rev.to_cbor().unwrap();
        let decoded = AdmissionRevocation::from_cbor(&bytes).unwrap();
        let d = key.domain();
        decoded.verify(&d.pubkey, &d.id).unwrap();
        assert_eq!(decoded, rev);
    }

    #[test]
    fn admission_revocation_signature_is_unique_per_peer() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let r1 = key.revoke_admission("peer-A".into(), 100, None);
        let r2 = key.revoke_admission("peer-B".into(), 100, None);
        assert_ne!(r1.signature, r2.signature);
    }

    /// **I-6 (security review)**. The H-12 admission handshake reads a
    /// peer-supplied CBOR blob — `AdmissionCert::from_cbor` must reject a
    /// depth-bomb input cleanly rather than recursing toward stack
    /// exhaustion.
    #[test]
    fn i6_admission_cert_from_cbor_refuses_depth_bomb() {
        let mut bytes = vec![0x81u8; 2048]; // 2048 × array(1)
        bytes.push(0x00); // leaf int
        let res = AdmissionCert::from_cbor(&bytes);
        assert!(matches!(res, Err(DomainError::Deserialize(_))));
    }

    /// **I-6 (security review)**. The H-12 piggy-back path and the
    /// `import-revocation` CLI both feed bytes to
    /// `AdmissionRevocation::from_cbor` — same depth-bomb posture.
    #[test]
    fn i6_admission_revocation_from_cbor_refuses_depth_bomb() {
        let mut bytes = vec![0x81u8; 2048];
        bytes.push(0x00);
        let res = AdmissionRevocation::from_cbor(&bytes);
        assert!(matches!(res, Err(DomainError::Deserialize(_))));
    }

    // -----------------------------------------------------------------
    // Z-1 Phase A — hybrid-sign admission cert + revocation tests
    // -----------------------------------------------------------------

    /// A v1 (Ed25519-only) `Domain` reports `is_hybrid() == false` and
    /// has no `pq_pubkey`; a v2-hybrid domain reports the inverse and
    /// the pq_pubkey has the FIPS 204 length.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_domain_descriptor_includes_pq_pubkey() {
        let v1 = DomainKey::generate("acme.com", &mut OsRng).domain();
        assert!(!v1.is_hybrid());
        assert!(v1.pq_pubkey.is_none());

        let v2 = DomainKey::generate_hybrid("acme.com", &mut OsRng).domain();
        assert!(v2.is_hybrid());
        let pq = v2.pq_pubkey.as_ref().expect("hybrid pq_pubkey");
        assert_eq!(pq.len(), MLDSA65_PK_LEN);
    }

    /// A v2 admission cert verifies under `verify_with_domain` against
    /// the issuing v2 domain. Both Ed25519 + ML-DSA-65 components are
    /// checked.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_admission_cert_verifies_with_domain() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let cert = key.issue_admission("12D3KooWHybrid".into(), 1000, Some(2000));
        assert!(cert.pq_signature.is_some());
        assert_eq!(cert.pq_signature.as_ref().unwrap().len(), MLDSA65_SIG_LEN);
        cert.verify_with_domain(&domain, "12D3KooWHybrid", 1500)
            .unwrap();
    }

    /// **The Phase A security gate.** A v2-hybrid `Domain` rejects an
    /// admission cert that lacks `pq_signature` — this is the
    /// post-quantum-forgeability defence: even if an attacker mints an
    /// Ed25519-only cert (e.g., via a future quantum break on the
    /// classical component), the v2 verifier refuses to admit them.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_domain_rejects_v1_cert_lacking_pq_signature() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        // Issue with only the Ed25519 half by stripping pq_signature.
        let mut cert = key.issue_admission("peer".into(), 0, None);
        cert.pq_signature = None;
        let err = cert
            .verify_with_domain(&domain, "peer", 0)
            .expect_err("hybrid domain must reject v1 cert");
        assert!(
            matches!(err, DomainError::Signature(_)),
            "expected Signature error, got {err:?}"
        );
    }

    /// A tampered PQ signature (single-bit flip) is rejected.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_admission_cert_rejects_tampered_pq_signature() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let mut cert = key.issue_admission("peer".into(), 0, None);
        cert.pq_signature.as_mut().unwrap()[0] ^= 0xff;
        let err = cert
            .verify_with_domain(&domain, "peer", 0)
            .expect_err("tampered pq_signature must be rejected");
        assert!(matches!(err, DomainError::Signature(_)));
    }

    /// Wrong-length PQ signature is rejected with a Signature error
    /// (rather than panicking inside the FIPS 204 verifier).
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_admission_cert_rejects_wrong_length_pq_signature() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let mut cert = key.issue_admission("peer".into(), 0, None);
        cert.pq_signature = Some(vec![0u8; 10]);
        let err = cert
            .verify_with_domain(&domain, "peer", 0)
            .expect_err("wrong-length pq_signature must be rejected");
        assert!(matches!(err, DomainError::Signature(_)));
    }

    /// Backwards-compat: a v1-only domain still accepts a v2 cert.
    /// The v2 verifier ignores `pq_signature` when the domain has no
    /// `pq_pubkey`, so a fleet that hasn't yet rotated to v2 keeps
    /// running unchanged even if a freshly-issued cert carries a PQ
    /// component.
    #[cfg(feature = "pq")]
    #[test]
    fn v1_domain_accepts_v2_cert() {
        // Hybrid issuer, but consume Domain only from a v1 view (no pq_pubkey).
        let hybrid_key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let mut v1_domain = hybrid_key.domain();
        v1_domain.pq_pubkey = None;
        let cert = hybrid_key.issue_admission("peer".into(), 0, None);
        cert.verify_with_domain(&v1_domain, "peer", 0).unwrap();
    }

    /// A v1 cert (no pq_signature) verifies cleanly under a v1 domain
    /// via the new `verify_with_domain` entry point. Ensures the v2
    /// verifier code path is fully backward-compatible.
    #[cfg(feature = "pq")]
    #[test]
    fn v1_domain_accepts_v1_cert_via_verify_with_domain() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let domain = key.domain();
        assert!(!domain.is_hybrid());
        let cert = key.issue_admission("peer".into(), 0, None);
        assert!(cert.pq_signature.is_none());
        cert.verify_with_domain(&domain, "peer", 0).unwrap();
    }

    /// Hybrid cert survives a CBOR round-trip and still verifies. The
    /// `pq_signature` is the long field (~3.3 KB) — pin that ciborium
    /// encodes/decodes it without truncation.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_admission_cert_cbor_roundtrip() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let cert = key.issue_admission("peer".into(), 0, Some(100));
        let bytes = cert.to_cbor().unwrap();
        let decoded = AdmissionCert::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.pq_signature, cert.pq_signature);
        let domain = key.domain();
        decoded.verify_with_domain(&domain, "peer", 50).unwrap();
    }

    /// Hybrid revocation: same shape as the cert path. Verifies under
    /// `verify_with_domain` against the issuing v2 domain.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_admission_revocation_verifies_with_domain() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let rev = key.revoke_admission("peer".into(), 1234, Some("rotated".into()));
        assert!(rev.pq_signature.is_some());
        assert_eq!(rev.pq_signature.as_ref().unwrap().len(), MLDSA65_SIG_LEN);
        rev.verify_with_domain(&domain).unwrap();
    }

    /// The Phase A gate also applies to revocations: a v2-hybrid
    /// domain refuses a v1 revocation that lacks `pq_signature`.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_domain_rejects_v1_revocation_lacking_pq_signature() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let mut rev = key.revoke_admission("peer".into(), 0, None);
        rev.pq_signature = None;
        let err = rev
            .verify_with_domain(&domain)
            .expect_err("hybrid domain must reject v1 revocation");
        assert!(matches!(err, DomainError::Signature(_)));
    }

    /// **Cross-message-type domain separation.** An ML-DSA-65 sig
    /// produced over an admission body (with the
    /// `dds-admission-v2/mldsa65` prefix) is NOT a valid revocation
    /// pq_signature, even if the body bytes were the same. Pins the
    /// `REVOCATION_PQ_PREFIX_V2 != ADMISSION_PQ_PREFIX_V2` invariant.
    #[cfg(feature = "pq")]
    #[test]
    fn admission_pq_signature_cannot_be_replayed_as_revocation() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let cert = key.issue_admission("peer".into(), 0, None);
        // Take the admission PQ signature and try to use it as a
        // revocation PQ signature over a body crafted to be byte-equal.
        // Even if the underlying body bytes were the same, the prefix
        // domain-separates the verification — the revocation verifier
        // recomputes the prefixed message with REVOCATION_PQ_PREFIX_V2
        // and the admission-prefixed sig won't match.
        let mut rev = key.revoke_admission("peer".into(), 0, None);
        rev.pq_signature = cert.pq_signature.clone();
        let err = rev
            .verify_with_domain(&domain)
            .expect_err("cross-type pq sig replay must fail");
        assert!(matches!(err, DomainError::Signature(_)));
    }

    /// `Domain::verify_self_consistent` rejects a domain with a
    /// wrong-length pq_pubkey. Defends against a tampered TOML file
    /// that ships a too-short or too-long PQ pubkey.
    #[cfg(feature = "pq")]
    #[test]
    fn domain_verify_self_consistent_rejects_wrong_length_pq_pubkey() {
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let mut domain = key.domain();
        domain.pq_pubkey = Some(vec![0u8; 10]); // too short
        assert!(matches!(
            domain.verify_self_consistent(),
            Err(DomainError::Mismatch(_))
        ));
    }

    /// `Domain` round-trips through CBOR with `pq_pubkey` populated.
    /// This is the on-wire shape used by provisioning bundles and any
    /// future Domain-as-CBOR ship path.
    #[cfg(feature = "pq")]
    #[test]
    fn hybrid_domain_cbor_roundtrip_preserves_pq_pubkey() {
        let key = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let domain = key.domain();
        let mut buf = Vec::new();
        ciborium::into_writer(&domain, &mut buf).unwrap();
        let decoded: Domain = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded, domain);
        assert!(decoded.is_hybrid());
    }

    /// **Backwards-compat wire format.** A v1 `Domain` (no pq_pubkey)
    /// CBOR-decodes from a v2 reader as a domain with `pq_pubkey:
    /// None` — and conversely a v2 `Domain` is consumable by a v1
    /// reader that ignores unknown fields. Mirrors the existing
    /// `admission_response_decodes_legacy_v1_wire_without_revocations_field`
    /// pattern in dds-net::admission.
    #[cfg(feature = "pq")]
    #[test]
    fn legacy_v1_domain_wire_decodes_under_v2_schema() {
        // Build a v1-shape Domain (no pq_pubkey field at all on the wire).
        #[derive(Serialize)]
        struct V1Domain<'a> {
            name: &'a str,
            id: DomainId,
            pubkey: [u8; 32],
        }
        let key = DomainKey::generate("acme.com", &mut OsRng);
        let v1 = V1Domain {
            name: &key.name,
            id: key.id(),
            pubkey: key.pubkey(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&v1, &mut buf).unwrap();
        let decoded: Domain = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.pubkey, key.pubkey());
        assert!(decoded.pq_pubkey.is_none());
        assert!(!decoded.is_hybrid());
    }

    /// `DomainPqKey::from_secret_bytes` rejects a secret/public-key
    /// mismatch via the self-test sign+verify probe inside the
    /// constructor. Catches bit-rot on the PQ secret blob at load
    /// time rather than the first signing attempt.
    #[cfg(feature = "pq")]
    #[test]
    fn domain_pq_key_from_secret_bytes_rejects_mismatch() {
        let a = DomainPqKey::generate();
        let b = DomainPqKey::generate();
        // A's secret with B's public is a deliberate mismatch.
        let res = DomainPqKey::from_secret_bytes(&a.secret_key_bytes(), &b.public_key_bytes());
        assert!(matches!(res, Err(DomainError::Crypto(_))));
        // Self-consistent pair round-trips cleanly.
        let ok =
            DomainPqKey::from_secret_bytes(&a.secret_key_bytes(), &a.public_key_bytes()).unwrap();
        assert_eq!(ok.public_key_bytes(), a.public_key_bytes());
    }

    /// `DomainKey::from_secret_bytes_hybrid` reconstructs the exact
    /// hybrid key — same Ed25519 pubkey, same DomainId, same v2
    /// `pq_pubkey`. Tested end-to-end by issuing a cert from the
    /// reconstructed key and verifying under the original domain.
    #[cfg(feature = "pq")]
    #[test]
    fn domain_key_from_secret_bytes_hybrid_round_trips() {
        let original = DomainKey::generate_hybrid("acme.com", &mut OsRng);
        let ed_secret = original.signing_key.to_bytes();
        let pq = original.pq.as_ref().unwrap();
        let pq_secret = pq.secret_key_bytes();
        let pq_public = pq.public_key_bytes();

        let restored =
            DomainKey::from_secret_bytes_hybrid("acme.com", ed_secret, &pq_secret, &pq_public)
                .unwrap();
        assert_eq!(restored.pubkey(), original.pubkey());
        assert_eq!(restored.id(), original.id());
        assert_eq!(restored.pq_pubkey_bytes(), Some(pq_public));

        // End-to-end: a cert from the restored key verifies under the
        // original key's domain.
        let cert = restored.issue_admission("peer".into(), 0, None);
        cert.verify_with_domain(&original.domain(), "peer", 0)
            .unwrap();
    }
}
