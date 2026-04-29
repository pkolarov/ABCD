//! Hybrid X25519 + ML-KEM-768 (FIPS 203) Key Encapsulation Mechanism.
//!
//! Phase B of the Z-1 PQC rollout uses this construction to wrap
//! per-publisher epoch AEAD keys for distribution to admitted peers.
//! See [`docs/pqc-phase-b-plan.md`](../../../docs/pqc-phase-b-plan.md)
//! for the full design.
//!
//! # Construction
//!
//! Combines X25519 ECDH with ML-KEM-768 in parallel and derives a
//! single 32-byte shared secret via HKDF-SHA256, mirroring the
//! IETF `draft-ietf-tls-hybrid-design` family pattern:
//!
//! ```text
//! ss_classical = X25519(eph_x_sk, recipient_x_pk)        # 32 bytes
//! (mlkem_ct, ss_pq) = MLKEM-768.encap(recipient_pq_pk)   # ct=1088B, ss=32B
//!
//! secret = HKDF-SHA256-Expand(
//!            HKDF-SHA256-Extract(salt = b"dds-pqc-kem-hybrid-v1",
//!                                ikm  = ss_classical || ss_pq),
//!            info = binding_info,
//!            len  = 32)
//! ```
//!
//! `binding_info` is supplied by the caller and **must** include any
//! per-instance domain separation (publisher pubkey, recipient pubkey,
//! epoch id, ...) so that an attacker cannot lift either component
//! shared secret out of one (publisher, recipient, epoch) tuple and
//! replay it elsewhere. This mirrors the M-2 / Phase A
//! domain-separation pattern.
//!
//! # Sizes
//!
//! - `HybridKemPublicKey`: 32 (X25519) + 1184 (ML-KEM-768) = 1216 bytes wire
//! - `HybridKemSecretKey`: 32 (X25519) + 64 (ML-KEM-768 seed) = 96 bytes on disk
//! - `KemCiphertext`: 32 (X25519 ephemeral) + 1088 (ML-KEM-768) = 1120 bytes wire
//! - Output shared secret: 32 bytes
//!
//! # Defence-in-depth
//!
//! Compromise of the X25519 leg alone (e.g. CRQC against the discrete
//! log) leaves the PQ leg intact; compromise of ML-KEM-768 alone
//! leaves the classical leg intact. Both must break for the derived
//! secret to be recovered.

use alloc::vec::Vec;
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::array::typenum::Unsigned;
use ml_kem::{B32, Decapsulate, KeyExport, MlKem768};
use ml_kem::{DecapsulationKey, EncapsulationKey};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use super::traits::CryptoError;

/// Length of the X25519 public key, ECDH share, and X25519 secret key.
pub const X25519_KEY_LEN: usize = 32;

/// Length of an ML-KEM-768 encapsulation key (public key, FIPS 203).
pub const MLKEM768_PUBKEY_LEN: usize = 1184;

/// Length of an ML-KEM-768 ciphertext (FIPS 203).
pub const MLKEM768_CT_LEN: usize = 1088;

/// Length of an ML-KEM-768 seed (used to deterministically rebuild the
/// decapsulation key).
pub const MLKEM768_SEED_LEN: usize = 64;

/// Wire size of [`HybridKemPublicKey`].
pub const HYBRID_KEM_PUBKEY_LEN: usize = X25519_KEY_LEN + MLKEM768_PUBKEY_LEN;

/// Wire size of [`KemCiphertext`].
pub const HYBRID_KEM_CT_LEN: usize = X25519_KEY_LEN + MLKEM768_CT_LEN;

/// Length of the shared secret produced by [`encap`] / [`decap`].
pub const SHARED_SECRET_LEN: usize = 32;

/// HKDF salt — pinned, version-suffixed so a future v2 hybrid KEM
/// produces a disjoint derived secret for the same inputs (defence
/// against cross-version replay).
pub const HKDF_SALT_V1: &[u8] = b"dds-pqc-kem-hybrid-v1";

/// Hybrid KEM public key: 32-byte X25519 pubkey followed by the
/// 1184-byte ML-KEM-768 encapsulation key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKemPublicKey {
    /// X25519 public key.
    pub x_pub: [u8; X25519_KEY_LEN],
    /// ML-KEM-768 encapsulation key bytes.
    pub mlkem_pub: Vec<u8>,
}

impl HybridKemPublicKey {
    /// Concatenated wire form (X25519 ∥ ML-KEM-768).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_KEM_PUBKEY_LEN);
        out.extend_from_slice(&self.x_pub);
        out.extend_from_slice(&self.mlkem_pub);
        out
    }

    /// Parse the concatenated wire form. Returns
    /// [`CryptoError::InvalidPublicKey`] on length mismatch or on an
    /// ML-KEM-768 encoding the underlying library refuses to accept.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_PUBKEY_LEN {
            return Err(CryptoError::InvalidPublicKey);
        }
        let (x_bytes, ml_bytes) = bytes.split_at(X25519_KEY_LEN);
        let mut x_pub = [0u8; X25519_KEY_LEN];
        x_pub.copy_from_slice(x_bytes);

        // Validate ML-KEM pubkey byte form by parsing it through the
        // library; reject any encoding the FIPS 203 verifier would
        // reject so we never persist a malformed pubkey on disk or
        // accept one off the wire.
        let ml_array: &Array<u8, <EncapsulationKey<MlKem768> as ml_kem::KeySizeUser>::KeySize> =
            ml_bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidPublicKey)?;
        let _ek = EncapsulationKey::<MlKem768>::new(ml_array)
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        Ok(Self {
            x_pub,
            mlkem_pub: ml_bytes.to_vec(),
        })
    }
}

/// Hybrid KEM secret key. The ML-KEM-768 component is stored as the
/// 64-byte seed (FIPS 203 §6.1) rather than the expanded 2400-byte
/// decapsulation key — `from_seed` is deterministic and the seed form
/// is the format the FIPS 203 final spec recommends.
///
/// This type holds raw secret material; callers are expected to wrap
/// it in zeroizing storage before persisting.
#[derive(Clone)]
pub struct HybridKemSecretKey {
    /// X25519 secret scalar (clamped at use time by the underlying
    /// `StaticSecret`).
    pub x_sk: [u8; X25519_KEY_LEN],
    /// ML-KEM-768 64-byte seed.
    pub mlkem_seed: [u8; MLKEM768_SEED_LEN],
}

impl core::fmt::Debug for HybridKemSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridKemSecretKey")
            .field("x_sk", &"<redacted>")
            .field("mlkem_seed", &"<redacted>")
            .finish()
    }
}

/// Hybrid KEM ciphertext: sender's ephemeral X25519 public key
/// followed by the ML-KEM-768 ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemCiphertext {
    /// Sender's ephemeral X25519 public key.
    pub x_eph_pub: [u8; X25519_KEY_LEN],
    /// ML-KEM-768 ciphertext bytes.
    pub mlkem_ct: Vec<u8>,
}

impl KemCiphertext {
    /// Concatenated wire form (X25519-eph-pub ∥ ML-KEM-768-ct).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_KEM_CT_LEN);
        out.extend_from_slice(&self.x_eph_pub);
        out.extend_from_slice(&self.mlkem_ct);
        out
    }

    /// Parse the concatenated wire form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != HYBRID_KEM_CT_LEN {
            return Err(CryptoError::InvalidSignature);
        }
        let (x_bytes, ct_bytes) = bytes.split_at(X25519_KEY_LEN);
        let mut x_eph_pub = [0u8; X25519_KEY_LEN];
        x_eph_pub.copy_from_slice(x_bytes);
        Ok(Self {
            x_eph_pub,
            mlkem_ct: ct_bytes.to_vec(),
        })
    }
}

/// Generate a new hybrid KEM keypair from the supplied RNG. The RNG
/// is consumed for the X25519 secret scalar and for the 64-byte
/// ML-KEM-768 seed — the resulting decapsulation key is therefore
/// reproducible from the secret-key material alone.
pub fn generate<R: CryptoRngCore>(rng: &mut R) -> (HybridKemSecretKey, HybridKemPublicKey) {
    let mut x_sk_bytes = [0u8; X25519_KEY_LEN];
    rng.fill_bytes(&mut x_sk_bytes);
    let x_static = XStaticSecret::from(x_sk_bytes);
    let x_pub = XPublicKey::from(&x_static).to_bytes();

    let mut seed_bytes = [0u8; MLKEM768_SEED_LEN];
    rng.fill_bytes(&mut seed_bytes);
    let seed = ml_kem::Seed::from(seed_bytes);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let mlkem_pub = dk.encapsulation_key().to_bytes().to_vec();

    let secret = HybridKemSecretKey {
        x_sk: x_sk_bytes,
        mlkem_seed: seed_bytes,
    };
    let public = HybridKemPublicKey { x_pub, mlkem_pub };
    (secret, public)
}

/// Recompute the public key bundle from a secret key. Useful at load
/// time to verify on-disk material has not been torn (the derived
/// pubkey must match the recorded pubkey).
#[must_use]
pub fn public_from_secret(sk: &HybridKemSecretKey) -> HybridKemPublicKey {
    let x_static = XStaticSecret::from(sk.x_sk);
    let x_pub = XPublicKey::from(&x_static).to_bytes();
    let seed = ml_kem::Seed::from(sk.mlkem_seed);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let mlkem_pub = dk.encapsulation_key().to_bytes().to_vec();
    HybridKemPublicKey { x_pub, mlkem_pub }
}

/// Encapsulate a fresh 32-byte shared secret to `recipient_pk` and
/// return the wire ciphertext alongside the derived secret.
///
/// `binding_info` must include all per-instance domain separation
/// (publisher pubkey, recipient pubkey, epoch id, …) so that the
/// derived secret cannot be lifted across (publisher, recipient,
/// epoch) tuples. This is mixed into the HKDF `info` parameter
/// along with both peers' pubkeys.
pub fn encap<R: CryptoRngCore>(
    rng: &mut R,
    recipient_pk: &HybridKemPublicKey,
    binding_info: &[u8],
) -> Result<(KemCiphertext, [u8; SHARED_SECRET_LEN]), CryptoError> {
    // Classical leg — ephemeral X25519 ECDH.
    let mut x_eph_bytes = [0u8; X25519_KEY_LEN];
    rng.fill_bytes(&mut x_eph_bytes);
    let x_eph_static = XStaticSecret::from(x_eph_bytes);
    let x_eph_pub = XPublicKey::from(&x_eph_static).to_bytes();
    let x_recipient_pk = XPublicKey::from(recipient_pk.x_pub);
    let ss_classical = x_eph_static.diffie_hellman(&x_recipient_pk);

    // PQ leg — ML-KEM-768 encapsulation. We feed 32 bytes of strong
    // randomness from the caller's RNG into the deterministic
    // FIPS 203 encapsulator rather than bridging the two `rand_core`
    // versions in use across the workspace (0.6 here vs 0.10 inside
    // `ml-kem` 0.3). The `m` value is the ephemeral randomness FIPS
    // 203 §6.2 calls for; using it once per encapsulation matches
    // exactly what `encapsulate_with_rng` does internally.
    let ml_array: &Array<u8, <EncapsulationKey<MlKem768> as ml_kem::KeySizeUser>::KeySize> =
        recipient_pk
            .mlkem_pub
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
    let ek =
        EncapsulationKey::<MlKem768>::new(ml_array).map_err(|_| CryptoError::InvalidPublicKey)?;
    let mut m_bytes = [0u8; 32];
    rng.fill_bytes(&mut m_bytes);
    let m = B32::from(m_bytes);
    let (mlkem_ct, ss_pq) = ek.encapsulate_deterministic(&m);
    let mlkem_ct_vec = mlkem_ct.to_vec();

    // Combine via HKDF-SHA256 with the version-pinned salt + caller
    // binding info + both pubkeys + the ML-KEM ciphertext.
    let mut shared = [0u8; SHARED_SECRET_LEN];
    derive_secret(
        ss_classical.as_bytes(),
        ss_pq.as_slice(),
        recipient_pk,
        &x_eph_pub,
        &mlkem_ct_vec,
        binding_info,
        &mut shared,
    )?;

    Ok((
        KemCiphertext {
            x_eph_pub,
            mlkem_ct: mlkem_ct_vec,
        },
        shared,
    ))
}

/// Decapsulate `ciphertext` against `secret_key` and return the same
/// 32-byte shared secret that the encapsulating peer derived. The
/// `binding_info` must match the value the encapsulating peer used,
/// otherwise the derivation will silently produce a different secret
/// (and the AEAD verify on the layer above will fail).
pub fn decap(
    secret_key: &HybridKemSecretKey,
    ciphertext: &KemCiphertext,
    binding_info: &[u8],
) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
    if ciphertext.mlkem_ct.len() != MLKEM768_CT_LEN {
        return Err(CryptoError::InvalidSignature);
    }

    // Classical leg.
    let x_static = XStaticSecret::from(secret_key.x_sk);
    let x_eph_pub = XPublicKey::from(ciphertext.x_eph_pub);
    let ss_classical = x_static.diffie_hellman(&x_eph_pub);

    // PQ leg.
    let seed = ml_kem::Seed::from(secret_key.mlkem_seed);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    let ct_array: &Array<u8, <MlKem768 as ml_kem::kem::Kem>::CiphertextSize> = ciphertext
        .mlkem_ct
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let ss_pq = dk.decapsulate(ct_array);

    // Recompute the recipient public key for the HKDF info binding.
    // (The receiver knows its own pubkey; we recompute rather than
    // pass it through the cipher to keep the wire format minimal.)
    let recipient_x_pub = XPublicKey::from(&x_static).to_bytes();
    let recipient_mlkem_pub = dk.encapsulation_key().to_bytes().to_vec();
    let recipient_pk = HybridKemPublicKey {
        x_pub: recipient_x_pub,
        mlkem_pub: recipient_mlkem_pub,
    };

    let mut shared = [0u8; SHARED_SECRET_LEN];
    derive_secret(
        ss_classical.as_bytes(),
        ss_pq.as_slice(),
        &recipient_pk,
        &ciphertext.x_eph_pub,
        &ciphertext.mlkem_ct,
        binding_info,
        &mut shared,
    )?;
    Ok(shared)
}

/// Common HKDF combiner. Both legs' shared secrets feed the IKM; the
/// HKDF info string folds in both pubkeys, the ML-KEM ciphertext, and
/// the caller-supplied per-instance binding so that the derived
/// secret is bound to the (sender-eph, recipient, ml-kem-ct,
/// caller-binding) tuple.
fn derive_secret(
    ss_classical: &[u8],
    ss_pq: &[u8],
    recipient_pk: &HybridKemPublicKey,
    sender_eph_x_pub: &[u8; X25519_KEY_LEN],
    mlkem_ct: &[u8],
    caller_binding: &[u8],
    out: &mut [u8; SHARED_SECRET_LEN],
) -> Result<(), CryptoError> {
    let mut ikm = Vec::with_capacity(ss_classical.len() + ss_pq.len());
    ikm.extend_from_slice(ss_classical);
    ikm.extend_from_slice(ss_pq);

    let mut info = Vec::with_capacity(
        X25519_KEY_LEN + HYBRID_KEM_PUBKEY_LEN + mlkem_ct.len() + caller_binding.len(),
    );
    info.extend_from_slice(sender_eph_x_pub);
    info.extend_from_slice(&recipient_pk.x_pub);
    info.extend_from_slice(&recipient_pk.mlkem_pub);
    info.extend_from_slice(mlkem_ct);
    info.extend_from_slice(caller_binding);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_V1), &ikm);
    hk.expand(&info, out)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

// Sanity guards — the FIPS 203 sizes are the only thing we depend on
// for wire-format constancy; these `const` checks fail compilation if
// the upstream crate ever changes them under us.
const _: () = {
    assert!(
        <<EncapsulationKey<MlKem768> as ml_kem::KeySizeUser>::KeySize as Unsigned>::USIZE
            == MLKEM768_PUBKEY_LEN
    );
    assert!(<<MlKem768 as ml_kem::kem::Kem>::CiphertextSize as Unsigned>::USIZE == MLKEM768_CT_LEN);
};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::{OsRng, StdRng};

    fn fresh_keypair() -> (HybridKemSecretKey, HybridKemPublicKey) {
        let mut rng = OsRng;
        generate(&mut rng)
    }

    #[test]
    fn keypair_sizes_match_fips203() {
        let (sk, pk) = fresh_keypair();
        assert_eq!(pk.x_pub.len(), X25519_KEY_LEN);
        assert_eq!(pk.mlkem_pub.len(), MLKEM768_PUBKEY_LEN);
        assert_eq!(pk.to_bytes().len(), HYBRID_KEM_PUBKEY_LEN);
        assert_eq!(sk.x_sk.len(), X25519_KEY_LEN);
        assert_eq!(sk.mlkem_seed.len(), MLKEM768_SEED_LEN);
    }

    #[test]
    fn encap_decap_roundtrip() {
        let (sk, pk) = fresh_keypair();
        let mut rng = OsRng;
        let binding = b"test/encap-decap-roundtrip";
        let (ct, ss_send) = encap(&mut rng, &pk, binding).expect("encap");
        let ss_recv = decap(&sk, &ct, binding).expect("decap");
        assert_eq!(ss_send, ss_recv);
        assert_eq!(ct.x_eph_pub.len(), X25519_KEY_LEN);
        assert_eq!(ct.mlkem_ct.len(), MLKEM768_CT_LEN);
        assert_eq!(ct.to_bytes().len(), HYBRID_KEM_CT_LEN);
    }

    #[test]
    fn pubkey_wire_roundtrip() {
        let (_, pk) = fresh_keypair();
        let bytes = pk.to_bytes();
        let parsed = HybridKemPublicKey::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, pk);
    }

    #[test]
    fn pubkey_wire_rejects_wrong_length() {
        let (_, pk) = fresh_keypair();
        let mut bytes = pk.to_bytes();
        bytes.pop();
        assert_eq!(
            HybridKemPublicKey::from_bytes(&bytes),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn ciphertext_wire_roundtrip() {
        let (_, pk) = fresh_keypair();
        let mut rng = OsRng;
        let (ct, _) = encap(&mut rng, &pk, b"binding").expect("encap");
        let bytes = ct.to_bytes();
        let parsed = KemCiphertext::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, ct);
    }

    #[test]
    fn ciphertext_wire_rejects_wrong_length() {
        assert_eq!(
            KemCiphertext::from_bytes(&[0u8; HYBRID_KEM_CT_LEN - 1]),
            Err(CryptoError::InvalidSignature)
        );
    }

    #[test]
    fn public_from_secret_matches_generate() {
        let (sk, pk) = fresh_keypair();
        let derived = public_from_secret(&sk);
        assert_eq!(derived, pk);
    }

    #[test]
    fn wrong_recipient_decap_returns_unequal_secret() {
        let (_sk_a, pk_a) = fresh_keypair();
        let (sk_b, _pk_b) = fresh_keypair();
        let mut rng = OsRng;
        let (ct, ss_send) = encap(&mut rng, &pk_a, b"binding").expect("encap");
        // Decap with the wrong secret key must NOT yield the same
        // shared secret. ML-KEM's implicit-rejection design makes
        // this branch return a deterministic-but-wrong secret rather
        // than erroring, so we assert inequality rather than error.
        let ss_wrong = decap(&sk_b, &ct, b"binding").expect("decap");
        assert_ne!(ss_send, ss_wrong);
    }

    #[test]
    fn tampered_classical_leg_fails() {
        let (sk, pk) = fresh_keypair();
        let mut rng = OsRng;
        let (mut ct, ss_send) = encap(&mut rng, &pk, b"binding").expect("encap");
        ct.x_eph_pub[0] ^= 0xFF;
        let ss_recv = decap(&sk, &ct, b"binding").expect("decap-tampered");
        assert_ne!(ss_send, ss_recv);
    }

    #[test]
    fn tampered_pq_leg_fails() {
        let (sk, pk) = fresh_keypair();
        let mut rng = OsRng;
        let (mut ct, ss_send) = encap(&mut rng, &pk, b"binding").expect("encap");
        ct.mlkem_ct[0] ^= 0xFF;
        // ML-KEM's implicit rejection means this returns SOME secret
        // rather than erroring; that secret must NOT match the sender's.
        let ss_recv = decap(&sk, &ct, b"binding").expect("decap-tampered");
        assert_ne!(ss_send, ss_recv);
    }

    #[test]
    fn binding_info_changes_secret() {
        // Same ciphertext + same key but different binding_info must
        // produce different shared secrets — defends against
        // (publisher, recipient, epoch) tuple replay.
        let (sk, pk) = fresh_keypair();
        let mut rng = OsRng;
        let (ct, ss_a) = encap(&mut rng, &pk, b"binding-A").expect("encap");
        let ss_b = decap(&sk, &ct, b"binding-B").expect("decap");
        assert_ne!(ss_a, ss_b);
    }

    /// **Component-lifting defence (mirrors the M-2 hybrid signature
    /// pattern).** A receiver who has only the X25519 leg (with a
    /// captured ephemeral pubkey + the X25519 ECDH shared secret)
    /// cannot recover the hybrid shared secret, because the HKDF info
    /// also folds in the ML-KEM ciphertext. Vice versa for the PQ leg.
    #[test]
    fn classical_leg_alone_cannot_recover_hybrid_secret() {
        let (sk, pk) = fresh_keypair();
        let mut rng = OsRng;
        let (ct, ss_hybrid) = encap(&mut rng, &pk, b"binding").expect("encap");

        // Recompute the X25519 leg standalone.
        let x_static = XStaticSecret::from(sk.x_sk);
        let x_eph_pub = XPublicKey::from(ct.x_eph_pub);
        let ss_classical = x_static.diffie_hellman(&x_eph_pub);

        // HKDF over ONLY the classical leg, with everything else
        // matching, must produce a different secret than the hybrid
        // (because the PQ ss is missing from the IKM).
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_V1), ss_classical.as_bytes());
        let mut info = Vec::new();
        info.extend_from_slice(&ct.x_eph_pub);
        info.extend_from_slice(&pk.x_pub);
        info.extend_from_slice(&pk.mlkem_pub);
        info.extend_from_slice(&ct.mlkem_ct);
        info.extend_from_slice(b"binding");
        let mut alone = [0u8; SHARED_SECRET_LEN];
        hk.expand(&info, &mut alone).unwrap();
        assert_ne!(alone, ss_hybrid);
    }

    /// Deterministic generate from a fixed seed produces the same
    /// keypair every time — pins the FIPS 203 `from_seed` contract
    /// and lets us reason about backup/restore equivalence.
    #[test]
    fn generate_is_deterministic_given_rng() {
        let mut rng_a = StdRng::seed_from_u64(0xDD5_DEAD_BEEFu64);
        let mut rng_b = StdRng::seed_from_u64(0xDD5_DEAD_BEEFu64);
        let (sk_a, pk_a) = generate(&mut rng_a);
        let (sk_b, pk_b) = generate(&mut rng_b);
        assert_eq!(sk_a.x_sk, sk_b.x_sk);
        assert_eq!(sk_a.mlkem_seed, sk_b.mlkem_seed);
        assert_eq!(pk_a, pk_b);
    }

    /// HKDF salt is version-pinned: a v2 salt would yield a different
    /// secret over the same inputs, defending against cross-version
    /// replay if a future `dds-pqc-kem-hybrid-v2` lands.
    #[test]
    fn hkdf_salt_pins_version() {
        assert_eq!(HKDF_SALT_V1, b"dds-pqc-kem-hybrid-v1");
    }
}
