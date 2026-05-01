//! AEAD wrap / unwrap of a 32-byte epoch AEAD key under a hybrid-KEM-derived
//! shared secret (Phase B.2 of the Z-1 PQC plan).
//!
//! See [`docs/pqc-phase-b-plan.md`](../../../docs/pqc-phase-b-plan.md) §4.3
//! and §4.4 for the full design. This module is the AEAD half of the
//! `EpochKeyRelease` construction:
//!
//! ```text
//! sender:                                                  recipient:
//!   shared = kem::encap(recipient_pq_kem_pk, binding)        shared = kem::decap(...)
//!   (nonce, ct) = epoch_key::wrap(shared, K_pub_epoch)       K' = epoch_key::unwrap(shared, nonce, ct)
//!   ship { kem_ct, nonce, ct } as the EpochKeyRelease body   assert K' == K_pub_epoch
//! ```
//!
//! The wrapper is intentionally a thin glue layer over
//! ChaCha20-Poly1305 — there is no new primitive here. Caller-side
//! domain separation already lives in [`super::kem`]'s `binding_info`,
//! so the AEAD's only AAD is a constant version-tag
//! ([`AAD_V1`]) for cross-version replay defence (a future
//! `dds-pqc-epoch-key-v2` lands disjoint from this one).
//!
//! # Sizes
//!
//! - Epoch key: 32 bytes (also the ChaCha20-Poly1305 key length).
//! - Wrap nonce: 12 bytes (ChaCha20-Poly1305 nonce length).
//! - Ciphertext: `EPOCH_KEY_LEN + AEAD_TAG_LEN = 48` bytes.

use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::CryptoRngCore;

use super::kem::SHARED_SECRET_LEN;
use super::traits::CryptoError;

/// Length of an epoch AEAD key (also the ChaCha20-Poly1305 key length).
pub const EPOCH_KEY_LEN: usize = 32;

/// Length of the ChaCha20-Poly1305 nonce used to wrap an epoch key.
pub const AEAD_NONCE_LEN: usize = 12;

/// Length of the ChaCha20-Poly1305 authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Wire size of a wrapped epoch key (`EPOCH_KEY_LEN + AEAD_TAG_LEN`).
pub const WRAPPED_EPOCH_KEY_LEN: usize = EPOCH_KEY_LEN + AEAD_TAG_LEN;

/// Constant AEAD additional-authenticated-data, version-pinned to
/// match the `dds-pqc-kem-hybrid-v1` HKDF salt in [`super::kem`]. A
/// future v2 wrapper produces a disjoint ciphertext over the same
/// inputs, defending against cross-version replay if a new wrapper is
/// ever added alongside this one.
pub const AAD_V1: &[u8] = b"dds-pqc-epoch-key-v1";

// Sanity guard — the FIPS 203 hybrid-KEM secret feeds directly into
// ChaCha20-Poly1305 as the AEAD key, so the two MUST be the same width.
const _: () = assert!(SHARED_SECRET_LEN == EPOCH_KEY_LEN);

/// Wrap a 32-byte epoch AEAD key under the supplied 32-byte
/// hybrid-KEM-derived shared secret.
///
/// Returns the (random 12-byte nonce, 48-byte ciphertext) tuple. The
/// caller stores both alongside the `KemCiphertext` in
/// `EpochKeyRelease`.
///
/// # Errors
/// [`CryptoError::InvalidSignature`] if the underlying AEAD encrypt
/// fails — in practice this only happens on allocator failure.
pub fn wrap<R: CryptoRngCore>(
    rng: &mut R,
    kem_shared: &[u8; SHARED_SECRET_LEN],
    epoch_key: &[u8; EPOCH_KEY_LEN],
) -> Result<([u8; AEAD_NONCE_LEN], Vec<u8>), CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kem_shared.as_slice()));
    let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: epoch_key.as_slice(),
                aad: AAD_V1,
            },
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    debug_assert_eq!(ct.len(), WRAPPED_EPOCH_KEY_LEN);
    Ok((nonce_bytes, ct))
}

/// **Z-1 Phase B.7** — constant AAD for gossip/sync payload AEAD.
/// Distinct from [`AAD_V1`] (which wraps the epoch key itself) to
/// prevent cross-construction ciphertext confusion: a blob encrypted
/// by `encrypt_payload` cannot be passed to `unwrap` and vice-versa.
pub const PAYLOAD_AAD_V3: &[u8] = b"dds-pqc-gossip-v3";

/// **Z-1 Phase B.7** — encrypt an arbitrary plaintext payload under the
/// supplied 32-byte epoch AEAD key.
///
/// Used by `dds-node` to wrap the CBOR-encoded `GossipMessage` (and
/// later `SyncPayload`) before publishing on an `enc-v3` domain.
///
/// Returns the (random 12-byte nonce, ciphertext + 16-byte Poly1305
/// tag) tuple. The caller stores both in `GossipEnvelopeV3`.
pub fn encrypt_payload<R: CryptoRngCore>(
    rng: &mut R,
    epoch_key: &[u8; EPOCH_KEY_LEN],
    plaintext: &[u8],
) -> Result<([u8; AEAD_NONCE_LEN], Vec<u8>), CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key.as_slice()));
    let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: PAYLOAD_AAD_V3,
            },
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok((nonce_bytes, ct))
}

/// **Z-1 Phase B.7** — decrypt a payload previously encrypted by
/// [`encrypt_payload`]. Returns the plaintext bytes, or
/// [`CryptoError::InvalidSignature`] if the AEAD tag does not verify
/// (wrong key, tampered ciphertext, tampered nonce, or tampered AAD).
pub fn decrypt_payload(
    epoch_key: &[u8; EPOCH_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(epoch_key.as_slice()));
    let nonce_ref = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ciphertext,
                aad: PAYLOAD_AAD_V3,
            },
        )
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Unwrap a wrapped epoch key under the supplied hybrid-KEM-derived
/// shared secret. Returns the recovered 32-byte epoch key, or
/// [`CryptoError::InvalidSignature`] if the AEAD authentication tag
/// does not verify (wrong key, tampered ciphertext, tampered nonce, or
/// tampered AAD).
pub fn unwrap(
    kem_shared: &[u8; SHARED_SECRET_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<[u8; EPOCH_KEY_LEN], CryptoError> {
    if ciphertext.len() != WRAPPED_EPOCH_KEY_LEN {
        return Err(CryptoError::InvalidSignature);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kem_shared.as_slice()));
    let nonce_ref = Nonce::from_slice(nonce);
    let pt = cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: ciphertext,
                aad: AAD_V1,
            },
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    if pt.len() != EPOCH_KEY_LEN {
        return Err(CryptoError::InvalidSignature);
    }
    let mut out = [0u8; EPOCH_KEY_LEN];
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem;
    use rand::rngs::OsRng;
    use rand_core::RngCore;

    fn fresh_shared() -> [u8; SHARED_SECRET_LEN] {
        let mut k = [0u8; SHARED_SECRET_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    fn fresh_epoch_key() -> [u8; EPOCH_KEY_LEN] {
        let mut k = [0u8; EPOCH_KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn wire_sizes_match_constants() {
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (nonce, ct) = wrap(&mut rng, &shared, &key).expect("wrap");
        assert_eq!(nonce.len(), AEAD_NONCE_LEN);
        assert_eq!(ct.len(), WRAPPED_EPOCH_KEY_LEN);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (nonce, ct) = wrap(&mut rng, &shared, &key).expect("wrap");
        let recovered = unwrap(&shared, &nonce, &ct).expect("unwrap");
        assert_eq!(recovered, key);
    }

    #[test]
    fn wrong_key_fails() {
        let shared_a = fresh_shared();
        let shared_b = fresh_shared();
        assert_ne!(shared_a, shared_b);
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (nonce, ct) = wrap(&mut rng, &shared_a, &key).expect("wrap");
        let r = unwrap(&shared_b, &nonce, &ct);
        assert_eq!(r, Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (nonce, mut ct) = wrap(&mut rng, &shared, &key).expect("wrap");
        ct[0] ^= 0x01;
        let r = unwrap(&shared, &nonce, &ct);
        assert_eq!(r, Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_tag_fails() {
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (nonce, mut ct) = wrap(&mut rng, &shared, &key).expect("wrap");
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        let r = unwrap(&shared, &nonce, &ct);
        assert_eq!(r, Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_nonce_fails() {
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (mut nonce, ct) = wrap(&mut rng, &shared, &key).expect("wrap");
        nonce[0] ^= 0xFF;
        let r = unwrap(&shared, &nonce, &ct);
        assert_eq!(r, Err(CryptoError::InvalidSignature));
    }

    #[test]
    fn wrong_length_ciphertext_rejected() {
        let shared = fresh_shared();
        let nonce = [0u8; AEAD_NONCE_LEN];
        // Too short.
        assert_eq!(
            unwrap(&shared, &nonce, &[0u8; WRAPPED_EPOCH_KEY_LEN - 1]),
            Err(CryptoError::InvalidSignature)
        );
        // Too long.
        assert_eq!(
            unwrap(&shared, &nonce, &[0u8; WRAPPED_EPOCH_KEY_LEN + 1]),
            Err(CryptoError::InvalidSignature)
        );
    }

    /// Two consecutive `wrap()` calls under the same key produce
    /// distinct nonces with overwhelming probability — the basic
    /// nonce-misuse defence the construction relies on. Probabilistic,
    /// but the 96-bit nonce gives ~2^-96 collision per call, so a
    /// single test run is a meaningful smoke test.
    #[test]
    fn fresh_nonces_across_wraps() {
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let mut rng = OsRng;
        let (n1, c1) = wrap(&mut rng, &shared, &key).expect("wrap-1");
        let (n2, c2) = wrap(&mut rng, &shared, &key).expect("wrap-2");
        assert_ne!(n1, n2);
        // Same plaintext + same key + different nonce ⇒ different ct.
        assert_ne!(c1, c2);
    }

    /// End-to-end composition: KEM encap → wrap → ship → KEM decap →
    /// unwrap. This is the full Phase B `EpochKeyRelease` flow minus
    /// the wire envelope; the AEAD half MUST compose cleanly with the
    /// hybrid KEM half from B.1.
    #[test]
    fn end_to_end_with_kem() {
        let mut rng = OsRng;
        let (recipient_sk, recipient_pk) = kem::generate(&mut rng);
        let publisher_epoch_key = fresh_epoch_key();
        let binding = b"dds-pqc-epoch-release-v1/publisher=ALICE/recipient=BOB/epoch_id=17";

        // Sender: encap, then wrap epoch key under the derived secret.
        let (kem_ct, ss_send) = kem::encap(&mut rng, &recipient_pk, binding).expect("encap");
        let (nonce, aead_ct) = wrap(&mut rng, &ss_send, &publisher_epoch_key).expect("wrap");

        // Recipient: decap, then unwrap epoch key.
        let ss_recv = kem::decap(&recipient_sk, &kem_ct, binding).expect("decap");
        let recovered = unwrap(&ss_recv, &nonce, &aead_ct).expect("unwrap");
        assert_eq!(recovered, publisher_epoch_key);
    }

    /// A wrong `binding_info` on the KEM side produces a different
    /// derived secret which then fails the AEAD verify here. This is
    /// the property §4.3 leans on for (publisher, recipient, epoch)
    /// replay defence — the KEM provides binding, the AEAD enforces
    /// it.
    #[test]
    fn binding_mismatch_propagates_to_aead_failure() {
        let mut rng = OsRng;
        let (recipient_sk, recipient_pk) = kem::generate(&mut rng);
        let key = fresh_epoch_key();
        let (kem_ct, ss_send) = kem::encap(&mut rng, &recipient_pk, b"binding-A").expect("encap");
        let (nonce, aead_ct) = wrap(&mut rng, &ss_send, &key).expect("wrap");

        // Decap with a different binding yields an unequal secret.
        let ss_wrong = kem::decap(&recipient_sk, &kem_ct, b"binding-B").expect("decap");
        assert_ne!(ss_send, ss_wrong);
        // ... and the AEAD verify fails.
        assert_eq!(
            unwrap(&ss_wrong, &nonce, &aead_ct),
            Err(CryptoError::InvalidSignature)
        );
    }

    /// AAD constant is version-pinned. A deliberate mismatch on the
    /// constant proves the AAD is actually authenticated — if a future
    /// `dds-pqc-epoch-key-v2` lands, its ciphertexts MUST NOT verify
    /// against this v1 path.
    #[test]
    fn aad_constant_pins_version() {
        // Pin the literal so a refactor that "improves" the AAD breaks
        // this test — at which point we need a v2 module rather than
        // an in-place change.
        assert_eq!(AAD_V1, b"dds-pqc-epoch-key-v1");

        // Smoke test: bypassing wrap() with a different AAD must not
        // unwrap() under the canonical AAD.
        let shared = fresh_shared();
        let key = fresh_epoch_key();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared));
        let nonce_bytes = [0u8; AEAD_NONCE_LEN];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: key.as_slice(),
                    aad: b"dds-pqc-epoch-key-v2-IMAGINARY",
                },
            )
            .expect("encrypt");
        assert_eq!(
            unwrap(&shared, &nonce_bytes, &ct),
            Err(CryptoError::InvalidSignature)
        );
    }
}
