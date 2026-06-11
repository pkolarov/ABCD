//! Apple Secure Enclave admission key backend — Phase A4.
//!
//! Generates or loads a P-256 key stored in the macOS Secure Enclave (T1/T2
//! or Apple Silicon). The private key never leaves the SE; signing is
//! performed in-hardware.
//!
//! **Prerequisite for distribution:** the `dds-node` binary must be signed
//! with a Developer ID certificate and carry the
//! `com.apple.developer.kernel.secure-enclave` hardened-runtime entitlement
//! before it can be distributed through notarization. Development builds and
//! test runs on the maintainer host do **not** require signing.
//!
//! See `docs/hardware-bound-admission-plan.md` §7.3.

use dds_core::key_provider::{AdmissionPublicKey, KeyProvider, ProviderKind, SignError};
use security_framework::{
    access_control::SecAccessControl,
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token},
};
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
use sha2::{Digest, Sha256};

/// Apple Secure Enclave ECDSA-P256 admission key.
///
/// The key is stored in the system keychain under a caller-supplied `label`
/// with `kSecAccessControlPrivateKeyUsage` (sign-only; no export, no
/// biometry gate on a daemon). `load_or_create(label)` is idempotent: it
/// returns the existing key if one with that label already exists.
///
/// **Algorithm:** ECDSA-P256 only — the SE does not expose Ed25519.
/// Signatures are DER-encoded (X9.62 format), compatible with
/// `verify_admission_challenge` in `node.rs`.
pub struct AppleSecureEnclaveKeyProvider {
    private_key: SecKey,
    /// SEC1 compressed public key (33 bytes: 02/03 prefix + 32-byte X coord).
    compressed_pubkey: Vec<u8>,
    /// Stable non-secret handle: the keychain label.
    label: String,
}

// SAFETY: `SecKey` wraps a Core Foundation `CFTypeRef` which is `*mut c_void`.
// CF objects are reference-counted and thread-safe for read operations (retain
// / release are atomic). We only ever sign with the private key (no mutation),
// and `security-framework`'s `SecKey` has the same `Send + Sync` property as
// the CF runtime itself.
unsafe impl Send for AppleSecureEnclaveKeyProvider {}
unsafe impl Sync for AppleSecureEnclaveKeyProvider {}

/// Error type returned by `AppleSecureEnclaveKeyProvider::load_or_create`.
#[derive(Debug)]
pub struct SeError(pub String);

impl std::fmt::Display for SeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Apple SE error: {}", self.0)
    }
}

impl std::error::Error for SeError {}

impl AppleSecureEnclaveKeyProvider {
    /// Load or create a P-256 SE key with the given keychain `label`.
    ///
    /// Creates the key when absent (stored permanently in the system keychain
    /// under `label`). Returns the existing key on subsequent calls — the SE
    /// key material is never exported; only the public half is accessed.
    ///
    /// Logs a startup INFO confirming hardware binding.
    pub fn load_or_create(label: &str) -> Result<Self, SeError> {
        let private_key = Self::find_existing(label)
            .or_else(|_| Self::create_new(label))
            .map_err(|e| {
                SeError(format!(
                    "SE key load/create failed for label {label:?}: {e}"
                ))
            })?;

        let compressed_pubkey = Self::extract_compressed_pubkey(&private_key)
            .map_err(|e| SeError(format!("could not read SE public key: {e}")))?;

        tracing::info!(
            label = label,
            pubkey_hex = hex::encode(&compressed_pubkey),
            "admission key loaded from Apple Secure Enclave"
        );

        Ok(Self {
            private_key,
            compressed_pubkey,
            label: label.to_string(),
        })
    }

    /// Look up an existing SE key by label in the default keychain.
    ///
    /// **AUDIT-2026-06-11 #29**: a keychain search by label alone will
    /// happily return a *software* key with the same label. Since
    /// `provider_kind()` and the startup log report this key as
    /// hardware-bound, we must confirm the returned `SecKey` actually
    /// resides in the Secure Enclave before trusting it. We require its
    /// `kSecAttrTokenID` attribute to equal `kSecAttrTokenIDSecureEnclave`
    /// and treat a key that is not SE-resident as not-found, so the
    /// caller's `.or_else(create_new)` regenerates a genuine SE key
    /// rather than adopting a planted software impostor.
    fn find_existing(label: &str) -> Result<SecKey, String> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label)
            .limit(1)
            .load_refs(true)
            .search()
            .map_err(|e| format!("keychain search error: {e}"))?;

        match results.into_iter().next() {
            Some(SearchResult::Ref(Reference::Key(k))) => {
                // AUDIT-2026-06-11 #29: reject a same-label key that is not
                // SE-resident. Without this, a planted software key is
                // trusted and misreported as hardware-bound.
                if is_secure_enclave_resident(&k) {
                    Ok(k)
                } else {
                    Err(format!(
                        "key with label {label:?} exists but is not Secure-Enclave-resident \
                         (kSecAttrTokenID != kSecAttrTokenIDSecureEnclave); refusing to treat \
                         a software key as hardware-bound"
                    ))
                }
            }
            Some(_) => Err("unexpected non-key reference in keychain search".to_string()),
            None => Err(format!("no SE key found with label {label:?}")),
        }
    }

    /// Generate a new SE P-256 key and store it permanently in the keychain.
    fn create_new(label: &str) -> Result<SecKey, String> {
        let access = SecAccessControl::create_with_flags(kSecAccessControlPrivateKeyUsage)
            .map_err(|e| format!("SecAccessControl creation failed: {e}"))?;

        let key = SecKey::new(
            GenerateKeyOptions::default()
                .set_key_type(KeyType::ec())
                .set_size_in_bits(256)
                .set_token(Token::SecureEnclave)
                .set_label(label)
                .set_location(Location::DefaultFileKeychain)
                .set_access_control(access),
        )
        .map_err(|e| format!("SecKeyCreateRandomKey failed: {e}"))?;

        tracing::info!(
            label = label,
            "new Apple Secure Enclave P-256 admission key created"
        );
        Ok(key)
    }

    /// Extract and compress the P-256 public key.
    ///
    /// `SecKeyCopyExternalRepresentation` on the *public* key of an SE pair
    /// returns the uncompressed X9.62 point (0x04 || X || Y = 65 bytes). We
    /// compress it to SEC1 form (0x02/0x03 || X = 33 bytes) which is what
    /// `AdmissionPublicKey::EcdsaP256` carries.
    fn extract_compressed_pubkey(private_key: &SecKey) -> Result<Vec<u8>, String> {
        let pub_key = private_key
            .public_key()
            .ok_or("SecKeyCopyPublicKey returned nil")?;

        let repr = pub_key
            .external_representation()
            .ok_or("SecKeyCopyExternalRepresentation failed for SE public key")?;

        let uncompressed = repr.to_vec();
        compress_p256_point(&uncompressed)
    }
}

/// **AUDIT-2026-06-11 #29**: return `true` iff `key`'s `kSecAttrTokenID`
/// attribute equals `kSecAttrTokenIDSecureEnclave`, i.e. the private key
/// genuinely lives in the Secure Enclave.
///
/// `SecKeyCopyAttributes` (via [`SecKey::attributes`]) returns the
/// effective key attributes; SE-resident keys carry
/// `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`, software keys omit
/// the attribute (or carry a different value). We compare the CFString
/// value for exact equality and fail closed if the attribute is missing.
///
/// macOS-only (`security-framework`); flagged for macOS CI — it cannot
/// be exercised on the build host used for this change.
fn is_secure_enclave_resident(key: &SecKey) -> bool {
    use core_foundation::base::{TCFType, ToVoid};
    use core_foundation::string::CFString;
    use security_framework_sys::item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave};

    let attrs = key.attributes();
    match attrs.find(unsafe { kSecAttrTokenID }.to_void()) {
        Some(value) => {
            // `value` is a borrowed CFStringRef inside the dictionary; the
            // SE token-id constant is also a CFString. Wrap both under the
            // get rule (no ownership transfer) and compare for equality.
            // `.cast()` on the `&*const c_void` mirrors the idiom in
            // `SecKey::application_label` upstream.
            let found = unsafe { CFString::wrap_under_get_rule(value.cast()) };
            let expected = unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) };
            found == expected
        }
        // No token id at all => software key. Fail closed.
        None => false,
    }
}

/// Compress an uncompressed P-256 X9.62 point (65 bytes, 0x04 prefix) to
/// SEC1 compressed form (33 bytes, 0x02 or 0x03 prefix).
fn compress_p256_point(uncompressed: &[u8]) -> Result<Vec<u8>, String> {
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(format!(
            "expected 65-byte uncompressed P-256 point (0x04 prefix), got {} bytes starting with 0x{:02x}",
            uncompressed.len(),
            uncompressed.first().copied().unwrap_or(0)
        ));
    }
    let x = &uncompressed[1..33];
    let y_lsb = uncompressed[64] & 1;
    let prefix = if y_lsb == 0 { 0x02u8 } else { 0x03u8 };
    let mut compressed = Vec::with_capacity(33);
    compressed.push(prefix);
    compressed.extend_from_slice(x);
    Ok(compressed)
}

impl KeyProvider for AppleSecureEnclaveKeyProvider {
    fn provider_kind(&self) -> ProviderKind {
        ProviderKind::AppleSecureEnclave
    }

    fn public_key(&self) -> AdmissionPublicKey {
        AdmissionPublicKey::EcdsaP256(self.compressed_pubkey.clone())
    }

    /// Sign `msg` with the SE P-256 key using ECDSA-SHA256.
    ///
    /// Returns a DER-encoded signature compatible with `verify_admission_challenge`
    /// which accepts `P256Signature::from_der`.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        self.private_key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, msg)
            .map_err(|e| SignError(format!("SE sign failed: {e}")))
    }

    /// Stable non-secret handle: the keychain label.
    fn identity_handle(&self) -> String {
        hex::encode(Sha256::digest(self.label.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dds_core::key_provider::AdmissionPublicKey;
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk, signature::Verifier as _};

    fn unique_label() -> String {
        format!("dds-test-se-{}", uuid::Uuid::new_v4())
    }

    /// Verify the SE provider round-trips: generate key, sign, verify.
    /// Requires an interactive macOS session with Secure Enclave access
    /// (Apple Silicon or T1/T2). OSStatus -25308 in CI = run locally.
    #[test]
    #[ignore = "requires SE hardware with interactive keychain session"]
    fn se_sign_verify_roundtrip() {
        let label = unique_label();
        let kp = AppleSecureEnclaveKeyProvider::load_or_create(&label)
            .expect("SE key creation should succeed on Apple Silicon / T1/T2 hardware");

        let msg = b"h12-challenge-nonce-12345678901234";
        let sig_bytes = kp.sign(msg).expect("SE sign should succeed");
        assert!(!sig_bytes.is_empty(), "signature must be non-empty");

        let compressed = match kp.public_key() {
            AdmissionPublicKey::EcdsaP256(b) => b,
            _ => panic!("SE must return EcdsaP256"),
        };
        assert_eq!(compressed.len(), 33, "compressed P-256 pubkey is 33 bytes");

        // Decompress via p256 crate and verify.
        let vk = P256Vk::from_sec1_bytes(&compressed).expect("valid SEC1 compressed P-256 pubkey");
        let sig = P256Sig::from_der(&sig_bytes).expect("SE returns DER signature");
        vk.verify(msg, &sig).expect("signature must verify");

        // Clean up test key from keychain.
        cleanup_test_key(&label);
    }

    /// SE public key is stable across load_or_create calls with the same label.
    #[test]
    #[ignore = "requires SE hardware with interactive keychain session"]
    fn se_stable_across_loads() {
        let label = unique_label();

        let kp1 = AppleSecureEnclaveKeyProvider::load_or_create(&label).unwrap();
        let pk1 = match kp1.public_key() {
            AdmissionPublicKey::EcdsaP256(b) => b,
            _ => panic!(),
        };

        let kp2 = AppleSecureEnclaveKeyProvider::load_or_create(&label).unwrap();
        let pk2 = match kp2.public_key() {
            AdmissionPublicKey::EcdsaP256(b) => b,
            _ => panic!(),
        };

        assert_eq!(pk1, pk2, "same label must return the same public key");

        cleanup_test_key(&label);
    }

    #[test]
    #[ignore = "requires SE hardware with interactive keychain session"]
    fn provider_kind_is_apple_se() {
        let label = unique_label();
        let kp = AppleSecureEnclaveKeyProvider::load_or_create(&label).unwrap();
        assert_eq!(kp.provider_kind(), ProviderKind::AppleSecureEnclave);
        cleanup_test_key(&label);
    }

    #[test]
    #[ignore = "requires SE hardware with interactive keychain session"]
    fn identity_handle_is_64_char_hex() {
        let label = unique_label();
        let kp = AppleSecureEnclaveKeyProvider::load_or_create(&label).unwrap();
        let h = kp.identity_handle();
        assert_eq!(h.len(), 64, "SHA-256 hex is 64 chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        cleanup_test_key(&label);
    }

    #[test]
    fn compress_p256_point_roundtrip() {
        // Synthesize a known uncompressed point (even Y — prefix 0x02).
        let mut raw = vec![0x04u8; 65];
        raw[1..33].fill(0xAB); // X
        raw[33..65].fill(0x00); // Y (even → prefix 0x02)
        raw[64] = 0xFE; // last Y byte: even (0xFE & 1 == 0)
        let compressed = compress_p256_point(&raw).unwrap();
        assert_eq!(compressed[0], 0x02);
        assert_eq!(&compressed[1..], &raw[1..33]);

        // Odd Y → prefix 0x03.
        raw[64] = 0xFF;
        let compressed = compress_p256_point(&raw).unwrap();
        assert_eq!(compressed[0], 0x03);
    }

    #[test]
    fn compress_p256_point_rejects_bad_input() {
        assert!(compress_p256_point(&[0x04u8; 64]).is_err()); // wrong length
        assert!(compress_p256_point(&[0x03u8; 65]).is_err()); // wrong prefix
    }

    /// Remove the test SE key from the keychain so tests don't accumulate keys.
    fn cleanup_test_key(label: &str) {
        use core_foundation::{
            base::{TCFType, ToVoid},
            boolean::CFBoolean,
            dictionary::CFMutableDictionary,
            string::CFString,
        };
        use security_framework_sys::{
            item::{
                kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrLabel, kSecClass, kSecClassKey,
                kSecMatchLimit, kSecMatchLimitAll,
            },
            keychain_item::SecItemDelete,
        };

        let query = CFMutableDictionary::from_CFType_pairs(&[
            (unsafe { kSecClass.to_void() }, unsafe {
                CFString::wrap_under_get_rule(kSecClassKey).to_void()
            }),
            (unsafe { kSecAttrKeyClass.to_void() }, unsafe {
                CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).to_void()
            }),
            (
                unsafe { kSecAttrLabel.to_void() },
                CFString::new(label).to_void(),
            ),
            (unsafe { kSecMatchLimit.to_void() }, unsafe {
                CFBoolean::wrap_under_get_rule(kSecMatchLimitAll as *mut _).to_void()
            }),
        ]);
        unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
    }
}
