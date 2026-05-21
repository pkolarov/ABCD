//! Admission key provider trait — abstracts software, TPM 2.0, and
//! Apple Secure Enclave backends.
//!
//! Concrete backends live in `dds-node` where platform-specific deps belong;
//! this crate stays `no_std`-compatible.
//!
//! See `docs/hardware-bound-admission-plan.md` §5 for the full design.
//! Phase A1 delivers this trait + the `SoftwareKeyfile` backend only;
//! Phase A2 adds serde to `AdmissionPublicKey` so it embeds in `AdmissionBody`.
//! TPM 2.0 (Phase A3) and Apple Secure Enclave (Phase A4) follow.

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Algorithm and public-key bytes for the admission key.
///
/// **Phase A2** — derives `Serialize`/`Deserialize` so it can be embedded in
/// `dds_domain::AdmissionBody` and carried in the signed cert body.
/// Serialised as a CBOR map `{"ed25519": <32-byte blob>}` or
/// `{"ecdsa-p256": <33-byte blob>}` via `serde_bytes` for compact wire
/// encoding; the variant tag is the map key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionPublicKey {
    /// Ed25519 compressed public key (32 bytes).
    #[serde(rename = "ed25519")]
    Ed25519(#[serde(with = "serde_bytes")] Vec<u8>),
    /// ECDSA-P256 SEC1 compressed public key (33 bytes).
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// Which hardware (or software) backend backs this provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Software Ed25519 key on disk — dev/CI fallback. Not hardware-bound.
    SoftwareKeyfile,
    /// TPM 2.0 resident key (Linux + Windows). Phase A3.
    Tpm2,
    /// Apple Secure Enclave resident key (macOS). Phase A4.
    AppleSecureEnclave,
}

/// Signing error returned by [`KeyProvider::sign`].
#[derive(Debug)]
pub struct SignError(pub String);

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "sign error: {}", self.0)
    }
}

/// Admission key provider: sign-only, no key export.
///
/// Implemented by `dds-node` backends. `Box<dyn KeyProvider>` is stored
/// in `DdsNode` and used across async task boundaries — hence `Send + Sync`.
///
/// Phase A1 introduces this trait with the `SoftwareKeyfile` backend.
/// Phase A2 wires `sign()` into the H-12 challenge-response step so that
/// a stolen `p2p_key.bin + admission.cbor` cannot impersonate the node.
///
/// See `docs/hardware-bound-admission-plan.md` §5.
pub trait KeyProvider: Send + Sync {
    /// Which backend is backing this provider.
    fn provider_kind(&self) -> ProviderKind;

    /// Public half of the admission key.
    fn public_key(&self) -> AdmissionPublicKey;

    /// Sign `msg` and return the raw signature bytes.
    ///
    /// For Ed25519: 64-byte signature.
    /// For ECDSA-P256: DER-encoded signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError>;

    /// Stable, non-secret identifier for logs and metrics.
    ///
    /// For `SoftwareKeyfile`: SHA-256 of the key file path (hex).
    /// For TPM 2.0: the persistent handle as `0x81xxxxxx` hex.
    /// For Secure Enclave: the keychain label.
    fn identity_handle(&self) -> String;
}
