//! Signed response envelopes for the dds-node localhost HTTP API.
//!
//! **H-2 / H-3 (security review)**: the Windows and macOS Policy Agents
//! consume `WindowsPolicyDocument` / `MacOsPolicyDocument` /
//! `SoftwareAssignment` from `127.0.0.1:5551/v1/*`. The agents run as
//! SYSTEM/root and apply registry edits, account changes, launchd
//! plists, and installer packages. Without an application-layer
//! signature, a local process that races the dds-node bind (or
//! hijacks the localhost endpoint) can serve arbitrary JSON and drive
//! the agent into SYSTEM/root code execution.
//!
//! This module defines a small envelope that binds the serialized
//! response payload to the issuing node's Ed25519 signing key. The
//! agent pins the node's public key (via MSI/provisioning-bundle
//! config) and verifies the envelope before dispatching any enforcer.
//!
//! ## Wire contract
//!
//! The signed message is constructed deterministically from primitive
//! parts so both sides (Rust signer and C# verifier) can reconstruct
//! the same byte sequence without depending on a canonical encoder:
//!
//! ```text
//! msg = DOMAIN_TAG_BYTES
//!     || u32_le(device_urn.len())   || device_urn.as_bytes()
//!     || u32_le(envelope_kind.len())|| envelope_kind.as_bytes()
//!     || u64_le(issued_at)
//!     || u32_le(payload.len())      || payload_bytes
//! ```
//!
//! `payload_bytes` is the UTF-8 JSON encoding of the inner response
//! body (the same bytes the agent will later parse with its JSON
//! deserializer). The signature is Ed25519 over `msg`.
//!
//! The domain tag `DOMAIN_TAG` is fixed per-envelope-version. Bumping
//! the tag rolls the signing domain, so old verifiers reject new
//! envelopes and vice-versa. `envelope_kind` is a short ASCII string
//! (`windows-policies`, `windows-software`, `macos-policies`,
//! `macos-software`) that gives **type separation** across endpoints
//! — an attacker cannot splice a signed software envelope into a
//! policy response, because the verifier pins the expected kind.
//!
//! ## Replay / freshness
//!
//! `issued_at` is Unix seconds at the point of signing. Agents should
//! reject envelopes older than a small window (suggest 300 seconds)
//! to prevent replay of a captured envelope against a later policy
//! state. The window is set agent-side so operators can widen it for
//! large clock skew.
//!
//! ## What this does not defend against
//!
//! - Compromise of the node's signing key (that's a full-node
//!   compromise and covered by the broader identity-key threat
//!   model).
//! - Agent-side configuration corruption that replaces the pinned
//!   node public key (needs file-system ACLs — tracked as L-16 on
//!   Windows).
//! - A publisher with the `dds:policy-publisher-*` capability
//!   publishing a bad policy. That's a separate authorization layer
//!   enforced by C-3 on the server side.

use alloc::string::String;
use alloc::vec::Vec;

/// Envelope version 1 domain-separation tag. Rolling this byte string
/// invalidates all outstanding envelopes.
pub const DOMAIN_TAG: &[u8] = b"dds-policy-envelope-v1";

/// Stable ASCII identifiers for each envelope flavour. Both sides
/// MUST agree; a mismatch means the verifier is pointed at the wrong
/// endpoint or an attacker is trying to splice one kind into another.
pub mod kind {
    pub const WINDOWS_POLICIES: &str = "windows-policies";
    pub const WINDOWS_SOFTWARE: &str = "windows-software";
    pub const MACOS_POLICIES: &str = "macos-policies";
    pub const MACOS_SOFTWARE: &str = "macos-software";
}

/// Build the exact byte sequence that both the signer and the
/// verifier hash. Returning a `Vec<u8>` instead of streaming through a
/// hasher keeps the cross-language contract trivial to reproduce.
pub fn signing_bytes(
    device_urn: &str,
    envelope_kind: &str,
    issued_at: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_TAG.len() + 4 + device_urn.len() + 4 + envelope_kind.len() + 8 + 4 + payload.len(),
    );
    out.extend_from_slice(DOMAIN_TAG);
    put_u32_le(&mut out, device_urn.len() as u32);
    out.extend_from_slice(device_urn.as_bytes());
    put_u32_le(&mut out, envelope_kind.len() as u32);
    out.extend_from_slice(envelope_kind.as_bytes());
    put_u64_le(&mut out, issued_at);
    put_u32_le(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    out
}

/// Sign an envelope. Returns the raw 64-byte Ed25519 signature.
#[cfg(feature = "std")]
pub fn sign_envelope(
    signing_key: &ed25519_dalek::SigningKey,
    device_urn: &str,
    envelope_kind: &str,
    issued_at: u64,
    payload: &[u8],
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let msg = signing_bytes(device_urn, envelope_kind, issued_at, payload);
    signing_key.sign(&msg).to_bytes()
}

/// Verify an envelope against a 32-byte Ed25519 public key.
///
/// Returns `Ok(())` on success, `Err(EnvelopeError)` otherwise. All
/// error variants are opaque by design — the verifier should not leak
/// which part of the envelope was wrong to a caller that it does not
/// already trust.
#[cfg(feature = "std")]
pub fn verify_envelope(
    public_key: &[u8; 32],
    device_urn: &str,
    envelope_kind: &str,
    issued_at: u64,
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), EnvelopeError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| EnvelopeError::BadPublicKey)?;
    let sig = Signature::from_bytes(signature);
    let msg = signing_bytes(device_urn, envelope_kind, issued_at, payload);
    vk.verify(&msg, &sig)
        .map_err(|_| EnvelopeError::BadSignature)
}

/// Opaque verification error. Do not leak specifics to untrusted
/// callers (see L-9 in the security review).
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    BadPublicKey,
    BadSignature,
}

#[cfg(feature = "std")]
impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadPublicKey => f.write_str("envelope public key malformed"),
            Self::BadSignature => f.write_str("envelope signature did not verify"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EnvelopeError {}

/// Serializable envelope header the HTTP layer attaches to every
/// signed policy/software response. The wrapped payload is the exact
/// bytes the agent will later parse.
///
/// `payload_b64` is a base64-standard-with-padding encoding of the
/// JSON body. Agents MUST verify the signature over the decoded
/// bytes, not the encoded form.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SignedPolicyEnvelope {
    /// Envelope-schema version. `1` corresponds to `DOMAIN_TAG`.
    pub version: u8,
    /// Which endpoint produced this envelope (see `kind::*`).
    pub kind: String,
    /// Device URN the envelope was bound to. The agent compares this
    /// against its own configured DeviceUrn before parsing payload.
    pub device_urn: String,
    /// Unix seconds the envelope was signed.
    pub issued_at: u64,
    /// Base64 (standard, with padding) of the JSON payload bytes.
    pub payload_b64: String,
    /// Base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
    /// URN of the signing node (informational; agent verifies
    /// against its pinned pubkey, not this URN).
    pub node_urn: String,
    /// Base64 of the 32-byte Ed25519 public key that signed. Agents
    /// MUST compare this to their pinned value; never trust the
    /// pubkey the server claims.
    pub node_pubkey_b64: String,
}

fn put_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn fresh_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn round_trip_verifies() {
        let k = fresh_key();
        let payload = br#"{"policies":[]}"#;
        let sig = sign_envelope(&k, "urn:vch:dev.abc", kind::WINDOWS_POLICIES, 100, payload);
        let pk = k.verifying_key().to_bytes();
        assert!(
            verify_envelope(
                &pk,
                "urn:vch:dev.abc",
                kind::WINDOWS_POLICIES,
                100,
                payload,
                &sig
            )
            .is_ok()
        );
    }

    #[test]
    fn tamper_device_urn_fails() {
        let k = fresh_key();
        let payload = br#"{"policies":[]}"#;
        let sig = sign_envelope(&k, "urn:vch:dev.abc", kind::WINDOWS_POLICIES, 100, payload);
        let pk = k.verifying_key().to_bytes();
        assert!(
            verify_envelope(
                &pk,
                "urn:vch:dev.xyz",
                kind::WINDOWS_POLICIES,
                100,
                payload,
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn tamper_kind_fails() {
        let k = fresh_key();
        let payload = br#"{"policies":[]}"#;
        let sig = sign_envelope(&k, "urn:vch:dev.abc", kind::WINDOWS_POLICIES, 100, payload);
        let pk = k.verifying_key().to_bytes();
        // Splicing a policies envelope into a software verifier must fail.
        assert!(
            verify_envelope(
                &pk,
                "urn:vch:dev.abc",
                kind::WINDOWS_SOFTWARE,
                100,
                payload,
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn tamper_issued_at_fails() {
        let k = fresh_key();
        let payload = br#"{"policies":[]}"#;
        let sig = sign_envelope(&k, "urn:vch:dev.abc", kind::WINDOWS_POLICIES, 100, payload);
        let pk = k.verifying_key().to_bytes();
        assert!(
            verify_envelope(
                &pk,
                "urn:vch:dev.abc",
                kind::WINDOWS_POLICIES,
                101,
                payload,
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn tamper_payload_fails() {
        let k = fresh_key();
        let payload = br#"{"policies":[]}"#;
        let sig = sign_envelope(&k, "urn:vch:dev.abc", kind::WINDOWS_POLICIES, 100, payload);
        let pk = k.verifying_key().to_bytes();
        let tampered = br#"{"policies":[{"p":"evil"}]}"#;
        assert!(
            verify_envelope(
                &pk,
                "urn:vch:dev.abc",
                kind::WINDOWS_POLICIES,
                100,
                tampered,
                &sig
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_key_fails() {
        let k = fresh_key();
        let attacker = fresh_key();
        let payload = br#"{"policies":[]}"#;
        let sig = sign_envelope(&k, "urn:vch:dev.abc", kind::WINDOWS_POLICIES, 100, payload);
        let pk = attacker.verifying_key().to_bytes();
        assert!(
            verify_envelope(
                &pk,
                "urn:vch:dev.abc",
                kind::WINDOWS_POLICIES,
                100,
                payload,
                &sig
            )
            .is_err()
        );
    }

    /// Cross-language determinism: the signing-bytes layout must be
    /// reproducible byte-for-byte by a C# verifier. Pin the layout
    /// here so an accidental refactor would flip this test.
    #[test]
    fn signing_bytes_layout_is_stable() {
        let msg = signing_bytes("d", "k", 0x0102030405060708, b"p");
        // DOMAIN_TAG (22 bytes) + 4 + 1 + 4 + 1 + 8 + 4 + 1 = 45.
        assert_eq!(msg.len(), DOMAIN_TAG.len() + 4 + 1 + 4 + 1 + 8 + 4 + 1);
        assert!(msg.starts_with(DOMAIN_TAG));
        // u32_le(1) right after the tag.
        let after_tag = &msg[DOMAIN_TAG.len()..];
        assert_eq!(&after_tag[..4], &[1, 0, 0, 0]);
        assert_eq!(after_tag[4], b'd');
    }

    /// **Cross-language interop fixture** (H-2 / H-3). The C# agents
    /// (Windows and macOS) pin the exact same deterministic test
    /// vector in their own test suites. If this test's expected hex
    /// values change, both C# sides must update in lockstep — which
    /// is what we want: drift in the Rust-side layout must be
    /// visible to anyone changing the format.
    #[test]
    fn interop_vector_is_stable() {
        use ed25519_dalek::Signer;
        // Deterministic 32-byte seed.
        let seed: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();

        let device_urn = "urn:vouchsafe:dev.abc";
        let kind = "windows-policies";
        let issued_at: u64 = 1_700_000_000;
        let payload: &[u8] = b"{\"policies\":[]}";

        let msg = signing_bytes(device_urn, kind, issued_at, payload);
        let sig = sk.sign(&msg).to_bytes();

        // Pinned outputs — C# tests pin the same hex. If this trips,
        // update the hex on all three test suites together, after
        // confirming the change was intentional.
        assert_eq!(hex_lower(&pk), PINNED_PUBKEY_HEX);
        assert_eq!(hex_lower(&sig), PINNED_SIG_HEX);
        // Sanity
        verify_envelope(&pk, device_urn, kind, issued_at, payload, &sig).unwrap();
    }

    // Ed25519 is deterministic — the (sk, msg) pair yields a fixed
    // signature, stable across runs and platforms. Computed once.
    const PINNED_PUBKEY_HEX: &str =
        "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    const PINNED_SIG_HEX: &str = "ec6c05fcf6ab6744ff8cba07ac93f6ac6fb69d1d214fdcc3b6f709a2fc63deaf37956c367c60185fc9e5dd91ff1c01bf4a4edfa7e5d7d25e595c861a98015c05";

    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(hex_nibble(b >> 4));
            s.push(hex_nibble(b & 0x0f));
        }
        s
    }

    fn hex_nibble(n: u8) -> char {
        match n {
            0..=9 => (b'0' + n) as char,
            _ => (b'a' + (n - 10)) as char,
        }
    }
}
