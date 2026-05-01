//! Phase B PQC wire types — encrypted gossip / sync envelopes and
//! per-recipient epoch-key releases.
//!
//! See [`docs/pqc-phase-b-plan.md`](../../docs/pqc-phase-b-plan.md) §4.4
//! for the full design. This module is the **pure data** layer: it
//! defines the on-wire shapes, cap constants, and CBOR round-trip
//! semantics. The encrypt / decrypt / sign / verify logic lives in
//! `dds-core::crypto::epoch_key`, `dds-core::crypto::kem`, and
//! `dds-domain` — `dds-net` stays cryptography-agnostic so the
//! networking layer compiles without the `pq` feature flag.
//!
//! # Wire-format invariants
//!
//! - PeerIds are shipped as `String` (libp2p's base58 form). Avoids a
//!   serde dep on `libp2p::PeerId` and lets dds-net stay a thin types
//!   crate. Receivers parse with `libp2p::PeerId::from_str`.
//! - All five types have `#[derive(Serialize, Deserialize)]` with
//!   `serde(default)` on every newly-introduced optional field so a
//!   future v4 wire shape stays additive without breaking v3 decoders
//!   on the other side of a rolling upgrade. Mirrors the M-2 token-
//!   versioning pattern and the [`AdmissionResponse::revocations`]
//!   piggy-back from [`crate::admission`].
//! - Caps are bounded so a hostile peer cannot wedge a handshake by
//!   over-sending. See [`MAX_EPOCH_KEY_RELEASES_PER_RESPONSE`] and
//!   [`MAX_EPOCH_KEY_REQUEST_PUBLISHERS`].

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// **Z-1 Phase B (§4.5 piggy-back, §4.5.1 late-join)** — wire cap on
/// the number of opaque CBOR-encoded `EpochKeyRelease` blobs an
/// `AdmissionResponse` or `EpochKeyResponse` may carry.
///
/// Each release is roughly: 52 (publisher PeerId) + 8 (epoch_id) +
/// 8 (issued_at) + 8 (expires_at) + 52 (recipient PeerId) + 1120
/// (kem_ct) + 12 (aead_nonce) + ~48 (aead_ciphertext) + 64 (Ed25519
/// sig) + ~3,309 (ML-DSA-65 sig) ≈ 4,700 B with v2 hybrid signing.
/// At the cap of 256 entries that is ~1.2 MB worst case, comfortably
/// under libp2p's request-response default frame budget while still
/// covering the foreseeable domain size for a single round-trip
/// late-join recovery (`EpochKeyRequest.publishers.len()` bounded
/// by the same constant).
pub const MAX_EPOCH_KEY_RELEASES_PER_RESPONSE: usize = 256;

/// **Z-1 Phase B (§4.5.1)** — wire cap on the number of publisher
/// PeerIds an `EpochKeyRequest` may name. Receivers that get a
/// request larger than this drop the entire request rather than
/// truncating, so a hostile peer cannot inflate response work by
/// over-asking.
pub const MAX_EPOCH_KEY_REQUEST_PUBLISHERS: usize = 256;

/// **Z-1 Phase B (§4.5.1)** — receivers reject any `EpochKeyRelease`
/// whose `issued_at` is more than this many seconds in the past
/// relative to the local wall clock. Bounds an attacker's ability to
/// shelve an old release and replay it after the publisher has
/// rotated. 7 days mirrors the M-9 revocation replay window.
pub const EPOCH_RELEASE_REPLAY_WINDOW_SECS: u64 = 7 * 86_400;

/// **Z-1 Phase B (§4.5.1)** — after a publisher rotates, receivers
/// retain the previous `(publisher, prev_epoch_id) → key` entry for
/// this many seconds so in-flight gossip with the older `epoch_id`
/// still decrypts. 5 minutes is generous for typical libp2p mesh
/// propagation delays without keeping stale keys around long enough
/// to widen the post-rotation forward-secrecy window meaningfully.
pub const EPOCH_KEY_GRACE_SECS: u64 = 300;

/// **Z-1 Phase B.4** — wire-form length of [`EpochKeyRelease::kem_ct`]:
/// 32-byte ephemeral X25519 pubkey concatenated with the 1,088-byte
/// ML-KEM-768 ciphertext = 1,120 B. Mirrors
/// `dds_core::crypto::kem::HYBRID_KEM_CT_LEN` — re-asserted here so
/// dds-net stays free of a dds-core dep.
pub const EPOCH_KEY_RELEASE_KEM_CT_LEN: usize = 32 + 1_088;

/// **Z-1 Phase B.4** — wire-form length of
/// [`EpochKeyRelease::aead_ciphertext`]: 32-byte epoch key plaintext
/// + 16-byte Poly1305 tag = 48 B (ChaCha20-Poly1305).
pub const EPOCH_KEY_RELEASE_AEAD_CT_LEN: usize = 32 + 16;

/// **Z-1 Phase B.4** — Ed25519 signature length on
/// [`EpochKeyRelease::signature`].
pub const EPOCH_KEY_RELEASE_ED25519_SIG_LEN: usize = 64;

/// **Z-1 Phase A inheritance** — ML-DSA-65 (FIPS 204) signature
/// length on the optional [`EpochKeyRelease::pq_signature`]. Mirrors
/// `dds_domain::MLDSA65_SIG_LEN`; re-asserted here so dds-net stays
/// free of a dds-domain dep.
pub const EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN: usize = 3_309;

/// **Z-1 Phase B.4** — schema-layer validation outcome for
/// [`EpochKeyRelease::validate`]. Mirrors the
/// `dds_domain::PublisherIdentityError` shape: a typed reason a
/// receiver can audit / log against without having to re-derive
/// which length check or invariant tripped.
#[derive(Debug, PartialEq, Eq)]
pub enum EpochKeyReleaseValidateError {
    /// `publisher` field is empty — receivers cannot route the
    /// release to a publisher key.
    EmptyPublisher,
    /// `recipient` field is empty — receivers cannot tell whether
    /// the release was meant for them.
    EmptyRecipient,
    /// `expires_at <= issued_at` — the release is dead on arrival.
    /// Receivers reject up front so a downstream consumer never has
    /// to reason about a "valid for 0 seconds" key.
    InvalidExpiry { issued_at: u64, expires_at: u64 },
    /// `kem_ct.len()` is not [`EPOCH_KEY_RELEASE_KEM_CT_LEN`].
    KemCtLen { actual: usize },
    /// `aead_ciphertext.len()` is not [`EPOCH_KEY_RELEASE_AEAD_CT_LEN`].
    AeadCtLen { actual: usize },
    /// `signature.len()` is not [`EPOCH_KEY_RELEASE_ED25519_SIG_LEN`].
    Ed25519SigLen { actual: usize },
    /// `pq_signature` is present but length is not
    /// [`EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN`].
    Mldsa65SigLen { actual: usize },
}

impl std::fmt::Display for EpochKeyReleaseValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPublisher => f.write_str("publisher field is empty"),
            Self::EmptyRecipient => f.write_str("recipient field is empty"),
            Self::InvalidExpiry {
                issued_at,
                expires_at,
            } => write!(
                f,
                "expires_at ({expires_at}) must be greater than issued_at ({issued_at})"
            ),
            Self::KemCtLen { actual } => write!(
                f,
                "kem_ct: expected {EPOCH_KEY_RELEASE_KEM_CT_LEN} bytes, got {actual}"
            ),
            Self::AeadCtLen { actual } => write!(
                f,
                "aead_ciphertext: expected {EPOCH_KEY_RELEASE_AEAD_CT_LEN} bytes, got {actual}"
            ),
            Self::Ed25519SigLen { actual } => write!(
                f,
                "signature: expected {EPOCH_KEY_RELEASE_ED25519_SIG_LEN} bytes, got {actual}"
            ),
            Self::Mldsa65SigLen { actual } => write!(
                f,
                "pq_signature: expected {EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN} bytes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for EpochKeyReleaseValidateError {}

/// **Z-1 Phase B.4** — schema-layer validation outcome for
/// [`EpochKeyRequest::validate`]. Mirrors
/// [`EpochKeyReleaseValidateError`]: a typed reason a receiver can
/// audit / log against without having to re-derive which invariant
/// tripped.
#[derive(Debug, PartialEq, Eq)]
pub enum EpochKeyRequestValidateError {
    /// `publishers.len()` exceeds [`MAX_EPOCH_KEY_REQUEST_PUBLISHERS`].
    /// Receivers drop the entire request rather than truncating, so a
    /// hostile peer cannot inflate response work by over-asking.
    TooManyPublishers { actual: usize, cap: usize },
    /// `publishers[i]` is an empty string — receivers cannot route
    /// the request to a publisher key.
    EmptyPublisher { index: usize },
    /// `outbound_releases.len()` exceeds [`MAX_EPOCH_KEY_RELEASES_PER_RESPONSE`].
    /// Receivers drop the entire request rather than processing partial
    /// pushes — mirrors the response cap so the same install budget applies.
    TooManyOutboundReleases { actual: usize, cap: usize },
}

impl std::fmt::Display for EpochKeyRequestValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyPublishers { actual, cap } => {
                write!(f, "publishers: {actual} entries exceeds cap of {cap}")
            }
            Self::EmptyPublisher { index } => {
                write!(f, "publishers[{index}] is empty")
            }
            Self::TooManyOutboundReleases { actual, cap } => {
                write!(
                    f,
                    "outbound_releases: {actual} entries exceeds cap of {cap}"
                )
            }
        }
    }
}

impl std::error::Error for EpochKeyRequestValidateError {}

/// **Z-1 Phase B.4** — schema-layer validation outcome for
/// [`EpochKeyResponse::validate`]. Mirrors
/// [`EpochKeyReleaseValidateError`].
#[derive(Debug, PartialEq, Eq)]
pub enum EpochKeyResponseValidateError {
    /// `releases.len()` exceeds [`MAX_EPOCH_KEY_RELEASES_PER_RESPONSE`].
    /// Receivers drop the entire response rather than truncating, so
    /// a hostile peer cannot wedge the handshake by oversending.
    TooManyReleases { actual: usize, cap: usize },
}

impl std::fmt::Display for EpochKeyResponseValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyReleases { actual, cap } => {
                write!(f, "releases: {actual} entries exceeds cap of {cap}")
            }
        }
    }
}

impl std::error::Error for EpochKeyResponseValidateError {}

/// Replaces the plaintext gossipsub `Op` envelope on a domain that
/// has flipped the `enc-v3` capability. The original `GossipMessage`
/// is AEAD-encrypted under the publisher's current epoch key; the
/// recipient looks up `(publisher, epoch_id)` in its local epoch-key
/// store, derives the AEAD key, and decrypts under `nonce`.
///
/// Detection: an `enc-v3` receiver pattern-matches on the
/// `epoch_id` + `ciphertext` fields. A v2 plaintext envelope on the
/// same gossipsub topic is accepted during the rolling-upgrade
/// window and rejected once the domain capability is set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipEnvelopeV3 {
    /// Publisher's libp2p PeerId in base58 form.
    pub publisher: String,
    /// Publisher's current epoch identifier. The receiver looks up
    /// `(publisher, epoch_id)` in its epoch-key store; if missing,
    /// it triggers an `EpochKeyRequest` recovery (§4.5.1) before
    /// dropping the envelope.
    pub epoch_id: u64,
    /// 12-byte ChaCha20-Poly1305 nonce. Per-message random, never
    /// reused across messages keyed under the same epoch key.
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 12],
    /// AEAD ciphertext over the original CBOR-encoded
    /// `GossipMessage`. Length = plaintext + 16-byte Poly1305 tag.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Sync responder analog of [`GossipEnvelopeV3`] — same shape, but
/// the publisher field is named `responder` for clarity (the
/// responder is encrypting under *its own* current epoch key, per
/// §4.6.1, so the requester decrypts using the responder's release
/// not the original publisher's).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncEnvelopeV3 {
    /// Sync responder's libp2p PeerId in base58 form.
    pub responder: String,
    /// Responder's current epoch identifier.
    pub epoch_id: u64,
    /// 12-byte ChaCha20-Poly1305 nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 12],
    /// AEAD ciphertext over the original CBOR-encoded sync payload.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

impl GossipEnvelopeV3 {
    /// Encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }
}

impl SyncEnvelopeV3 {
    /// Encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }
}

/// Per-recipient release of a publisher's epoch key. The publisher
/// runs the hybrid X25519+ML-KEM-768 KEM (`dds-core::crypto::kem`)
/// against the recipient's KEM pubkey, derives a one-shot AEAD key
/// via HKDF, and uses it to encrypt the 32-byte epoch key. The
/// release is signed by the publisher (Ed25519 always; ML-DSA-65
/// also when the domain is v2 hybrid per Phase A) so a receiver
/// verifies authenticity against the publisher's `AdmissionCert`
/// before installing the epoch key.
///
/// Distribution channels (§4.5):
///
/// 1. **H-12 piggy-back** via [`crate::admission::AdmissionResponse::epoch_key_releases`].
/// 2. **Dedicated request-response** via [`EpochKeyRequest`] /
///    [`EpochKeyResponse`] over the
///    `/dds/epoch-keys/1.0.0/<domain>` libp2p protocol.
///
/// Both paths ship the release as opaque CBOR-encoded bytes inside
/// `Vec<Vec<u8>>` so the network layer doesn't depend on dds-domain
/// for verification. dds-node decodes via [`Self::from_cbor`] and
/// routes through the higher-layer verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochKeyRelease {
    /// Publisher's libp2p PeerId in base58 form.
    pub publisher: String,
    /// Epoch identifier this release installs the key for.
    pub epoch_id: u64,
    /// UNIX seconds at issuance. Receivers gate on
    /// [`EPOCH_RELEASE_REPLAY_WINDOW_SECS`] relative to local clock.
    pub issued_at: u64,
    /// UNIX seconds when this epoch ends. After this, the receiver
    /// should expect a fresh release for `epoch_id + 1` (or roll the
    /// publisher to "no current epoch" if no release arrives).
    pub expires_at: u64,
    /// Recipient PeerId in base58 form. Receivers verify this
    /// matches their own PeerId before attempting decap — defends
    /// against a bystander peer being handed someone else's release
    /// blob and trying to decap it (which would fail anyway, but
    /// failing fast saves a wasted ML-KEM-768 decap roundtrip).
    pub recipient: String,
    /// Hybrid KEM ciphertext: 32-byte ephemeral X25519 pubkey
    /// concatenated with the 1,088-byte ML-KEM-768 ciphertext.
    /// Total 1,120 bytes (`HYBRID_KEM_CT_LEN` in dds-core).
    #[serde(with = "serde_bytes")]
    pub kem_ct: Vec<u8>,
    /// 12-byte AEAD nonce. Per-release random.
    #[serde(with = "serde_bytes")]
    pub aead_nonce: [u8; 12],
    /// AEAD-encrypted 32-byte epoch key (48 bytes including the
    /// 16-byte Poly1305 tag).
    #[serde(with = "serde_bytes")]
    pub aead_ciphertext: Vec<u8>,
    /// 64-byte Ed25519 signature over the canonical body bytes
    /// (everything above this field, in declaration order, CBOR-
    /// encoded). Verified against the publisher's
    /// `AdmissionCert.body.signature`-issuer key.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// **Z-1 Phase A inheritance** — 3,309-byte ML-DSA-65
    /// signature over the same canonical body bytes, present when
    /// the publisher's domain is v2 hybrid. Verified against the
    /// publisher's `AdmissionCert.pq_kem_pubkey`-paired domain
    /// `pq_pubkey`. Absent on v1 (Ed25519-only) domains;
    /// [`#[serde(default)]`](serde::Deserialize) lets a v1 wire
    /// shape decode cleanly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<ByteBuf>,
}

impl EpochKeyRelease {
    /// CBOR-encode for the wire. The opaque `Vec<u8>` shipped in
    /// [`crate::admission::AdmissionResponse::epoch_key_releases`]
    /// and [`EpochKeyResponse::releases`] is the output of this.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// CBOR-decode an opaque blob. Caller must apply the
    /// `dds-core::cbor_bounded` depth cap (security review I-6) when
    /// the bytes originate from an untrusted peer over the wire —
    /// dds-net doesn't take a dep on dds-core, so the bounded decode
    /// happens at the dds-node ingest site (mirrors how
    /// [`dds_domain::AdmissionRevocation::from_cbor`] is wired).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    /// **Z-1 Phase B.4 schema-layer gate.** Run after [`Self::from_cbor`]
    /// and *before* any cryptographic verify (Ed25519 / ML-DSA-65 /
    /// hybrid-KEM decap). Mirrors the
    /// `dds_domain::PublisherIdentity::validate` fail-closed pattern:
    /// a malformed shape is rejected at the decode boundary so a
    /// downstream consumer (B.5 epoch-key store, B.6 release ingest,
    /// B.7 / B.8 envelope decrypt) never has to reason about a
    /// half-shaped release.
    ///
    /// Receivers that are about to spend an ML-KEM-768 decap on the
    /// release's `kem_ct` can short-circuit the wasted work when the
    /// blob never could have decapped. Each error variant names a
    /// single named invariant so the audit / log surface can record
    /// the typed reason rather than a free-form string.
    ///
    /// Note: this is the *schema* gate — it does not check
    /// `recipient == self.peer_id`, `issued_at` against
    /// [`EPOCH_RELEASE_REPLAY_WINDOW_SECS`], publisher signatures,
    /// or anything else that requires runtime context. Those live
    /// at the B.5 / B.6 ingest call site.
    pub fn validate(&self) -> Result<(), EpochKeyReleaseValidateError> {
        if self.publisher.is_empty() {
            return Err(EpochKeyReleaseValidateError::EmptyPublisher);
        }
        if self.recipient.is_empty() {
            return Err(EpochKeyReleaseValidateError::EmptyRecipient);
        }
        if self.expires_at <= self.issued_at {
            return Err(EpochKeyReleaseValidateError::InvalidExpiry {
                issued_at: self.issued_at,
                expires_at: self.expires_at,
            });
        }
        if self.kem_ct.len() != EPOCH_KEY_RELEASE_KEM_CT_LEN {
            return Err(EpochKeyReleaseValidateError::KemCtLen {
                actual: self.kem_ct.len(),
            });
        }
        if self.aead_ciphertext.len() != EPOCH_KEY_RELEASE_AEAD_CT_LEN {
            return Err(EpochKeyReleaseValidateError::AeadCtLen {
                actual: self.aead_ciphertext.len(),
            });
        }
        if self.signature.len() != EPOCH_KEY_RELEASE_ED25519_SIG_LEN {
            return Err(EpochKeyReleaseValidateError::Ed25519SigLen {
                actual: self.signature.len(),
            });
        }
        if let Some(pq) = self.pq_signature.as_ref() {
            if pq.len() != EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN {
                return Err(EpochKeyReleaseValidateError::Mldsa65SigLen { actual: pq.len() });
            }
        }
        Ok(())
    }
}

/// Late-join recovery request (§4.5.1). A receiver that observes a
/// `GossipEnvelopeV3` from publisher `P` for which it has no cached
/// epoch key emits a single request listing `P` (and any other
/// publishers it's also missing keys for, batched). The responder
/// is typically `P` itself, but may be any admitted peer that
/// currently holds a fresh release for the requested publishers
/// (gossip-style fan-out for resilience).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochKeyRequest {
    /// PeerIds (base58) of publishers we want current epoch keys
    /// for. Capped at [`MAX_EPOCH_KEY_REQUEST_PUBLISHERS`] —
    /// requests larger than this are dropped wholesale at the
    /// receive side rather than truncated.
    #[serde(default)]
    pub publishers: Vec<String>,
    /// Optional outbound `EpochKeyRelease` blobs the sender is pushing
    /// to the recipient (e.g. proactive rotation fan-out). Each blob
    /// is a CBOR-encoded `EpochKeyRelease` encapsulated *to the
    /// recipient's* hybrid KEM pubkey, processed by the receiver's
    /// normal `install_epoch_key_release` pipeline. Capped at
    /// [`MAX_EPOCH_KEY_RELEASES_PER_RESPONSE`] (same budget as a
    /// response). A request with only `outbound_releases` (empty
    /// `publishers`) is valid — the responder answers with an empty
    /// `EpochKeyResponse` and just installs the pushed releases.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_releases: Vec<Vec<u8>>,
}

impl EpochKeyRequest {
    /// **Z-1 Phase B.4 schema-layer gate.** Run on the receive side
    /// after [`ciborium::from_reader`] and before the B.5 responder
    /// spends any work fetching keys. Mirrors
    /// [`EpochKeyRelease::validate`]: a malformed shape is rejected at
    /// the decode boundary so a downstream consumer never has to reason
    /// about a half-shaped request.
    ///
    /// Enforces:
    /// - `publishers.len() <= MAX_EPOCH_KEY_REQUEST_PUBLISHERS` so a
    ///   hostile peer cannot inflate response work by over-asking.
    /// - Each `publishers[i]` is non-empty (an empty string cannot
    ///   route to a publisher key).
    pub fn validate(&self) -> Result<(), EpochKeyRequestValidateError> {
        if self.publishers.len() > MAX_EPOCH_KEY_REQUEST_PUBLISHERS {
            return Err(EpochKeyRequestValidateError::TooManyPublishers {
                actual: self.publishers.len(),
                cap: MAX_EPOCH_KEY_REQUEST_PUBLISHERS,
            });
        }
        for (i, p) in self.publishers.iter().enumerate() {
            if p.is_empty() {
                return Err(EpochKeyRequestValidateError::EmptyPublisher { index: i });
            }
        }
        if self.outbound_releases.len() > MAX_EPOCH_KEY_RELEASES_PER_RESPONSE {
            return Err(EpochKeyRequestValidateError::TooManyOutboundReleases {
                actual: self.outbound_releases.len(),
                cap: MAX_EPOCH_KEY_RELEASES_PER_RESPONSE,
            });
        }
        Ok(())
    }
}

/// Late-join recovery response (§4.5.1). Carries opaque CBOR-encoded
/// [`EpochKeyRelease`] blobs (one per requested publisher the
/// responder could honor); same shape as the
/// [`crate::admission::AdmissionResponse::epoch_key_releases`]
/// piggy-back so receivers can route both through a single
/// `EpochKeyRelease::from_cbor` decode pipeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochKeyResponse {
    /// Opaque CBOR-encoded `EpochKeyRelease` blobs, one per
    /// publisher the responder could honor. Empty / absent ⇒ "I
    /// have nothing to release for those publishers right now"
    /// (the requester retries via gossip-style fan-out to a
    /// different peer or directly to the publisher).
    /// Capped at [`MAX_EPOCH_KEY_RELEASES_PER_RESPONSE`].
    #[serde(default)]
    pub releases: Vec<Vec<u8>>,
}

impl EpochKeyResponse {
    /// **Z-1 Phase B.4 schema-layer gate.** Run on the receive side
    /// after CBOR decode and before per-blob
    /// [`EpochKeyRelease::from_cbor`] / [`EpochKeyRelease::validate`]
    /// / cryptographic verify. Mirrors the cap on the AdmissionResponse
    /// revocations field enforced by dds-node — drop wholesale, do not
    /// truncate, so a hostile peer cannot wedge the handshake by
    /// oversending.
    ///
    /// Note: this is the *outer* cap. Each individual release blob
    /// must still be decoded via [`EpochKeyRelease::from_cbor`] and
    /// shape-checked via [`EpochKeyRelease::validate`] at the B.6
    /// ingest call site.
    pub fn validate(&self) -> Result<(), EpochKeyResponseValidateError> {
        if self.releases.len() > MAX_EPOCH_KEY_RELEASES_PER_RESPONSE {
            return Err(EpochKeyResponseValidateError::TooManyReleases {
                actual: self.releases.len(),
                cap: MAX_EPOCH_KEY_RELEASES_PER_RESPONSE,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_release() -> EpochKeyRelease {
        EpochKeyRelease {
            publisher: "12D3KooWPublisher".into(),
            epoch_id: 17,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            recipient: "12D3KooWRecipient".into(),
            kem_ct: vec![0xab; 1120],
            aead_nonce: [0u8; 12],
            aead_ciphertext: vec![0xcd; 48],
            signature: vec![0xee; 64],
            pq_signature: None,
        }
    }

    #[test]
    fn gossip_envelope_v3_cbor_roundtrip() {
        let env = GossipEnvelopeV3 {
            publisher: "12D3KooWAlpha".into(),
            epoch_id: 7,
            nonce: [1u8; 12],
            ciphertext: vec![0u8, 1, 2, 3],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&env, &mut buf).unwrap();
        let round: GossipEnvelopeV3 = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round, env);
    }

    #[test]
    fn sync_envelope_v3_cbor_roundtrip() {
        let env = SyncEnvelopeV3 {
            responder: "12D3KooWBeta".into(),
            epoch_id: 42,
            nonce: [2u8; 12],
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&env, &mut buf).unwrap();
        let round: SyncEnvelopeV3 = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round, env);
    }

    #[test]
    fn epoch_key_release_v1_cbor_roundtrip() {
        let r = sample_release();
        let bytes = r.to_cbor().unwrap();
        let round = EpochKeyRelease::from_cbor(&bytes).unwrap();
        assert_eq!(round, r);
        assert!(round.pq_signature.is_none());
    }

    #[test]
    fn epoch_key_release_v2_hybrid_cbor_roundtrip() {
        let mut r = sample_release();
        r.pq_signature = Some(ByteBuf::from(vec![0x55; 3309]));
        let bytes = r.to_cbor().unwrap();
        let round = EpochKeyRelease::from_cbor(&bytes).unwrap();
        assert_eq!(round, r);
        assert_eq!(round.pq_signature.as_ref().map(|b| b.len()), Some(3309));
    }

    /// **Backwards-compat wire format.** A v1 (Ed25519-only)
    /// `EpochKeyRelease` encoded *without* the `pq_signature` field
    /// at all on the wire must decode cleanly under the v2 schema
    /// with `pq_signature: None`. Mirrors the v1↔v2 invariant from
    /// `dds-domain::Domain` and `dds_net::admission::AdmissionResponse`.
    #[test]
    fn legacy_v1_release_wire_decodes_under_v2_schema() {
        #[derive(Serialize)]
        struct V1Wire<'a> {
            publisher: &'a str,
            epoch_id: u64,
            issued_at: u64,
            expires_at: u64,
            recipient: &'a str,
            #[serde(with = "serde_bytes")]
            kem_ct: &'a [u8],
            #[serde(with = "serde_bytes")]
            aead_nonce: &'a [u8; 12],
            #[serde(with = "serde_bytes")]
            aead_ciphertext: &'a [u8],
            #[serde(with = "serde_bytes")]
            signature: &'a [u8],
        }
        let nonce = [9u8; 12];
        let v1 = V1Wire {
            publisher: "12D3KooWLegacy",
            epoch_id: 1,
            issued_at: 100,
            expires_at: 200,
            recipient: "12D3KooWLegacyRecv",
            kem_ct: &[0xaa; 1120],
            aead_nonce: &nonce,
            aead_ciphertext: &[0xbb; 48],
            signature: &[0xcc; 64],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&v1, &mut buf).unwrap();

        let round = EpochKeyRelease::from_cbor(&buf).unwrap();
        assert_eq!(round.publisher, "12D3KooWLegacy");
        assert_eq!(round.epoch_id, 1);
        assert_eq!(round.kem_ct.len(), 1120);
        assert!(
            round.pq_signature.is_none(),
            "missing v2 field must default to None"
        );
    }

    #[test]
    fn epoch_key_request_cbor_roundtrip_and_default_empty() {
        let req = EpochKeyRequest {
            publishers: vec!["12D3KooWP1".into(), "12D3KooWP2".into()],
            outbound_releases: vec![],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let round: EpochKeyRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.publishers, req.publishers);

        // Default constructor yields the empty-publishers request.
        let empty = EpochKeyRequest::default();
        assert!(empty.publishers.is_empty());
    }

    #[test]
    fn epoch_key_response_cbor_roundtrip_with_releases() {
        let resp = EpochKeyResponse {
            releases: vec![
                sample_release().to_cbor().unwrap(),
                sample_release().to_cbor().unwrap(),
            ],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: EpochKeyResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.releases.len(), 2);
        let inner = EpochKeyRelease::from_cbor(&round.releases[0]).unwrap();
        assert_eq!(inner.publisher, "12D3KooWPublisher");
    }

    #[test]
    fn epoch_key_response_default_is_empty_releases() {
        let resp = EpochKeyResponse::default();
        assert!(resp.releases.is_empty());
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: EpochKeyResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert!(round.releases.is_empty());
    }

    /// A v1 wire `EpochKeyResponse` that omits `releases` entirely
    /// (e.g. emitted by an early prototype before this struct grew
    /// the field) must decode as an empty-list response under the
    /// v2 schema. Defends the additive-fields invariant.
    #[test]
    fn legacy_v1_response_wire_without_releases_field_decodes_empty() {
        #[derive(Serialize)]
        struct V1Wire {}
        let v1 = V1Wire {};
        let mut buf = Vec::new();
        ciborium::into_writer(&v1, &mut buf).unwrap();
        let round: EpochKeyResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert!(round.releases.is_empty());
    }

    #[test]
    fn cap_constants_are_documented_values() {
        assert_eq!(MAX_EPOCH_KEY_RELEASES_PER_RESPONSE, 256);
        assert_eq!(MAX_EPOCH_KEY_REQUEST_PUBLISHERS, 256);
        assert_eq!(EPOCH_RELEASE_REPLAY_WINDOW_SECS, 7 * 86_400);
        assert_eq!(EPOCH_KEY_GRACE_SECS, 300);
    }

    /// **Z-1 Phase B.4** — pin the wire-form length constants so a
    /// future bump must update the docstring + every receiver that
    /// hardcodes a matching number. Each value is also asserted
    /// against the source-of-truth in `dds_core::crypto::kem` /
    /// `dds_domain` via the `kem_ct` / `aead_ciphertext` /
    /// `signature` / `pq_signature` length invariants.
    #[test]
    fn release_length_constants_are_documented_values() {
        assert_eq!(EPOCH_KEY_RELEASE_KEM_CT_LEN, 1_120);
        assert_eq!(EPOCH_KEY_RELEASE_AEAD_CT_LEN, 48);
        assert_eq!(EPOCH_KEY_RELEASE_ED25519_SIG_LEN, 64);
        assert_eq!(EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN, 3_309);
    }

    #[test]
    fn validate_accepts_well_formed_v1_release() {
        sample_release().validate().unwrap();
    }

    #[test]
    fn validate_accepts_well_formed_v2_hybrid_release() {
        let mut r = sample_release();
        r.pq_signature = Some(ByteBuf::from(vec![0x55; EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN]));
        r.validate().unwrap();
    }

    #[test]
    fn validate_rejects_empty_publisher() {
        let mut r = sample_release();
        r.publisher.clear();
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::EmptyPublisher
        );
    }

    #[test]
    fn validate_rejects_empty_recipient() {
        let mut r = sample_release();
        r.recipient.clear();
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::EmptyRecipient
        );
    }

    #[test]
    fn validate_rejects_expires_at_equal_to_issued_at() {
        let mut r = sample_release();
        r.expires_at = r.issued_at;
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::InvalidExpiry {
                issued_at: r.issued_at,
                expires_at: r.expires_at,
            }
        );
    }

    #[test]
    fn validate_rejects_expires_at_before_issued_at() {
        let mut r = sample_release();
        r.expires_at = r.issued_at - 1;
        let err = r.validate().unwrap_err();
        assert!(matches!(
            err,
            EpochKeyReleaseValidateError::InvalidExpiry { .. }
        ));
    }

    #[test]
    fn validate_rejects_short_kem_ct() {
        let mut r = sample_release();
        r.kem_ct.truncate(EPOCH_KEY_RELEASE_KEM_CT_LEN - 1);
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::KemCtLen {
                actual: EPOCH_KEY_RELEASE_KEM_CT_LEN - 1
            }
        );
    }

    #[test]
    fn validate_rejects_long_kem_ct() {
        let mut r = sample_release();
        r.kem_ct.push(0);
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::KemCtLen {
                actual: EPOCH_KEY_RELEASE_KEM_CT_LEN + 1
            }
        );
    }

    #[test]
    fn validate_rejects_wrong_aead_ciphertext_length() {
        let mut r = sample_release();
        r.aead_ciphertext.pop();
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::AeadCtLen {
                actual: EPOCH_KEY_RELEASE_AEAD_CT_LEN - 1
            }
        );
    }

    #[test]
    fn validate_rejects_wrong_signature_length() {
        let mut r = sample_release();
        r.signature.pop();
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::Ed25519SigLen {
                actual: EPOCH_KEY_RELEASE_ED25519_SIG_LEN - 1
            }
        );
    }

    #[test]
    fn validate_rejects_wrong_pq_signature_length() {
        let mut r = sample_release();
        r.pq_signature = Some(ByteBuf::from(vec![
            0x55;
            EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN - 1
        ]));
        assert_eq!(
            r.validate().unwrap_err(),
            EpochKeyReleaseValidateError::Mldsa65SigLen {
                actual: EPOCH_KEY_RELEASE_MLDSA65_SIG_LEN - 1
            }
        );
    }

    /// `pq_signature: None` is the v1 (Ed25519-only domain) wire shape
    /// and must not trigger the ML-DSA-65 length gate. Pins the
    /// rolling-upgrade compatibility surface — a v2 hybrid receiver
    /// that gets a v1 release on a non-hybrid domain stays backward-
    /// compatible.
    #[test]
    fn validate_accepts_absent_pq_signature() {
        let mut r = sample_release();
        r.pq_signature = None;
        r.validate().unwrap();
    }

    /// `Display` impls feed log lines + audit fields downstream;
    /// pin the formatting so a renderer change is loud.
    #[test]
    fn validate_error_display_strings_include_actual_lengths() {
        let e = EpochKeyReleaseValidateError::KemCtLen { actual: 999 };
        let s = format!("{e}");
        assert!(s.contains("kem_ct"), "got: {s}");
        assert!(s.contains("999"), "got: {s}");
        assert!(
            s.contains(&EPOCH_KEY_RELEASE_KEM_CT_LEN.to_string()),
            "got: {s}"
        );
    }

    #[test]
    fn epoch_key_request_validate_accepts_empty_request() {
        EpochKeyRequest::default().validate().unwrap();
    }

    #[test]
    fn epoch_key_request_validate_accepts_well_formed_request() {
        let req = EpochKeyRequest {
            publishers: vec!["12D3KooWP1".into(), "12D3KooWP2".into()],
            outbound_releases: vec![],
        };
        req.validate().unwrap();
    }

    #[test]
    fn epoch_key_request_validate_accepts_request_at_cap() {
        let req = EpochKeyRequest {
            publishers: (0..MAX_EPOCH_KEY_REQUEST_PUBLISHERS)
                .map(|i| format!("12D3KooWP{i}"))
                .collect(),
            outbound_releases: vec![],
        };
        req.validate().unwrap();
    }

    #[test]
    fn epoch_key_request_validate_rejects_request_over_cap() {
        let req = EpochKeyRequest {
            publishers: (0..MAX_EPOCH_KEY_REQUEST_PUBLISHERS + 1)
                .map(|i| format!("12D3KooWP{i}"))
                .collect(),
            outbound_releases: vec![],
        };
        assert_eq!(
            req.validate().unwrap_err(),
            EpochKeyRequestValidateError::TooManyPublishers {
                actual: MAX_EPOCH_KEY_REQUEST_PUBLISHERS + 1,
                cap: MAX_EPOCH_KEY_REQUEST_PUBLISHERS,
            }
        );
    }

    #[test]
    fn epoch_key_request_validate_rejects_empty_publisher_string() {
        let req = EpochKeyRequest {
            publishers: vec!["12D3KooWP1".into(), String::new(), "12D3KooWP3".into()],
            outbound_releases: vec![],
        };
        assert_eq!(
            req.validate().unwrap_err(),
            EpochKeyRequestValidateError::EmptyPublisher { index: 1 }
        );
    }

    #[test]
    fn epoch_key_request_validate_error_display_includes_cap_and_index() {
        let too_many = EpochKeyRequestValidateError::TooManyPublishers {
            actual: 999,
            cap: MAX_EPOCH_KEY_REQUEST_PUBLISHERS,
        };
        let s = format!("{too_many}");
        assert!(s.contains("999"), "got: {s}");
        assert!(
            s.contains(&MAX_EPOCH_KEY_REQUEST_PUBLISHERS.to_string()),
            "got: {s}"
        );

        let empty = EpochKeyRequestValidateError::EmptyPublisher { index: 7 };
        let s = format!("{empty}");
        assert!(s.contains("publishers[7]"), "got: {s}");
    }

    #[test]
    fn epoch_key_response_validate_accepts_empty_response() {
        EpochKeyResponse::default().validate().unwrap();
    }

    #[test]
    fn epoch_key_response_validate_accepts_response_at_cap() {
        let blob = sample_release().to_cbor().unwrap();
        let resp = EpochKeyResponse {
            releases: (0..MAX_EPOCH_KEY_RELEASES_PER_RESPONSE)
                .map(|_| blob.clone())
                .collect(),
        };
        resp.validate().unwrap();
    }

    #[test]
    fn epoch_key_response_validate_rejects_response_over_cap() {
        let blob = sample_release().to_cbor().unwrap();
        let resp = EpochKeyResponse {
            releases: (0..MAX_EPOCH_KEY_RELEASES_PER_RESPONSE + 1)
                .map(|_| blob.clone())
                .collect(),
        };
        assert_eq!(
            resp.validate().unwrap_err(),
            EpochKeyResponseValidateError::TooManyReleases {
                actual: MAX_EPOCH_KEY_RELEASES_PER_RESPONSE + 1,
                cap: MAX_EPOCH_KEY_RELEASES_PER_RESPONSE,
            }
        );
    }

    #[test]
    fn epoch_key_response_validate_does_not_decode_inner_releases() {
        // The outer schema gate is a count check only — it must not
        // attempt to decode the opaque blobs. Pin the contract so a
        // future implementer doesn't accidentally fold inner-decode
        // work into the cap path (which the B.6 ingest site owns).
        let resp = EpochKeyResponse {
            releases: vec![vec![0xff, 0xff, 0xff], vec![0x00]],
        };
        resp.validate().unwrap();
    }

    #[test]
    fn epoch_key_response_validate_error_display_includes_cap() {
        let e = EpochKeyResponseValidateError::TooManyReleases {
            actual: 9_999,
            cap: MAX_EPOCH_KEY_RELEASES_PER_RESPONSE,
        };
        let s = format!("{e}");
        assert!(s.contains("9999") || s.contains("9_999"), "got: {s}");
        assert!(
            s.contains(&MAX_EPOCH_KEY_RELEASES_PER_RESPONSE.to_string()),
            "got: {s}"
        );
    }
}
