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
}
