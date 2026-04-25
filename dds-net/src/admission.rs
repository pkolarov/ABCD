//! Per-peer admission exchange (H-12 from the security review).
//!
//! **Problem.** Without this handshake, any libp2p peer that completes
//! Noise can publish into the gossip / sync streams of any node in the
//! domain. The node verifies its *own* admission cert at startup, but
//! it has no way to tell, on a per-message basis, whether the peer
//! that sent the message is itself admitted to the domain.
//!
//! **Fix.** Immediately after a connection is established we run a
//! request / response exchange over `/dds/admission/1.0.0/<domain>`
//! in which each peer asks the other for its admission cert. We
//! verify the peer's cert against the domain pubkey, the domain id,
//! and the peer's own libp2p `PeerId`. Only peers whose cert verifies
//! are added to the local `admitted_peers` set; gossip and sync
//! messages from any other peer are dropped at the behaviour layer.
//!
//! `dds-net` stays layer-independent of `dds-domain`: the cert is
//! shipped as opaque CBOR bytes in the response, and `dds-node` is
//! responsible for encoding / decoding / verifying it. That keeps
//! the network layer reusable with a different domain-cert scheme.
//!
//! ## Revocation piggyback (threat-model §1 / open item #4 follow-up)
//!
//! [`AdmissionResponse`] also carries an optional list of
//! domain-signed admission-revocation blobs. When two admitted peers
//! complete the H-12 handshake they piggy-back their local revocation
//! list onto the response so the requester can merge any new entries
//! into its own store. This turns admission revocation from a
//! manual file-distribution model into an eventually-consistent
//! gossip overlay — an admin issues `dds-node revoke-admission`
//! against any one node, and as that node's neighbours connect they
//! pick up the revocation transitively. Each entry is independently
//! signed by the domain key, so a malicious admitted peer cannot
//! forge or rewrite revocations; the worst it can do is omit them
//! (no worse than today's manual flow).
//!
//! The wire field is bounded by [`MAX_REVOCATIONS_PER_RESPONSE`]
//! to keep a hostile peer from ballooning a single response. The
//! field is `#[serde(default)]` so a v1-format peer that does not
//! set it still parses cleanly and conversely a v1 peer that does
//! not understand the field simply ignores any extra bytes.

use serde::{Deserialize, Serialize};

/// Per-response wire cap on the number of opaque CBOR-encoded
/// admission-revocation blobs an `AdmissionResponse` may carry.
///
/// 1024 entries × ~120 bytes per revocation (peer_id ≈ 52 +
/// signature 64 + small reason) ≈ 125 KB worst case — comfortably
/// under libp2p's request-response default size budget while still
/// large enough to cover the foreseeable revocation ledger of a
/// single domain. When a sender's local list exceeds this number
/// it should ship the first `MAX_REVOCATIONS_PER_RESPONSE` entries
/// and rely on subsequent reconnections to fan out the rest. A
/// receiver that gets more than this cap drops the entire
/// revocations vector (without rejecting the cert itself) so a
/// hostile peer cannot wedge the handshake by oversending.
pub const MAX_REVOCATIONS_PER_RESPONSE: usize = 1024;

/// Asks the remote peer for its admission cert. Carries no state —
/// the request is the entire handshake on the requester side.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmissionRequest;

/// Response carrying the peer's admission cert and (optionally) a
/// piggy-backed snapshot of the peer's known admission revocations.
///
/// The cert is shipped as opaque CBOR bytes so the network layer
/// doesn't need to depend on `dds-domain`. On the responder side,
/// `cert_cbor` is `Some(<AdmissionCert::to_cbor>)`. On the requester
/// side, `None` means the peer refused or did not have a cert — in
/// either case the remote peer stays **unadmitted**.
///
/// `revocations` carries up to [`MAX_REVOCATIONS_PER_RESPONSE`]
/// opaque CBOR-encoded `AdmissionRevocation` blobs. The receiver
/// verifies each entry independently against the domain pubkey
/// before merging into its local store, so a hostile sender cannot
/// poison the list. Empty / absent vector ⇒ "I have nothing to
/// share" and is the v1 default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmissionResponse {
    pub cert_cbor: Option<Vec<u8>>,
    /// Opaque CBOR-encoded `dds_domain::AdmissionRevocation` blobs.
    /// Default empty so legacy v1 peers (encoded without this field)
    /// deserialize cleanly.
    #[serde(default)]
    pub revocations: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_request_roundtrip() {
        let req = AdmissionRequest;
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let _: AdmissionRequest = ciborium::from_reader(&buf[..]).unwrap();
    }

    #[test]
    fn admission_response_roundtrip_some() {
        let resp = AdmissionResponse {
            cert_cbor: Some(b"opaque-cbor-bytes".to_vec()),
            revocations: Vec::new(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: AdmissionResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.cert_cbor, resp.cert_cbor);
        assert!(round.revocations.is_empty());
    }

    #[test]
    fn admission_response_roundtrip_none() {
        let resp = AdmissionResponse {
            cert_cbor: None,
            revocations: Vec::new(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: AdmissionResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert!(round.cert_cbor.is_none());
        assert!(round.revocations.is_empty());
    }

    #[test]
    fn admission_response_roundtrip_with_revocations() {
        // Three opaque revocation blobs of varying sizes, exactly as
        // `dds-node` would ship them after `AdmissionRevocation::to_cbor`.
        let resp = AdmissionResponse {
            cert_cbor: Some(b"opaque-cert".to_vec()),
            revocations: vec![
                b"rev-blob-1".to_vec(),
                b"rev-blob-2-longer".to_vec(),
                vec![0xa1, 0x82, 0x03, 0x07, 0x42, 0xde, 0xad],
            ],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: AdmissionResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.cert_cbor, resp.cert_cbor);
        assert_eq!(round.revocations.len(), 3);
        assert_eq!(round.revocations[0], b"rev-blob-1");
        assert_eq!(
            round.revocations[2],
            vec![0xa1, 0x82, 0x03, 0x07, 0x42, 0xde, 0xad]
        );
    }

    /// A v1 sender (no `revocations` field at all) must still decode
    /// cleanly under the v2 schema, with `revocations` defaulting to
    /// empty. This is the backward-compat invariant a deployed
    /// network depends on during a rolling upgrade.
    #[test]
    fn admission_response_decodes_legacy_v1_wire_without_revocations_field() {
        // The v1 struct only had `cert_cbor`. Reproduce its on-wire
        // shape directly so the test pins the wire format, not just
        // the current Rust struct.
        #[derive(Serialize)]
        struct V1Wire<'a> {
            cert_cbor: Option<&'a [u8]>,
        }
        let v1 = V1Wire {
            cert_cbor: Some(b"v1-cert"),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&v1, &mut buf).unwrap();

        let round: AdmissionResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.cert_cbor.as_deref(), Some(b"v1-cert".as_ref()));
        assert!(
            round.revocations.is_empty(),
            "missing v2 field must default to an empty Vec"
        );
    }

    /// Symmetric: a v2 sender encoding `revocations` must still be
    /// decodable by a v1 reader that ignores unknown fields. ciborium
    /// silently drops unknown fields by default — pin that.
    #[test]
    fn legacy_v1_reader_skips_v2_revocations_field() {
        #[derive(Deserialize)]
        struct V1Wire {
            cert_cbor: Option<Vec<u8>>,
        }
        let v2 = AdmissionResponse {
            cert_cbor: Some(b"v2-cert".to_vec()),
            revocations: vec![b"rev-1".to_vec(), b"rev-2".to_vec()],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&v2, &mut buf).unwrap();

        let round: V1Wire = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.cert_cbor.as_deref(), Some(b"v2-cert".as_ref()));
    }

    #[test]
    fn cap_constant_is_documented_value() {
        // Pin the wire-cap constant so a future bump must update the
        // docstring + every receiver that hardcodes a matching number.
        assert_eq!(MAX_REVOCATIONS_PER_RESPONSE, 1024);
    }
}
