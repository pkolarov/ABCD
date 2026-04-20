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

use serde::{Deserialize, Serialize};

/// Asks the remote peer for its admission cert. Carries no state —
/// the request is the entire handshake on the requester side.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmissionRequest;

/// Response carrying the peer's admission cert.
///
/// The cert is shipped as opaque CBOR bytes so the network layer
/// doesn't need to depend on `dds-domain`. On the responder side,
/// `cert_cbor` is `Some(<AdmissionCert::to_cbor>)`. On the requester
/// side, `None` means the peer refused or did not have a cert — in
/// either case the remote peer stays **unadmitted**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionResponse {
    pub cert_cbor: Option<Vec<u8>>,
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
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: AdmissionResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(round.cert_cbor, resp.cert_cbor);
    }

    #[test]
    fn admission_response_roundtrip_none() {
        let resp = AdmissionResponse { cert_cbor: None };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let round: AdmissionResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert!(round.cert_cbor.is_none());
    }
}
