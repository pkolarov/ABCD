//! # dds-domain
//!
//! Typed domain documents that serialize into `TokenPayload::body_type` + `body_cbor`.
//!
//! Core (`dds-core`) never interprets these payloads; this crate provides
//! typed constructors and extractors for each document type:
//!
//! | Document | body_type | Use Case |
//! |---|---|---|
//! | `UserAuthAttestation` | `dds:user-auth-attestation` | FIDO2/passkey enrollment |
//! | `DeviceJoinDocument` | `dds:device-join` | Device enrollment |
//! | `WindowsPolicyDocument` | `dds:windows-policy` | GPO-equivalent policy |
//! | `MacOsPolicyDocument` | `dds:macos-policy` | macOS managed-device policy |
//! | `MacAccountBindingDocument` | `dds:macos-account-binding` | Bind DDS subject/device to a macOS local account |
//! | `SsoIdentityLinkDocument` | `dds:sso-identity-link` | Link enterprise IdP identity to a DDS subject |
//! | `SoftwareAssignment` | `dds:software-assignment` | App deployment manifests |
//! | `ServicePrincipalDocument` | `dds:service-principal` | Machine/service identity |
//! | `SessionDocument` | `dds:session` | Short-lived auth session |

pub mod domain;
pub mod fido2;
pub mod types;

pub use domain::{
    AdmissionBody, AdmissionCert, AdmissionRevocation, Domain, DomainId, DomainKey, DomainSigner,
    RevocationBody,
};
pub use types::*;

use dds_core::token::TokenPayload;

/// Body type URI constants.
pub mod body_types {
    pub const USER_AUTH_ATTESTATION: &str = "dds:user-auth-attestation";
    pub const DEVICE_JOIN: &str = "dds:device-join";
    pub const WINDOWS_POLICY: &str = "dds:windows-policy";
    pub const MACOS_POLICY: &str = "dds:macos-policy";
    pub const MACOS_ACCOUNT_BINDING: &str = "dds:macos-account-binding";
    pub const SSO_IDENTITY_LINK: &str = "dds:sso-identity-link";
    pub const SOFTWARE_ASSIGNMENT: &str = "dds:software-assignment";
    pub const SERVICE_PRINCIPAL: &str = "dds:service-principal";
    pub const SESSION: &str = "dds:session";
}

/// Trait for domain documents that can be embedded in a token payload.
pub trait DomainDocument: serde::Serialize + serde::de::DeserializeOwned {
    /// The body_type URI for this document type.
    const BODY_TYPE: &'static str;

    /// Serialize this document to CBOR bytes.
    fn to_cbor(&self) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| DomainError::Serialize(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes.
    ///
    /// Uses [`dds_core::cbor_bounded`] (depth cap = 16) because
    /// `body_cbor` ultimately rides inside attacker-controllable
    /// token payloads delivered via gossip / sync — security review
    /// I-6.
    fn from_cbor(bytes: &[u8]) -> Result<Self, DomainError> {
        dds_core::cbor_bounded::from_reader(bytes)
            .map_err(|e| DomainError::Deserialize(e.to_string()))
    }

    /// Embed this document into a token payload's body fields.
    fn embed(&self, payload: &mut TokenPayload) -> Result<(), DomainError> {
        payload.body_type = Some(Self::BODY_TYPE.to_string());
        payload.body_cbor = Some(self.to_cbor()?);
        Ok(())
    }

    /// Extract this document from a token payload.
    /// Returns `None` if body_type doesn't match; `Err` if CBOR decode fails.
    fn extract(payload: &TokenPayload) -> Result<Option<Self>, DomainError> {
        match (&payload.body_type, &payload.body_cbor) {
            (Some(bt), Some(cbor)) if bt == Self::BODY_TYPE => Ok(Some(Self::from_cbor(cbor)?)),
            (Some(_), _) => Ok(None), // different body type
            (None, _) => Ok(None),    // no body
        }
    }
}

/// Domain document errors.
#[derive(Debug)]
pub enum DomainError {
    Serialize(String),
    Deserialize(String),
    InvalidBodyType { expected: String, got: String },
}

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainError::Serialize(e) => write!(f, "serialize: {e}"),
            DomainError::Deserialize(e) => write!(f, "deserialize: {e}"),
            DomainError::InvalidBodyType { expected, got } => {
                write!(f, "body_type mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for DomainError {}
