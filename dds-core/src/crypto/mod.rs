//! Cryptographic abstraction layer with hybrid quantum-resistant support.
//!
//! Provides a [`SigningScheme`] trait with two implementations:
//! - **Classical** (`Ed25519Only`) — Ed25519 signatures (32B pubkey, 64B sig)
//! - **Hybrid** (`HybridEdMldsa`) — Ed25519 + ML-DSA-65 composite signatures
//!   (FIPS 204, ~2KB pubkey, ~3.4KB sig). Both must verify for acceptance.
//!
//! The hybrid scheme follows IETF draft-ietf-lamps-pq-composite-sigs and
//! recommendations from ANSSI, BSI, and NIST for transitional quantum resistance.
//!
//! # Feature flags
//! - `pq` (default) — Enables hybrid ML-DSA-65 support via `pqcrypto-mldsa`
//! - Without `pq` — Only classical Ed25519 is available

pub mod classical;
pub mod ecdsa;
#[cfg(feature = "pq")]
pub mod hybrid;
#[cfg(feature = "pq")]
pub mod kem;
pub mod traits;
#[cfg(feature = "pq")]
pub mod triple_hybrid;

pub use classical::Ed25519Only;
pub use ecdsa::EcdsaP256Only;
#[cfg(feature = "pq")]
pub use hybrid::HybridEdMldsa;
pub use traits::*;
#[cfg(feature = "pq")]
pub use triple_hybrid::TripleHybridEdEcdsaMldsa65;
