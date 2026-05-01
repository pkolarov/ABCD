//! DDS node library — config, event loop, local authority service.

// Shared mutex for tests that mutate process environment variables
// (e.g. DDS_DOMAIN_PASSPHRASE).  All test modules that call set_var /
// remove_var must hold this guard so they don't race each other.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod admission_revocation_store;
pub mod config;
pub mod device_binding;
pub mod domain_store;
pub mod epoch_key_store;
pub mod expiry;
pub(crate) mod file_acl;
pub mod http;
pub mod identity_store;
pub mod node;
pub mod p2p_identity;
pub mod peer_cert_store;
pub mod provision;
pub mod service;
pub mod telemetry;
