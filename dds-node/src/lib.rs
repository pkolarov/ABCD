//! DDS node library — config, event loop, local authority service.

// Shared mutex for tests that mutate process environment variables
// (e.g. DDS_DOMAIN_PASSPHRASE).  All test modules that call set_var /
// remove_var must hold this guard so they don't race each other.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod config;
pub mod domain_store;
pub mod expiry;
pub mod http;
pub mod identity_store;
pub mod node;
pub mod p2p_identity;
pub mod provision;
pub mod service;
