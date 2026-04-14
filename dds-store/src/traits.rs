//! Storage trait definitions.
//!
//! All storage backends implement these traits, allowing the node
//! to swap between redb (desktop/mobile) and in-memory (embedded/test).

use std::collections::BTreeSet;
use std::fmt;

use dds_core::audit::AuditLogEntry;
use dds_core::crdt::causal_dag::Operation;
use dds_core::token::{Token, TokenKind};

/// Errors from storage operations.
#[derive(Debug)]
pub enum StoreError {
    /// Serialization / deserialization failure.
    Serde(String),
    /// Backend I/O error.
    Io(String),
    /// Item not found.
    NotFound(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Serde(e) => write!(f, "serialization error: {e}"),
            StoreError::Io(e) => write!(f, "I/O error: {e}"),
            StoreError::NotFound(key) => write!(f, "not found: {key}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type StoreResult<T> = Result<T, StoreError>;

/// Token storage — stores signed Vouchsafe tokens by JTI.
pub trait TokenStore {
    /// Store a token. Overwrites if JTI already exists.
    fn put_token(&mut self, token: &Token) -> StoreResult<()>;

    /// Retrieve a token by JTI.
    fn get_token(&self, jti: &str) -> StoreResult<Token>;

    /// Delete a token by JTI.
    fn delete_token(&mut self, jti: &str) -> StoreResult<()>;

    /// Check if a token exists.
    fn has_token(&self, jti: &str) -> bool;

    /// List all token JTIs, optionally filtered by kind.
    fn list_tokens(&self, kind: Option<TokenKind>) -> StoreResult<Vec<String>>;

    /// Count tokens, optionally filtered by kind.
    fn count_tokens(&self, kind: Option<TokenKind>) -> StoreResult<usize>;
}

/// Revocation set storage — tracks revoked JTIs and burned identity URNs.
pub trait RevocationStore {
    /// Mark a JTI as revoked.
    fn revoke(&mut self, jti: &str) -> StoreResult<()>;

    /// Check if a JTI is revoked.
    fn is_revoked(&self, jti: &str) -> bool;

    /// Mark an identity URN as burned.
    fn burn(&mut self, urn: &str) -> StoreResult<()>;

    /// Check if an identity URN is burned.
    fn is_burned(&self, urn: &str) -> bool;

    /// Get all revoked JTIs.
    fn revoked_set(&self) -> StoreResult<BTreeSet<String>>;

    /// Get all burned URNs.
    fn burned_set(&self) -> StoreResult<BTreeSet<String>>;
}

/// Operation log — append-only log of DAG operations for sync.
pub trait OperationStore {
    /// Append an operation. Idempotent (duplicate IDs are no-ops).
    fn put_operation(&mut self, op: &Operation) -> StoreResult<bool>;

    /// Retrieve an operation by ID.
    fn get_operation(&self, id: &str) -> StoreResult<Operation>;

    /// Check if an operation exists.
    fn has_operation(&self, id: &str) -> bool;

    /// List all operation IDs.
    fn operation_ids(&self) -> StoreResult<BTreeSet<String>>;

    /// Count operations.
    fn count_operations(&self) -> StoreResult<usize>;

    /// Get operations that are missing compared to a remote set.
    fn missing_operations(&self, remote_ids: &BTreeSet<String>) -> StoreResult<Vec<String>>;
}

/// Audit log storage — stores append-only cryptographic audit log entries.
pub trait AuditStore {
    /// Append an audit log entry.
    fn append_audit_entry(&mut self, entry: &AuditLogEntry) -> StoreResult<()>;

    /// Retrieve all audit log entries, ordered by insertion.
    fn list_audit_entries(&self) -> StoreResult<Vec<AuditLogEntry>>;

    /// Count the total number of audit log entries.
    fn count_audit_entries(&self) -> StoreResult<usize>;

    /// Remove audit entries older than the given Unix timestamp.
    /// Returns the number of entries removed.
    fn prune_audit_entries_before(&mut self, before_timestamp: u64) -> StoreResult<usize>;

    /// Remove the oldest entries to keep at most `max_entries`.
    /// Returns the number of entries removed.
    fn prune_audit_entries_to_max(&mut self, max_entries: usize) -> StoreResult<usize>;
}

/// Short-lived challenge storage for FIDO2 assertion freshness.
///
/// Challenges are server-issued 32-byte nonces with a TTL. Each challenge
/// is single-use: `consume_challenge` atomically validates, removes, and
/// returns the nonce bytes so the caller can reconstruct `clientDataJSON`
/// and verify `client_data_hash`.
pub trait ChallengeStore {
    /// Record a new server-issued challenge.
    /// `bytes` is 32 raw nonce bytes; `expires_at` is a Unix timestamp.
    fn put_challenge(&mut self, id: &str, bytes: &[u8; 32], expires_at: u64) -> StoreResult<()>;

    /// Atomically verify the challenge exists and is not expired, delete it,
    /// and return its bytes. Returns `StoreError::NotFound` if the id is
    /// unknown or already consumed; returns a descriptive `StoreError::Io`
    /// if the challenge has expired.
    fn consume_challenge(&mut self, id: &str, now: u64) -> StoreResult<[u8; 32]>;

    /// Delete all challenges whose `expires_at <= now`. Returns the count.
    fn sweep_expired_challenges(&mut self, now: u64) -> StoreResult<usize>;
}

/// Per-credential sign-count storage for FIDO2 replay detection.
///
/// Persists the highest observed `sign_count` per credential so that
/// non-monotonic counters (clone/replay attacks) can be detected.
pub trait CredentialStateStore {
    /// Return the stored sign count for a credential, or `None` if never seen.
    fn get_sign_count(&self, credential_id: &str) -> StoreResult<Option<u32>>;

    /// Persist a new sign count. Must be called only after verifying the
    /// new count exceeds the stored count.
    fn set_sign_count(&mut self, credential_id: &str, count: u32) -> StoreResult<()>;
}

/// Combined directory store — convenience trait bundling all stores.
pub trait DirectoryStore:
    TokenStore + RevocationStore + OperationStore + AuditStore + ChallengeStore + CredentialStateStore
{
}
