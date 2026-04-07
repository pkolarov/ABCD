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

    /// Retrieve all audit log entries, optionally sorted by timestamp.
    fn list_audit_entries(&self) -> StoreResult<Vec<AuditLogEntry>>;
}

/// Combined directory store — convenience trait bundling all stores.
pub trait DirectoryStore: TokenStore + RevocationStore + OperationStore + AuditStore {}
