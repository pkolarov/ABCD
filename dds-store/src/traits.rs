//! Storage trait definitions.
//!
//! All storage backends implement these traits, allowing the node
//! to swap between redb (desktop/mobile) and in-memory (embedded/test).

use std::collections::{BTreeMap, BTreeSet};
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
    /// **L-18 (security review)**: atomic sign-count bump refused
    /// because the new count is not strictly greater than the
    /// stored one. Returned by `CredentialStateStore::bump_sign_count`
    /// — either a clone/replay attempt or a racing caller that
    /// already consumed this counter value.
    SignCountReplay { stored: u32, attempted: u32 },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Serde(e) => write!(f, "serialization error: {e}"),
            StoreError::Io(e) => write!(f, "I/O error: {e}"),
            StoreError::NotFound(key) => write!(f, "not found: {key}"),
            StoreError::SignCountReplay { stored, attempted } => write!(
                f,
                "sign-count replay: attempted {attempted} <= stored {stored}"
            ),
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
    ///
    /// **L-12 (security review)**: implementations MUST verify the
    /// hash chain on append. Specifically: if the store already has
    /// at least one entry, the incoming `entry.prev_hash` must equal
    /// the last stored entry's `chain_hash()`. For an empty store the
    /// incoming `prev_hash` must be empty ("genesis"). Violations
    /// return `StoreError::Serde(...)` with a message describing the
    /// break so callers can surface it. Implementations that want to
    /// opt out of chain enforcement for legacy reasons should do so
    /// behind a clearly-labelled `*_unchecked` helper.
    fn append_audit_entry(&mut self, entry: &AuditLogEntry) -> StoreResult<()>;

    /// Return the `chain_hash` of the last stored entry, or `None` if
    /// the store is empty. Used by callers that need to construct
    /// chained entries with the correct `prev_hash`.
    fn audit_chain_head(&self) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .list_audit_entries()?
            .last()
            .and_then(|e| e.chain_hash().ok()))
    }

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
    ///
    /// **B-5 (security review):** when the row is found expired the
    /// backend MUST delete it before returning the expiry error so a
    /// caller that probes a stale id contributes to cleanup rather
    /// than letting the row accumulate.
    fn consume_challenge(&mut self, id: &str, now: u64) -> StoreResult<[u8; 32]>;

    /// Delete all challenges whose `expires_at <= now`. Returns the count.
    fn sweep_expired_challenges(&mut self, now: u64) -> StoreResult<usize>;

    /// Total number of challenge rows currently outstanding (expired or not).
    /// Used by issue paths to enforce a global cap after sweeping expired rows.
    fn count_challenges(&self) -> StoreResult<usize>;
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

    /// **L-18 (security review)**: atomic check-and-set. Returns
    /// `Ok(())` if `new_count > stored`; else
    /// `Err(StoreError::SignCountReplay { .. })`. The backend MUST
    /// perform the compare and the write under the same lock /
    /// transaction so two concurrent callers cannot both read the
    /// same stored value, see their `new_count > stored`, and each
    /// commit — which would allow the second caller to reuse an
    /// assertion that was already consumed by the first.
    ///
    /// Default implementation is intentionally non-atomic and only
    /// suitable for backends whose `get_sign_count` +
    /// `set_sign_count` are serialized by an outer mutex. Backends
    /// must override this when they hold their own concurrency
    /// domain (e.g. a redb write transaction).
    fn bump_sign_count(&mut self, credential_id: &str, new_count: u32) -> StoreResult<()> {
        let stored = self.get_sign_count(credential_id)?.unwrap_or(0);
        if new_count <= stored {
            return Err(StoreError::SignCountReplay {
                stored,
                attempted: new_count,
            });
        }
        self.set_sign_count(credential_id, new_count)
    }
}

/// Per-table stored-byte snapshot for the `dds_store_bytes{table=...}`
/// Prometheus gauge (observability-plan.md Phase C). Implementations
/// return a map keyed by stable table name (matching the redb table
/// definitions) whose value is the count of bytes the backend reports
/// as currently occupied by stored payloads (i.e. the data the table
/// actually holds, not metadata or fragmentation overhead).
///
/// Bytes vs. entries: this trait reports *bytes*. Entry counts are
/// already exposed by the per-domain methods (`count_tokens`,
/// `count_audit_entries`, `count_challenges`, …) and need not be
/// duplicated here.
///
/// Backends with no notion of byte size (in-memory backends used in
/// tests) return an empty map. The metrics renderer treats an empty
/// snapshot as "family present, no series" so the `# HELP` / `# TYPE`
/// headers stay discoverable.
pub trait StoreSizeStats {
    /// Snapshot of bytes-stored per known table. The keys are static
    /// table-name strings so the metric `table` label is a fixed
    /// vocabulary.
    ///
    /// Returns a `StoreResult` so a failed read at scrape time can be
    /// surfaced to the renderer (which degrades to zero rather than
    /// panicking the scrape task — matches the `trust_graph_counts`
    /// poison-tolerance pattern).
    fn table_stored_bytes(&self) -> StoreResult<BTreeMap<&'static str, u64>>;
}

/// Combined directory store — convenience trait bundling all stores.
pub trait DirectoryStore:
    TokenStore + RevocationStore + OperationStore + AuditStore + ChallengeStore + CredentialStateStore
{
}
