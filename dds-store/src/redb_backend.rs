//! redb storage backend.
//!
//! Persistent, ACID-compliant key-value store using redb.
//! Stores directory entries, CRDT state, operation log, and revocation sets.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use dds_core::audit::AuditLogEntry;
use dds_core::crdt::causal_dag::Operation;
use dds_core::token::{Token, TokenKind};

use crate::traits::*;

// Table definitions
const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");
const REVOKED: TableDefinition<&str, &[u8]> = TableDefinition::new("revoked");
const BURNED: TableDefinition<&str, &[u8]> = TableDefinition::new("burned");
const OPERATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("operations");
const AUDIT_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("audit_log");
// Value: 8-byte expires_at (u64 big-endian) || 32-byte nonce
const CHALLENGES: TableDefinition<&str, &[u8]> = TableDefinition::new("challenges");
// Value: 4-byte sign_count (u32 big-endian)
const CREDENTIAL_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("credential_state");

/// redb-backed persistent storage.
#[derive(Clone)]
pub struct RedbBackend {
    db: Arc<Database>,
}

impl RedbBackend {
    /// Open or create a redb database at the given path.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let path = path.as_ref();
        let db = Database::create(path).map_err(|e| StoreError::Io(e.to_string()))?;
        // M-20 (security review): restrict the database file to owner
        // read/write. redb creates it with process umask (typically
        // 0o644), leaving tokens, audit entries, and credential
        // metadata readable by any local user. Windows inherits parent
        // ACL; we document that operators must restrict the data dir.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        // Ensure all tables exist
        let write_txn = db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(TOKENS)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let _ = write_txn
                .open_table(REVOKED)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let _ = write_txn
                .open_table(BURNED)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let _ = write_txn
                .open_table(OPERATIONS)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let _ = write_txn
                .open_table(AUDIT_LOG)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let _ = write_txn
                .open_table(CHALLENGES)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let _ = write_txn
                .open_table(CREDENTIAL_STATE)
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    fn serialize_token(token: &Token) -> StoreResult<Vec<u8>> {
        token
            .to_cbor()
            .map_err(|e| StoreError::Serde(e.to_string()))
    }

    fn deserialize_token(bytes: &[u8]) -> StoreResult<Token> {
        Token::from_cbor(bytes).map_err(|e| StoreError::Serde(e.to_string()))
    }

    fn serialize_op(op: &Operation) -> StoreResult<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(op, &mut buf).map_err(|e| StoreError::Serde(e.to_string()))?;
        Ok(buf)
    }

    fn deserialize_op(bytes: &[u8]) -> StoreResult<Operation> {
        ciborium::from_reader(bytes).map_err(|e| StoreError::Serde(e.to_string()))
    }
}

impl TokenStore for RedbBackend {
    fn put_token(&mut self, token: &Token) -> StoreResult<()> {
        let bytes = Self::serialize_token(token)?;
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TOKENS)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .insert(token.payload.jti.as_str(), bytes.as_slice())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_token(&self, jti: &str) -> StoreResult<Token> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(TOKENS)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let guard = table
            .get(jti)
            .map_err(|e| StoreError::Io(e.to_string()))?
            .ok_or_else(|| StoreError::NotFound(jti.to_string()))?;
        Self::deserialize_token(guard.value())
    }

    fn delete_token(&mut self, jti: &str) -> StoreResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(TOKENS)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .remove(jti)
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn has_token(&self, jti: &str) -> bool {
        self.get_token(jti).is_ok()
    }

    fn list_tokens(&self, kind: Option<TokenKind>) -> StoreResult<Vec<String>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(TOKENS)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut result = Vec::new();
        for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
            let (key, value) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            match kind {
                None => result.push(key.value().to_string()),
                Some(k) => {
                    let token = Self::deserialize_token(value.value())?;
                    if token.payload.kind == k {
                        result.push(key.value().to_string());
                    }
                }
            }
        }
        Ok(result)
    }

    fn count_tokens(&self, kind: Option<TokenKind>) -> StoreResult<usize> {
        self.list_tokens(kind).map(|v| v.len())
    }
}

impl RevocationStore for RedbBackend {
    fn revoke(&mut self, jti: &str) -> StoreResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(REVOKED)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .insert(jti, &[] as &[u8])
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn is_revoked(&self, jti: &str) -> bool {
        let Ok(read_txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = read_txn.open_table(REVOKED) else {
            return false;
        };
        table.get(jti).ok().flatten().is_some()
    }

    fn burn(&mut self, urn: &str) -> StoreResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(BURNED)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .insert(urn, &[] as &[u8])
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn is_burned(&self, urn: &str) -> bool {
        let Ok(read_txn) = self.db.begin_read() else {
            return false;
        };
        let Ok(table) = read_txn.open_table(BURNED) else {
            return false;
        };
        table.get(urn).ok().flatten().is_some()
    }

    fn revoked_set(&self) -> StoreResult<BTreeSet<String>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(REVOKED)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut set = BTreeSet::new();
        for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
            let (key, _) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            set.insert(key.value().to_string());
        }
        Ok(set)
    }

    fn burned_set(&self) -> StoreResult<BTreeSet<String>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(BURNED)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut set = BTreeSet::new();
        for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
            let (key, _) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            set.insert(key.value().to_string());
        }
        Ok(set)
    }
}

impl OperationStore for RedbBackend {
    fn put_operation(&mut self, op: &Operation) -> StoreResult<bool> {
        if self.has_operation(&op.id) {
            return Ok(false);
        }
        let bytes = Self::serialize_op(op)?;
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(OPERATIONS)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .insert(op.id.as_str(), bytes.as_slice())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(true)
    }

    fn get_operation(&self, id: &str) -> StoreResult<Operation> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(OPERATIONS)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let guard = table
            .get(id)
            .map_err(|e| StoreError::Io(e.to_string()))?
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        Self::deserialize_op(guard.value())
    }

    fn has_operation(&self, id: &str) -> bool {
        self.get_operation(id).is_ok()
    }

    fn operation_ids(&self) -> StoreResult<BTreeSet<String>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(OPERATIONS)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut set = BTreeSet::new();
        for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
            let (key, _) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            set.insert(key.value().to_string());
        }
        Ok(set)
    }

    fn count_operations(&self) -> StoreResult<usize> {
        self.operation_ids().map(|s| s.len())
    }

    fn missing_operations(&self, remote_ids: &BTreeSet<String>) -> StoreResult<Vec<String>> {
        let local = self.operation_ids()?;
        Ok(remote_ids.difference(&local).cloned().collect())
    }
}
impl AuditStore for RedbBackend {
    fn append_audit_entry(&mut self, entry: &AuditLogEntry) -> StoreResult<()> {
        let mut buf = Vec::new();
        ciborium::into_writer(entry, &mut buf).map_err(|e| StoreError::Serde(e.to_string()))?;

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(AUDIT_LOG)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            // **L-12 (security review)**: enforce the hash chain
            // inside the same write transaction so a chain-break is
            // either atomically rejected or the append is atomic.
            let next_id = table.len().unwrap_or(0);
            if next_id > 0 {
                // Fetch the last entry (highest id).
                let last_bytes = table
                    .get(next_id - 1)
                    .map_err(|e| StoreError::Io(e.to_string()))?
                    .ok_or_else(|| StoreError::Io("missing last audit entry".into()))?;
                let last: AuditLogEntry = ciborium::from_reader(last_bytes.value())
                    .map_err(|e| StoreError::Serde(format!("prev audit decode: {e}")))?;
                let expected = last
                    .chain_hash()
                    .map_err(|e| StoreError::Serde(format!("prev chain_hash: {e}")))?;
                if entry.prev_hash != expected {
                    return Err(StoreError::Serde(format!(
                        "audit chain break: entry prev_hash does not match last entry's \
                         chain_hash (expected {} bytes, got {} bytes)",
                        expected.len(),
                        entry.prev_hash.len()
                    )));
                }
            } else if !entry.prev_hash.is_empty() {
                return Err(StoreError::Serde(
                    "audit chain break: first entry must have empty prev_hash".into(),
                ));
            }
            table
                .insert(next_id, buf.as_slice())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn list_audit_entries(&self) -> StoreResult<Vec<AuditLogEntry>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(AUDIT_LOG)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut result = Vec::new();
        for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
            let (_, value) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            let audit_entry: AuditLogEntry = ciborium::from_reader(value.value())
                .map_err(|e| StoreError::Serde(e.to_string()))?;
            result.push(audit_entry);
        }
        Ok(result)
    }

    fn count_audit_entries(&self) -> StoreResult<usize> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(AUDIT_LOG)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(table.len().unwrap_or(0) as usize)
    }

    fn prune_audit_entries_before(&mut self, before_timestamp: u64) -> StoreResult<usize> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut removed = 0usize;
        {
            let mut table = write_txn
                .open_table(AUDIT_LOG)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            // Collect keys to remove (iterate, then delete)
            let mut keys_to_remove = Vec::new();
            for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
                let (key, value) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
                if let Ok(audit_entry) = ciborium::from_reader::<AuditLogEntry, _>(value.value()) {
                    if audit_entry.timestamp < before_timestamp {
                        keys_to_remove.push(key.value());
                    }
                } else {
                    keys_to_remove.push(key.value()); // remove corrupt
                }
            }
            for key in &keys_to_remove {
                let _ = table
                    .remove(key)
                    .map_err(|e| StoreError::Io(e.to_string()))?;
                removed += 1;
            }
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(removed)
    }

    fn prune_audit_entries_to_max(&mut self, max_entries: usize) -> StoreResult<usize> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut removed = 0usize;
        {
            let mut table = write_txn
                .open_table(AUDIT_LOG)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let count = table.len().unwrap_or(0) as usize;
            if count > max_entries {
                let to_remove = count - max_entries;
                // Keys are sequential u64, so remove the smallest ones
                let mut keys_to_remove = Vec::new();
                for entry in table.iter().map_err(|e| StoreError::Io(e.to_string()))? {
                    if keys_to_remove.len() >= to_remove {
                        break;
                    }
                    let (key, _) = entry.map_err(|e| StoreError::Io(e.to_string()))?;
                    keys_to_remove.push(key.value());
                }
                for key in &keys_to_remove {
                    let _ = table
                        .remove(key)
                        .map_err(|e| StoreError::Io(e.to_string()))?;
                    removed += 1;
                }
            }
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(removed)
    }
}

impl ChallengeStore for RedbBackend {
    fn put_challenge(&mut self, id: &str, bytes: &[u8; 32], expires_at: u64) -> StoreResult<()> {
        // Value: 8-byte expires_at (big-endian) || 32-byte nonce
        let mut value = [0u8; 40];
        value[..8].copy_from_slice(&expires_at.to_be_bytes());
        value[8..].copy_from_slice(bytes);

        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CHALLENGES)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .insert(id, value.as_slice())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn consume_challenge(&mut self, id: &str, now: u64) -> StoreResult<[u8; 32]> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        // Outer Result lets us delete an expired row in the same write-txn
        // before returning the expiry error (B-5).
        let outcome: Result<[u8; 32], StoreError> = {
            let mut table = write_txn
                .open_table(CHALLENGES)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let encoded: Vec<u8> = {
                let guard = table
                    .get(id)
                    .map_err(|e| StoreError::Io(e.to_string()))?
                    .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
                guard.value().to_vec()
            };
            if encoded.len() < 40 {
                // Treat malformed rows like expired ones — drop them so a
                // probe contributes to cleanup.
                let _ = table.remove(id);
                Err(StoreError::Serde("challenge record too short".into()))
            } else {
                let expires_at = u64::from_be_bytes(encoded[..8].try_into().unwrap());
                if now >= expires_at {
                    // B-5: delete the expired row inside the same transaction.
                    table
                        .remove(id)
                        .map_err(|e| StoreError::Io(e.to_string()))?;
                    Err(StoreError::Io(format!(
                        "challenge '{}' has expired (expired at {expires_at}, now {now})",
                        id
                    )))
                } else {
                    let mut nonce = [0u8; 32];
                    nonce.copy_from_slice(&encoded[8..40]);
                    table
                        .remove(id)
                        .map_err(|e| StoreError::Io(e.to_string()))?;
                    Ok(nonce)
                }
            }
        };
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        outcome
    }

    fn sweep_expired_challenges(&mut self, now: u64) -> StoreResult<usize> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let count = {
            let mut table = write_txn
                .open_table(CHALLENGES)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let expired: Vec<String> = table
                .iter()
                .map_err(|e| StoreError::Io(e.to_string()))?
                .filter_map(|entry| {
                    let (key, value) = entry.ok()?;
                    let raw = value.value();
                    if raw.len() < 8 {
                        return Some(key.value().to_string());
                    }
                    let expires_at = u64::from_be_bytes(raw[..8].try_into().ok()?);
                    if now >= expires_at {
                        Some(key.value().to_string())
                    } else {
                        None
                    }
                })
                .collect();
            let n = expired.len();
            for id in &expired {
                table
                    .remove(id.as_str())
                    .map_err(|e| StoreError::Io(e.to_string()))?;
            }
            n
        };
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(count)
    }

    fn count_challenges(&self) -> StoreResult<usize> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = match read_txn.open_table(CHALLENGES) {
            Ok(t) => t,
            // No challenges have ever been written; treat as empty.
            Err(_) => return Ok(0),
        };
        Ok(table.len().unwrap_or(0) as usize)
    }
}

impl CredentialStateStore for RedbBackend {
    fn get_sign_count(&self, credential_id: &str) -> StoreResult<Option<u32>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let table = read_txn
            .open_table(CREDENTIAL_STATE)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        match table
            .get(credential_id)
            .map_err(|e| StoreError::Io(e.to_string()))?
        {
            None => Ok(None),
            Some(guard) => {
                let raw = guard.value();
                if raw.len() < 4 {
                    return Err(StoreError::Serde(
                        "credential_state record too short".into(),
                    ));
                }
                Ok(Some(u32::from_be_bytes(raw[..4].try_into().unwrap())))
            }
        }
    }

    fn set_sign_count(&mut self, credential_id: &str, count: u32) -> StoreResult<()> {
        let value = count.to_be_bytes();
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CREDENTIAL_STATE)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            table
                .insert(credential_id, value.as_slice())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    /// **L-18 (security review)**: perform the compare and the write
    /// inside a single write transaction. redb serializes write
    /// transactions, so two concurrent callers cannot both observe
    /// the pre-bump stored value and each commit their own update.
    fn bump_sign_count(&mut self, credential_id: &str, new_count: u32) -> StoreResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let (stored, should_write) = {
            let table = write_txn
                .open_table(CREDENTIAL_STATE)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let stored = match table
                .get(credential_id)
                .map_err(|e| StoreError::Io(e.to_string()))?
            {
                None => 0u32,
                Some(guard) => {
                    let raw = guard.value();
                    if raw.len() < 4 {
                        return Err(StoreError::Serde(
                            "credential_state record too short".into(),
                        ));
                    }
                    u32::from_be_bytes(raw[..4].try_into().unwrap())
                }
            };
            (stored, new_count > stored)
        };
        if !should_write {
            // Abort the write transaction without touching the table.
            // redb does not require an explicit abort — dropping the
            // txn is sufficient — but we do it explicitly for clarity.
            drop(write_txn);
            return Err(StoreError::SignCountReplay {
                stored,
                attempted: new_count,
            });
        }
        {
            let mut table = write_txn
                .open_table(CREDENTIAL_STATE)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            let value = new_count.to_be_bytes();
            table
                .insert(credential_id, value.as_slice())
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }
}

impl DirectoryStore for RedbBackend {}

#[cfg(test)]
mod l18_sign_count_tests {
    use super::*;
    use tempfile::TempDir;

    fn open_temp() -> (TempDir, RedbBackend) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.redb");
        let be = RedbBackend::open(&path).unwrap();
        (dir, be)
    }

    /// L-18: the redb backend performs the compare-and-write inside
    /// a single write transaction — this is what makes the primitive
    /// safe against the race the finding warns about. The test only
    /// exercises behaviour (true concurrency is in the mutex layer).
    #[test]
    fn bump_sign_count_redb_behaviour() {
        let (_dir, mut be) = open_temp();

        be.bump_sign_count("cred-x", 10).unwrap();
        assert_eq!(be.get_sign_count("cred-x").unwrap(), Some(10));

        be.bump_sign_count("cred-x", 11).unwrap();
        assert_eq!(be.get_sign_count("cred-x").unwrap(), Some(11));

        let err = be.bump_sign_count("cred-x", 11).unwrap_err();
        assert!(matches!(
            err,
            StoreError::SignCountReplay {
                stored: 11,
                attempted: 11
            }
        ));
        assert_eq!(be.get_sign_count("cred-x").unwrap(), Some(11));

        assert!(matches!(
            be.bump_sign_count("cred-x", 5),
            Err(StoreError::SignCountReplay {
                stored: 11,
                attempted: 5
            })
        ));
        assert_eq!(be.get_sign_count("cred-x").unwrap(), Some(11));
    }
}

#[cfg(test)]
mod b5_challenge_cleanup_tests {
    use super::*;
    use tempfile::TempDir;

    fn open_temp() -> (TempDir, RedbBackend) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.redb");
        let be = RedbBackend::open(&path).unwrap();
        (dir, be)
    }

    /// B-5: `consume_challenge` on an expired row removes it so the
    /// table cannot accumulate rows when callers probe stale ids.
    #[test]
    fn consume_expired_drops_row() {
        let (_dir, mut be) = open_temp();
        be.put_challenge("c1", &[7u8; 32], 100).unwrap();
        assert_eq!(be.count_challenges().unwrap(), 1);

        let err = be.consume_challenge("c1", 200).unwrap_err();
        assert!(matches!(err, StoreError::Io(_)));
        assert_eq!(be.count_challenges().unwrap(), 0);

        // A second probe of the same id is now a plain NotFound.
        let err2 = be.consume_challenge("c1", 200).unwrap_err();
        assert!(matches!(err2, StoreError::NotFound(_)));
    }

    /// B-5: `count_challenges` reflects live rows on a fresh DB and
    /// after sweep / consume.
    #[test]
    fn count_and_sweep_track_outstanding() {
        let (_dir, mut be) = open_temp();
        // Empty table → CHALLENGES has never been written; count is 0.
        assert_eq!(be.count_challenges().unwrap(), 0);

        be.put_challenge("a", &[1u8; 32], 100).unwrap();
        be.put_challenge("b", &[2u8; 32], 200).unwrap();
        be.put_challenge("c", &[3u8; 32], 300).unwrap();
        assert_eq!(be.count_challenges().unwrap(), 3);

        let removed = be.sweep_expired_challenges(150).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(be.count_challenges().unwrap(), 2);

        let nonce = be.consume_challenge("b", 150).unwrap();
        assert_eq!(nonce, [2u8; 32]);
        assert_eq!(be.count_challenges().unwrap(), 1);
    }
}
