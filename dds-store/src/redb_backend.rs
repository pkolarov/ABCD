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
        let db = Database::create(path).map_err(|e| StoreError::Io(e.to_string()))?;

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
            let next_id = table.len().unwrap_or(0);
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
        let result = {
            let mut table = write_txn
                .open_table(CHALLENGES)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            // Copy raw bytes out before any mutable operation on the table.
            let encoded: Vec<u8> = {
                let guard = table
                    .get(id)
                    .map_err(|e| StoreError::Io(e.to_string()))?
                    .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
                guard.value().to_vec()
            };
            if encoded.len() < 40 {
                return Err(StoreError::Serde("challenge record too short".into()));
            }
            let expires_at = u64::from_be_bytes(encoded[..8].try_into().unwrap());
            if now >= expires_at {
                return Err(StoreError::Io(format!(
                    "challenge '{}' has expired (expired at {expires_at}, now {now})",
                    id
                )));
            }
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&encoded[8..40]);
            table
                .remove(id)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            nonce
        };
        write_txn
            .commit()
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(result)
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
}

impl DirectoryStore for RedbBackend {}
