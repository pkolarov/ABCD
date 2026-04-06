//! redb storage backend.
//!
//! Persistent, ACID-compliant key-value store using redb.
//! Stores directory entries, CRDT state, operation log, and revocation sets.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};

use dds_core::crdt::causal_dag::Operation;
use dds_core::token::{Token, TokenKind};

use crate::traits::*;

// Table definitions
const TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("tokens");
const REVOKED: TableDefinition<&str, &[u8]> = TableDefinition::new("revoked");
const BURNED: TableDefinition<&str, &[u8]> = TableDefinition::new("burned");
const OPERATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("operations");

/// redb-backed persistent storage.
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

impl DirectoryStore for RedbBackend {}
