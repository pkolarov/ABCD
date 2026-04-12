//! In-memory storage backend.
//!
//! Used for unit tests and embedded/RTOS deployments where
//! persistent storage is not available or not needed.

use std::collections::{BTreeMap, BTreeSet};

use dds_core::audit::AuditLogEntry;
use dds_core::crdt::causal_dag::Operation;
use dds_core::token::{Token, TokenKind};

use crate::traits::*;

/// In-memory storage backend. All data lives in heap-allocated collections.
#[derive(Debug)]
pub struct MemoryBackend {
    tokens: BTreeMap<String, Vec<u8>>,
    revoked: BTreeSet<String>,
    burned: BTreeSet<String>,
    operations: BTreeMap<String, Vec<u8>>,
    audit_log: Vec<Vec<u8>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            tokens: BTreeMap::new(),
            revoked: BTreeSet::new(),
            burned: BTreeSet::new(),
            operations: BTreeMap::new(),
            audit_log: Vec::new(),
        }
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

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore for MemoryBackend {
    fn put_token(&mut self, token: &Token) -> StoreResult<()> {
        let bytes = Self::serialize_token(token)?;
        self.tokens.insert(token.payload.jti.clone(), bytes);
        Ok(())
    }

    fn get_token(&self, jti: &str) -> StoreResult<Token> {
        let bytes = self
            .tokens
            .get(jti)
            .ok_or_else(|| StoreError::NotFound(jti.to_string()))?;
        Self::deserialize_token(bytes)
    }

    fn delete_token(&mut self, jti: &str) -> StoreResult<()> {
        self.tokens.remove(jti);
        Ok(())
    }

    fn has_token(&self, jti: &str) -> bool {
        self.tokens.contains_key(jti)
    }

    fn list_tokens(&self, kind: Option<TokenKind>) -> StoreResult<Vec<String>> {
        match kind {
            None => Ok(self.tokens.keys().cloned().collect()),
            Some(k) => {
                let mut result = Vec::new();
                for (jti, bytes) in &self.tokens {
                    let token = Self::deserialize_token(bytes)?;
                    if token.payload.kind == k {
                        result.push(jti.clone());
                    }
                }
                Ok(result)
            }
        }
    }

    fn count_tokens(&self, kind: Option<TokenKind>) -> StoreResult<usize> {
        self.list_tokens(kind).map(|v| v.len())
    }
}

impl RevocationStore for MemoryBackend {
    fn revoke(&mut self, jti: &str) -> StoreResult<()> {
        self.revoked.insert(jti.to_string());
        Ok(())
    }

    fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains(jti)
    }

    fn burn(&mut self, urn: &str) -> StoreResult<()> {
        self.burned.insert(urn.to_string());
        Ok(())
    }

    fn is_burned(&self, urn: &str) -> bool {
        self.burned.contains(urn)
    }

    fn revoked_set(&self) -> StoreResult<BTreeSet<String>> {
        Ok(self.revoked.clone())
    }

    fn burned_set(&self) -> StoreResult<BTreeSet<String>> {
        Ok(self.burned.clone())
    }
}

impl OperationStore for MemoryBackend {
    fn put_operation(&mut self, op: &Operation) -> StoreResult<bool> {
        if self.operations.contains_key(&op.id) {
            return Ok(false);
        }
        let bytes = Self::serialize_op(op)?;
        self.operations.insert(op.id.clone(), bytes);
        Ok(true)
    }

    fn get_operation(&self, id: &str) -> StoreResult<Operation> {
        let bytes = self
            .operations
            .get(id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        Self::deserialize_op(bytes)
    }

    fn has_operation(&self, id: &str) -> bool {
        self.operations.contains_key(id)
    }

    fn operation_ids(&self) -> StoreResult<BTreeSet<String>> {
        Ok(self.operations.keys().cloned().collect())
    }

    fn count_operations(&self) -> StoreResult<usize> {
        Ok(self.operations.len())
    }

    fn missing_operations(&self, remote_ids: &BTreeSet<String>) -> StoreResult<Vec<String>> {
        Ok(remote_ids
            .iter()
            .filter(|id| !self.operations.contains_key(*id))
            .cloned()
            .collect())
    }
}

impl AuditStore for MemoryBackend {
    fn append_audit_entry(&mut self, entry: &AuditLogEntry) -> StoreResult<()> {
        let mut buf = Vec::new();
        ciborium::into_writer(entry, &mut buf).map_err(|e| StoreError::Serde(e.to_string()))?;
        self.audit_log.push(buf);
        Ok(())
    }

    fn list_audit_entries(&self) -> StoreResult<Vec<AuditLogEntry>> {
        self.audit_log
            .iter()
            .map(|bytes| {
                ciborium::from_reader(bytes.as_slice())
                    .map_err(|e| StoreError::Serde(e.to_string()))
            })
            .collect()
    }
}
impl DirectoryStore for MemoryBackend {}
