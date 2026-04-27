//! In-memory storage backend.
//!
//! Used for unit tests and embedded/RTOS deployments where
//! persistent storage is not available or not needed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    /// (nonce_bytes, expires_at)
    challenges: HashMap<String, ([u8; 32], u64)>,
    credential_sign_counts: HashMap<String, u32>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            tokens: BTreeMap::new(),
            revoked: BTreeSet::new(),
            burned: BTreeSet::new(),
            operations: BTreeMap::new(),
            audit_log: Vec::new(),
            challenges: HashMap::new(),
            credential_sign_counts: HashMap::new(),
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
        // **L-12 (security review)**: enforce the hash chain on
        // append. The first entry must have an empty `prev_hash`;
        // every subsequent entry's `prev_hash` must equal the
        // previous entry's `chain_hash`. Breaking the chain here
        // surfaces as a `StoreError::Serde` so the caller can log
        // the forensic event and refuse to persist corrupted state.
        if let Some(last_bytes) = self.audit_log.last() {
            let last: AuditLogEntry = ciborium::from_reader(last_bytes.as_slice())
                .map_err(|e| StoreError::Serde(format!("prev audit decode: {e}")))?;
            let expected = last
                .chain_hash()
                .map_err(|e| StoreError::Serde(format!("prev chain_hash: {e}")))?;
            if entry.prev_hash != expected {
                return Err(StoreError::Serde(format!(
                    "audit chain break: entry prev_hash does not match last entry's chain_hash \
                     (expected {} bytes, got {} bytes)",
                    expected.len(),
                    entry.prev_hash.len()
                )));
            }
        } else if !entry.prev_hash.is_empty() {
            return Err(StoreError::Serde(
                "audit chain break: first entry must have empty prev_hash".into(),
            ));
        }
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

    fn count_audit_entries(&self) -> StoreResult<usize> {
        Ok(self.audit_log.len())
    }

    fn prune_audit_entries_before(&mut self, before_timestamp: u64) -> StoreResult<usize> {
        let before_len = self.audit_log.len();
        self.audit_log.retain(|bytes| {
            if let Ok(entry) = ciborium::from_reader::<AuditLogEntry, _>(bytes.as_slice()) {
                entry.timestamp >= before_timestamp
            } else {
                false
            }
        });
        Ok(before_len - self.audit_log.len())
    }

    fn prune_audit_entries_to_max(&mut self, max_entries: usize) -> StoreResult<usize> {
        if self.audit_log.len() <= max_entries {
            return Ok(0);
        }
        let remove_count = self.audit_log.len() - max_entries;
        self.audit_log.drain(..remove_count);
        Ok(remove_count)
    }
}
impl ChallengeStore for MemoryBackend {
    fn put_challenge(&mut self, id: &str, bytes: &[u8; 32], expires_at: u64) -> StoreResult<()> {
        self.challenges.insert(id.to_string(), (*bytes, expires_at));
        Ok(())
    }

    fn consume_challenge(&mut self, id: &str, now: u64) -> StoreResult<[u8; 32]> {
        let (nonce, expires_at) = self
            .challenges
            .get(id)
            .copied()
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        if now >= expires_at {
            // B-5: delete the expired row so a probe of a stale id helps clean
            // up rather than leaving the entry to accumulate.
            self.challenges.remove(id);
            return Err(StoreError::Io(format!(
                "challenge '{}' has expired (expired at {expires_at}, now {now})",
                id
            )));
        }
        self.challenges.remove(id);
        Ok(nonce)
    }

    fn sweep_expired_challenges(&mut self, now: u64) -> StoreResult<usize> {
        let before = self.challenges.len();
        self.challenges.retain(|_, (_, exp)| now < *exp);
        Ok(before - self.challenges.len())
    }

    fn count_challenges(&self) -> StoreResult<usize> {
        Ok(self.challenges.len())
    }
}

impl CredentialStateStore for MemoryBackend {
    fn get_sign_count(&self, credential_id: &str) -> StoreResult<Option<u32>> {
        Ok(self.credential_sign_counts.get(credential_id).copied())
    }

    fn set_sign_count(&mut self, credential_id: &str, count: u32) -> StoreResult<()> {
        self.credential_sign_counts
            .insert(credential_id.to_string(), count);
        Ok(())
    }
}

impl DirectoryStore for MemoryBackend {}

impl StoreSizeStats for MemoryBackend {
    /// In-memory backend has no persistent file layout, so the
    /// "stored bytes" notion is not directly meaningful (heap allocator
    /// overhead would be the real answer, but exposing that would couple
    /// metric values to allocator state in unhelpful ways). We return an
    /// empty map so the metrics renderer emits the family's `# HELP` /
    /// `# TYPE` headers without any series — the catalog stays
    /// discoverable and an operator scraping a memory-backed harness
    /// sees zero series rather than misleading numbers.
    fn table_stored_bytes(&self) -> StoreResult<std::collections::BTreeMap<&'static str, u64>> {
        Ok(std::collections::BTreeMap::new())
    }
}

#[cfg(test)]
mod l18_sign_count_tests {
    use super::*;

    /// L-18: `bump_sign_count` must accept a strictly-greater value
    /// and reject anything else, atomically from the caller's point
    /// of view.
    #[test]
    fn bump_sign_count_memory_behaviour() {
        let mut be = MemoryBackend::new();

        // First bump from 0 → 5 succeeds; state visible.
        be.bump_sign_count("cred-a", 5).unwrap();
        assert_eq!(be.get_sign_count("cred-a").unwrap(), Some(5));

        // Strictly greater → accepted.
        be.bump_sign_count("cred-a", 6).unwrap();
        assert_eq!(be.get_sign_count("cred-a").unwrap(), Some(6));

        // Equal → rejected, state unchanged.
        let err = be.bump_sign_count("cred-a", 6).unwrap_err();
        match err {
            StoreError::SignCountReplay { stored, attempted } => {
                assert_eq!(stored, 6);
                assert_eq!(attempted, 6);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(be.get_sign_count("cred-a").unwrap(), Some(6));

        // Less-than → rejected.
        assert!(matches!(
            be.bump_sign_count("cred-a", 2),
            Err(StoreError::SignCountReplay {
                stored: 6,
                attempted: 2
            })
        ));

        // Separate credentials don't interfere.
        be.bump_sign_count("cred-b", 1).unwrap();
        assert_eq!(be.get_sign_count("cred-b").unwrap(), Some(1));
    }
}

#[cfg(test)]
mod b5_challenge_cleanup_tests {
    use super::*;

    /// B-5: `consume_challenge` on an expired row removes it so the
    /// table doesn't leak rows when callers probe stale ids.
    #[test]
    fn consume_expired_drops_row() {
        let mut be = MemoryBackend::new();
        be.put_challenge("c1", &[7u8; 32], 100).unwrap();
        assert_eq!(be.count_challenges().unwrap(), 1);

        // now > expires_at — consume returns Err but row is dropped.
        let err = be.consume_challenge("c1", 200).unwrap_err();
        assert!(matches!(err, StoreError::Io(_)));
        assert_eq!(be.count_challenges().unwrap(), 0);
    }

    /// B-5: `count_challenges` reflects live rows; `sweep_expired_challenges`
    /// drops expired ones and leaves valid ones intact.
    #[test]
    fn sweep_and_count_track_outstanding() {
        let mut be = MemoryBackend::new();
        be.put_challenge("a", &[1u8; 32], 100).unwrap();
        be.put_challenge("b", &[2u8; 32], 200).unwrap();
        be.put_challenge("c", &[3u8; 32], 300).unwrap();
        assert_eq!(be.count_challenges().unwrap(), 3);

        // now=150 expires only "a".
        let removed = be.sweep_expired_challenges(150).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(be.count_challenges().unwrap(), 2);

        // Successful consume of a live row also drops it.
        let nonce = be.consume_challenge("b", 150).unwrap();
        assert_eq!(nonce, [2u8; 32]);
        assert_eq!(be.count_challenges().unwrap(), 1);
    }
}
