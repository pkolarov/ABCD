//! Delta-sync protocol for efficient state convergence.
//!
//! When two nodes connect or reconnect:
//! 1. Exchange state summaries (operation count + head hashes)
//! 2. If different, exchange operation ID sets
//! 3. Transfer missing operations in topological order
//! 4. Validate and CRDT-merge each received operation
//!
//! This module defines the sync messages and the state-machine logic.
//! Transport is handled by the gossip/transport layers.

use std::collections::BTreeSet;

use dds_core::crdt::causal_dag::{CausalDag, DagError, Operation};
use dds_core::token::{Token, TokenKind};
use dds_store::traits::{DirectoryStore, StoreError};
use serde::{Deserialize, Serialize};

/// A state summary exchanged at the beginning of a sync session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateSummary {
    /// Total number of operations in the local DAG.
    pub op_count: usize,
    /// Set of current DAG head operation IDs.
    pub heads: BTreeSet<String>,
    /// Number of revoked JTIs.
    pub revocation_count: usize,
    /// Number of burned URNs.
    pub burn_count: usize,
}

/// Messages in the sync protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    /// Step 1: Exchange state summaries.
    Summary(StateSummary),
    /// Step 2: Send the full set of operation IDs.
    OperationIds(BTreeSet<String>),
    /// Step 3: Request specific operations by ID.
    RequestOps(Vec<String>),
    /// Step 4: Send operations (CBOR-encoded).
    SendOps(Vec<SyncPayload>),
    /// Sync complete acknowledgement.
    Done,
}

/// A single operation + its backing token, sent during sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPayload {
    /// CBOR-encoded Operation.
    pub op_bytes: Vec<u8>,
    /// CBOR-encoded Token backing this operation.
    pub token_bytes: Vec<u8>,
}

impl SyncMessage {
    /// Serialize to CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }

    /// Deserialize from CBOR.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| e.to_string())
    }
}

/// Build a state summary from the local store and DAG.
pub fn build_summary(
    dag: &CausalDag,
    store: &dyn DirectoryStore,
) -> Result<StateSummary, StoreError> {
    Ok(StateSummary {
        op_count: dag.len(),
        heads: dag.heads().clone(),
        revocation_count: store.revoked_set()?.len(),
        burn_count: store.burned_set()?.len(),
    })
}

/// Determine which operations we need from a remote peer.
///
/// Returns the list of operation IDs that the remote has but we don't.
pub fn compute_missing_ops(
    local_ids: &BTreeSet<String>,
    remote_ids: &BTreeSet<String>,
) -> Vec<String> {
    remote_ids.difference(local_ids).cloned().collect()
}

/// Result of applying a sync payload.
#[derive(Debug, Default)]
pub struct SyncResult {
    /// Number of new operations merged into the DAG.
    pub ops_merged: usize,
    /// Number of new tokens stored.
    pub tokens_stored: usize,
    /// Number of new revocations applied.
    pub revocations_applied: usize,
    /// Number of new burns applied.
    pub burns_applied: usize,
    /// Errors encountered (non-fatal — processing continues).
    pub errors: Vec<String>,
}

/// Apply received sync payloads to the local state.
///
/// For each payload:
/// 1. Deserialize and validate the token
/// 2. Store the token
/// 3. Handle revocations/burns
/// 4. Insert the operation into the DAG
///
/// Operations are sorted topologically before insertion so that
/// dependencies are satisfied.
pub fn apply_sync_payloads(
    payloads: &[SyncPayload],
    dag: &mut CausalDag,
    store: &mut dyn DirectoryStore,
) -> SyncResult {
    let mut result = SyncResult::default();

    // Phase 1: Deserialize all payloads
    let mut items: Vec<(Operation, Token)> = Vec::new();
    for payload in payloads {
        let op: Operation = match ciborium::from_reader(payload.op_bytes.as_slice()) {
            Ok(op) => op,
            Err(e) => {
                result.errors.push(format!("op deserialize: {e}"));
                continue;
            }
        };
        let token = match Token::from_cbor(&payload.token_bytes) {
            Ok(t) => t,
            Err(e) => {
                result.errors.push(format!("token deserialize: {e}"));
                continue;
            }
        };

        // Validate token signature and issuer binding
        if let Err(e) = token.validate() {
            result.errors.push(format!("token validation: {e}"));
            continue;
        }

        items.push((op, token));
    }

    // Phase 2: Process tokens (revocations/burns first for safety)
    // Sort: Burns first, then Revocations, then everything else
    items.sort_by_key(|(_, t)| match t.payload.kind {
        TokenKind::Burn => 0,
        TokenKind::Revoke => 1,
        TokenKind::Attest => 2,
        TokenKind::Vouch => 3,
    });

    for (op, token) in &items {
        // Store the token
        match store.put_token(token) {
            Ok(()) => result.tokens_stored += 1,
            Err(e) => {
                result.errors.push(format!("token store: {e}"));
                continue;
            }
        }

        // Handle revocations and burns
        match token.payload.kind {
            TokenKind::Revoke => {
                if let Some(ref target_jti) = token.payload.revokes {
                    if !store.is_revoked(target_jti) {
                        if let Err(e) = store.revoke(target_jti) {
                            result.errors.push(format!("revoke: {e}"));
                        } else {
                            result.revocations_applied += 1;
                        }
                    }
                }
            }
            TokenKind::Burn => {
                let urn = &token.payload.iss;
                if !store.is_burned(urn) {
                    if let Err(e) = store.burn(urn) {
                        result.errors.push(format!("burn: {e}"));
                    } else {
                        result.burns_applied += 1;
                    }
                }
            }
            _ => {}
        }

        // Insert operation into DAG
        match dag.insert(op.clone()) {
            Ok(true) => result.ops_merged += 1,
            Ok(false) => {} // duplicate, skip
            Err(DagError::MissingDependency(_)) => {
                // Will retry in topological sort pass below
            }
        }
    }

    // Phase 3: Retry any operations that failed due to missing deps
    // (they may now be satisfied after other ops were inserted)
    let mut retry: Vec<&Operation> = items
        .iter()
        .filter(|(op, _)| !dag.contains(&op.id))
        .map(|(op, _)| op)
        .collect();

    let mut progress = true;
    while progress && !retry.is_empty() {
        progress = false;
        let mut remaining = Vec::new();
        for op in retry {
            match dag.insert(op.clone()) {
                Ok(true) => {
                    result.ops_merged += 1;
                    progress = true;
                }
                Ok(false) => {}
                Err(_) => remaining.push(op),
            }
        }
        retry = remaining;
    }

    if !retry.is_empty() {
        result.errors.push(format!(
            "{} ops could not be merged (missing deps)",
            retry.len()
        ));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dds_core::crdt::causal_dag::Operation;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_store::traits::{RevocationStore, TokenStore};
    use dds_store::MemoryBackend;
    use rand::rngs::OsRng;

    fn make_identity(label: &str) -> Identity {
        Identity::generate(label, &mut OsRng)
    }

    fn make_attest_token(ident: &Identity) -> Token {
        Token::sign(
            TokenPayload {
                iss: ident.id.to_urn(),
                iss_key: ident.public_key.clone(),
                jti: format!("attest-{}", ident.id.label()),
                sub: ident.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: Some("test".to_string()),
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 1000,
                exp: Some(9999),
                body_type: None, body_cbor: None,
            },
            &ident.signing_key,
        )
        .unwrap()
    }

    fn make_op(id: &str, deps: Vec<&str>) -> Operation {
        Operation {
            id: id.to_string(),
            author: "test".to_string(),
            deps: deps.into_iter().map(String::from).collect(),
            data: vec![],
            timestamp: 42,
        }
    }

    fn serialize_op(op: &Operation) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(op, &mut buf).unwrap();
        buf
    }

    #[test]
    fn test_state_summary() {
        let mut dag = CausalDag::new();
        dag.insert(make_op("a", vec![])).unwrap();
        dag.insert(make_op("b", vec!["a"])).unwrap();

        let mut store = MemoryBackend::new();
        store.revoke("r1").unwrap();
        store.burn("urn:x").unwrap();

        let summary = build_summary(&dag, &store).unwrap();
        assert_eq!(summary.op_count, 2);
        assert_eq!(summary.heads.len(), 1);
        assert!(summary.heads.contains("b"));
        assert_eq!(summary.revocation_count, 1);
        assert_eq!(summary.burn_count, 1);
    }

    #[test]
    fn test_compute_missing_ops() {
        let local: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let remote: BTreeSet<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let missing = compute_missing_ops(&local, &remote);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"c".to_string()));
        assert!(missing.contains(&"d".to_string()));
    }

    #[test]
    fn test_compute_missing_ops_identical() {
        let local: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let missing = compute_missing_ops(&local, &local);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_sync_message_cbor_roundtrip() {
        let msg = SyncMessage::Summary(StateSummary {
            op_count: 5,
            heads: ["h1".to_string()].into_iter().collect(),
            revocation_count: 1,
            burn_count: 0,
        });
        let encoded = msg.to_cbor().unwrap();
        let decoded = SyncMessage::from_cbor(&encoded).unwrap();
        assert!(matches!(decoded, SyncMessage::Summary(s) if s.op_count == 5));
    }

    #[test]
    fn test_apply_sync_payloads_basic() {
        let ident = make_identity("alice");
        let token = make_attest_token(&ident);
        let op = make_op("op-1", vec![]);

        let payload = SyncPayload {
            op_bytes: serialize_op(&op),
            token_bytes: token.to_cbor().unwrap(),
        };

        let mut dag = CausalDag::new();
        let mut store = MemoryBackend::new();

        let result = apply_sync_payloads(&[payload], &mut dag, &mut store);
        assert_eq!(result.ops_merged, 1);
        assert_eq!(result.tokens_stored, 1);
        assert!(result.errors.is_empty());
        assert!(dag.contains("op-1"));
        assert!(store.has_token(&format!("attest-{}", ident.id.label())));
    }

    #[test]
    fn test_apply_sync_payloads_with_revocation() {
        let admin = make_identity("admin");
        let revoke_token = Token::sign(
            TokenPayload {
                iss: admin.id.to_urn(),
                iss_key: admin.public_key.clone(),
                jti: "revoke-1".to_string(),
                sub: "target".to_string(),
                kind: TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some("vouch-1".to_string()),
                iat: 2000,
                exp: None,
                body_type: None, body_cbor: None,
            },
            &admin.signing_key,
        )
        .unwrap();

        let op = make_op("op-revoke", vec![]);
        let payload = SyncPayload {
            op_bytes: serialize_op(&op),
            token_bytes: revoke_token.to_cbor().unwrap(),
        };

        let mut dag = CausalDag::new();
        let mut store = MemoryBackend::new();

        let result = apply_sync_payloads(&[payload], &mut dag, &mut store);
        assert_eq!(result.revocations_applied, 1);
        assert!(store.is_revoked("vouch-1"));
    }

    #[test]
    fn test_apply_sync_payloads_with_burn() {
        let user = make_identity("burned-user");
        let burn_token = Token::sign(
            TokenPayload {
                iss: user.id.to_urn(),
                iss_key: user.public_key.clone(),
                jti: "burn-1".to_string(),
                sub: user.id.to_urn(),
                kind: TokenKind::Burn,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: 2000,
                exp: None,
                body_type: None, body_cbor: None,
            },
            &user.signing_key,
        )
        .unwrap();

        let op = make_op("op-burn", vec![]);
        let payload = SyncPayload {
            op_bytes: serialize_op(&op),
            token_bytes: burn_token.to_cbor().unwrap(),
        };

        let mut dag = CausalDag::new();
        let mut store = MemoryBackend::new();

        let result = apply_sync_payloads(&[payload], &mut dag, &mut store);
        assert_eq!(result.burns_applied, 1);
        assert!(store.is_burned(&user.id.to_urn()));
    }

    #[test]
    fn test_apply_sync_payloads_invalid_token() {
        let op = make_op("op-bad", vec![]);
        let payload = SyncPayload {
            op_bytes: serialize_op(&op),
            token_bytes: vec![0xff, 0xfe], // invalid CBOR
        };

        let mut dag = CausalDag::new();
        let mut store = MemoryBackend::new();

        let result = apply_sync_payloads(&[payload], &mut dag, &mut store);
        assert_eq!(result.ops_merged, 0);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_apply_sync_payloads_topological_order() {
        let ident = make_identity("alice");
        let token = make_attest_token(&ident);

        // Send ops in reverse order — b depends on a, but b comes first
        let op_a = make_op("a", vec![]);
        let op_b = make_op("b", vec!["a"]);

        let payloads = vec![
            SyncPayload {
                op_bytes: serialize_op(&op_b),
                token_bytes: token.to_cbor().unwrap(),
            },
            SyncPayload {
                op_bytes: serialize_op(&op_a),
                token_bytes: token.to_cbor().unwrap(),
            },
        ];

        let mut dag = CausalDag::new();
        let mut store = MemoryBackend::new();

        let result = apply_sync_payloads(&payloads, &mut dag, &mut store);
        assert_eq!(result.ops_merged, 2);
        assert!(dag.contains("a"));
        assert!(dag.contains("b"));
        assert!(result.errors.is_empty());
    }
}
