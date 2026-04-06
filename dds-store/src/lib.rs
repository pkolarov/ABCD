//! # dds-store
//!
//! Storage layer for the Decentralized Directory Service.
//!
//! Provides a trait-based storage abstraction with implementations:
//! - [`RedbBackend`](redb_backend::RedbBackend) — Persistent storage via redb (ACID, pure Rust)
//! - [`MemoryBackend`](memory_backend::MemoryBackend) — In-memory storage for tests and embedded devices

pub mod memory_backend;
pub mod redb_backend;
pub mod traits;

pub use memory_backend::MemoryBackend;
pub use redb_backend::RedbBackend;
pub use traits::*;

#[cfg(test)]
mod tests {
    use super::*;
    use dds_core::crdt::causal_dag::Operation;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use rand::rngs::OsRng;
    use std::collections::BTreeSet;

    fn make_test_token(label: &str, kind: TokenKind) -> (Identity, Token) {
        let ident = Identity::generate(label, &mut OsRng);
        let payload = TokenPayload {
            iss: ident.id.to_urn(),
            iss_key: ident.public_key.clone(),
            jti: format!("jti-{label}"),
            sub: format!("sub-{label}"),
            kind,
            purpose: Some("test".to_string()),
            vch_iss: if kind == TokenKind::Vouch {
                Some("urn:vouchsafe:target.hash".to_string())
            } else {
                None
            },
            vch_sum: if kind == TokenKind::Vouch {
                Some("fakehash".to_string())
            } else {
                None
            },
            revokes: if kind == TokenKind::Revoke {
                Some("target-jti".to_string())
            } else {
                None
            },
            iat: 1000,
            exp: if matches!(kind, TokenKind::Revoke | TokenKind::Burn) {
                None
            } else {
                Some(9999)
            },
            body_type: None, body_cbor: None,
        };
        let token = Token::sign(payload, &ident.signing_key).unwrap();
        (ident, token)
    }

    fn make_test_op(id: &str, deps: Vec<&str>) -> Operation {
        Operation {
            id: id.to_string(),
            author: "test-author".to_string(),
            deps: deps.into_iter().map(String::from).collect(),
            data: vec![1, 2, 3],
            timestamp: 42,
        }
    }

    // ---- Generic test functions that work on any DirectoryStore impl ----

    fn test_token_crud(store: &mut dyn DirectoryStore) {
        let (_, token) = make_test_token("alice", TokenKind::Attest);
        store.put_token(&token).unwrap();
        assert!(store.has_token("jti-alice"));
        let retrieved = store.get_token("jti-alice").unwrap();
        assert_eq!(retrieved.payload.jti, "jti-alice");
        assert_eq!(retrieved.payload.kind, TokenKind::Attest);

        store.delete_token("jti-alice").unwrap();
        assert!(!store.has_token("jti-alice"));
    }

    fn test_token_list_filter(store: &mut dyn DirectoryStore) {
        let (_, t1) = make_test_token("a1", TokenKind::Attest);
        let (_, t2) = make_test_token("v1", TokenKind::Vouch);
        store.put_token(&t1).unwrap();
        store.put_token(&t2).unwrap();

        let all = store.list_tokens(None).unwrap();
        assert_eq!(all.len(), 2);
        let attests = store.list_tokens(Some(TokenKind::Attest)).unwrap();
        assert_eq!(attests.len(), 1);
        assert_eq!(attests[0], "jti-a1");
        let vouches = store.list_tokens(Some(TokenKind::Vouch)).unwrap();
        assert_eq!(vouches.len(), 1);
        assert_eq!(vouches[0], "jti-v1");

        assert_eq!(store.count_tokens(None).unwrap(), 2);
        assert_eq!(store.count_tokens(Some(TokenKind::Attest)).unwrap(), 1);
    }

    fn test_revocation(store: &mut dyn DirectoryStore) {
        assert!(!store.is_revoked("jti-1"));
        store.revoke("jti-1").unwrap();
        assert!(store.is_revoked("jti-1"));

        let set = store.revoked_set().unwrap();
        assert!(set.contains("jti-1"));
    }

    fn test_burn(store: &mut dyn DirectoryStore) {
        assert!(!store.is_burned("urn:vouchsafe:alice.hash"));
        store.burn("urn:vouchsafe:alice.hash").unwrap();
        assert!(store.is_burned("urn:vouchsafe:alice.hash"));

        let set = store.burned_set().unwrap();
        assert!(set.contains("urn:vouchsafe:alice.hash"));
    }

    fn test_operations(store: &mut dyn DirectoryStore) {
        let op1 = make_test_op("op-1", vec![]);
        let op2 = make_test_op("op-2", vec![]);

        assert!(store.put_operation(&op1).unwrap()); // new
        assert!(!store.put_operation(&op1).unwrap()); // duplicate
        assert!(store.put_operation(&op2).unwrap());

        assert!(store.has_operation("op-1"));
        assert!(!store.has_operation("op-999"));

        let retrieved = store.get_operation("op-1").unwrap();
        assert_eq!(retrieved.id, "op-1");
        assert_eq!(retrieved.data, vec![1, 2, 3]);

        assert_eq!(store.count_operations().unwrap(), 2);

        let ids = store.operation_ids().unwrap();
        assert!(ids.contains("op-1"));
        assert!(ids.contains("op-2"));
    }

    fn test_missing_operations(store: &mut dyn DirectoryStore) {
        let op1 = make_test_op("op-a", vec![]);
        store.put_operation(&op1).unwrap();

        let mut remote = BTreeSet::new();
        remote.insert("op-a".to_string());
        remote.insert("op-b".to_string());
        remote.insert("op-c".to_string());

        let missing = store.missing_operations(&remote).unwrap();
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"op-b".to_string()));
        assert!(missing.contains(&"op-c".to_string()));
    }

    fn test_not_found(store: &mut dyn DirectoryStore) {
        let result = store.get_token("nonexistent");
        assert!(result.is_err());
        let result = store.get_operation("nonexistent");
        assert!(result.is_err());
    }

    // ---- MemoryBackend tests ----

    #[test]
    fn memory_token_crud() {
        test_token_crud(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_token_list_filter() {
        test_token_list_filter(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_revocation() {
        test_revocation(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_burn() {
        test_burn(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_operations() {
        test_operations(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_missing_operations() {
        test_missing_operations(&mut MemoryBackend::new());
    }

    #[test]
    fn memory_not_found() {
        test_not_found(&mut MemoryBackend::new());
    }

    // ---- RedbBackend tests ----

    fn make_redb() -> (RedbBackend, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");
        let backend = RedbBackend::open(&db_path).unwrap();
        (backend, dir) // dir must live as long as the test
    }

    #[test]
    fn redb_token_crud() {
        let (mut store, _dir) = make_redb();
        test_token_crud(&mut store);
    }

    #[test]
    fn redb_token_list_filter() {
        let (mut store, _dir) = make_redb();
        test_token_list_filter(&mut store);
    }

    #[test]
    fn redb_revocation() {
        let (mut store, _dir) = make_redb();
        test_revocation(&mut store);
    }

    #[test]
    fn redb_burn() {
        let (mut store, _dir) = make_redb();
        test_burn(&mut store);
    }

    #[test]
    fn redb_operations() {
        let (mut store, _dir) = make_redb();
        test_operations(&mut store);
    }

    #[test]
    fn redb_missing_operations() {
        let (mut store, _dir) = make_redb();
        test_missing_operations(&mut store);
    }

    #[test]
    fn redb_not_found() {
        let (mut store, _dir) = make_redb();
        test_not_found(&mut store);
    }

    #[test]
    fn redb_persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("persist.redb");

        // Write
        {
            let mut store = RedbBackend::open(&db_path).unwrap();
            let (_, token) = make_test_token("persist-test", TokenKind::Attest);
            store.put_token(&token).unwrap();
            store.revoke("some-jti").unwrap();
            store.burn("urn:vouchsafe:dead.hash").unwrap();
            let op = make_test_op("persistent-op", vec![]);
            store.put_operation(&op).unwrap();
        }

        // Re-open and verify
        {
            let store = RedbBackend::open(&db_path).unwrap();
            assert!(store.has_token("jti-persist-test"));
            assert!(store.is_revoked("some-jti"));
            assert!(store.is_burned("urn:vouchsafe:dead.hash"));
            assert!(store.has_operation("persistent-op"));
        }
    }
}
