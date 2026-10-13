//! Background token-expiry sweeper.
//!
//! Periodically scans the trust graph for tokens whose `exp` is in the
//! past, removes them from the trust graph, and marks them as revoked
//! in the store. Runs as a tokio task at a configurable interval
//! (`NodeConfig::expiry_scan_interval_secs`).

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dds_core::token::TokenKind;
use dds_core::trust::TrustGraph;
use dds_store::traits::{OperationStore, RevocationStore, TokenStore};
use tracing::{debug, info, warn};

/// Result of one sweep pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    pub scanned: usize,
    pub expired: usize,
}

/// Run a single expiry sweep.
///
/// `now` is the current epoch second. Any token in the trust graph whose
/// `exp` is `Some(t)` with `now > t` (i.e. `t < now`, strictly) will be
/// removed from the graph and marked revoked in the store. A token is
/// **not** swept when `exp == now`; only the next second (`now == exp + 1`)
/// triggers removal. This matches the `now > exp` convention used by
/// `token.rs`, `trust.rs`, and `domain.rs`. Tokens with no expiry are left
/// alone.
pub fn sweep_once<S>(graph: &mut TrustGraph, store: &mut S, now: u64) -> SweepStats
where
    S: TokenStore + RevocationStore,
{
    let entries = graph.token_expiries();
    let mut stats = SweepStats {
        scanned: entries.len(),
        expired: 0,
    };
    for (jti, exp) in entries {
        if let Some(exp_secs) = exp {
            if now > exp_secs {
                if graph.remove_token(&jti) {
                    stats.expired += 1;
                }
                if let Err(e) = store.revoke(&jti) {
                    warn!(jti = %jti, "expiry: failed to mark revoked in store: {e}");
                }
                debug!(jti = %jti, exp = exp_secs, "expired token swept");
            }
        }
    }
    if stats.expired > 0 {
        info!(
            scanned = stats.scanned,
            expired = stats.expired,
            "expiry sweep completed"
        );
    }
    stats
}

/// Result of one unanchored-identity prune pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PruneStats {
    /// Issuers examined.
    pub identities_scanned: usize,
    /// Issuers whose tokens were removed.
    pub identities_pruned: usize,
    /// JTIs removed from the graph and the store (their canonical
    /// `op-<jti>` operations were removed from the store as well). The
    /// caller drops them from its in-memory DAG and sync cache.
    pub pruned_jtis: Vec<String>,
}

/// Whether an identity's token set is of the kind the pruner may remove:
/// plain attestations, user-auth attestations and vouches. Any other
/// document type (device join, policy, software, account bindings, SSO
/// links, service principals, sessions, self-update) marks an identity
/// the pruner leaves alone — those are legitimately unvouched or are
/// gated elsewhere.
pub fn is_prunable_token(token: &dds_core::token::Token) -> bool {
    match token.payload.kind {
        TokenKind::Vouch => true,
        TokenKind::Attest => matches!(
            token.payload.body_type.as_deref(),
            None | Some(dds_domain::body_types::USER_AUTH_ATTESTATION)
        ),
        TokenKind::Revoke | TokenKind::Burn => false,
    }
}

/// **R1 (single-node review 2026-10-13)** — remove identities that have
/// been *unanchored* for longer than `ttl_secs`.
///
/// An identity is unanchored when it has no effective vouch — nobody with
/// a chain to a trusted root currently signs for it. That is the state a
/// throw-away identity minted by a hostile peer is in forever, and the
/// state a legitimately offboarded user enters when their vouch is
/// revoked or expires. The clock starts at
/// [`TrustGraph::unanchored_since`] (the identity's first own token, or
/// the loss of its last vouch, whichever is later), so an offboarded user
/// keeps their record for the full `ttl_secs` after the offboarding,
/// while an identity nobody ever vouched cannot postpone its own pruning
/// by issuing more tokens.
///
/// Never pruned: `trusted_roots`, anything in `protected` (the bootstrap
/// admin and this node's own identity), identities that are not purely
/// made of prunable tokens (see [`is_prunable_token`] — device-join
/// identities in particular), and identities with an effective vouch.
/// Burned identities lose their tokens like any other but stay in the
/// graph's burned set.
///
/// Every node evaluates the same rule on the same replicated data, so
/// nodes prune at (about) the same time; the matching ingest rule in
/// `dds-node::node` refuses tokens older than the TTL from an issuer no
/// vouch claims, so pruned material cannot return through anti-entropy
/// from a lagging peer.
pub fn prune_unanchored_once<S>(
    graph: &mut TrustGraph,
    store: &mut S,
    trusted_roots: &BTreeSet<String>,
    protected: &BTreeSet<String>,
    now: u64,
    ttl_secs: u64,
) -> PruneStats
where
    S: TokenStore + OperationStore,
{
    let mut stats = PruneStats::default();
    if ttl_secs == 0 {
        return stats;
    }
    let issuers = graph.issuers();
    stats.identities_scanned = issuers.len();
    for urn in issuers {
        if trusted_roots.contains(&urn) || protected.contains(&urn) {
            continue;
        }
        if graph.has_effective_vouch(&urn, trusted_roots) {
            continue;
        }
        let jtis: Vec<String> = {
            let tokens = graph.tokens_issued_by(&urn);
            if tokens.is_empty() || !tokens.iter().all(|t| is_prunable_token(t)) {
                continue;
            }
            tokens.iter().map(|t| t.payload.jti.clone()).collect()
        };
        let Some(since) = graph.unanchored_since(&urn) else {
            continue;
        };
        if now <= since.saturating_add(ttl_secs) {
            continue;
        }
        for jti in jtis {
            // Keep the revocation record (follow-up review 2026-10-13,
            // finding 1): a pruned token that had been revoked must stay
            // revoked, or a replayed copy would come back live. The
            // store keeps its revoked mark across `delete_token` for the
            // same reason, and both ingest paths refuse a revoked JTI.
            graph.remove_token_keep_revocation(&jti);
            if let Err(e) = store.delete_token(&jti) {
                warn!(jti = %jti, "prune: delete_token failed: {e}");
            }
            let op_id = dds_net::sync::canonical_op_id(&jti);
            if let Err(e) = store.delete_operation(&op_id) {
                warn!(op_id = %op_id, "prune: delete_operation failed: {e}");
            }
            stats.pruned_jtis.push(jti);
        }
        stats.identities_pruned += 1;
        debug!(identity = %urn, unanchored_since = since, "pruned unanchored identity");
    }
    if stats.identities_pruned > 0 {
        info!(
            scanned = stats.identities_scanned,
            identities = stats.identities_pruned,
            tokens = stats.pruned_jtis.len(),
            "unanchored-identity prune completed"
        );
    }
    stats
}

/// Long-running async loop that calls `sweep_once` every `interval`.
///
/// Intended to be spawned as a tokio task. Returns when cancelled.
pub async fn expiry_loop<F>(interval: Duration, mut sweep: F)
where
    F: FnMut(u64) + Send,
{
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick — we want to wait one interval
    // before the first sweep so callers can pre-populate the graph.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        sweep(now_epoch());
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dds_core::identity::Identity;
    use dds_core::token::{Token, TokenKind, TokenPayload};
    use dds_store::memory_backend::MemoryBackend;
    use rand::rngs::OsRng;

    fn make_token(label: &str, exp: Option<u64>) -> Token {
        let id = Identity::generate(label, &mut OsRng);
        let payload = TokenPayload {
            iss: id.id.to_urn(),
            iss_key: id.public_key.clone(),
            jti: format!("jti-{label}"),
            sub: id.id.to_urn(),
            kind: TokenKind::Attest,
            purpose: None,
            vch_iss: None,
            vch_sum: None,
            revokes: None,
            iat: 0,
            exp,
            body_type: None,
            body_cbor: None,
        };
        Token::sign(payload, &id.signing_key).unwrap()
    }

    #[test]
    fn test_sweep_removes_expired_only() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();

        let expired = make_token("expired", Some(100));
        let live = make_token("live", Some(4102444800));
        let no_exp = make_token("noexp", None);

        graph.add_token(expired.clone()).unwrap();
        graph.add_token(live.clone()).unwrap();
        graph.add_token(no_exp.clone()).unwrap();

        // Use current time so that token with exp=100 is expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stats = sweep_once(&mut graph, &mut store, now);
        assert_eq!(stats.scanned, 3);
        assert_eq!(stats.expired, 1);

        assert_eq!(graph.attestation_count(), 2);
        assert!(store.is_revoked(&expired.payload.jti));
        assert!(!store.is_revoked(&live.payload.jti));
        assert!(!store.is_revoked(&no_exp.payload.jti));
    }

    #[test]
    fn test_sweep_idempotent() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        graph.add_token(make_token("a", Some(1))).unwrap();
        let s1 = sweep_once(&mut graph, &mut store, 1000);
        assert_eq!(s1.expired, 1);
        let s2 = sweep_once(&mut graph, &mut store, 1000);
        assert_eq!(s2.expired, 0);
        assert_eq!(s2.scanned, 0);
    }

    #[test]
    fn test_sweep_not_expired_at_exact_boundary() {
        // Convention across the codebase: `now > exp` means expired.
        // A token is NOT swept when exp == now (only when exp < now).
        // This matches token.rs and trust.rs so test/production behaviour is consistent.
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        graph.add_token(make_token("boundary", Some(500))).unwrap();
        let s = sweep_once(&mut graph, &mut store, 500); // exp == now
        assert_eq!(s.expired, 0, "token at exp==now must NOT be swept");
        let s2 = sweep_once(&mut graph, &mut store, 501); // now > exp
        assert_eq!(s2.expired, 1, "token with now > exp must be swept");
    }

    #[test]
    fn test_sweep_nothing_to_do() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        graph
            .add_token(make_token("future", Some(1_000_000)))
            .unwrap();
        let s = sweep_once(&mut graph, &mut store, 100);
        assert_eq!(s.expired, 0);
        assert_eq!(s.scanned, 1);
    }

    // ---------- R1: unanchored-identity pruning ----------

    use dds_store::traits::OperationStore;
    use std::collections::BTreeSet;

    fn attest_at(id: &Identity, jti: &str, iat: u64, body_type: Option<&str>) -> Token {
        Token::sign(
            TokenPayload {
                iss: id.id.to_urn(),
                iss_key: id.public_key.clone(),
                jti: jti.into(),
                sub: id.id.to_urn(),
                kind: TokenKind::Attest,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat,
                exp: None,
                body_type: body_type.map(String::from),
                body_cbor: body_type.map(|_| vec![0xa0]),
            },
            &id.signing_key,
        )
        .unwrap()
    }

    fn vouch_at(
        voucher: &Identity,
        target: &Identity,
        target_tok: &Token,
        jti: &str,
        iat: u64,
    ) -> Token {
        Token::sign(
            TokenPayload {
                iss: voucher.id.to_urn(),
                iss_key: voucher.public_key.clone(),
                jti: jti.into(),
                sub: target.id.to_urn(),
                kind: TokenKind::Vouch,
                purpose: Some("dds:session".into()),
                vch_iss: Some(target.id.to_urn()),
                vch_sum: Some(target_tok.payload_hash()),
                revokes: None,
                iat,
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &voucher.signing_key,
        )
        .unwrap()
    }

    fn revoke_at(revoker: &Identity, target_jti: &str, jti: &str, iat: u64) -> Token {
        Token::sign(
            TokenPayload {
                iss: revoker.id.to_urn(),
                iss_key: revoker.public_key.clone(),
                jti: jti.into(),
                sub: revoker.id.to_urn(),
                kind: TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some(target_jti.into()),
                iat,
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &revoker.signing_key,
        )
        .unwrap()
    }

    /// Put a token in both the graph and the store, with its canonical op.
    fn land(graph: &mut TrustGraph, store: &mut MemoryBackend, t: &Token) {
        graph.add_token(t.clone()).unwrap();
        store.put_token(t).unwrap();
        store
            .put_operation(&dds_core::crdt::causal_dag::Operation {
                id: dds_net::sync::canonical_op_id(&t.payload.jti),
                author: t.payload.iss.clone(),
                deps: vec![],
                data: vec![],
                timestamp: 0,
            })
            .unwrap();
    }

    const DAY: u64 = 86_400;

    #[test]
    fn prune_removes_only_old_unanchored_identities() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        let root = Identity::generate("root", &mut OsRng);
        let roots: BTreeSet<String> = [root.id.to_urn()].into_iter().collect();
        let protected: BTreeSet<String> = BTreeSet::new();

        let ghost = Identity::generate("ghost", &mut OsRng); // never vouched, old
        let fresh = Identity::generate("fresh", &mut OsRng); // never vouched, recent
        let user = Identity::generate("user", &mut OsRng); // vouched by root
        let device = Identity::generate("device", &mut OsRng); // device-join, never vouched

        let t0 = 1_000_000u64;
        land(
            &mut graph,
            &mut store,
            &attest_at(&ghost, "a-ghost", t0, None),
        );
        land(
            &mut graph,
            &mut store,
            &attest_at(&fresh, "a-fresh", t0 + 40 * DAY, None),
        );
        let user_tok = attest_at(&user, "a-user", t0, None);
        land(&mut graph, &mut store, &user_tok);
        land(
            &mut graph,
            &mut store,
            &vouch_at(&root, &user, &user_tok, "v-user", t0),
        );
        land(
            &mut graph,
            &mut store,
            &attest_at(
                &device,
                "a-device",
                t0,
                Some(dds_domain::body_types::DEVICE_JOIN),
            ),
        );
        // The root's own attestation is config-anchored, never pruned.
        land(
            &mut graph,
            &mut store,
            &attest_at(&root, "a-root", t0, None),
        );

        let now = t0 + 45 * DAY;
        let stats =
            prune_unanchored_once(&mut graph, &mut store, &roots, &protected, now, 30 * DAY);
        assert_eq!(stats.identities_pruned, 1, "{stats:?}");
        assert_eq!(stats.pruned_jtis, vec!["a-ghost".to_string()]);
        assert!(!graph.knows_issuer(&ghost.id.to_urn()));
        assert!(!store.has_token("a-ghost"));
        assert!(!store.has_operation("op-a-ghost"));
        for kept in ["a-fresh", "a-user", "v-user", "a-device", "a-root"] {
            assert!(store.has_token(kept), "{kept} must survive");
        }
        assert!(graph.knows_issuer(&fresh.id.to_urn()));
        assert!(graph.knows_issuer(&device.id.to_urn()));

        // Disabled TTL is a no-op.
        let off = prune_unanchored_once(&mut graph, &mut store, &roots, &protected, now + DAY, 0);
        assert_eq!(off, PruneStats::default());
    }

    #[test]
    fn offboarded_user_is_kept_for_ttl_after_the_revocation_then_pruned() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        let root = Identity::generate("root", &mut OsRng);
        let roots: BTreeSet<String> = [root.id.to_urn()].into_iter().collect();
        let protected = BTreeSet::new();
        let user = Identity::generate("user", &mut OsRng);
        let t0 = 1_000_000u64;
        let user_tok = attest_at(&user, "a-user", t0, None);
        land(&mut graph, &mut store, &user_tok);
        land(
            &mut graph,
            &mut store,
            &vouch_at(&root, &user, &user_tok, "v-user", t0),
        );
        // Offboarded a year later.
        let t_revoke = t0 + 365 * DAY;
        land(
            &mut graph,
            &mut store,
            &revoke_at(&root, "v-user", "r-user", t_revoke),
        );

        // 20 days after revocation: inside the TTL measured from the
        // revocation, even though the enrollment is >1 year old.
        let s = prune_unanchored_once(
            &mut graph,
            &mut store,
            &roots,
            &protected,
            t_revoke + 20 * DAY,
            30 * DAY,
        );
        assert_eq!(s.identities_pruned, 0);
        assert!(store.has_token("a-user"));

        // 31 days after: pruned. The root's revoke token is not an
        // issuer token of the user and stays.
        let s = prune_unanchored_once(
            &mut graph,
            &mut store,
            &roots,
            &protected,
            t_revoke + 31 * DAY,
            30 * DAY,
        );
        assert_eq!(s.identities_pruned, 1);
        assert!(!store.has_token("a-user"));
        assert!(store.has_token("r-user"));
    }

    /// **Follow-up review (2026-10-13), finding 1.** Pruning a revoked
    /// token must not undo its revocation: the graph keeps the record,
    /// the store keeps its mark, and a replayed copy re-enters revoked.
    #[test]
    fn prune_keeps_revocation_records_so_a_replayed_token_stays_revoked() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        let roots: BTreeSet<String> = BTreeSet::new();
        let protected = BTreeSet::new();
        let user = Identity::generate("user", &mut OsRng);
        let t0 = 1_000_000u64;
        let user_tok = attest_at(&user, "a-user", t0, None);
        land(&mut graph, &mut store, &user_tok);
        // The user revokes its own attestation (the only authorized
        // revoker); the node's apply path also marks the store.
        land(
            &mut graph,
            &mut store,
            &revoke_at(&user, "a-user", "r-user", t0 + DAY),
        );
        store.revoke("a-user").unwrap();
        assert!(graph.is_revoked("a-user"));

        let s = prune_unanchored_once(
            &mut graph,
            &mut store,
            &roots,
            &protected,
            t0 + 31 * DAY,
            30 * DAY,
        );
        assert_eq!(s.identities_pruned, 1);
        assert_eq!(s.pruned_jtis, vec!["a-user".to_string()]);
        assert!(!store.has_token("a-user"));
        assert!(
            graph.has_revocation_record("a-user"),
            "record survives the prune"
        );
        assert!(graph.is_revoked("a-user"));
        assert!(
            store.is_revoked("a-user"),
            "store mark survives delete_token"
        );

        // Replay: the graph takes the token back only as a revoked one.
        graph.add_token(user_tok).unwrap();
        assert!(graph.is_revoked("a-user"));
    }

    /// **Follow-up review (2026-10-13), finding 3.** An identity nobody
    /// vouches cannot keep itself alive by issuing a new token every day:
    /// the clock runs from its first token.
    #[test]
    fn continuous_issuance_does_not_postpone_pruning() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        let roots: BTreeSet<String> = BTreeSet::new();
        let protected = BTreeSet::new();
        let ghost = Identity::generate("ghost", &mut OsRng);
        let t0 = 1_000_000u64;
        for day in 0..40u64 {
            land(
                &mut graph,
                &mut store,
                &attest_at(&ghost, &format!("a-ghost-{day}"), t0 + day * DAY, None),
            );
        }
        let s = prune_unanchored_once(
            &mut graph,
            &mut store,
            &roots,
            &protected,
            t0 + 40 * DAY,
            30 * DAY,
        );
        assert_eq!(s.identities_pruned, 1, "{s:?}");
        assert_eq!(s.pruned_jtis.len(), 40);
        assert!(!graph.knows_issuer(&ghost.id.to_urn()));
    }

    #[test]
    fn protected_identities_and_burned_set_survive_pruning() {
        let mut graph = TrustGraph::new();
        let mut store = MemoryBackend::new();
        let roots: BTreeSet<String> = BTreeSet::new();
        let node_id = Identity::generate("node", &mut OsRng);
        let protected: BTreeSet<String> = [node_id.id.to_urn()].into_iter().collect();
        let burned = Identity::generate("burned", &mut OsRng);
        let t0 = 1_000_000u64;
        land(
            &mut graph,
            &mut store,
            &attest_at(&node_id, "a-node", t0, None),
        );
        land(
            &mut graph,
            &mut store,
            &attest_at(&burned, "a-burned", t0, None),
        );
        let burn = Token::sign(
            TokenPayload {
                iss: burned.id.to_urn(),
                iss_key: burned.public_key.clone(),
                jti: "b-burned".into(),
                sub: burned.id.to_urn(),
                kind: TokenKind::Burn,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: None,
                iat: t0 + 1,
                exp: None,
                body_type: None,
                body_cbor: None,
            },
            &burned.signing_key,
        )
        .unwrap();
        graph.add_token(burn.clone()).unwrap();
        store.put_token(&burn).unwrap();

        let s = prune_unanchored_once(
            &mut graph,
            &mut store,
            &roots,
            &protected,
            t0 + 60 * DAY,
            30 * DAY,
        );
        assert_eq!(s.identities_pruned, 1);
        assert!(
            store.has_token("a-node"),
            "protected node identity survives"
        );
        assert!(
            !store.has_token("a-burned"),
            "burned identity's tokens are pruned"
        );
        assert!(graph.is_burned(&burned.id.to_urn()), "…but it stays burned");
    }

    #[tokio::test(start_paused = true)]
    async fn test_expiry_loop_runs_periodically() {
        use std::sync::{Arc, Mutex};
        let count = Arc::new(Mutex::new(0u32));
        let count_c = count.clone();
        let handle = tokio::spawn(async move {
            expiry_loop(Duration::from_secs(1), move |_now| {
                *count_c.lock().unwrap() += 1;
            })
            .await;
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.abort();
        let n = *count.lock().unwrap();
        // Should have ticked roughly 4 times (initial tick is consumed).
        assert!(n >= 3, "expected at least 3 ticks, got {n}");
    }
}
