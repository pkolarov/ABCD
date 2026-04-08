//! Background token-expiry sweeper.
//!
//! Periodically scans the trust graph for tokens whose `exp` is in the
//! past, removes them from the trust graph, and marks them as revoked
//! in the store. Runs as a tokio task at a configurable interval
//! (`NodeConfig::expiry_scan_interval_secs`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dds_core::trust::TrustGraph;
use dds_store::traits::{RevocationStore, TokenStore};
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
/// `exp` is `Some(t)` with `t <= now` will be removed from the graph and
/// marked revoked in the store. Tokens with no expiry are left alone.
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
            if exp_secs <= now {
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
