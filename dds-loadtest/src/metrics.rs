//! Latency histograms, counters, and gauge samples.
//!
//! Hot paths take a parking_lot-style mutex via `std::sync::Mutex`.
//! Histograms are recorded in nanoseconds for crypto / sub-µs ops and
//! microseconds for end-to-end ops; the unit is documented per-op.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;
use serde::Serialize;

/// Names of all tracked operation histograms.
pub const OP_NAMES: &[&str] = &[
    "enroll_user",
    "enroll_device",
    "issue_session",
    "evaluate_policy",
    "session_validate",
    "ed25519_verify",
    "crdt_merge",
    "gossip_propagation",
    "revocation_propagation",
];

/// Per-op histogram + error/op counter pair.
pub struct OpStats {
    /// nanoseconds.
    pub hist: Histogram<u64>,
    pub ok: u64,
    pub err: u64,
}

impl OpStats {
    fn new() -> Self {
        // Up to 60 s in ns, 3 sig figs.
        Self {
            hist: Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).expect("hist bounds"),
            ok: 0,
            err: 0,
        }
    }
}

/// Snapshot of one gauge sample taken every 30s.
#[derive(Debug, Clone, Serialize)]
pub struct GaugeSample {
    pub elapsed_secs: u64,
    pub rss_bytes: u64,
    pub trust_graph_tokens: Vec<usize>,
    pub store_tokens: Vec<usize>,
    pub gossip_tx_bytes_per_sec: f64,
}

#[derive(Default)]
pub struct Metrics {
    inner: Mutex<MetricsInner>,
    pub start: std::sync::OnceLock<std::time::Instant>,
}

struct MetricsInner {
    ops: BTreeMap<String, OpStats>,
    gauges: Vec<GaugeSample>,
}

impl Default for MetricsInner {
    fn default() -> Self {
        let mut ops = BTreeMap::new();
        for n in OP_NAMES {
            ops.insert((*n).to_string(), OpStats::new());
        }
        Self {
            ops,
            gauges: Vec::new(),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        let m = Self::default();
        let _ = m.start.set(std::time::Instant::now());
        m
    }

    pub fn record(&self, op: &str, dur: Duration, ok: bool) {
        let nanos = dur.as_nanos().min(u64::MAX as u128) as u64;
        let mut g = self.inner.lock().expect("metrics poisoned");
        let entry = g.ops.entry(op.to_string()).or_insert_with(OpStats::new);
        // hdrhistogram rejects 0 — clamp.
        let _ = entry.hist.record(nanos.max(1));
        if ok {
            entry.ok += 1;
        } else {
            entry.err += 1;
        }
    }

    pub fn record_gauge(&self, sample: GaugeSample) {
        let mut g = self.inner.lock().expect("metrics poisoned");
        g.gauges.push(sample);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let g = self.inner.lock().expect("metrics poisoned");
        let mut ops = BTreeMap::new();
        for (k, v) in g.ops.iter() {
            ops.insert(
                k.clone(),
                OpSnapshot {
                    count: v.ok + v.err,
                    ok: v.ok,
                    err: v.err,
                    p50_ns: v.hist.value_at_quantile(0.50),
                    p90_ns: v.hist.value_at_quantile(0.90),
                    p99_ns: v.hist.value_at_quantile(0.99),
                    max_ns: v.hist.max(),
                    mean_ns: v.hist.mean() as u64,
                },
            );
        }
        MetricsSnapshot {
            generated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            ops,
            gauges: g.gauges.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OpSnapshot {
    pub count: u64,
    pub ok: u64,
    pub err: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub mean_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub generated_at: u64,
    pub ops: BTreeMap<String, OpSnapshot>,
    pub gauges: Vec<GaugeSample>,
}
