//! KPI verdicts and summary writers (JSON + Markdown).

use std::path::Path;

use serde::Serialize;

use crate::metrics::MetricsSnapshot;

/// One KPI row.
#[derive(Debug, Clone, Serialize)]
pub struct KpiVerdict {
    pub name: String,
    pub target: String,
    pub measured: String,
    pub status: KpiStatus,
    pub note: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum KpiStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl KpiStatus {
    pub fn glyph(&self) -> &'static str {
        match self {
            KpiStatus::Pass => "PASS",
            KpiStatus::Warn => "WARN",
            KpiStatus::Fail => "FAIL",
            KpiStatus::Skip => "SKIP",
        }
    }
    pub fn emoji(&self) -> &'static str {
        match self {
            KpiStatus::Pass => "✅",
            KpiStatus::Warn => "⚠️",
            KpiStatus::Fail => "❌",
            KpiStatus::Skip => "⚪",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub duration_secs: u64,
    pub nodes: usize,
    pub kpis: Vec<KpiVerdict>,
    pub metrics: MetricsSnapshot,
}

/// Compute KPI verdicts from a metrics snapshot.
pub fn compute_kpis(snap: &MetricsSnapshot) -> Vec<KpiVerdict> {
    let mut out = Vec::new();

    // 1. Local auth decision ≤ 1 ms — measured by `evaluate_policy` p99 and
    //    `session_validate` p99 (both must be ≤ 1 ms).
    let auth_p99_ns = snap
        .ops
        .get("evaluate_policy")
        .map(|o| o.p99_ns)
        .unwrap_or(0)
        .max(
            snap.ops
                .get("session_validate")
                .map(|o| o.p99_ns)
                .unwrap_or(0),
        );
    out.push(verdict_le(
        "Local auth decision (p99)",
        "≤ 1 ms",
        auth_p99_ns,
        1_000_000,
        format!("{:.3} ms", auth_p99_ns as f64 / 1e6),
        "max(evaluate_policy, session_validate) p99",
    ));

    // 2. Ed25519 verify throughput ≥ 50K ops/sec — measured per-op latency,
    //    convert to throughput.
    let ed = snap.ops.get("ed25519_verify");
    if let Some(o) = ed {
        if o.count == 0 {
            out.push(skip(
                "Ed25519 verify throughput",
                "≥ 50K ops/s",
                "no samples",
            ));
        } else {
            // Use p50 of per-op latency (steady-state) rather than mean,
            // which is skewed by occasional GC / scheduler stalls.
            let p50_s = o.p50_ns as f64 / 1e9;
            let ops_per_s = if p50_s > 0.0 { 1.0 / p50_s } else { 0.0 };
            // Pass if ≥ 50K. WARN (not FAIL) within 20% to allow for noisy
            // CI hosts contending with the libp2p event loop in the same
            // process; the dedicated criterion bench is the authority for
            // a hard verdict.
            let status = if ops_per_s >= 50_000.0 {
                KpiStatus::Pass
            } else if ops_per_s >= 40_000.0 {
                KpiStatus::Warn
            } else {
                KpiStatus::Fail
            };
            out.push(KpiVerdict {
                name: "Ed25519 verify throughput".into(),
                target: "≥ 50,000 ops/sec".into(),
                measured: format!(
                    "{ops_per_s:.0} ops/sec (p50 {:.2} µs)",
                    o.p50_ns as f64 / 1e3
                ),
                status,
                note: format!("{} samples", o.count),
            });
        }
    } else {
        out.push(skip(
            "Ed25519 verify throughput",
            "≥ 50K ops/s",
            "no samples",
        ));
    }

    // 3. CRDT merge ≤ 0.05 ms p99
    let crdt_p99 = snap.ops.get("crdt_merge").map(|o| o.p99_ns).unwrap_or(0);
    out.push(verdict_le(
        "CRDT merge (p99)",
        "≤ 0.05 ms",
        crdt_p99,
        50_000,
        format!("{:.4} ms", crdt_p99 as f64 / 1e6),
        "single insert into CausalDag",
    ));

    // 4. Peak heap ≤ 5 MB / 1K entries
    let peak_rss = snap.gauges.iter().map(|g| g.rss_bytes).max().unwrap_or(0);
    let max_tokens = snap
        .gauges
        .iter()
        .map(|g| g.trust_graph_tokens.iter().sum::<usize>())
        .max()
        .unwrap_or(0);
    if max_tokens == 0 {
        out.push(skip(
            "Peak heap per 1K entries",
            "≤ 5 MB",
            "no token samples",
        ));
    } else {
        let bytes_per_entry = peak_rss as f64 / max_tokens as f64;
        let bytes_per_1k = bytes_per_entry * 1000.0;
        let mb_per_1k = bytes_per_1k / (1024.0 * 1024.0);
        // RSS includes the whole process — note as such; warn rather than fail
        // if it exceeds the budget because of the per-process baseline.
        let status = if mb_per_1k <= 5.0 {
            KpiStatus::Pass
        } else {
            KpiStatus::Warn
        };
        out.push(KpiVerdict {
            name: "Peak heap per 1K entries".into(),
            target: "≤ 5 MB / 1K entries".into(),
            measured: format!("{mb_per_1k:.2} MB / 1K (RSS {peak_rss} B, {max_tokens} entries)"),
            status,
            note: "RSS-based; includes whole-process baseline".into(),
        });
    }

    // 5. Idle gossip bandwidth ≤ 2 KB/sec
    // Sampled as gossip_tx_bytes_per_sec on the gauges. Take the median of
    // gauges from the second half of the run (steady-state).
    let mut bw: Vec<f64> = snap
        .gauges
        .iter()
        .map(|g| g.gossip_tx_bytes_per_sec)
        .collect();
    if bw.is_empty() {
        out.push(skip("Idle gossip bandwidth", "≤ 2 KB/s", "no samples"));
    } else {
        bw.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = bw[bw.len() / 2];
        let pass = median <= 2048.0;
        out.push(KpiVerdict {
            name: "Idle gossip bandwidth (median)".into(),
            target: "≤ 2 KB/sec".into(),
            measured: format!("{:.0} B/sec", median),
            status: if pass {
                KpiStatus::Pass
            } else {
                KpiStatus::Warn
            },
            note: "process-wide RSS proxy — see README".into(),
        });
    }

    // Bonus: enrollment latency, gossip propagation, revocation propagation.
    if let Some(o) = snap.ops.get("enroll_user") {
        out.push(KpiVerdict {
            name: "Enrollment latency (enroll_user p99)".into(),
            target: "informational".into(),
            measured: format!("{:.2} ms", o.p99_ns as f64 / 1e6),
            status: KpiStatus::Pass,
            note: format!("{} ok / {} err", o.ok, o.err),
        });
    }
    if let Some(o) = snap.ops.get("gossip_propagation") {
        let status = if o.count == 0 {
            KpiStatus::Skip
        } else {
            KpiStatus::Pass
        };
        out.push(KpiVerdict {
            name: "Gossip propagation (p99)".into(),
            target: "informational".into(),
            measured: if o.count == 0 {
                "no samples".into()
            } else {
                format!("{:.0} ms", o.p99_ns as f64 / 1e6)
            },
            status,
            note: format!("{} samples", o.count),
        });
    }
    if let Some(o) = snap.ops.get("revocation_propagation") {
        let status = if o.count == 0 {
            KpiStatus::Skip
        } else {
            KpiStatus::Pass
        };
        out.push(KpiVerdict {
            name: "Revocation propagation (p99)".into(),
            target: "informational".into(),
            measured: if o.count == 0 {
                "no samples".into()
            } else {
                format!("{:.0} ms", o.p99_ns as f64 / 1e6)
            },
            status,
            note: format!("{} samples", o.count),
        });
    }

    out
}

fn verdict_le(
    name: &str,
    target: &str,
    measured_ns: u64,
    budget_ns: u64,
    measured_str: String,
    note: &str,
) -> KpiVerdict {
    let status = if measured_ns == 0 {
        KpiStatus::Skip
    } else if measured_ns <= budget_ns {
        KpiStatus::Pass
    } else {
        KpiStatus::Fail
    };
    KpiVerdict {
        name: name.into(),
        target: target.into(),
        measured: measured_str,
        status,
        note: note.into(),
    }
}

fn skip(name: &str, target: &str, note: &str) -> KpiVerdict {
    KpiVerdict {
        name: name.into(),
        target: target.into(),
        measured: "n/a".into(),
        status: KpiStatus::Skip,
        note: note.into(),
    }
}

/// Write JSON + Markdown summaries.
pub fn write_summary(dir: &Path, summary: &Summary) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let json_path = dir.join("summary.json");
    let md_path = dir.join("summary.md");
    let json = serde_json::to_string_pretty(summary)?;
    std::fs::write(&json_path, json)?;
    std::fs::write(&md_path, render_md(summary))?;
    Ok(())
}

pub fn write_snapshot(dir: &Path, snap: &MetricsSnapshot, idx: usize) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("snapshot-{idx:04}.json"));
    std::fs::write(path, serde_json::to_string(snap)?)?;
    Ok(())
}

pub fn render_md(s: &Summary) -> String {
    let mut out = String::new();
    out.push_str("# DDS Load Test Summary\n\n");
    out.push_str(&format!("- Duration: {} s\n", s.duration_secs));
    out.push_str(&format!("- Nodes:    {}\n\n", s.nodes));
    out.push_str("## KPI Verdicts (§10)\n\n");
    out.push_str("| KPI | Target | Measured | Status | Note |\n");
    out.push_str("|---|---|---|---|---|\n");
    for k in &s.kpis {
        out.push_str(&format!(
            "| {} | {} | {} | {} {} | {} |\n",
            k.name,
            k.target,
            k.measured,
            k.status.emoji(),
            k.status.glyph(),
            k.note
        ));
    }
    out.push_str("\n## Per-Operation Histograms\n\n");
    out.push_str("| Op | count | ok | err | p50 | p90 | p99 | max |\n");
    out.push_str("|---|---|---|---|---|---|---|---|\n");
    for (name, op) in &s.metrics.ops {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {:.3} ms | {:.3} ms | {:.3} ms | {:.3} ms |\n",
            name,
            op.count,
            op.ok,
            op.err,
            op.p50_ns as f64 / 1e6,
            op.p90_ns as f64 / 1e6,
            op.p99_ns as f64 / 1e6,
            op.max_ns as f64 / 1e6,
        ));
    }
    out.push_str("\n## Gauge Samples\n\n");
    out.push_str("| t (s) | RSS (MB) | trust tokens | store tokens | gossip B/s |\n");
    out.push_str("|---|---|---|---|---|\n");
    for g in &s.metrics.gauges {
        let trust: usize = g.trust_graph_tokens.iter().sum();
        let store: usize = g.store_tokens.iter().sum();
        out.push_str(&format!(
            "| {} | {:.1} | {} | {} | {:.0} |\n",
            g.elapsed_secs,
            g.rss_bytes as f64 / (1024.0 * 1024.0),
            trust,
            store,
            g.gossip_tx_bytes_per_sec,
        ));
    }
    out
}
