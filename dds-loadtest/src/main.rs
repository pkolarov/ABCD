//! DDS load/soak harness — multi-node in-process driver.
//!
//! See `README.md` for the workload, KPI mapping, and how to run a 24h
//! soak. This binary is a measurement tool, not production code.

mod harness;
mod metrics;
mod report;
mod workload;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
#[command(name = "dds-loadtest", about = "DDS multinode load/soak harness")]
pub struct Cli {
    /// Number of in-process nodes to spin up.
    #[arg(long, default_value_t = 5)]
    pub nodes: usize,

    /// Total run duration (humantime: e.g. `60s`, `15m`, `24h`).
    #[arg(long, default_value = "24h")]
    pub duration: String,

    /// RNG seed for reproducible workloads.
    #[arg(long, default_value_t = 0xDD5C0DEu64)]
    pub seed: u64,

    /// Output directory for snapshots and final summary.
    #[arg(long, default_value = "./loadtest-results")]
    pub output_dir: PathBuf,

    /// Workload knob: target users created per hour.
    #[arg(long, default_value_t = 500)]
    pub users_per_hour: u64,

    /// Workload knob: target devices created per hour.
    #[arg(long, default_value_t = 1000)]
    pub devices_per_hour: u64,

    /// Workload knob: target sessions issued per second.
    #[arg(long, default_value_t = 50)]
    pub sessions_per_second: u64,

    /// Workload knob: target policy evaluations per second.
    #[arg(long, default_value_t = 200)]
    pub policy_evals_per_second: u64,

    /// Workload knob: target revocations per hour.
    #[arg(long, default_value_t = 5)]
    pub revocations_per_hour: u64,

    /// Smoke mode: short run (60s) with 3 nodes — used by CI.
    #[arg(long, default_value_t = false)]
    pub smoke: bool,

    /// Enable chaos layer: randomly pause/resume nodes to simulate
    /// offline/rejoin churn. Disabled in smoke mode.
    #[arg(long, default_value_t = false)]
    pub chaos: bool,

    /// Mean interval between chaos events (humantime), e.g. `90s`, `5m`.
    #[arg(long, default_value = "90s")]
    pub chaos_interval: String,

    /// Mean offline duration per paused node (humantime), e.g. `30s`, `2m`.
    #[arg(long, default_value = "45s")]
    pub chaos_offline: String,

    /// Maximum fraction of nodes that may be offline at once (0.0..1.0).
    /// Hard cap: never pause the last reachable node.
    #[arg(long, default_value_t = 0.34)]
    pub chaos_max_fraction: f64,
}

impl Cli {
    pub fn effective_duration(&self) -> Duration {
        if self.smoke {
            Duration::from_secs(60)
        } else {
            humantime::parse_duration(&self.duration)
                .unwrap_or_else(|_| Duration::from_secs(24 * 3600))
        }
    }

    pub fn effective_nodes(&self) -> usize {
        if self.smoke { 3 } else { self.nodes.max(1) }
    }

    pub fn chaos_enabled(&self) -> bool {
        self.chaos && !self.smoke
    }

    pub fn chaos_interval_dur(&self) -> Duration {
        humantime::parse_duration(&self.chaos_interval).unwrap_or(Duration::from_secs(90))
    }

    pub fn chaos_offline_dur(&self) -> Duration {
        humantime::parse_duration(&self.chaos_offline).unwrap_or(Duration::from_secs(45))
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,libp2p=warn,dds_net=warn")),
        )
        .try_init();

    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.output_dir)?;

    // Watch channel instead of Notify: `Notify::notify_waiters()` only
    // wakes *current* waiters, so a SIGINT racing with the select loop
    // (e.g. arriving between iterations) is silently dropped. A watch
    // channel keeps the state, so the next `changed().await` resolves
    // immediately. The 2026-04-09 soak hit this race during shutdown.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("ctrl-c received; shutting down");
            let _ = stop_tx.send(true);
        }
    });

    harness::run(cli, stop_rx).await
}
