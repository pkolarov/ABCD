//! DDS load/soak harness — multi-node in-process driver.
//!
//! See `README.md` for the workload, KPI mapping, and how to run a 24h
//! soak. This binary is a measurement tool, not production code.

mod harness;
mod metrics;
mod report;
mod workload;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::Notify;
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

    let stop = Arc::new(Notify::new());
    let stop_sig = stop.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::warn!("ctrl-c received; shutting down");
            stop_sig.notify_waiters();
        }
    });

    harness::run(cli, stop).await
}
