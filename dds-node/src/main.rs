//! DDS node entry point — starts the P2P node, storage, and local API.

mod config;
mod node;

use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::NodeConfig;
use crate::node::DdsNode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dds.toml"));

    let config = if config_path.exists() {
        info!(path = %config_path.display(), "loading config");
        NodeConfig::from_file(&config_path)?
    } else {
        eprintln!("Usage: dds-node [config.toml]");
        eprintln!("No config file found at {}", config_path.display());
        std::process::exit(1);
    };

    let mut node = DdsNode::init(config)?;
    node.start()?;

    info!(peer_id = %node.peer_id, "DDS node running — press Ctrl+C to stop");

    node.run().await
}
