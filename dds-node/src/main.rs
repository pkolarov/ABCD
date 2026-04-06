//! DDS node entry point — starts the P2P node, storage, and local API.

use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dds_node::config::NodeConfig;
use dds_node::identity_store;
use dds_node::node::DdsNode;

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

    // Load (or generate + persist) the long-lived node signing identity.
    // Encrypted at rest if DDS_NODE_PASSPHRASE is set.
    std::fs::create_dir_all(&node.config.data_dir).ok();
    let identity_path = node.config.identity_key_path();
    let node_identity = identity_store::load_or_create(&identity_path, "dds-node")?;
    info!(urn = %node_identity.id.to_urn(), path = %identity_path.display(), "loaded node identity");

    info!(peer_id = %node.peer_id, "DDS node running — press Ctrl+C to stop");

    node.run().await
}
