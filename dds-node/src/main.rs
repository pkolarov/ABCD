//! DDS node entry point — starts the P2P node, storage, and local API.
//!
//! Subcommands (hand-rolled, no clap dependency):
//!
//! - `dds-node init-domain --name <NAME> --dir <DIR>`
//!   Genesis ceremony. Creates a fresh domain Ed25519 keypair, writes
//!   `<DIR>/domain.toml` (public — share with siblings) and
//!   `<DIR>/domain_key.bin` (secret — keep safe; encrypted with
//!   `DDS_DOMAIN_PASSPHRASE` if set). Stage 2 will replace the secret
//!   half with a FIDO2-backed signer.
//!
//! - `dds-node gen-node-key --data-dir <DIR>`
//!   Generates the persistent libp2p keypair and prints the resulting
//!   `PeerId`. Run this on a sibling machine to discover the peer id
//!   that the admin needs in order to issue an admission cert.
//!
//! - `dds-node admit --domain-key <FILE> --domain <FILE> --peer-id <ID> [--out FILE] [--ttl-days N]`
//!   The admin signs an admission cert for a sibling node's peer id.
//!   Ship the resulting cert to the sibling and place it at
//!   `<data_dir>/admission.cbor`.
//!
//! - `dds-node run [config.toml]`
//!   Default action. Loads config, verifies admission cert, runs the
//!   P2P node.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dds_domain::DomainKey;
use dds_domain::domain::to_hex;
use dds_node::config::NodeConfig;
use dds_node::domain_store;
use dds_node::http;
use dds_node::identity_store;
use dds_node::node::DdsNode;
use dds_node::p2p_identity;
use dds_node::provision;
use dds_node::service::LocalService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let sub = args.first().map(|s| s.as_str()).unwrap_or("run");

    match sub {
        "init-domain" => cmd_init_domain(&args[1..]),
        "gen-node-key" => cmd_gen_node_key(&args[1..]),
        "admit" => cmd_admit(&args[1..]),
        "create-provision-bundle" => cmd_create_bundle(&args[1..]),
        "provision" => cmd_provision(&args[1..]),
        "run" => cmd_run(&args[1..]).await,
        // Back-compat: if first arg looks like a config path (or there are no args)
        // treat it as `run <arg>`.
        s if s.ends_with(".toml") || s.ends_with(".dds") || !s.starts_with('-') => {
            if s.ends_with(".dds") {
                cmd_provision(&args)
            } else {
                cmd_run(&args).await
            }
        }
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage:
  dds-node init-domain --name <NAME> --dir <DIR> [--fido2]
  dds-node gen-node-key --data-dir <DIR>
  dds-node admit --domain-key <FILE> --domain <FILE> --peer-id <ID> [--out <FILE>] [--ttl-days <N>]
  dds-node create-provision-bundle --dir <DIR> --org <ORG> [--out <FILE>]
  dds-node provision <BUNDLE.dds> [--data-dir <DIR>] [--no-start]
  dds-node run [config.toml]"
    );
}

/// Tiny `--key value` argument parser. Unknown keys are returned as None.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name && i + 1 < args.len() {
            return Some(&args[i + 1]);
        }
        i += 1;
    }
    None
}

fn require_flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    flag(args, name).ok_or_else(|| format!("missing required flag {name}").into())
}

fn cmd_init_domain(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let name = require_flag(args, "--name")?;
    let dir = PathBuf::from(require_flag(args, "--dir")?);
    let use_fido2 = args.iter().any(|a| a == "--fido2");
    std::fs::create_dir_all(&dir)?;

    let mut rng = rand::rngs::OsRng;
    let key = DomainKey::generate(name, &mut rng);
    let domain = key.domain();

    let domain_path = dir.join("domain.toml");
    let key_path = dir.join("domain_key.bin");
    domain_store::save_domain_file(&domain_path, &domain)?;

    if use_fido2 {
        #[cfg(feature = "fido2")]
        {
            println!("Protecting domain key with FIDO2 authenticator...");
            domain_store::save_domain_key_fido2(&key_path, &key)?;
            println!("  Domain key is FIDO2-protected (no passphrase needed)");
        }
        #[cfg(not(feature = "fido2"))]
        {
            eprintln!("Error: --fido2 requires dds-node built with --features fido2");
            std::process::exit(1);
        }
    } else {
        domain_store::save_domain_key(&key_path, &key)?;
    }

    println!("Domain created:");
    println!("  name:        {}", domain.name);
    println!("  id:          {}", domain.id);
    println!("  pubkey:      {}", to_hex(&domain.pubkey));
    println!(
        "  domain.toml: {} (share with siblings)",
        domain_path.display()
    );
    println!("  domain_key:  {} (keep secret)", key_path.display());
    if use_fido2 {
        println!("  protection:  FIDO2 hardware key (touch to unlock)");
    }
    Ok(())
}

fn cmd_gen_node_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    std::fs::create_dir_all(&data_dir)?;
    let p2p_path = data_dir.join("p2p_key.bin");
    let kp = p2p_identity::load_or_create(&p2p_path)?;
    let peer_id = libp2p::PeerId::from(kp.public());
    println!("Node libp2p identity:");
    println!("  data_dir: {}", data_dir.display());
    println!("  p2p_key:  {}", p2p_path.display());
    println!("  peer_id:  {}", peer_id);
    println!();
    println!("Send this peer id to the domain admin to obtain an admission cert.");
    Ok(())
}

fn cmd_admit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let domain_key_path = PathBuf::from(require_flag(args, "--domain-key")?);
    let domain_path = PathBuf::from(require_flag(args, "--domain")?);
    let peer_id = require_flag(args, "--peer-id")?;
    let out = PathBuf::from(flag(args, "--out").unwrap_or("admission.cbor"));
    let ttl_days: Option<u64> = flag(args, "--ttl-days").map(|s| s.parse()).transpose()?;

    let key = domain_store::load_domain_key(&domain_key_path)?;
    let domain = domain_store::load_domain_file(&domain_path)?;
    if key.id() != domain.id {
        return Err("domain key does not match domain.toml id".into());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let expires_at = ttl_days.map(|d| now + d * 86_400);
    let cert = key.issue_admission(peer_id.to_string(), now, expires_at);
    domain_store::save_admission_cert(&out, &cert)?;

    println!("Admission cert issued:");
    println!("  domain:    {} ({})", domain.name, domain.id);
    println!("  peer_id:   {peer_id}");
    println!("  issued_at: {now}");
    if let Some(exp) = expires_at {
        println!("  expires:   {exp}");
    } else {
        println!("  expires:   never");
    }
    println!("  out:       {}", out.display());
    Ok(())
}

fn cmd_create_bundle(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(require_flag(args, "--dir")?);
    let org = require_flag(args, "--org")?;
    let out = PathBuf::from(flag(args, "--out").unwrap_or("provision.dds"));

    provision::create_bundle(&dir, org, &out)?;
    println!("Provision bundle created:");
    println!("  file: {}", out.display());
    println!("  Copy to USB stick, then on a new machine:");
    println!("  sudo dds-node provision {}", out.display());
    Ok(())
}

fn cmd_provision(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .ok_or("provision requires a bundle path (e.g., provision.dds)")?;
    let data_dir = flag(args, "--data-dir").map(PathBuf::from);
    let no_start = args.iter().any(|a| a == "--no-start");

    let summary = provision::run_provision(
        &bundle_path,
        data_dir.as_deref(),
        !no_start,
    )?;

    println!();
    println!("============================================================");
    println!("  Node Provisioned");
    println!("============================================================");
    println!();
    println!("  Domain:     {} ({})", summary.domain_name, summary.domain_id);
    println!("  Peer ID:    {}", summary.peer_id);
    if let Some(urn) = &summary.device_urn {
        println!("  Device URN: {urn}");
    }
    println!("  Data dir:   {}", summary.data_dir.display());
    println!("  Config:     {}", summary.config_path.display());
    println!();
    println!("  The node will auto-discover other nodes on the LAN via mDNS.");
    println!("  Enrolled users will sync via gossip within ~60 seconds.");
    Ok(())
}

async fn cmd_run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dds.toml"));

    if !config_path.exists() {
        eprintln!("No config file at {}", config_path.display());
        print_usage();
        std::process::exit(1);
    }
    info!(path = %config_path.display(), "loading config");
    let config = NodeConfig::from_file(&config_path)?;
    std::fs::create_dir_all(&config.data_dir)?;

    // Load (or generate) the persistent libp2p keypair before init so the
    // admission cert can be verified against a stable peer_id.
    let p2p_path = config.p2p_key_path();
    let p2p_keypair = p2p_identity::load_or_create(&p2p_path)?;
    let peer_id = libp2p::PeerId::from(p2p_keypair.public());
    info!(%peer_id, p2p_key = %p2p_path.display(), "loaded libp2p identity");

    let mut node = DdsNode::init(config.clone(), p2p_keypair)?;
    node.start()?;

    // Long-lived node signing identity (Vouchsafe-shaped, separate from libp2p).
    let identity_path = node.config.identity_key_path();
    let node_identity = identity_store::load_or_create(&identity_path, "dds-node")?;
    info!(urn = %node_identity.id.to_urn(), path = %identity_path.display(), "loaded node identity");

    // Start the local HTTP API server alongside the P2P node. Share the
    // trust graph handle (Arc clone) so the swarm event loop and the
    // HTTP service observe the same in-memory state — fixes B5b.
    let api_addr = config.network.api_addr.clone();
    let trusted_roots = config.trusted_roots.iter().cloned().collect();
    let api_store = node.store.clone();
    let api_trust_graph = std::sync::Arc::clone(&node.trust_graph);
    let mut svc = LocalService::new(node_identity, api_trust_graph, trusted_roots, api_store);
    svc.set_data_dir(config.data_dir.clone());
    let shared_svc = Arc::new(tokio::sync::Mutex::new(svc));
    let node_info = http::NodeInfo {
        peer_id: node.peer_id.to_string(),
    };
    tokio::spawn(async move {
        if let Err(e) = http::serve(&api_addr, shared_svc, node_info).await {
            tracing::error!("HTTP API server error: {e}");
        }
    });

    info!(peer_id = %node.peer_id, "DDS node running — press Ctrl+C to stop");
    node.run().await
}

// Suppress dead-code warnings for the helper used only in cmd_run path
#[allow(dead_code)]
fn _silence_unused(_p: &Path) {}
