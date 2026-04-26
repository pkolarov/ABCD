use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use dds_core::crdt::causal_dag::Operation;
use dds_core::identity::Identity;
use dds_core::token::{Token, TokenKind, TokenPayload};
use dds_domain::domain::to_hex;
use dds_domain::{
    DomainDocument, DomainKey, LaunchdAction, LaunchdDirective, MacOsPolicyDocument, MacOsSettings,
    PolicyScope, PreferenceAction, PreferenceDirective, PreferenceScope as DomainPreferenceScope,
    SoftwareAssignment,
};
use dds_net::gossip::GossipMessage;
use dds_node::config::{DomainConfig, NetworkConfig, NodeConfig};
use dds_node::domain_store;
use dds_node::http::{MacOsPoliciesResponse, MacOsSoftwareResponse};
use dds_node::node::DdsNode;
use dds_node::p2p_identity;
use dds_node::service::NodeStatus;
use futures::StreamExt;
use libp2p::PeerId;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};

fn main_usage() -> &'static str {
    "Usage:
  dds-macos-e2e publish --domain-key <FILE> --domain <FILE> --bootstrap-peer <MULTIADDR> --package-source <SOURCE> --package-sha256 <SHA> --package-version <VERSION> [--out <FILE>]
  dds-macos-e2e collect --manifest <FILE> --node-url <URL> [--machine-id <ID>] (--device-urn <URN> | --device-urn-file <FILE>) --state-dir <DIR> --managed-preferences-dir <DIR> [--launchd-state-file <FILE>] [--out <FILE>]
  dds-macos-e2e compare --summary-a <FILE> --summary-b <FILE> [--out <FILE>]
"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");

    match sub {
        "publish" => cmd_publish(&args[1..]).await,
        "collect" => cmd_collect(&args[1..]).await,
        "compare" => cmd_compare(&args[1..]),
        "gen-publisher-seed" => cmd_gen_publisher_seed(&args[1..]),
        _ => {
            eprintln!("{}", main_usage());
            std::process::exit(2);
        }
    }
}

/// Generate a fresh 32-byte Ed25519 seed for the e2e publisher,
/// write it as 64 hex chars to `--out`, and print the derived URN on
/// stdout so the smoke harness can slot it into node.toml's
/// `trusted_roots` before launching the node. C-3's
/// `publisher_capability_ok` only admits policy/software tokens
/// whose issuer chains back to a trusted root — so the e2e publisher
/// self-vouches for the `dds:policy-publisher-macos` and
/// `dds:software-publisher` purposes, which is only accepted if the
/// publisher IS a trusted root.
fn cmd_gen_publisher_seed(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use rand::RngCore;
    let out = PathBuf::from(require_flag(args, "--out")?);
    let label = flag(args, "--label").unwrap_or("macos-e2e-publisher");
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let hex = seed.iter().map(|b| format!("{b:02x}")).collect::<String>();
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&out, &hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
    }
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let identity = Identity::from_signing_key(label, sk);
    println!("seed_file: {}", out.display());
    println!("urn:       {}", identity.id.to_urn());
    Ok(())
}

/// Parse a 32-byte seed from a file containing 64 hex chars.
fn load_publisher_seed(path: &std::path::Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "publisher seed file {} must contain 64 hex chars, got {}",
            path.display(),
            trimmed.len()
        )
        .into());
    }
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex in {}: {e}", path.display()))?;
    }
    Ok(seed)
}

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

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    generated_at: u64,
    org_hash: String,
    tag: String,
    policy_id: String,
    policy_version: u64,
    package_id: String,
    package_version: String,
    package_source: String,
    package_sha256: String,
    preference_domain: String,
    preference_key: String,
    preference_value_json: String,
    launchd_label: String,
    launchd_plist_path: String,
    launchd_marker_path: String,
    package_marker_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckResult {
    id: String,
    pass: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppliedEntry {
    version: String,
    content_hash: String,
    applied_at: u64,
    status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AppliedState {
    #[serde(default)]
    policies: BTreeMap<String, AppliedEntry>,
    #[serde(default)]
    software: BTreeMap<String, AppliedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalSummary {
    collected_at: u64,
    machine_id: String,
    hostname: String,
    node_url: String,
    device_urn: String,
    manifest: Manifest,
    status: NodeStatus,
    policy_count: usize,
    software_count: usize,
    policy_versions_seen: Vec<u64>,
    software_versions_seen: Vec<String>,
    observed_preference_value_json: Option<String>,
    launchd_binding_ok: bool,
    launchd_marker_exists: bool,
    package_installed_version: Option<String>,
    package_marker_exists: bool,
    applied_policy: Option<AppliedEntry>,
    applied_software: Option<AppliedEntry>,
    checks: Vec<CheckResult>,
    all_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComparisonSummary {
    compared_at: u64,
    all_passed: bool,
    summary_a: LocalSummary,
    summary_b: LocalSummary,
    checks: Vec<CheckResult>,
}

async fn cmd_publish(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let domain_key_path = PathBuf::from(require_flag(args, "--domain-key")?);
    let domain_path = PathBuf::from(require_flag(args, "--domain")?);
    let bootstrap_peer = require_flag(args, "--bootstrap-peer")?;
    let package_source = require_flag(args, "--package-source")?.to_string();
    let package_sha256 = normalize_sha256(require_flag(args, "--package-sha256")?);
    let package_version = require_flag(args, "--package-version")?.to_string();
    let out_path = flag(args, "--out").map(PathBuf::from);

    let org_hash = flag(args, "--org-hash").unwrap_or("dds-macos-e2e");
    let tag = flag(args, "--tag").unwrap_or("dds-macos-e2e");
    let policy_id = flag(args, "--policy-id").unwrap_or("e2e/macos-two-machine");
    let policy_version: u64 = flag(args, "--policy-version").unwrap_or("1").parse()?;
    let package_id = flag(args, "--package-id").unwrap_or("com.dds.e2e.marker");
    let package_display_name =
        flag(args, "--package-display-name").unwrap_or("DDS macOS E2E Marker");
    let preference_domain = flag(args, "--preference-domain").unwrap_or("com.dds.e2e");
    let preference_key = flag(args, "--preference-key").unwrap_or("FleetMessage");
    let preference_value_json =
        normalize_json(flag(args, "--preference-value-json").unwrap_or("\"dds-macos-e2e\""))?;
    let launchd_label = flag(args, "--launchd-label").unwrap_or("com.dds.e2e.marker");
    let launchd_plist_path = flag(args, "--launchd-plist-path")
        .unwrap_or("/tmp/dds-macos-e2e/LaunchDaemons/com.dds.e2e.marker.plist");
    let launchd_marker_path =
        flag(args, "--launchd-marker-path").unwrap_or("/tmp/dds-macos-e2e/launchd-fired.txt");
    let package_marker_path = flag(args, "--package-marker-path")
        .unwrap_or("/tmp/dds-macos-e2e/install-root/software-installed.txt");
    let publish_count: usize = flag(args, "--publish-count").unwrap_or("4").parse()?;
    let publish_interval_ms: u64 = flag(args, "--publish-interval-ms")
        .unwrap_or("1500")
        .parse()?;
    let connect_timeout_secs: u64 = flag(args, "--connect-timeout-secs")
        .unwrap_or("20")
        .parse()?;
    let publisher_seed_path = flag(args, "--publisher-seed-file").map(PathBuf::from);

    let domain_key = domain_store::load_domain_key(&domain_key_path)?;
    let domain = domain_store::load_domain_file(&domain_path)?;
    let manifest = publish_fixture(
        &domain_key,
        &domain,
        bootstrap_peer,
        &PublishSpec {
            org_hash: org_hash.to_string(),
            tag: tag.to_string(),
            policy_id: policy_id.to_string(),
            policy_version,
            package_id: package_id.to_string(),
            package_display_name: package_display_name.to_string(),
            package_version,
            package_source,
            package_sha256,
            preference_domain: preference_domain.to_string(),
            preference_key: preference_key.to_string(),
            preference_value_json,
            launchd_label: launchd_label.to_string(),
            launchd_plist_path: launchd_plist_path.to_string(),
            launchd_marker_path: launchd_marker_path.to_string(),
            package_marker_path: package_marker_path.to_string(),
            publish_count,
            publish_interval_ms,
            connect_timeout_secs,
            publisher_seed_path,
        },
    )
    .await?;

    write_json(&manifest, out_path.as_deref())?;
    Ok(())
}

struct PublishSpec {
    org_hash: String,
    tag: String,
    policy_id: String,
    policy_version: u64,
    package_id: String,
    package_display_name: String,
    package_version: String,
    package_source: String,
    package_sha256: String,
    preference_domain: String,
    preference_key: String,
    preference_value_json: String,
    launchd_label: String,
    launchd_plist_path: String,
    launchd_marker_path: String,
    package_marker_path: String,
    publish_count: usize,
    publish_interval_ms: u64,
    connect_timeout_secs: u64,
    /// Optional path to a 32-byte seed (64 hex chars) that
    /// deterministically derives the publisher identity. When set,
    /// the smoke harness has already inserted the resulting URN
    /// into node.toml's `trusted_roots`, so the publisher's
    /// self-vouch for `dds:policy-publisher-macos` chains back to a
    /// trusted root and C-3's `publisher_capability_ok` admits the
    /// policy / software tokens. When `None` (legacy behaviour), a
    /// fresh random identity is used and the ingest side will
    /// reject the tokens.
    publisher_seed_path: Option<PathBuf>,
}

async fn publish_fixture(
    domain_key: &DomainKey,
    domain: &dds_domain::Domain,
    bootstrap_peer: &str,
    spec: &PublishSpec,
) -> Result<Manifest, Box<dyn std::error::Error>> {
    let temp_root = std::env::temp_dir().join(format!(
        "dds-macos-e2e-publisher-{}-{}",
        now_millis(),
        std::process::id()
    ));
    std::fs::create_dir_all(&temp_root)?;

    let p2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(p2p_keypair.public());
    p2p_identity::save(&temp_root.join("p2p_key.bin"), &p2p_keypair)?;

    let cert = domain_key.issue_admission(peer_id.to_string(), now_epoch(), None);
    domain_store::save_admission_cert(&temp_root.join("admission.cbor"), &cert)?;

    let config = NodeConfig {
        data_dir: temp_root.clone(),
        network: NetworkConfig {
            listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
            bootstrap_peers: vec![bootstrap_peer.to_string()],
            mdns_enabled: false,
            heartbeat_secs: 1,
            idle_timeout_secs: 60,
            api_addr: "127.0.0.1:0".to_string(),
            api_auth: Default::default(),
            allow_legacy_v1_tokens: false,
        },
        org_hash: spec.org_hash.clone(),
        domain: DomainConfig {
            name: domain.name.clone(),
            id: domain.id.to_string(),
            pubkey: to_hex(&domain.pubkey),
            admission_path: None,
            audit_log_enabled: false,
            max_delegation_depth: 5,
            audit_log_max_entries: 0,
            audit_log_retention_days: 0,
            enforce_device_scope_vouch: false,
            allow_unattested_credentials: false,
            fido2_allowed_aaguids: Vec::new(),
        },
        trusted_roots: Vec::new(),
        bootstrap_admin_urn: None,
        identity_path: None,
        expiry_scan_interval_secs: 60,
    };

    let mut node = DdsNode::init(config, p2p_keypair)?;
    node.start()?;
    wait_for_mesh(&mut node, Duration::from_secs(spec.connect_timeout_secs)).await?;

    // Publisher identity: deterministic from a seed file when the
    // harness provides one, else fresh random. The smoke's
    // `gen-publisher-seed` subcommand writes the seed and prints the
    // URN so the test setup can slot it into `trusted_roots` on the
    // target node before we start publishing.
    let publisher = match &spec.publisher_seed_path {
        Some(p) => {
            let seed = load_publisher_seed(p)?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            Identity::from_signing_key("macos-e2e-publisher", sk)
        }
        None => Identity::generate("macos-e2e-publisher", &mut OsRng),
    };

    // C-3: publish self-attestation + self-vouches for the
    // publisher-capability purposes the policy/software tokens
    // require. Node-side `publisher_capability_ok` only admits
    // those tokens once these vouches have been ingested — so we
    // publish them first, pump a heartbeat for gossip to settle,
    // and THEN fire the policy/software tokens.
    {
        let self_attest_token = self_attest_identity(&publisher)?;
        let attest_hash = self_attest_token.payload_hash();
        publish_operation(&mut node, &self_attest_token)?;

        let policy_vouch = self_vouch_purpose(
            &publisher,
            &attest_hash,
            dds_core::token::purpose::POLICY_PUBLISHER_MACOS,
            "macos-e2e-vouch-policy-publisher-macos",
        )?;
        publish_operation(&mut node, &policy_vouch)?;

        let software_vouch = self_vouch_purpose(
            &publisher,
            &attest_hash,
            dds_core::token::purpose::SOFTWARE_PUBLISHER,
            "macos-e2e-vouch-software-publisher",
        )?;
        publish_operation(&mut node, &software_vouch)?;

        // Give node_a time to ingest the attest + vouches before we
        // send policy/software tokens that reference them. Without
        // this, the policy token can arrive before the vouch and
        // `publisher_capability_ok` rejects it.
        pump_for(&mut node, Duration::from_millis(spec.publish_interval_ms)).await;
    }

    let value_json: serde_json::Value = serde_json::from_str(&spec.preference_value_json)?;
    let policy = MacOsPolicyDocument {
        policy_id: spec.policy_id.clone(),
        display_name: "DDS macOS Two-Machine E2E".to_string(),
        version: spec.policy_version,
        scope: PolicyScope {
            device_tags: vec![spec.tag.clone()],
            org_units: Vec::new(),
            identity_urns: Vec::new(),
        },
        settings: Vec::new(),
        enforcement: dds_domain::Enforcement::Enforce,
        macos: Some(MacOsSettings {
            preferences: vec![PreferenceDirective {
                domain: spec.preference_domain.clone(),
                key: spec.preference_key.clone(),
                value: Some(value_json),
                scope: DomainPreferenceScope::System,
                action: PreferenceAction::Set,
            }],
            local_accounts: Vec::new(),
            launchd: vec![
                LaunchdDirective {
                    label: spec.launchd_label.clone(),
                    plist_path: spec.launchd_plist_path.clone(),
                    enabled: Some(true),
                    action: LaunchdAction::Configure,
                },
                LaunchdDirective {
                    label: spec.launchd_label.clone(),
                    plist_path: spec.launchd_plist_path.clone(),
                    enabled: Some(true),
                    action: LaunchdAction::Load,
                },
                LaunchdDirective {
                    label: spec.launchd_label.clone(),
                    plist_path: spec.launchd_plist_path.clone(),
                    enabled: Some(true),
                    action: LaunchdAction::Kickstart,
                },
            ],
            profiles: Vec::new(),
        }),
    };

    let software = SoftwareAssignment {
        package_id: spec.package_id.clone(),
        display_name: spec.package_display_name.clone(),
        version: spec.package_version.clone(),
        source: spec.package_source.clone(),
        sha256: spec.package_sha256.clone(),
        action: dds_domain::InstallAction::Install,
        scope: PolicyScope {
            device_tags: vec![spec.tag.clone()],
            org_units: Vec::new(),
            identity_urns: Vec::new(),
        },
        silent: true,
        pre_install_script: None,
        post_install_script: None,
    };

    let policy_token = attest_with_body(
        &publisher,
        &format!("macos-e2e-policy-{}", spec.policy_version),
        &policy,
    )?;
    let software_token = attest_with_body(
        &publisher,
        &format!("macos-e2e-software-{}", spec.package_version),
        &software,
    )?;

    for _ in 0..spec.publish_count {
        publish_operation(&mut node, &policy_token)?;
        publish_operation(&mut node, &software_token)?;
        pump_for(&mut node, Duration::from_millis(spec.publish_interval_ms)).await;
    }

    pump_for(&mut node, Duration::from_secs(2)).await;

    Ok(Manifest {
        generated_at: now_epoch(),
        org_hash: spec.org_hash.clone(),
        tag: spec.tag.clone(),
        policy_id: spec.policy_id.clone(),
        policy_version: spec.policy_version,
        package_id: spec.package_id.clone(),
        package_version: spec.package_version.clone(),
        package_source: spec.package_source.clone(),
        package_sha256: spec.package_sha256.clone(),
        preference_domain: spec.preference_domain.clone(),
        preference_key: spec.preference_key.clone(),
        preference_value_json: spec.preference_value_json.clone(),
        launchd_label: spec.launchd_label.clone(),
        launchd_plist_path: spec.launchd_plist_path.clone(),
        launchd_marker_path: spec.launchd_marker_path.clone(),
        package_marker_path: spec.package_marker_path.clone(),
    })
}

/// Self-attestation for the e2e publisher. The resulting token's
/// `payload_hash()` is the `vch_sum` the capability vouches must
/// reference for `has_purpose` to accept them.
fn self_attest_identity(identity: &Identity) -> Result<Token, Box<dyn std::error::Error>> {
    let payload = TokenPayload {
        iss: identity.id.to_urn(),
        iss_key: identity.public_key.clone(),
        jti: format!("attest-{}", identity.id.label()),
        sub: identity.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: now_epoch(),
        exp: Some(now_epoch() + 86_400),
        body_type: None,
        body_cbor: None,
    };
    Token::sign(payload, &identity.signing_key).map_err(|e| format!("sign attest: {e}").into())
}

/// Self-vouch issuing `purpose` over the publisher's own identity
/// (`vch_sum` pins the attestation's payload hash). Accepted only
/// when the publisher's URN is in the target node's `trusted_roots`.
fn self_vouch_purpose(
    identity: &Identity,
    attest_hash: &str,
    purpose: &str,
    jti: &str,
) -> Result<Token, Box<dyn std::error::Error>> {
    let payload = TokenPayload {
        iss: identity.id.to_urn(),
        iss_key: identity.public_key.clone(),
        jti: jti.to_string(),
        sub: identity.id.to_urn(),
        kind: TokenKind::Vouch,
        purpose: Some(purpose.to_string()),
        vch_iss: Some(identity.id.to_urn()),
        vch_sum: Some(attest_hash.to_string()),
        revokes: None,
        iat: now_epoch(),
        exp: Some(now_epoch() + 86_400),
        body_type: None,
        body_cbor: None,
    };
    Token::sign(payload, &identity.signing_key).map_err(|e| format!("sign vouch: {e}").into())
}

fn attest_with_body<T: DomainDocument>(
    identity: &Identity,
    jti: &str,
    document: &T,
) -> Result<Token, Box<dyn std::error::Error>> {
    let mut payload = TokenPayload {
        iss: identity.id.to_urn(),
        iss_key: identity.public_key.clone(),
        jti: jti.to_string(),
        sub: identity.id.to_urn(),
        kind: TokenKind::Attest,
        purpose: None,
        vch_iss: None,
        vch_sum: None,
        revokes: None,
        iat: now_epoch(),
        exp: Some(now_epoch() + 86_400),
        body_type: None,
        body_cbor: None,
    };
    document.embed(&mut payload)?;
    Token::sign(payload, &identity.signing_key).map_err(|e| format!("sign token: {e}").into())
}

fn publish_operation(node: &mut DdsNode, token: &Token) -> Result<(), Box<dyn std::error::Error>> {
    let op = Operation {
        id: format!("op-{}", token.payload.jti),
        author: token.payload.iss.clone(),
        deps: Vec::new(),
        data: vec![0],
        timestamp: 0,
    };

    let mut op_bytes = Vec::new();
    ciborium::into_writer(&op, &mut op_bytes)?;
    let token_bytes = token
        .to_cbor()
        .map_err(|e| format!("encode token cbor: {e}"))?;
    let msg = GossipMessage::DirectoryOp {
        op_bytes,
        token_bytes,
    };
    let topic = node.topics.operations.to_ident_topic();
    let cbor = msg.to_cbor()?;
    let _ = node.swarm.behaviour_mut().gossipsub.publish(topic, cbor);
    Ok(())
}

async fn wait_for_mesh(
    node: &mut DdsNode,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // H-12: it's not enough to have a TCP connection; the remote peer
    // must also be in `admitted_peers` (i.e. its admission cert has
    // verified) before any gossip we emit will be accepted. Return
    // only after both conditions hold.
    let deadline = Instant::now() + timeout;
    loop {
        if node.swarm.connected_peers().count() > 0 && !node.admitted_peers().is_empty() {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "timed out waiting for publisher to be admitted \
                 (connected={}, admitted={})",
                node.swarm.connected_peers().count(),
                node.admitted_peers().len(),
            )
            .into());
        }
        if let Ok(event) = tokio::time::timeout(
            remaining.min(Duration::from_millis(500)),
            node.swarm.select_next_some(),
        )
        .await
        {
            node.handle_swarm_event(event);
        }
    }
}

async fn pump_for(node: &mut DdsNode, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(
            remaining.min(Duration::from_millis(250)),
            node.swarm.select_next_some(),
        )
        .await
        {
            Ok(event) => node.handle_swarm_event(event),
            Err(_) => break,
        }
    }
}

async fn cmd_collect(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_path = PathBuf::from(require_flag(args, "--manifest")?);
    let node_url = require_flag(args, "--node-url")?
        .trim_end_matches('/')
        .to_string();
    let state_dir = PathBuf::from(require_flag(args, "--state-dir")?);
    let managed_preferences_dir = PathBuf::from(require_flag(args, "--managed-preferences-dir")?);
    let launchd_state_file = flag(args, "--launchd-state-file")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("launchd-state.json"));
    let machine_id = flag(args, "--machine-id")
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_hostname);
    let out_path = flag(args, "--out").map(PathBuf::from);

    let device_urn = if let Some(value) = flag(args, "--device-urn") {
        value.to_string()
    } else if let Some(path) = flag(args, "--device-urn-file") {
        std::fs::read_to_string(path)?.trim().to_string()
    } else {
        return Err("collect requires --device-urn or --device-urn-file".into());
    };

    let manifest: Manifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

    let status: NodeStatus = client
        .get(format!("{node_url}/v1/status"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    // H-3 (security review): endpoints now return a signed envelope
    // around the original JSON. This diagnostic binary unwraps
    // without verifying (the real Policy Agent pins the node pubkey
    // and verifies). The envelope-kind check still catches an
    // attacker splicing a software envelope into a policies response.
    use base64::Engine as _;
    let envelope_b64 = base64::engine::general_purpose::STANDARD;
    let policies_env: dds_core::envelope::SignedPolicyEnvelope = client
        .get(format!("{node_url}/v1/macos/policies"))
        .query(&[("device_urn", &device_urn)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if policies_env.kind != dds_core::envelope::kind::MACOS_POLICIES {
        return Err(format!("unexpected envelope kind: {}", policies_env.kind).into());
    }
    let policies_bytes = envelope_b64.decode(&policies_env.payload_b64)?;
    let policies: MacOsPoliciesResponse = serde_json::from_slice(&policies_bytes)?;

    let software_env: dds_core::envelope::SignedPolicyEnvelope = client
        .get(format!("{node_url}/v1/macos/software"))
        .query(&[("device_urn", &device_urn)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if software_env.kind != dds_core::envelope::kind::MACOS_SOFTWARE {
        return Err(format!("unexpected envelope kind: {}", software_env.kind).into());
    }
    let software_bytes = envelope_b64.decode(&software_env.payload_b64)?;
    let software: MacOsSoftwareResponse = serde_json::from_slice(&software_bytes)?;

    let applied_state = load_applied_state(&state_dir.join("applied-state.json"))?;
    let observed_preference_value_json = read_plist_json_value(
        &managed_preferences_dir.join(format!("{}.plist", manifest.preference_domain)),
        &manifest.preference_key,
    );
    let launchd_binding_ok = launchd_binding_matches(
        &launchd_state_file,
        &manifest.launchd_label,
        &manifest.launchd_plist_path,
    );
    let launchd_marker_exists = Path::new(&manifest.launchd_marker_path).exists();
    let package_marker_exists = Path::new(&manifest.package_marker_path).exists();
    let package_installed_version = read_pkg_receipt_version(&manifest.package_id);

    let policy_versions_seen = policies
        .policies
        .iter()
        .filter(|p| p.document.policy_id == manifest.policy_id)
        .map(|p| p.document.version)
        .collect::<Vec<_>>();
    let software_versions_seen = software
        .software
        .iter()
        .filter(|s| s.document.package_id == manifest.package_id)
        .map(|s| s.document.version.clone())
        .collect::<Vec<_>>();

    let applied_policy = applied_state.policies.get(&manifest.policy_id).cloned();
    let applied_software = applied_state.software.get(&manifest.package_id).cloned();

    let checks = evaluate_local_checks(
        &manifest,
        &status,
        policies.policies.len(),
        software.software.len(),
        &policy_versions_seen,
        &software_versions_seen,
        observed_preference_value_json.as_deref(),
        launchd_binding_ok,
        launchd_marker_exists,
        package_installed_version.as_deref(),
        package_marker_exists,
        applied_policy.as_ref(),
        applied_software.as_ref(),
    );
    let all_passed = checks.iter().all(|c| c.pass);

    let summary = LocalSummary {
        collected_at: now_epoch(),
        machine_id,
        hostname: default_hostname(),
        node_url,
        device_urn,
        manifest,
        status,
        policy_count: policies.policies.len(),
        software_count: software.software.len(),
        policy_versions_seen,
        software_versions_seen,
        observed_preference_value_json,
        launchd_binding_ok,
        launchd_marker_exists,
        package_installed_version,
        package_marker_exists,
        applied_policy,
        applied_software,
        checks,
        all_passed,
    };

    write_json(&summary, out_path.as_deref())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_local_checks(
    manifest: &Manifest,
    status: &NodeStatus,
    policy_count: usize,
    software_count: usize,
    policy_versions_seen: &[u64],
    software_versions_seen: &[String],
    observed_preference_value_json: Option<&str>,
    launchd_binding_ok: bool,
    launchd_marker_exists: bool,
    package_installed_version: Option<&str>,
    package_marker_exists: bool,
    applied_policy: Option<&AppliedEntry>,
    applied_software: Option<&AppliedEntry>,
) -> Vec<CheckResult> {
    vec![
        check(
            "connected_peer",
            status.connected_peers >= 1,
            format!("connected_peers={}", status.connected_peers),
        ),
        check(
            "policy_visible",
            policy_count >= 1 && policy_versions_seen.contains(&manifest.policy_version),
            format!("policy_count={policy_count}, seen_versions={policy_versions_seen:?}"),
        ),
        check(
            "software_visible",
            software_count >= 1
                && software_versions_seen
                    .iter()
                    .any(|v| v == &manifest.package_version),
            format!("software_count={software_count}, seen_versions={software_versions_seen:?}"),
        ),
        check(
            "policy_applied_ok",
            applied_policy
                .map(|e| e.status == "ok" && e.version == manifest.policy_version.to_string())
                .unwrap_or(false),
            format!("applied_policy={applied_policy:?}"),
        ),
        check(
            "software_applied_ok",
            applied_software
                .map(|e| e.status == "ok" && e.version == manifest.package_version)
                .unwrap_or(false),
            format!("applied_software={applied_software:?}"),
        ),
        check(
            "preference_value_match",
            observed_preference_value_json == Some(manifest.preference_value_json.as_str()),
            format!(
                "expected={}, observed={:?}",
                manifest.preference_value_json, observed_preference_value_json
            ),
        ),
        check(
            "launchd_binding_present",
            launchd_binding_ok,
            format!(
                "label={} plist={}",
                manifest.launchd_label, manifest.launchd_plist_path
            ),
        ),
        check(
            "launchd_marker_exists",
            launchd_marker_exists,
            manifest.launchd_marker_path.clone(),
        ),
        check(
            "package_receipt_present",
            package_installed_version == Some(manifest.package_version.as_str()),
            format!(
                "package_id={} expected_version={} observed={package_installed_version:?}",
                manifest.package_id, manifest.package_version
            ),
        ),
        check(
            "package_marker_exists",
            package_marker_exists,
            manifest.package_marker_path.clone(),
        ),
    ]
}

fn check(id: &str, pass: bool, detail: String) -> CheckResult {
    CheckResult {
        id: id.to_string(),
        pass,
        detail,
    }
}

fn load_applied_state(path: &Path) -> Result<AppliedState, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(AppliedState::default());
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn read_plist_json_value(path: &Path, key: &str) -> Option<String> {
    if !path.exists() {
        return None;
    }

    let output = Command::new("/usr/bin/plutil")
        .arg("-extract")
        .arg(key)
        .arg("json")
        .arg("-o")
        .arg("-")
        .arg(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn launchd_binding_matches(path: &Path, label: &str, expected_plist_path: &str) -> bool {
    if !path.exists() {
        return false;
    }

    let Ok(map) = serde_json::from_slice::<BTreeMap<String, String>>(
        &std::fs::read(path).unwrap_or_default(),
    ) else {
        return false;
    };
    map.get(label)
        .map(|value| value == expected_plist_path)
        .unwrap_or(false)
}

fn read_pkg_receipt_version(package_id: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/pkgutil")
        .arg("--pkg-info")
        .arg(package_id)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(version) = trimmed.strip_prefix("version:") {
            return Some(version.trim().to_string());
        }
    }
    None
}

fn default_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            Command::new("/bin/hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn cmd_compare(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let summary_a_path = PathBuf::from(require_flag(args, "--summary-a")?);
    let summary_b_path = PathBuf::from(require_flag(args, "--summary-b")?);
    let out_path = flag(args, "--out").map(PathBuf::from);

    let summary_a: LocalSummary = serde_json::from_slice(&std::fs::read(summary_a_path)?)?;
    let summary_b: LocalSummary = serde_json::from_slice(&std::fs::read(summary_b_path)?)?;

    let checks = vec![
        check(
            "machine_a_passed",
            summary_a.all_passed,
            format!("machine_id={}", summary_a.machine_id),
        ),
        check(
            "machine_b_passed",
            summary_b.all_passed,
            format!("machine_id={}", summary_b.machine_id),
        ),
        check(
            "same_policy_version",
            summary_a
                .applied_policy
                .as_ref()
                .map(|e| e.version.as_str())
                == summary_b
                    .applied_policy
                    .as_ref()
                    .map(|e| e.version.as_str()),
            format!(
                "a={:?} b={:?}",
                summary_a.applied_policy.as_ref().map(|e| e.version.clone()),
                summary_b.applied_policy.as_ref().map(|e| e.version.clone())
            ),
        ),
        check(
            "same_package_version",
            summary_a
                .applied_software
                .as_ref()
                .map(|e| e.version.as_str())
                == summary_b
                    .applied_software
                    .as_ref()
                    .map(|e| e.version.as_str()),
            format!(
                "a={:?} b={:?}",
                summary_a
                    .applied_software
                    .as_ref()
                    .map(|e| e.version.clone()),
                summary_b
                    .applied_software
                    .as_ref()
                    .map(|e| e.version.clone())
            ),
        ),
        check(
            "same_preference_value",
            summary_a.observed_preference_value_json == summary_b.observed_preference_value_json,
            format!(
                "a={:?} b={:?}",
                summary_a.observed_preference_value_json, summary_b.observed_preference_value_json
            ),
        ),
        check(
            "both_connected",
            summary_a.status.connected_peers >= 1 && summary_b.status.connected_peers >= 1,
            format!(
                "a={} b={}",
                summary_a.status.connected_peers, summary_b.status.connected_peers
            ),
        ),
    ];
    let all_passed = checks.iter().all(|c| c.pass);
    let comparison = ComparisonSummary {
        compared_at: now_epoch(),
        all_passed,
        summary_a,
        summary_b,
        checks,
    };

    write_json(&comparison, out_path.as_deref())?;
    if !comparison.all_passed {
        std::process::exit(1);
    }
    Ok(())
}

fn normalize_json(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(serde_json::to_string(&serde_json::from_str::<
        serde_json::Value,
    >(raw)?)?)
}

fn normalize_sha256(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase()
}

fn write_json<T: Serialize>(
    value: &T,
    path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(value)?;
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, json.as_bytes())?;
        println!("{}", path.display());
    } else {
        println!("{json}");
    }
    Ok(())
}
