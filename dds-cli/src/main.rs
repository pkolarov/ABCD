//! DDS command-line interface.
//!
//! Provides subcommands for identity management, group operations,
//! policy evaluation, enrollment, admin bootstrap, platform applier
//! queries, audit-log inspection, and diagnostics.
//!
//! Commands that need a running `dds-node` share the top-level
//! `--node-url` flag (defaults to the loopback API at
//! `http://127.0.0.1:5551`).

mod audit_format;
mod client;
mod dump;

use clap::{Parser, Subcommand};
use client::{DEFAULT_NODE_URL, get_json, get_with_status, post_json, post_no_body};
use dds_core::identity::Identity;
use dds_store::RedbBackend;
use dds_store::traits::*;
use dump::{DUMP_VERSION, DdsDump};
/// **Z-5** — magic prefix for hybrid-KEM-encrypted export files.
/// Distinct from the CBOR dump so `handle_import` can detect the
/// encrypted format without ambiguity.
const EXPORT_ENC_MAGIC: &[u8] = b"DDSDUMP_ENC_V1\0";
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "dds", about = "Decentralized Directory Service CLI")]
struct Cli {
    /// Path to the local storage directory (used by offline subcommands).
    #[arg(long, global = true, default_value = ".dds")]
    data_dir: PathBuf,

    /// dds-node HTTP API base URL (used by remote subcommands).
    #[arg(long, global = true, default_value = DEFAULT_NODE_URL)]
    node_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Identity management.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Group operations (local store).
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Policy evaluation (offline by default, or `--remote`).
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Store diagnostics (local by default, or `--remote`).
    Status {
        /// Query a running dds-node's /v1/status endpoint instead of the local store.
        #[arg(long)]
        remote: bool,
    },
    /// Enrollment — register a user (FIDO2) or device.
    Enroll {
        #[command(subcommand)]
        action: EnrollAction,
    },
    /// Admin bootstrap — set up the first admin or vouch via FIDO2 assertion.
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Audit log inspection.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Platform applier queries (Windows / macOS).
    Platform {
        #[command(subcommand)]
        action: PlatformAction,
    },
    /// Credential Provider operations.
    Cp {
        #[command(subcommand)]
        action: CpAction,
        /// Override the top-level --node-url (kept for back-compat).
        #[arg(long)]
        node_url: Option<String>,
    },
    /// Debugging / diagnostic helpers.
    Debug {
        #[command(subcommand)]
        action: DebugAction,
    },
    /// Snapshot of the most-asked operational metrics — peer count,
    /// trust-graph + store sizes, audit chain length and head age.
    /// **observability-plan.md Phase F.** Pretty-prints by default;
    /// pass `--format json` for scripting.
    Stats {
        /// Output format: `text` (pretty, default) or `json`.
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Probe the node's `/readyz` endpoint and summarize the result.
    /// **observability-plan.md Phase F.** Exits 0 when ready, 1 when
    /// not — suitable for orchestrator health checks and shell pipelines.
    Health {
        /// Output format: `text` (pretty, default) or `json`.
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Export the local store to a single `.ddsdump` file for air-gapped sync.
    Export {
        /// Destination path for the dump file.
        #[arg(long)]
        out: PathBuf,
        /// **Z-5 (security review)** — encrypt the dump for a specific
        /// recipient using their hybrid X25519 + ML-KEM-768 public key
        /// (1,216 bytes as hex). Obtain the recipient's pubkey with
        /// `dds pq status` on the target node (printed as "KEM pubkey (hex)"). When set,
        /// the dump is wrapped in a hybrid-KEM AEAD envelope so only the
        /// holder of the matching KEM secret key can read it. Suppresses
        /// the "NOT encrypted" warning.
        #[arg(long, value_name = "HEX")]
        encrypt_to: Option<String>,
    },
    /// Import a `.ddsdump` file into the local store (idempotent).
    Import {
        /// Source path of the dump file.
        #[arg(long = "in")]
        input: PathBuf,
        /// Parse and validate the file but make no store writes.
        #[arg(long)]
        dry_run: bool,
        /// **M-16 (security review)**: opt in to importing an unsigned
        /// legacy v1 dump. Default is to refuse — an attacker who can
        /// tamper with the dump can also strip a v2 signature, so v1
        /// must never be silently downgraded. Operators who really
        /// need to migrate from v1 must pass this flag explicitly.
        #[arg(long)]
        allow_unsigned: bool,
    },
    /// Z-1 Phase B operator surface — inspect the local node's
    /// post-quantum encryption posture (hybrid KEM pubkey, current
    /// epoch_id, cached peer cert / release counts). Most actions read
    /// the on-disk state under `--data-dir` directly. `rotate` contacts
    /// the running node via `--node-url`.
    Pq {
        #[command(subcommand)]
        action: PqAction,
    },
}

// ---- Identity ----

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new identity.
    Create {
        /// Human-readable label.
        label: String,
        /// Use hybrid (quantum-resistant) keys.
        #[arg(long)]
        hybrid: bool,
    },
    /// Show identity info from a URN.
    Show {
        /// Identity URN.
        urn: String,
    },
}

// ---- Group ----

#[derive(Subcommand)]
enum GroupAction {
    /// Vouch for a user (add to group).
    Vouch {
        #[arg(long)]
        as_label: String,
        #[arg(long)]
        user: String,
        #[arg(long)]
        purpose: String,
    },
    /// Revoke a vouch by JTI.
    Revoke {
        #[arg(long)]
        as_label: String,
        #[arg(long)]
        jti: String,
    },
}

// ---- Policy ----

#[derive(Subcommand)]
enum PolicyAction {
    /// Check if a subject can perform an action.
    Check {
        #[arg(long)]
        user: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        action: String,
        /// Query a running dds-node instead of the offline engine.
        #[arg(long)]
        remote: bool,
    },
}

// ---- Enroll ----

#[derive(Subcommand)]
enum EnrollAction {
    /// Register a user via FIDO2 attestation (POST /v1/enroll/user).
    User {
        #[arg(long)]
        label: String,
        #[arg(long)]
        credential_id: String,
        /// Base64 WebAuthn attestation object.
        #[arg(long)]
        attestation_object: String,
        /// Base64 SHA-256(clientDataJSON).
        #[arg(long)]
        client_data_hash: String,
        #[arg(long)]
        rp_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long, default_value = "platform")]
        authenticator_type: String,
    },
    /// Register a device (POST /v1/enroll/device).
    Device {
        #[arg(long)]
        label: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        os: String,
        #[arg(long)]
        os_version: String,
        #[arg(long)]
        tpm_ek_hash: Option<String>,
        #[arg(long)]
        org_unit: Option<String>,
        /// Repeatable.
        #[arg(long)]
        tag: Vec<String>,
    },
}

// ---- Admin ----

#[derive(Subcommand)]
enum AdminAction {
    /// Bootstrap the first admin (POST /v1/admin/setup).
    Setup {
        #[arg(long)]
        label: String,
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        attestation_object: String,
        #[arg(long)]
        client_data_hash: String,
        #[arg(long)]
        rp_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long, default_value = "platform")]
        authenticator_type: String,
    },
    /// Admin vouches for a subject via FIDO2 assertion (POST /v1/admin/vouch).
    Vouch {
        #[arg(long)]
        subject_urn: String,
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        authenticator_data: String,
        #[arg(long)]
        client_data_hash: String,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        purpose: Option<String>,
    },
}

// ---- Audit ----

#[derive(Subcommand)]
enum AuditAction {
    /// List recent audit log entries (GET /v1/audit/entries).
    List {
        /// Filter by action (e.g. attest, vouch, revoke, enroll).
        #[arg(long)]
        action: Option<String>,
        /// Maximum entries to return (newest first).
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Stream audit entries to stdout in a SIEM-friendly format.
    /// Phase B.1 of the observability plan: implemented as a polling
    /// loop over `GET /v1/audit/entries?since=N`. JTI / URNs in the
    /// output come from the *verified* token, not a copy of the line.
    Tail {
        /// Only emit entries with `timestamp >= since` (Unix seconds).
        /// On a follow run, the CLI advances this watermark internally
        /// after each poll so each entry is only emitted once.
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Output format: `jsonl` (canonical, default — one JSON object
        /// per line, schema `{ts, action, reason, node_urn, chain_hash,
        /// prev_hash, sig_ok, token_cbor_b64}`); `cef` (ArcSight /
        /// Splunk Common Event Format, single line); `syslog` (RFC 5424
        /// with the audit fields in STRUCTURED-DATA `dds@32473`). The
        /// CEF / syslog severity mapping is fixed by
        /// `docs/observability/audit-event-schema.md` §5.
        #[arg(long, default_value = "jsonl")]
        format: String,
        /// Stay attached and keep polling for new entries on this
        /// interval (seconds). 0 = single-shot, exit after first batch.
        #[arg(long, default_value_t = 0)]
        follow_interval: u64,
        /// Filter by action (forwarded to the server as a query param).
        #[arg(long)]
        action: Option<String>,
    },
    /// Walk the audit chain end-to-end and verify every entry's
    /// signature + chain link. Phase B.2 of the observability plan.
    /// Reports the first break with `(index, expected, actual)`.
    Verify {
        /// Filter by action (forwarded to the server as a query param).
        /// Off by default — verification walks the full chain.
        #[arg(long)]
        action: Option<String>,
    },
    /// One-shot range dump of audit entries to stdout or a file.
    /// **observability-plan.md Phase F.** Like a single-pass `audit
    /// tail` with optional `--until` upper bound and `--out` file
    /// destination — intended for offline forensics and incident
    /// response bundles. Each line is verified locally before emission
    /// so a tampered entry is flagged with `sig_ok=false` rather than
    /// silently trusted.
    Export {
        /// Lower bound: include only entries with `timestamp >= since`
        /// (Unix seconds). Default 0 = no lower bound.
        #[arg(long, default_value_t = 0)]
        since: u64,
        /// Upper bound: include only entries with `timestamp <= until`
        /// (Unix seconds). Optional; omit for no upper bound.
        #[arg(long)]
        until: Option<u64>,
        /// Filter by action (forwarded to the server as a query param).
        #[arg(long)]
        action: Option<String>,
        /// Output format: `jsonl` (canonical, default), `cef`
        /// (ArcSight / Splunk single line), or `syslog` (RFC 5424 with
        /// the audit fields in STRUCTURED-DATA `dds@32473`). See
        /// `docs/observability/audit-event-schema.md` §5–§6 for the
        /// severity map and field templates.
        #[arg(long, default_value = "jsonl")]
        format: String,
        /// File path to write to. If omitted, writes to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

// ---- Platform ----

#[derive(Subcommand)]
enum PlatformAction {
    /// Windows applier queries.
    Windows {
        #[command(subcommand)]
        action: WindowsAction,
    },
    /// macOS applier queries.
    Macos {
        #[command(subcommand)]
        action: MacosAction,
    },
    /// Linux applier queries.
    Linux {
        #[command(subcommand)]
        action: LinuxAction,
    },
}

#[derive(Subcommand)]
enum WindowsAction {
    /// GET /v1/windows/policies?device_urn=...
    Policies {
        #[arg(long)]
        device_urn: String,
    },
    /// GET /v1/windows/software?device_urn=...
    Software {
        #[arg(long)]
        device_urn: String,
    },
    /// POST /v1/windows/applied — reports an AppliedReport JSON file.
    Applied {
        /// Path to an AppliedReport JSON file.
        #[arg(long)]
        from_file: PathBuf,
    },
    /// POST /v1/windows/claim-account
    ClaimAccount {
        #[arg(long)]
        device_urn: String,
        /// Base64 CBOR-encoded session token.
        #[arg(long)]
        session_token_b64: String,
    },
}

#[derive(Subcommand)]
enum MacosAction {
    /// GET /v1/macos/policies?device_urn=...
    Policies {
        #[arg(long)]
        device_urn: String,
    },
    /// GET /v1/macos/software?device_urn=...
    Software {
        #[arg(long)]
        device_urn: String,
    },
    /// POST /v1/macos/applied — reports an AppliedReport JSON file.
    Applied {
        #[arg(long)]
        from_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum LinuxAction {
    /// GET /v1/linux/policies?device_urn=...
    Policies {
        #[arg(long)]
        device_urn: String,
    },
    /// GET /v1/linux/software?device_urn=...
    Software {
        #[arg(long)]
        device_urn: String,
    },
    /// POST /v1/linux/applied — reports an AppliedReport JSON file.
    Applied {
        #[arg(long)]
        from_file: PathBuf,
    },
}

// ---- CP (existing) ----

#[derive(Subcommand)]
enum CpAction {
    /// GET /v1/enrolled-users
    EnrolledUsers {
        #[arg(long, default_value = "")]
        device_urn: String,
    },
    /// POST /v1/session/assert
    SessionAssert {
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        authenticator_data: String,
        #[arg(long)]
        client_data_hash: String,
        #[arg(long)]
        signature: String,
        #[arg(long)]
        subject_urn: Option<String>,
        #[arg(long, default_value = "3600")]
        duration_secs: u64,
    },
}

// ---- Debug ----

#[derive(Subcommand)]
enum DebugAction {
    /// Ping the node's /v1/status endpoint to check reachability.
    Ping,
    /// Fetch and pretty-print full node statistics.
    Stats,
    /// Parse and validate a dds-node config file without starting the node.
    Config {
        /// Path to the config.toml to validate.
        file: PathBuf,
    },
}

// ---- Pq (Z-1 Phase B operator surface) ----

#[derive(Subcommand)]
enum PqAction {
    /// Summarize the local node's PQ posture: hybrid KEM pubkey hash,
    /// current epoch_id, cached peer-release count, cached peer cert
    /// count, and the subset of peer certs that already advertise a
    /// Phase-B `pq_kem_pubkey`. Reads `<data-dir>/epoch_keys.cbor` and
    /// `<data-dir>/peer_certs.cbor` directly.
    Status,
    /// List every cached peer admission cert and its hybrid KEM pubkey
    /// hash (sha256 prefix). Used by an admin to confirm 100% Phase-B
    /// coverage of the admitted peer set before flipping `enc-v3` on
    /// the domain.
    ListPubkeys,
    /// Trigger an immediate epoch-key rotation on the running node and
    /// fan-out the new release to all admitted peers. Requires admin
    /// credentials on the target node (loopback TCP or UDS/pipe identity).
    Rotate,
}

// ================================================================
// entry point
// ================================================================

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identity { action } => handle_identity(action),
        Commands::Group { action } => handle_group(action, &cli.data_dir),
        Commands::Policy { action } => handle_policy(action, &cli.node_url).await,
        Commands::Status { remote } => {
            if remote {
                handle_status_remote(&cli.node_url).await;
            } else {
                handle_status_local(&cli.data_dir);
            }
        }
        Commands::Enroll { action } => handle_enroll(action, &cli.node_url).await,
        Commands::Admin { action } => handle_admin(action, &cli.node_url).await,
        Commands::Audit { action } => handle_audit(action, &cli.node_url).await,
        Commands::Platform { action } => handle_platform(action, &cli.node_url).await,
        Commands::Cp { action, node_url } => {
            let url = node_url.unwrap_or(cli.node_url);
            handle_cp(action, &url).await;
        }
        Commands::Debug { action } => handle_debug(action, &cli.node_url).await,
        Commands::Stats { format } => handle_stats(&cli.node_url, &format).await,
        Commands::Health { format } => handle_health(&cli.node_url, &format).await,
        Commands::Export { out, encrypt_to } => {
            handle_export(&cli.data_dir, &out, encrypt_to.as_deref())
        }
        Commands::Import {
            input,
            dry_run,
            allow_unsigned,
        } => handle_import(&cli.data_dir, &input, dry_run, allow_unsigned),
        Commands::Pq { action } => handle_pq(action, &cli.data_dir, &cli.node_url).await,
    }
}

// ================================================================
// identity
// ================================================================

fn handle_identity(action: IdentityAction) {
    match action {
        IdentityAction::Create { label, hybrid } => {
            if hybrid {
                #[cfg(feature = "pq")]
                {
                    let ident = Identity::generate_hybrid(&label, &mut OsRng);
                    println!("Generated hybrid (Ed25519+ML-DSA-65) identity:");
                    println!("  URN:    {}", ident.id.to_urn());
                    println!("  Scheme: {}", ident.public_key.scheme);
                    println!("  PubKey: {} bytes", ident.public_key.bytes.len());
                }
                #[cfg(not(feature = "pq"))]
                {
                    eprintln!("Error: hybrid crypto requires the 'pq' feature");
                    std::process::exit(1);
                }
            } else {
                let ident = Identity::generate(&label, &mut OsRng);
                println!("Generated classical (Ed25519) identity:");
                println!("  URN:    {}", ident.id.to_urn());
                println!("  Scheme: {}", ident.public_key.scheme);
                println!("  PubKey: {} bytes", ident.public_key.bytes.len());
            }
        }
        IdentityAction::Show { urn } => match dds_core::identity::VouchsafeId::from_urn(&urn) {
            Ok(id) => {
                println!("Identity:");
                println!("  Label: {}", id.label());
                println!("  Hash:  {}", id.hash());
                println!("  URN:   {}", id.to_urn());
            }
            Err(e) => {
                eprintln!("Invalid URN: {e}");
                std::process::exit(1);
            }
        },
    }
}

// ================================================================
// group (local store)
// ================================================================

fn handle_group(action: GroupAction, data_dir: &PathBuf) {
    std::fs::create_dir_all(data_dir).unwrap_or_else(|e| {
        eprintln!("Failed to create data dir {}: {e}", data_dir.display());
        std::process::exit(1);
    });
    let db_path = data_dir.join("directory.redb");
    let mut store = match RedbBackend::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open store at {}: {e}", db_path.display());
            std::process::exit(1);
        }
    };

    match action {
        GroupAction::Vouch {
            as_label,
            user,
            purpose,
        } => {
            let voucher = Identity::generate(&as_label, &mut OsRng);
            let payload = dds_core::token::TokenPayload {
                iss: voucher.id.to_urn(),
                iss_key: voucher.public_key.clone(),
                jti: format!("vouch-{}-{}", as_label, uuid_v4()),
                sub: user.clone(),
                kind: dds_core::token::TokenKind::Vouch,
                purpose: Some(purpose.clone()),
                vch_iss: Some(user.clone()),
                vch_sum: Some(format!("cli-vouch-{}", uuid_v4())),
                revokes: None,
                iat: now_epoch(),
                exp: Some(now_epoch() + 365 * 86400),
                body_type: None,
                body_cbor: None,
            };
            let token = dds_core::token::Token::sign(payload, &voucher.signing_key).unwrap();
            store.put_token(&token).unwrap();
            println!("Vouch created:");
            println!("  JTI:     {}", token.payload.jti);
            println!("  Purpose: {purpose}");
            println!("  Voucher: {}", voucher.id.to_urn());
        }
        GroupAction::Revoke { as_label, jti } => {
            let revoker = Identity::generate(&as_label, &mut OsRng);
            let payload = dds_core::token::TokenPayload {
                iss: revoker.id.to_urn(),
                iss_key: revoker.public_key.clone(),
                jti: format!("revoke-{}", uuid_v4()),
                sub: "revocation".to_string(),
                kind: dds_core::token::TokenKind::Revoke,
                purpose: None,
                vch_iss: None,
                vch_sum: None,
                revokes: Some(jti.clone()),
                iat: now_epoch(),
                exp: None,
                body_type: None,
                body_cbor: None,
            };
            let token = dds_core::token::Token::sign(payload, &revoker.signing_key).unwrap();
            store.put_token(&token).unwrap();
            store.revoke(&jti).unwrap();
            println!("Revoked JTI: {jti}");
        }
    }
}

// ================================================================
// policy
// ================================================================

async fn handle_policy(action: PolicyAction, node_url: &str) {
    match action {
        PolicyAction::Check {
            user,
            resource,
            action,
            remote,
        } => {
            if remote {
                let req = PolicyRequest {
                    subject_urn: user,
                    resource,
                    action,
                };
                let r: PolicyResult = post_json(node_url, "/v1/policy/evaluate", &req).await;
                println!(
                    "Policy decision: {}",
                    if r.allowed { "ALLOW" } else { "DENY" }
                );
                println!("  Reason: {}", r.reason);
            } else {
                let trust_graph = dds_core::trust::TrustGraph::new();
                let engine = dds_core::policy::PolicyEngine::new();
                let roots = std::collections::BTreeSet::new();
                let decision = engine.evaluate(&user, &resource, &action, &trust_graph, &roots);
                println!("Policy decision: {decision}");
            }
        }
    }
}

// ================================================================
// status
// ================================================================

fn handle_status_local(data_dir: &Path) {
    let db_path = data_dir.join("directory.redb");
    if !db_path.exists() {
        println!("No store found at {}", db_path.display());
        println!("Run a command to initialize the store.");
        return;
    }
    let store = match RedbBackend::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to open store: {e}");
            std::process::exit(1);
        }
    };
    let total = store.count_tokens(None).unwrap_or(0);
    let attests = store
        .count_tokens(Some(dds_core::token::TokenKind::Attest))
        .unwrap_or(0);
    let vouches = store
        .count_tokens(Some(dds_core::token::TokenKind::Vouch))
        .unwrap_or(0);
    let revoked = store.revoked_set().map(|s| s.len()).unwrap_or(0);
    let burned = store.burned_set().map(|s| s.len()).unwrap_or(0);

    println!("DDS Store Status (local)");
    println!("  Path:         {}", db_path.display());
    println!("  Tokens:       {total}");
    println!("    Attestations: {attests}");
    println!("    Vouches:      {vouches}");
    println!("  Revocations:  {revoked}");
    println!("  Burns:        {burned}");
}

async fn handle_status_remote(node_url: &str) {
    let s: NodeStatusJson = get_json(node_url, "/v1/status", &[]).await;
    print_status(&s);
}

fn print_status(s: &NodeStatusJson) {
    println!("DDS Node Status (remote)");
    println!("  Peer ID:          {}", s.peer_id);
    println!("  Uptime (secs):    {}", s.uptime_secs);
    println!("  Connected peers:  {}", s.connected_peers);
    println!("  DAG operations:   {}", s.dag_operations);
    println!("  Trust tokens:     {}", s.trust_graph_tokens);
    println!("  Trusted roots:    {}", s.trusted_roots);
    println!("  Store tokens:     {}", s.store_tokens);
    println!("  Store revoked:    {}", s.store_revoked);
    println!("  Store burned:     {}", s.store_burned);
}

// ================================================================
// enroll
// ================================================================

async fn handle_enroll(action: EnrollAction, node_url: &str) {
    match action {
        EnrollAction::User {
            label,
            credential_id,
            attestation_object,
            client_data_hash,
            rp_id,
            display_name,
            authenticator_type,
        } => {
            let req = EnrollUserRequest {
                label,
                credential_id,
                attestation_object_b64: attestation_object,
                client_data_hash_b64: client_data_hash,
                rp_id,
                display_name,
                authenticator_type,
            };
            let r: EnrollmentResponse = post_json(node_url, "/v1/enroll/user", &req).await;
            print_enrollment(&r);
        }
        EnrollAction::Device {
            label,
            device_id,
            hostname,
            os,
            os_version,
            tpm_ek_hash,
            org_unit,
            tag,
        } => {
            let req = EnrollDeviceRequest {
                label,
                device_id,
                hostname,
                os,
                os_version,
                tpm_ek_hash,
                org_unit,
                tags: tag,
            };
            let r: EnrollmentResponse = post_json(node_url, "/v1/enroll/device", &req).await;
            print_enrollment(&r);
        }
    }
}

fn print_enrollment(r: &EnrollmentResponse) {
    println!("Enrolled:");
    println!("  URN:   {}", r.urn);
    println!("  JTI:   {}", r.jti);
    println!(
        "  Token: {}...",
        &r.token_cbor_b64[..64.min(r.token_cbor_b64.len())]
    );
}

// ================================================================
// admin
// ================================================================

async fn handle_admin(action: AdminAction, node_url: &str) {
    match action {
        AdminAction::Setup {
            label,
            credential_id,
            attestation_object,
            client_data_hash,
            rp_id,
            display_name,
            authenticator_type,
        } => {
            let req = EnrollUserRequest {
                label,
                credential_id,
                attestation_object_b64: attestation_object,
                client_data_hash_b64: client_data_hash,
                rp_id,
                display_name,
                authenticator_type,
            };
            let r: EnrollmentResponse = post_json(node_url, "/v1/admin/setup", &req).await;
            println!("Admin provisioned:");
            print_enrollment(&r);
        }
        AdminAction::Vouch {
            subject_urn,
            credential_id,
            authenticator_data,
            client_data_hash,
            signature,
            purpose,
        } => {
            let req = AdminVouchRequest {
                subject_urn,
                credential_id,
                authenticator_data,
                client_data_hash,
                signature,
                purpose,
            };
            let r: AdminVouchResponse = post_json(node_url, "/v1/admin/vouch", &req).await;
            println!("Admin vouch issued:");
            println!("  Vouch JTI:   {}", r.vouch_jti);
            println!("  Subject URN: {}", r.subject_urn);
            println!("  Admin URN:   {}", r.admin_urn);
        }
    }
}

// ================================================================
// audit
// ================================================================

async fn handle_audit(action: AuditAction, node_url: &str) {
    match action {
        AuditAction::List { action, limit } => {
            let mut q: Vec<(&str, String)> = Vec::new();
            if let Some(ref a) = action {
                q.push(("action", a.clone()));
            }
            if let Some(l) = limit {
                q.push(("limit", l.to_string()));
            }
            let query_refs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let r: AuditEntriesResponse =
                get_json(node_url, "/v1/audit/entries", &query_refs).await;
            println!("Audit log ({} entries):", r.total);
            if r.entries.is_empty() {
                println!("  (no entries)");
            }
            for e in &r.entries {
                println!(
                    "  [{}] action={} node={} token={}...",
                    e.timestamp,
                    e.action,
                    e.node_urn,
                    &e.token_cbor_b64[..32.min(e.token_cbor_b64.len())]
                );
            }
        }
        AuditAction::Tail {
            since,
            format,
            follow_interval,
            action,
        } => {
            run_audit_tail(node_url, since, &format, follow_interval, action.as_deref()).await;
        }
        AuditAction::Verify { action } => {
            run_audit_verify(node_url, action.as_deref()).await;
        }
        AuditAction::Export {
            since,
            until,
            action,
            format,
            out,
        } => {
            run_audit_export(
                node_url,
                since,
                until,
                &format,
                action.as_deref(),
                out.as_deref(),
            )
            .await;
        }
    }
}

/// **observability-plan.md Phase B.1.** Polling tail loop. Each batch
/// pulls entries with `timestamp >= since`; after emitting, the
/// watermark advances to `last_emitted_ts + 1` so duplicate-timestamp
/// entries within a single second are still emitted on the *next*
/// poll if needed (we de-dupe by chain_hash).
async fn run_audit_tail(
    node_url: &str,
    since: u64,
    format: &str,
    follow_interval: u64,
    action: Option<&str>,
) {
    let fmt = match audit_format::AuditFormat::parse(format) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    // Resolve once per invocation: CEF Device Version is the
    // dds-cli build (workspace-versioned 1:1 with dds-node), and
    // syslog hostname is the host running the tail loop.
    let dds_version = env!("CARGO_PKG_VERSION");
    let hostname = audit_format::current_hostname();

    let mut watermark = since;
    let mut seen_chain_hashes: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        let mut q: Vec<(&str, String)> = Vec::new();
        q.push(("since", watermark.to_string()));
        if let Some(a) = action {
            q.push(("action", a.to_string()));
        }
        let query_refs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r: AuditEntriesResponse = get_json(node_url, "/v1/audit/entries", &query_refs).await;

        let mut emitted_in_batch = 0usize;
        for e in &r.entries {
            // De-duplication across polls: chain_hash uniquely names an
            // entry. Rely on it when present; fall back to a synthetic
            // (ts|action|token) key for very old nodes that do not yet
            // populate chain_hash_hex.
            let dedup_key = e
                .chain_hash_hex
                .clone()
                .unwrap_or_else(|| format!("{}|{}|{}", e.timestamp, e.action, e.token_cbor_b64));
            if !seen_chain_hashes.insert(dedup_key) {
                continue;
            }

            // Verify the signature + URN binding before emitting so a
            // SIEM forwarder cannot be tricked into accepting a
            // tampered line. `sig_ok=false` lines are still emitted so
            // operators can spot tampering — they are *not* silently
            // dropped.
            let sig_ok = match decode_audit_entry(e) {
                Some(decoded) => decoded.verify().is_ok(),
                None => false,
            };

            let line = audit_format::AuditLine {
                ts: e.timestamp,
                action: &e.action,
                reason: e.reason.as_deref(),
                node_urn: &e.node_urn,
                chain_hash: e.chain_hash_hex.as_deref(),
                prev_hash: e.prev_hash_hex.as_deref(),
                sig_ok,
                token_cbor_b64: &e.token_cbor_b64,
            };
            println!("{}", render_audit_line(&line, fmt, dds_version, &hostname));

            if e.timestamp >= watermark {
                watermark = e.timestamp + 1;
            }
            emitted_in_batch += 1;
        }

        if follow_interval == 0 {
            // Single-shot exit so a Vector `exec` source can rely on
            // EOF as the batch boundary.
            let _ = emitted_in_batch;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(follow_interval)).await;
    }
}

/// Tiny dispatcher that picks the right formatter for a parsed
/// `AuditFormat`. Kept in `main.rs` so the formatter module stays
/// free of dispatch glue.
fn render_audit_line(
    line: &audit_format::AuditLine<'_>,
    fmt: audit_format::AuditFormat,
    dds_version: &str,
    hostname: &str,
) -> String {
    match fmt {
        audit_format::AuditFormat::Jsonl => audit_format::render_jsonl(line),
        audit_format::AuditFormat::Cef => audit_format::render_cef(line, dds_version),
        audit_format::AuditFormat::Syslog => audit_format::render_syslog(line, hostname),
    }
}

/// **observability-plan.md Phase B.2.** Walk the chain. For each
/// entry: re-derive `chain_hash`, verify the signature + URN binding
/// against `node_public_key`, and check that `prev_hash` matches the
/// previous entry's `chain_hash`. Reports the first break with
/// `(index, expected, actual)` and exits 1.
async fn run_audit_verify(node_url: &str, action: Option<&str>) {
    let mut q: Vec<(&str, String)> = Vec::new();
    if let Some(a) = action {
        q.push(("action", a.to_string()));
    }
    let query_refs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r: AuditEntriesResponse = get_json(node_url, "/v1/audit/entries", &query_refs).await;

    if r.entries.is_empty() {
        println!("Audit chain verify: 0 entries — nothing to check.");
        return;
    }

    let mut prev_hash_hex_expected: Option<String> = None;
    for (idx, raw) in r.entries.iter().enumerate() {
        let Some(decoded) = decode_audit_entry(raw) else {
            eprintln!(
                "FAIL: entry {idx} (action={}, ts={}) — missing entry_cbor_b64; \
                 the node is on an older build that does not expose the signed \
                 bytes. Verification requires dds-node ≥ phase-B.",
                raw.action, raw.timestamp
            );
            std::process::exit(1);
        };

        if let Err(e) = decoded.verify() {
            eprintln!(
                "FAIL: entry {idx} (action={}, ts={}) — signature/URN verify failed: {e}",
                raw.action, raw.timestamp
            );
            std::process::exit(1);
        }

        // Chain link check: this entry's prev_hash must match the
        // previous entry's chain_hash.
        let expected_prev = prev_hash_hex_expected.clone().unwrap_or_default();
        let got_prev = hex::encode(&decoded.prev_hash);
        if got_prev != expected_prev {
            eprintln!(
                "FAIL: entry {idx} (action={}, ts={}) — chain break:\n  \
                 expected prev_hash={expected_prev}\n  \
                 actual   prev_hash={got_prev}",
                raw.action, raw.timestamp
            );
            std::process::exit(1);
        }

        // Tee the chain head off this entry so the next iteration can
        // compare.
        let head = decoded
            .chain_hash()
            .map(|b| hex::encode(&b))
            .unwrap_or_default();
        prev_hash_hex_expected = Some(head);
    }

    println!(
        "Audit chain verify: OK ({} entries, signatures + chain links intact).",
        r.entries.len()
    );
}

/// **observability-plan.md Phase F.** One-shot range dump of audit
/// entries. Single GET against `/v1/audit/entries` with the
/// server-side `since` + `action` filters; the `until` upper bound is
/// applied client-side because the endpoint does not (yet) expose it
/// — fine for v1 because audit chains are bounded by
/// `audit_log_max_entries`. Each line is verified locally before
/// emission, so a tampered entry surfaces as `sig_ok=false` rather
/// than being silently trusted by an offline forensics consumer.
async fn run_audit_export(
    node_url: &str,
    since: u64,
    until: Option<u64>,
    format: &str,
    action: Option<&str>,
    out: Option<&Path>,
) {
    let fmt = match audit_format::AuditFormat::parse(format) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let dds_version = env!("CARGO_PKG_VERSION");
    let hostname = audit_format::current_hostname();

    let mut q: Vec<(&str, String)> = Vec::new();
    q.push(("since", since.to_string()));
    if let Some(a) = action {
        q.push(("action", a.to_string()));
    }
    let query_refs: Vec<(&str, &str)> = q.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r: AuditEntriesResponse = get_json(node_url, "/v1/audit/entries", &query_refs).await;

    // Collect formatted lines first so a write to `--out` is atomic
    // from the caller's perspective: either the dump is whole or not
    // there at all. Audit chains are bounded so the buffer stays small.
    let mut lines: Vec<String> = Vec::with_capacity(r.entries.len());
    let mut emitted: usize = 0;
    for e in &r.entries {
        if let Some(u) = until {
            if e.timestamp > u {
                continue;
            }
        }
        let sig_ok = match decode_audit_entry(e) {
            Some(decoded) => decoded.verify().is_ok(),
            None => false,
        };
        let line = audit_format::AuditLine {
            ts: e.timestamp,
            action: &e.action,
            reason: e.reason.as_deref(),
            node_urn: &e.node_urn,
            chain_hash: e.chain_hash_hex.as_deref(),
            prev_hash: e.prev_hash_hex.as_deref(),
            sig_ok,
            token_cbor_b64: &e.token_cbor_b64,
        };
        lines.push(render_audit_line(&line, fmt, dds_version, &hostname));
        emitted += 1;
    }

    let body = lines.join("\n");
    match out {
        Some(path) => {
            // One trailing newline so the file is POSIX-correct.
            let mut payload = body.clone();
            if !payload.is_empty() {
                payload.push('\n');
            }
            std::fs::write(path, payload).unwrap_or_else(|e| {
                eprintln!("Error: cannot write {}: {e}", path.display());
                std::process::exit(1);
            });
            // L-5 (security review) parity with `dds-cli export`: the
            // audit dump exposes node URNs, action labels, base64-encoded
            // signed token CBOR, and the chain hashes that anchor the
            // append-only log — sensitive forensic material that should
            // not be world-readable. Set 0o600 on Unix; Windows inherits
            // the parent dir DACL applied by the data-dir hardening.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            println!(
                "Exported {emitted} audit entr{} to {}",
                if emitted == 1 { "y" } else { "ies" },
                path.display()
            );
        }
        None => {
            if !body.is_empty() {
                println!("{body}");
            }
        }
    }
}

/// **observability-plan.md Phase F.** Probe the node's `/readyz`
/// endpoint and summarize. Exits 0 when ready, 1 otherwise — so
/// `dds-cli health && deploy.sh` works as the natural gate. We use
/// `get_with_status` rather than `get_json` because `/readyz` returns
/// HTTP 503 with a JSON body when not ready and that body is the
/// expected output, not an error to propagate.
async fn handle_health(node_url: &str, format: &str) {
    let (status, body) = get_with_status(node_url, "/readyz", &[]).await;
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Error: /readyz returned non-JSON body (HTTP {status}): {e}\n  body: {}",
                String::from_utf8_lossy(&body)
            );
            std::process::exit(1);
        }
    };
    let ready = parsed
        .get("ready")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    match format {
        "json" => {
            let mut envelope = serde_json::Map::new();
            envelope.insert(
                "http_status".to_string(),
                serde_json::Value::from(status.as_u16()),
            );
            envelope.insert("ready".to_string(), serde_json::Value::Bool(ready));
            if let Some(checks) = parsed.get("checks") {
                envelope.insert("checks".to_string(), checks.clone());
            }
            println!("{}", serde_json::Value::Object(envelope));
        }
        "text" => {
            println!(
                "DDS Node Health: {} (HTTP {})",
                if ready { "READY" } else { "NOT READY" },
                status.as_u16()
            );
            if let Some(checks) = parsed.get("checks").and_then(|v| v.as_object()) {
                println!("  Checks:");
                for (name, value) in checks {
                    let v = match value {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    println!("    {name}: {v}");
                }
            }
        }
        other => {
            eprintln!("Error: unsupported health format `{other}` — use `text` or `json`.");
            std::process::exit(1);
        }
    }

    if !ready {
        std::process::exit(1);
    }
}

/// **observability-plan.md Phase F.** One-shot snapshot of the most-
/// asked operational metrics. Composes `/v1/status` (peer count,
/// trust-graph + store sizes, uptime) with a single
/// `/v1/audit/entries` call to derive audit chain length and head age.
/// Pretty-prints by default; `--format json` emits a single JSON
/// object suitable for piping into `jq` or Prometheus textfile
/// scrapers that have not been migrated to the future `/metrics`
/// endpoint (Phase C).
async fn handle_stats(node_url: &str, format: &str) {
    let status: NodeStatusJson = get_json(node_url, "/v1/status", &[]).await;
    // Pull the full chain — bounded by `audit_log_max_entries`, so the
    // request stays small. `total` from the response is the post-filter
    // count which equals the chain length when no filter is supplied.
    let audit: AuditEntriesResponse = get_json(node_url, "/v1/audit/entries", &[]).await;
    let chain_length = audit.total;
    let head = audit.entries.last();
    let head_ts = head.map(|e| e.timestamp);
    let head_action = head.map(|e| e.action.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let head_age_secs = head_ts.map(|ts| now.saturating_sub(ts));
    // observability-plan.md Phase F closure for the deferred
    // `last admission failure` row. Older nodes (and freshly booted
    // ones with no failure yet) omit the timestamp; we render it as
    // "(none since boot)" so an operator can distinguish "no failures"
    // from "field unsupported".
    let last_admission_failure_age_secs = status
        .last_admission_failure_ts
        .map(|ts| now.saturating_sub(ts));

    match format {
        "json" => {
            let mut store = serde_json::json!({
                "tokens": status.store_tokens,
                "revoked": status.store_revoked,
                "burned": status.store_burned,
            });
            // observability-plan.md Phase F closure for the deferred
            // store-bytes row. Older nodes omit the field; we keep the
            // JSON shape the same in that case so existing scripts still
            // parse (the `bytes` key is simply absent rather than
            // `null`). Newer nodes serving an empty map ship `bytes:
            // {}`, mirroring the "family present, no series" Prometheus
            // semantics — operators can tell "backend doesn't report"
            // (missing key) from "backend reports zero" (empty object).
            if let Some(bytes) = status.store_bytes.as_ref() {
                store["bytes"] = serde_json::to_value(bytes).unwrap_or(serde_json::Value::Null);
            }
            // Admission section mirrors the
            // `dds_admission_handshake_last_failure_seconds` Prometheus
            // gauge. Older nodes omit `last_failure_ts`; the JSON shape
            // simply leaves the keys absent (no `null`) so existing
            // scripts pinning the older shape keep parsing.
            let mut admission = serde_json::Map::new();
            if let Some(ts) = status.last_admission_failure_ts {
                admission.insert("last_failure_ts".into(), serde_json::Value::from(ts));
                if let Some(age) = last_admission_failure_age_secs {
                    admission.insert("last_failure_age_secs".into(), serde_json::Value::from(age));
                }
            }
            let body = serde_json::json!({
                "node": {
                    "peer_id": status.peer_id,
                    "uptime_secs": status.uptime_secs,
                    "connected_peers": status.connected_peers,
                },
                "trust_graph": {
                    "tokens": status.trust_graph_tokens,
                    "trusted_roots": status.trusted_roots,
                    "dag_operations": status.dag_operations,
                },
                "store": store,
                "admission": admission,
                "audit": {
                    "chain_length": chain_length,
                    "head_ts": head_ts,
                    "head_action": head_action,
                    "head_age_secs": head_age_secs,
                },
            });
            println!("{body}");
        }
        "text" => {
            println!("DDS Node Stats");
            println!("  Peer ID:          {}", status.peer_id);
            println!("  Uptime:           {}s", status.uptime_secs);
            println!("  Connected peers:  {}", status.connected_peers);
            println!("  Trust graph:");
            println!("    Tokens:         {}", status.trust_graph_tokens);
            println!("    Trusted roots:  {}", status.trusted_roots);
            println!("    DAG operations: {}", status.dag_operations);
            println!("  Store:");
            println!("    Tokens:         {}", status.store_tokens);
            println!("    Revocations:    {}", status.store_revoked);
            println!("    Burned:         {}", status.store_burned);
            // observability-plan.md Phase F closure for the deferred
            // store-bytes row. Pretty-print one indented line per redb
            // table, sorted by table name (BTreeMap iteration is
            // already alphabetical) so the output is stable across
            // runs. `(unsupported)` distinguishes "older node /
            // MemoryBackend, no snapshot available" from "backend
            // reports zero tables" (an empty map prints just the
            // header with no children).
            match status.store_bytes.as_ref() {
                Some(bytes) if !bytes.is_empty() => {
                    println!("    Bytes per table:");
                    for (table, n) in bytes {
                        println!("      {table:<18} {n}");
                    }
                }
                Some(_) => {
                    println!("    Bytes per table: (none)");
                }
                None => {
                    println!("    Bytes per table: (unsupported)");
                }
            }
            // observability-plan.md Phase F closure for the deferred
            // `last admission failure` row. Pretty-print the unix-seconds
            // timestamp + a "Xs ago" age so the operator does not need
            // to subtract the current time. `(none since boot)`
            // distinguishes "no failures since this process started"
            // from `(unsupported)` ("older node, field absent on the
            // wire") — mirrors the store-bytes pretty-printing
            // semantics above.
            println!("  Admission:");
            match (
                status.last_admission_failure_ts,
                last_admission_failure_age_secs,
            ) {
                (Some(ts), Some(age)) => {
                    println!("    Last failure ts:  {ts}");
                    println!("    Last failure age: {age}s");
                }
                _ => {
                    // `last_admission_failure_ts` is `None` either
                    // because telemetry has not stamped a failure yet
                    // (fresh process, no rejected peer) or because the
                    // node predates the field. Both reduce to the same
                    // operator signal: there is nothing to act on.
                    println!("    Last failure:     (none since boot)");
                }
            }
            println!("  Audit:");
            println!("    Chain length:   {chain_length}");
            match (head_ts, head_action.as_deref(), head_age_secs) {
                (Some(ts), Some(act), Some(age)) => {
                    println!("    Head ts:        {ts}");
                    println!("    Head action:    {act}");
                    println!("    Head age:       {age}s");
                }
                _ => {
                    println!("    (chain empty)");
                }
            }
        }
        other => {
            eprintln!("Error: unsupported stats format `{other}` — use `text` or `json`.");
            std::process::exit(1);
        }
    }
}

/// Decode the `entry_cbor_b64` field from an `/v1/audit/entries` row
/// back into a `dds_core::audit::AuditLogEntry`. Returns `None` when
/// the field is absent (older nodes) or when CBOR decoding fails — the
/// caller decides how to treat the absence.
fn decode_audit_entry(raw: &AuditEntry) -> Option<dds_core::audit::AuditLogEntry> {
    use base64::Engine as _;
    let b64 = raw.entry_cbor_b64.as_deref()?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    ciborium::from_reader(&bytes[..]).ok()
}

// ================================================================
// platform
// ================================================================

async fn handle_platform(action: PlatformAction, node_url: &str) {
    match action {
        PlatformAction::Windows { action } => match action {
            WindowsAction::Policies { device_urn } => {
                let env: dds_core::envelope::SignedPolicyEnvelope = get_json(
                    node_url,
                    "/v1/windows/policies",
                    &[("device_urn", &device_urn)],
                )
                .await;
                let bytes = unwrap_envelope(env, dds_core::envelope::kind::WINDOWS_POLICIES);
                let r: WindowsPoliciesPayload = serde_json::from_slice(&bytes).unwrap();
                println!(
                    "Windows policies for {} ({}):",
                    device_urn,
                    r.policies.len()
                );
                for p in &r.policies {
                    println!("  - jti={} issuer={} iat={}", p.jti, p.issuer, p.iat);
                }
            }
            WindowsAction::Software { device_urn } => {
                let env: dds_core::envelope::SignedPolicyEnvelope = get_json(
                    node_url,
                    "/v1/windows/software",
                    &[("device_urn", &device_urn)],
                )
                .await;
                let bytes = unwrap_envelope(env, dds_core::envelope::kind::WINDOWS_SOFTWARE);
                let r: WindowsSoftwarePayload = serde_json::from_slice(&bytes).unwrap();
                println!(
                    "Windows software for {} ({}):",
                    device_urn,
                    r.software.len()
                );
                for s in &r.software {
                    println!("  - jti={} issuer={} iat={}", s.jti, s.issuer, s.iat);
                }
            }
            WindowsAction::Applied { from_file } => {
                let report = load_applied_report(&from_file);
                post_no_body(node_url, "/v1/windows/applied", &report).await;
                println!("Applied report accepted.");
            }
            WindowsAction::ClaimAccount {
                device_urn,
                session_token_b64,
            } => {
                let req = ClaimAccountRequest {
                    device_urn,
                    session_token_cbor_b64: session_token_b64,
                };
                let r: ClaimAccountResponse =
                    post_json(node_url, "/v1/windows/claim-account", &req).await;
                println!("Windows account claim:");
                println!("  Subject:  {}", r.subject_urn);
                println!("  Username: {}", r.username);
                if let Some(fullname) = &r.full_name {
                    println!("  Full name: {fullname}");
                }
                if !r.groups.is_empty() {
                    println!("  Groups:   {}", r.groups.join(", "));
                }
            }
        },
        PlatformAction::Macos { action } => match action {
            MacosAction::Policies { device_urn } => {
                let env: dds_core::envelope::SignedPolicyEnvelope = get_json(
                    node_url,
                    "/v1/macos/policies",
                    &[("device_urn", &device_urn)],
                )
                .await;
                let bytes = unwrap_envelope(env, dds_core::envelope::kind::MACOS_POLICIES);
                let r: MacosPoliciesPayload = serde_json::from_slice(&bytes).unwrap();
                println!("macOS policies for {} ({}):", device_urn, r.policies.len());
                for p in &r.policies {
                    println!("  - jti={} issuer={} iat={}", p.jti, p.issuer, p.iat);
                }
            }
            MacosAction::Software { device_urn } => {
                let env: dds_core::envelope::SignedPolicyEnvelope = get_json(
                    node_url,
                    "/v1/macos/software",
                    &[("device_urn", &device_urn)],
                )
                .await;
                let bytes = unwrap_envelope(env, dds_core::envelope::kind::MACOS_SOFTWARE);
                let r: MacosSoftwarePayload = serde_json::from_slice(&bytes).unwrap();
                println!("macOS software for {} ({}):", device_urn, r.software.len());
                for s in &r.software {
                    println!("  - jti={} issuer={} iat={}", s.jti, s.issuer, s.iat);
                }
            }
            MacosAction::Applied { from_file } => {
                let report = load_applied_report(&from_file);
                post_no_body(node_url, "/v1/macos/applied", &report).await;
                println!("Applied report accepted.");
            }
        },
        PlatformAction::Linux { action } => match action {
            LinuxAction::Policies { device_urn } => {
                let env: dds_core::envelope::SignedPolicyEnvelope = get_json(
                    node_url,
                    "/v1/linux/policies",
                    &[("device_urn", &device_urn)],
                )
                .await;
                let bytes = unwrap_envelope(env, dds_core::envelope::kind::LINUX_POLICIES);
                let r: LinuxPoliciesPayload = serde_json::from_slice(&bytes).unwrap();
                println!("Linux policies for {} ({}):", device_urn, r.policies.len());
                for p in &r.policies {
                    println!("  - jti={} issuer={} iat={}", p.jti, p.issuer, p.iat);
                }
            }
            LinuxAction::Software { device_urn } => {
                let env: dds_core::envelope::SignedPolicyEnvelope = get_json(
                    node_url,
                    "/v1/linux/software",
                    &[("device_urn", &device_urn)],
                )
                .await;
                let bytes = unwrap_envelope(env, dds_core::envelope::kind::LINUX_SOFTWARE);
                let r: LinuxSoftwarePayload = serde_json::from_slice(&bytes).unwrap();
                println!("Linux software for {} ({}):", device_urn, r.software.len());
                for s in &r.software {
                    println!("  - jti={} issuer={} iat={}", s.jti, s.issuer, s.iat);
                }
            }
            LinuxAction::Applied { from_file } => {
                let report = load_applied_report(&from_file);
                post_no_body(node_url, "/v1/linux/applied", &report).await;
                println!("Applied report accepted.");
            }
        },
    }
}

fn load_applied_report(path: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", path.display());
        std::process::exit(1);
    });
    serde_json::from_str(&body).unwrap_or_else(|e| {
        eprintln!("Failed to parse {} as JSON: {e}", path.display());
        std::process::exit(1);
    })
}

// ================================================================
// cp (existing)
// ================================================================

async fn handle_cp(action: CpAction, node_url: &str) {
    match action {
        CpAction::EnrolledUsers { device_urn } => {
            let r: EnrolledUsersResponse = get_json(
                node_url,
                "/v1/enrolled-users",
                &[("device_urn", &device_urn)],
            )
            .await;
            if r.users.is_empty() {
                println!("No enrolled users.");
            } else {
                println!("{} enrolled user(s):", r.users.len());
                for u in &r.users {
                    println!("  {} ({})", u.display_name, u.subject_urn);
                    println!("    credential_id: {}", u.credential_id);
                }
            }
        }
        CpAction::SessionAssert {
            credential_id,
            authenticator_data,
            client_data_hash,
            signature,
            subject_urn,
            duration_secs,
        } => {
            let req = SessionAssertRequest {
                subject_urn,
                credential_id,
                client_data_hash,
                authenticator_data,
                signature,
                duration_secs: Some(duration_secs),
            };
            let r: SessionResponse = post_json(node_url, "/v1/session/assert", &req).await;
            println!("Session issued:");
            println!("  session_id:  {}", r.session_id);
            println!("  expires_at:  {}", r.expires_at);
            println!(
                "  token (b64): {}...",
                &r.token_cbor_b64[..64.min(r.token_cbor_b64.len())]
            );
        }
    }
}

// ================================================================
// debug
// ================================================================

async fn handle_debug(action: DebugAction, node_url: &str) {
    match action {
        DebugAction::Ping => {
            let s: NodeStatusJson = get_json(node_url, "/v1/status", &[]).await;
            println!(
                "OK — node {} reachable (peer_id={}, uptime={}s)",
                node_url, s.peer_id, s.uptime_secs
            );
        }
        DebugAction::Stats => {
            let s: NodeStatusJson = get_json(node_url, "/v1/status", &[]).await;
            print_status(&s);
        }
        DebugAction::Config { file } => {
            let body = std::fs::read_to_string(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });
            // Parse as generic TOML first so we can reject bad syntax cleanly.
            let doc: toml::Value = toml::from_str(&body).unwrap_or_else(|e| {
                eprintln!("Invalid TOML: {e}");
                std::process::exit(1);
            });
            println!("Config file: {}", file.display());
            println!(
                "  Top-level keys: {:?}",
                doc.as_table().map(|t| t.keys().collect::<Vec<_>>())
            );
            // Highlight a few well-known fields if present.
            if let Some(domain) = doc.get("domain") {
                println!("\n[domain]");
                if let Some(v) = domain.get("max_chain_depth") {
                    println!("  max_chain_depth: {v}");
                }
                if let Some(v) = domain.get("max_delegation_depth") {
                    println!("  max_delegation_depth: {v}");
                }
                if let Some(v) = domain.get("audit_log_enabled") {
                    println!("  audit_log_enabled: {v}");
                }
                if let Some(v) = domain.get("audit_log_max_entries") {
                    println!("  audit_log_max_entries: {v}");
                }
                if let Some(v) = domain.get("audit_log_retention_days") {
                    println!("  audit_log_retention_days: {v}");
                }
            }
            println!("\nNote: dds-node does not expose logs over HTTP — use OS log tooling");
            println!("  (journalctl, Event Viewer, `Console.app`) to view tracing output.");
        }
    }
}

// ================================================================
// export / import (air-gapped sync)
// ================================================================

/// Read the `domain.toml` next to the store and return its `id` field.
/// Returns `None` if the file doesn't exist; errors out on parse failure.
fn read_domain_id(data_dir: &Path) -> Option<String> {
    let path = data_dir.join("domain.toml");
    if !path.exists() {
        return None;
    }
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", path.display());
        std::process::exit(1);
    });
    #[derive(Deserialize)]
    struct DomainToml {
        id: String,
    }
    let d: DomainToml = toml::from_str(&body).unwrap_or_else(|e| {
        eprintln!("Failed to parse {}: {e}", path.display());
        std::process::exit(1);
    });
    Some(d.id)
}

/// Read the `pubkey` field from the local `domain.toml`, hex-decoded.
/// Returns `None` when the file is absent. Exits on parse failure.
fn read_domain_pubkey(data_dir: &Path) -> Option<Vec<u8>> {
    let path = data_dir.join("domain.toml");
    if !path.exists() {
        return None;
    }
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", path.display());
        std::process::exit(1);
    });
    #[derive(Deserialize)]
    struct DomainToml {
        pubkey: String,
    }
    let d: DomainToml = toml::from_str(&body).unwrap_or_else(|e| {
        eprintln!("Failed to parse {}: {e}", path.display());
        std::process::exit(1);
    });
    let bytes = dds_domain::domain::from_hex(&d.pubkey).unwrap_or_else(|e| {
        eprintln!("Failed to decode domain_pubkey hex: {e}");
        std::process::exit(1);
    });
    if bytes.len() != 32 {
        eprintln!("Domain pubkey must be 32 bytes");
        std::process::exit(1);
    }
    Some(bytes)
}

fn open_store_or_exit(data_dir: &Path, create: bool) -> RedbBackend {
    if create {
        std::fs::create_dir_all(data_dir).unwrap_or_else(|e| {
            eprintln!("Failed to create data dir {}: {e}", data_dir.display());
            std::process::exit(1);
        });
    }
    let db_path = data_dir.join("directory.redb");
    if !create && !db_path.exists() {
        eprintln!("No store found at {}", db_path.display());
        std::process::exit(1);
    }
    RedbBackend::open(&db_path).unwrap_or_else(|e| {
        eprintln!("Failed to open store at {}: {e}", db_path.display());
        std::process::exit(1);
    })
}

fn handle_export(data_dir: &Path, out: &Path, encrypt_to: Option<&str>) {
    let store = open_store_or_exit(data_dir, false);

    let domain_id = read_domain_id(data_dir).unwrap_or_else(|| {
        eprintln!(
            "Error: no domain.toml in {} — export requires a provisioned node.",
            data_dir.display()
        );
        std::process::exit(1);
    });

    // Collect tokens.
    let jtis = store.list_tokens(None).unwrap_or_else(|e| {
        eprintln!("Failed to list tokens: {e}");
        std::process::exit(1);
    });
    let mut tokens: Vec<Vec<u8>> = Vec::with_capacity(jtis.len());
    for jti in &jtis {
        let token = store.get_token(jti).unwrap_or_else(|e| {
            eprintln!("Failed to read token {jti}: {e}");
            std::process::exit(1);
        });
        let bytes = token.to_cbor().unwrap_or_else(|e| {
            eprintln!("Failed to encode token {jti}: {e}");
            std::process::exit(1);
        });
        tokens.push(bytes);
    }

    // Collect operations.
    let op_ids = store.operation_ids().unwrap_or_else(|e| {
        eprintln!("Failed to list operations: {e}");
        std::process::exit(1);
    });
    let mut operations: Vec<Vec<u8>> = Vec::with_capacity(op_ids.len());
    for id in &op_ids {
        let op = store.get_operation(id).unwrap_or_else(|e| {
            eprintln!("Failed to read operation {id}: {e}");
            std::process::exit(1);
        });
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&op, &mut bytes).unwrap_or_else(|e| {
            eprintln!("Failed to encode operation {id}: {e}");
            std::process::exit(1);
        });
        operations.push(bytes);
    }

    // Revoked + burned sets.
    let revoked: Vec<String> = store
        .revoked_set()
        .unwrap_or_else(|e| {
            eprintln!("Failed to read revoked set: {e}");
            std::process::exit(1);
        })
        .into_iter()
        .collect();
    let burned: Vec<String> = store
        .burned_set()
        .unwrap_or_else(|e| {
            eprintln!("Failed to read burned set: {e}");
            std::process::exit(1);
        })
        .into_iter()
        .collect();

    let mut dump = DdsDump {
        version: DUMP_VERSION,
        domain_id: domain_id.clone(),
        exported_at: now_epoch(),
        tokens,
        operations,
        revoked,
        burned,
        signature: Vec::new(),
    };

    // **M-16 (security review)**: sign the canonical digest of the
    // dump with the domain signing key so the importer can reject
    // a tampered file. Requires the operator to unwrap the domain
    // key (triggers the passphrase/FIDO2 prompt).
    let domain_key_path = data_dir.join("domain_key.bin");
    let signer = match dds_node::domain_store::load_domain_key(&domain_key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "Failed to load/unwrap domain key at {}: {e} — \
                 `dds export` must run on a host that holds the domain signing key",
                domain_key_path.display()
            );
            std::process::exit(1);
        }
    };
    use ed25519_dalek::Signer;
    dump.signature = signer
        .signing_key
        .sign(&dump.signing_bytes())
        .to_bytes()
        .to_vec();

    let signed_cbor = dump.to_cbor().unwrap_or_else(|e| {
        eprintln!("Failed to encode dump: {e}");
        std::process::exit(1);
    });

    // **Z-5 (security review)**: if `--encrypt-to` is set, wrap the signed
    // CBOR in a hybrid-KEM AEAD envelope (X25519 + ML-KEM-768 key agreement,
    // ChaCha20-Poly1305 bulk encryption). The recipient decrypts with
    // `dds import --in <file>` after presenting the matching KEM secret key
    // (from their `epoch_keys.cbor`).
    let (write_bytes, encrypted) = if let Some(pubkey_hex) = encrypt_to {
        use dds_core::crypto::{epoch_key, kem};

        let pk_bytes = hex::decode(pubkey_hex).unwrap_or_else(|e| {
            eprintln!("--encrypt-to: invalid hex: {e}");
            std::process::exit(1);
        });
        let recipient_pk = kem::HybridKemPublicKey::from_bytes(&pk_bytes).unwrap_or_else(|_| {
            eprintln!(
                "--encrypt-to: expected {} bytes (hybrid X25519 + ML-KEM-768 pubkey), got {}",
                kem::HYBRID_KEM_PUBKEY_LEN,
                pk_bytes.len()
            );
            std::process::exit(1);
        });

        let mut rng = OsRng;
        let (kem_ct, shared) = kem::encap(&mut rng, &recipient_pk, b"dds-export-v1")
            .unwrap_or_else(|_| {
                eprintln!("KEM encap failed");
                std::process::exit(1);
            });
        let (aead_nonce, aead_ct) = epoch_key::encrypt_export(&mut rng, &shared, &signed_cbor)
            .unwrap_or_else(|_| {
                eprintln!("AEAD encrypt failed");
                std::process::exit(1);
            });

        // Wire format: MAGIC ∥ kem_ct (1120 B) ∥ aead_nonce (12 B) ∥ aead_ct
        let kem_ct_bytes = kem_ct.to_bytes();
        let mut enc = Vec::with_capacity(
            EXPORT_ENC_MAGIC.len() + kem_ct_bytes.len() + aead_nonce.len() + aead_ct.len(),
        );
        enc.extend_from_slice(EXPORT_ENC_MAGIC);
        enc.extend_from_slice(&kem_ct_bytes);
        enc.extend_from_slice(&aead_nonce);
        enc.extend_from_slice(&aead_ct);
        (enc, true)
    } else {
        (signed_cbor, false)
    };

    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create {}: {e}", parent.display());
            std::process::exit(1);
        });
    }
    std::fs::write(out, &write_bytes).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {e}", out.display());
        std::process::exit(1);
    });
    // L-5 (security review): restrict dump file to owner-only read.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600));
    }

    println!("Exported dump to {}", out.display());
    println!("  Domain:     {domain_id}");
    println!("  Tokens:     {}", dump.tokens.len());
    println!("  Operations: {}", dump.operations.len());
    println!("  Revoked:    {}", dump.revoked.len());
    println!("  Burned:     {}", dump.burned.len());
    println!("  Size:       {} bytes", write_bytes.len());
    if encrypted {
        eprintln!();
        eprintln!("Dump is hybrid-KEM encrypted (X25519 + ML-KEM-768 + ChaCha20-Poly1305).");
        eprintln!("Only the holder of the matching KEM secret key can import it.");
    } else {
        // Z-5 (security review) — the dump is signed for integrity but is
        // NOT encrypted for confidentiality. Treat it as Restricted material
        // in transit: it contains every signed token (credential IDs, device
        // tags, attestations), every CRDT operation, and the revoked / burned
        // sets — i.e. a complete snapshot of directory state. Operators
        // shipping it through couriers or USB sticks must add their own
        // confidentiality layer (FDE, GPG, age, etc.) until the encrypted
        // export variant lands, or use `--encrypt-to <kem-pubkey>`.
        eprintln!();
        eprintln!("WARNING: The dump file is signed for integrity but is NOT encrypted.");
        eprintln!("         It contains the full directory state in plaintext CBOR.");
        eprintln!(
            "         Use --encrypt-to <hex-pubkey> or encrypt before transit (GPG / age / FDE)."
        );
    }
}

fn handle_import(data_dir: &Path, input: &Path, dry_run: bool, allow_unsigned: bool) {
    // Parse dump first — validating the file before opening the store means
    // a bad file never perturbs on-disk state.
    let raw_bytes = std::fs::read(input).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", input.display());
        std::process::exit(1);
    });

    // **Z-5 (security review)**: detect and decrypt a hybrid-KEM-encrypted
    // dump. The encrypted format starts with `EXPORT_ENC_MAGIC`; plaintext
    // CBOR dumps start with 0xa4..0xa7 (CBOR map headers).
    let bytes: Vec<u8> = if raw_bytes.starts_with(EXPORT_ENC_MAGIC) {
        use dds_core::crypto::{epoch_key, kem};

        let rest = &raw_bytes[EXPORT_ENC_MAGIC.len()..];
        let ct_len = kem::HYBRID_KEM_CT_LEN;
        if rest.len() < ct_len + epoch_key::AEAD_NONCE_LEN {
            eprintln!(
                "Error: encrypted dump is truncated (need at least {} bytes after magic, got {})",
                ct_len + epoch_key::AEAD_NONCE_LEN,
                rest.len()
            );
            std::process::exit(1);
        }
        let (kem_ct_bytes, rest) = rest.split_at(ct_len);
        let (nonce_bytes, aead_ct) = rest.split_at(epoch_key::AEAD_NONCE_LEN);

        let kem_ct = kem::KemCiphertext::from_bytes(kem_ct_bytes).unwrap_or_else(|_| {
            eprintln!("Error: malformed KEM ciphertext in encrypted dump");
            std::process::exit(1);
        });
        let mut nonce = [0u8; epoch_key::AEAD_NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);

        // Load the local node's KEM secret key from epoch_keys.cbor.
        let epoch_path = data_dir.join("epoch_keys.cbor");
        if !epoch_path.exists() {
            eprintln!(
                "Error: encrypted dump requires the KEM secret key at {}",
                epoch_path.display()
            );
            eprintln!(
                "       Run `dds-node` on this host first to initialise the epoch key store,"
            );
            eprintln!(
                "       or re-export targeting a node whose epoch_keys.cbor is present here."
            );
            std::process::exit(1);
        }
        let epoch_store =
            dds_node::epoch_key_store::EpochKeyStore::load_or_create(&epoch_path, &mut OsRng)
                .unwrap_or_else(|e| {
                    eprintln!(
                        "Failed to load epoch key store at {}: {e}",
                        epoch_path.display()
                    );
                    std::process::exit(1);
                });

        let shared = kem::decap(epoch_store.kem_secret(), &kem_ct, b"dds-export-v1")
            .unwrap_or_else(|_| {
                eprintln!(
                    "Error: KEM decapsulation failed — wrong KEM secret key or corrupted file"
                );
                std::process::exit(1);
            });

        let plaintext = epoch_key::decrypt_export(&shared, &nonce, aead_ct).unwrap_or_else(|_| {
            eprintln!(
                "Error: AEAD decryption failed — wrong key, tampered ciphertext, or corrupted file"
            );
            std::process::exit(1);
        });

        eprintln!(
            "Decrypted hybrid-KEM-encrypted dump ({} bytes).",
            raw_bytes.len()
        );
        plaintext
    } else {
        raw_bytes
    };

    let dump = DdsDump::from_cbor(&bytes).unwrap_or_else(|e| {
        eprintln!("Failed to parse dump: {e}");
        std::process::exit(1);
    });

    use dump::DUMP_MIN_READ_VERSION;
    if dump.version < DUMP_MIN_READ_VERSION || dump.version > DUMP_VERSION {
        eprintln!(
            "Error: unsupported dump version {} (this CLI understands \
             v{DUMP_MIN_READ_VERSION}..=v{DUMP_VERSION})",
            dump.version
        );
        std::process::exit(1);
    }

    // Domain-id check — refuse to cross-pollinate stores from different
    // domains. If the local node hasn't been provisioned yet, accept the
    // dump (the caller is bootstrapping from the dump itself).
    let local_domain_id = read_domain_id(data_dir);
    if let Some(ref local_id) = local_domain_id
        && local_id != &dump.domain_id
    {
        eprintln!(
            "Error: domain mismatch — dump is for {}, local store is for {}",
            dump.domain_id, local_id
        );
        std::process::exit(1);
    }

    // **M-16 (security review)**: verify the dump signature before
    // applying anything. v2+ dumps MUST be signed; v1 dumps are
    // accepted with a loud warning because they pre-date signing.
    //
    // The verifying key is the local domain pubkey when we have one
    // (the common "import into a provisioned node" case). If we're
    // bootstrapping a fresh node from the dump, there is no local
    // pubkey yet — we refuse to proceed without a sibling `domain.toml`
    // so the importer cannot be tricked by an unsigned dump from an
    // unknown domain. Operators who really want to bootstrap from an
    // unsigned dump must first write a legitimate `domain.toml` by
    // another means (provisioning bundle, manual copy, etc.).
    if dump.version >= 2 {
        let pubkey_bytes = match read_domain_pubkey(data_dir) {
            Some(pk) => pk,
            None => {
                eprintln!(
                    "Error: cannot verify dump signature — local node has no \
                     domain.toml (provision first, then import)"
                );
                std::process::exit(1);
            }
        };
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if dump.signature.len() != 64 {
            eprintln!(
                "Error: dump signature is {} bytes, expected 64",
                dump.signature.len()
            );
            std::process::exit(1);
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey_bytes);
        let vk = VerifyingKey::from_bytes(&pk_arr).unwrap_or_else(|e| {
            eprintln!("Error: local domain pubkey invalid: {e}");
            std::process::exit(1);
        });
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&dump.signature);
        let sig = Signature::from_bytes(&sig_arr);
        let msg = dump.signing_bytes();
        if vk.verify(&msg, &sig).is_err() {
            eprintln!(
                "Error: dump signature does not verify against local domain \
                 pubkey — the dump was tampered with or was exported by a \
                 different domain"
            );
            std::process::exit(1);
        }
    } else if allow_unsigned {
        // Operator has explicitly opted in to loading a legacy unsigned
        // dump (e.g. one-time migration from a pre-M-16 export). The
        // integrity of the payload depends entirely on the operator's
        // out-of-band chain of custody — there is no cryptographic
        // check after this point.
        eprintln!(
            "WARNING: loading legacy v{} dump with --allow-unsigned — \
             no cryptographic integrity check is possible. Verify the \
             dump was transferred through a trusted channel.",
            dump.version
        );
    } else {
        // **M-16 downgrade defense**: a v2 dump carries the signature
        // INSIDE the file, so a tamper that strips the signature and
        // rewrites `version` to 1 would bypass verification. Refuse
        // v1 by default; require an explicit `--allow-unsigned` flag
        // to proceed.
        eprintln!(
            "Error: refusing to import legacy v{} dump — pre-v{DUMP_VERSION} \
             dumps carry no signature and are indistinguishable from a \
             tampered signed dump where the signature was stripped. \
             Re-export from an up-to-date host for a signed v{DUMP_VERSION} \
             dump, or pass --allow-unsigned if the dump's integrity is \
             established through other means.",
            dump.version
        );
        std::process::exit(1);
    }

    println!("Dump:");
    println!("  Domain:      {}", dump.domain_id);
    println!("  Exported at: {}", dump.exported_at);
    println!("  Tokens:      {}", dump.tokens.len());
    println!("  Operations:  {}", dump.operations.len());
    println!("  Revoked:     {}", dump.revoked.len());
    println!("  Burned:      {}", dump.burned.len());

    if dry_run {
        println!("(dry run — no writes performed)");
        return;
    }

    let mut store = open_store_or_exit(data_dir, true);

    let mut new_tokens = 0usize;
    let mut dup_tokens = 0usize;
    for (i, raw) in dump.tokens.iter().enumerate() {
        let token = dds_core::token::Token::from_cbor(raw).unwrap_or_else(|e| {
            eprintln!("Failed to decode token #{i}: {e}");
            std::process::exit(1);
        });
        let jti = token.payload.jti.clone();
        if store.has_token(&jti) {
            dup_tokens += 1;
        } else {
            new_tokens += 1;
        }
        store.put_token(&token).unwrap_or_else(|e| {
            eprintln!("Failed to write token {jti}: {e}");
            std::process::exit(1);
        });
    }

    let mut new_ops = 0usize;
    let mut dup_ops = 0usize;
    for (i, raw) in dump.operations.iter().enumerate() {
        let op: dds_core::crdt::causal_dag::Operation = ciborium::de::from_reader(raw.as_slice())
            .unwrap_or_else(|e| {
                eprintln!("Failed to decode operation #{i}: {e}");
                std::process::exit(1);
            });
        let inserted = store.put_operation(&op).unwrap_or_else(|e| {
            eprintln!("Failed to write operation {}: {e}", op.id);
            std::process::exit(1);
        });
        if inserted {
            new_ops += 1;
        } else {
            dup_ops += 1;
        }
    }

    for jti in &dump.revoked {
        store.revoke(jti).unwrap_or_else(|e| {
            eprintln!("Failed to revoke {jti}: {e}");
            std::process::exit(1);
        });
    }
    for urn in &dump.burned {
        store.burn(urn).unwrap_or_else(|e| {
            eprintln!("Failed to burn {urn}: {e}");
            std::process::exit(1);
        });
    }

    println!("Imported:");
    println!("  Tokens:     {new_tokens} new, {dup_tokens} already present");
    println!("  Operations: {new_ops} new, {dup_ops} already present");
    println!("  Revoked:    {} applied", dump.revoked.len());
    println!("  Burned:     {} applied", dump.burned.len());
}

// ================================================================
// pq (Z-1 Phase B operator surface)
// ================================================================

async fn handle_pq(action: PqAction, data_dir: &Path, node_url: &str) {
    match action {
        PqAction::Status => handle_pq_status(data_dir),
        PqAction::ListPubkeys => handle_pq_list_pubkeys(data_dir),
        PqAction::Rotate => handle_pq_rotate(node_url).await,
    }
}

async fn handle_pq_rotate(node_url: &str) {
    let status = post_no_body(node_url, "/v1/pq/rotate", &()).await;
    if status.is_success() {
        println!("Epoch key rotation triggered.");
    } else {
        eprintln!("Error: node returned HTTP {status}");
        std::process::exit(1);
    }
}

/// Hex-encode the first 8 bytes of `sha256(bytes)` (16 lowercase hex
/// chars) — a stable short fingerprint suitable for human comparison.
fn pq_pubkey_short_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

fn handle_pq_status(data_dir: &Path) {
    let epoch_path = data_dir.join("epoch_keys.cbor");
    let cert_path = data_dir.join("peer_certs.cbor");
    println!("DDS PQ Status (Z-1 Phase B)");
    println!("  Data dir:                 {}", data_dir.display());
    if epoch_path.exists() {
        match dds_node::epoch_key_store::EpochKeyStore::load_or_create(&epoch_path, &mut OsRng) {
            Ok(store) => {
                let pk_bytes = store.kem_public().to_bytes();
                let (epoch_id, _) = store.my_current_epoch();
                println!(
                    "  KEM pubkey hash (sha256:8): {}",
                    pq_pubkey_short_hash(&pk_bytes)
                );
                println!("  KEM pubkey size:          {} bytes", pk_bytes.len());
                println!("  KEM pubkey (hex):         {}", hex::encode(&pk_bytes));
                println!("  Current epoch_id:         {}", epoch_id);
                println!("  Cached peer releases:     {}", store.peer_release_count());
            }
            Err(e) => {
                eprintln!("Failed to load {}: {e}", epoch_path.display());
                std::process::exit(1);
            }
        }
    } else {
        println!(
            "  Epoch key store:          not initialized ({} missing)",
            epoch_path.display()
        );
    }
    if cert_path.exists() {
        match dds_node::peer_cert_store::load_or_empty(&cert_path) {
            Ok(certs) => {
                let total = certs.len();
                let kem_capable = certs.iter_kem_pubkeys().count();
                println!("  Cached peer certs:        {total}");
                println!("    With pq_kem_pubkey:     {kem_capable}");
                if total > 0 {
                    let pct = (kem_capable as f64 / total as f64) * 100.0;
                    println!("    v3 coverage:            {pct:.1}%");
                }
            }
            Err(e) => {
                eprintln!("Failed to load {}: {e}", cert_path.display());
                std::process::exit(1);
            }
        }
    } else {
        println!(
            "  Peer cert cache:          not initialized ({} missing)",
            cert_path.display()
        );
    }
}

fn handle_pq_list_pubkeys(data_dir: &Path) {
    let cert_path = data_dir.join("peer_certs.cbor");
    if !cert_path.exists() {
        println!("No peer cert cache at {}", cert_path.display());
        println!("Run dds-node and complete at least one H-12 admission handshake first.");
        return;
    }
    let certs = match dds_node::peer_cert_store::load_or_empty(&cert_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load {}: {e}", cert_path.display());
            std::process::exit(1);
        }
    };
    if certs.is_empty() {
        println!("No cached peer certs (cache file is empty).");
        return;
    }
    println!("Cached peer admission certs ({} total)", certs.len());
    println!("{:<60} {:>6}  KEM_HASH (sha256:8)", "PEER_ID", "KEM");
    for (peer_id, cert) in certs.iter() {
        match &cert.pq_kem_pubkey {
            Some(pk) => {
                println!(
                    "{peer_id:<60} {:>6}  {}",
                    pk.len(),
                    pq_pubkey_short_hash(pk),
                );
            }
            None => {
                println!("{peer_id:<60} {:>6}  -", "none");
            }
        }
    }
}

// ================================================================
// helpers + wire types
// ================================================================

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = OsRng;
    let bytes: [u8; 16] = rng.r#gen();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        (bytes[6] & 0x0f) | 0x40,
        bytes[7],
        (bytes[8] & 0x3f) | 0x80,
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

// ---- Wire types (mirror dds-node::http shapes, but defined locally so
// the CLI doesn't depend on the full dds-node crate) ----

#[derive(Serialize)]
struct EnrollUserRequest {
    label: String,
    credential_id: String,
    attestation_object_b64: String,
    client_data_hash_b64: String,
    rp_id: String,
    display_name: String,
    authenticator_type: String,
}

#[derive(Serialize)]
struct EnrollDeviceRequest {
    label: String,
    device_id: String,
    hostname: String,
    os: String,
    os_version: String,
    tpm_ek_hash: Option<String>,
    org_unit: Option<String>,
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct EnrollmentResponse {
    urn: String,
    jti: String,
    token_cbor_b64: String,
}

#[derive(Serialize)]
struct AdminVouchRequest {
    subject_urn: String,
    credential_id: String,
    authenticator_data: String,
    client_data_hash: String,
    signature: String,
    purpose: Option<String>,
}

#[derive(Deserialize)]
struct AdminVouchResponse {
    vouch_jti: String,
    subject_urn: String,
    admin_urn: String,
}

#[derive(Serialize)]
struct PolicyRequest {
    subject_urn: String,
    resource: String,
    action: String,
}

#[derive(Deserialize)]
struct PolicyResult {
    allowed: bool,
    reason: String,
}

#[derive(Deserialize)]
struct NodeStatusJson {
    peer_id: String,
    connected_peers: usize,
    dag_operations: usize,
    trust_graph_tokens: usize,
    trusted_roots: usize,
    store_tokens: usize,
    store_revoked: usize,
    store_burned: usize,
    uptime_secs: u64,
    /// Per-redb-table stored-byte snapshot. Mirrors the
    /// `dds_store_bytes{table=...}` Prometheus gauge from
    /// observability-plan.md Phase C, surfaced via `/v1/status` so
    /// `dds-cli stats` does not have to scrape `/metrics` to show
    /// on-disk usage. Absent (deserialised as `None`) when the node
    /// runs an older build that predates the field, *or* when the
    /// backend does not implement `StoreSizeStats` (in-memory test
    /// fixtures); empty (`Some({})`) when the backend supports the
    /// snapshot but has zero tables of interest, mirroring the
    /// "family present, no series" semantics of the Prometheus gauge.
    #[serde(default)]
    store_bytes: Option<std::collections::BTreeMap<String, u64>>,
    /// Unix-seconds timestamp of the most recent non-`ok` inbound H-12
    /// admission handshake. Mirrors the
    /// `dds_admission_handshake_last_failure_seconds` Prometheus
    /// gauge surfaced via `/v1/status`, closing the Phase F
    /// `last admission failure` deferred row. Absent (deserialised
    /// as `None`) on older nodes that predate the field and before
    /// the first non-`ok` admission outcome lands.
    #[serde(default)]
    last_admission_failure_ts: Option<u64>,
}

#[derive(Serialize)]
struct SessionAssertRequest {
    subject_urn: Option<String>,
    credential_id: String,
    client_data_hash: String,
    authenticator_data: String,
    signature: String,
    duration_secs: Option<u64>,
}

#[derive(Deserialize)]
struct SessionResponse {
    session_id: String,
    token_cbor_b64: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct EnrolledUser {
    subject_urn: String,
    display_name: String,
    credential_id: String,
}

#[derive(Deserialize)]
struct EnrolledUsersResponse {
    users: Vec<EnrolledUser>,
}

#[derive(Deserialize)]
struct ApplicablePolicyJson {
    jti: String,
    issuer: String,
    iat: u64,
}

#[derive(Deserialize)]
struct WindowsPoliciesPayload {
    policies: Vec<ApplicablePolicyJson>,
}

#[derive(Deserialize)]
struct WindowsSoftwarePayload {
    software: Vec<ApplicablePolicyJson>,
}

#[derive(Deserialize)]
struct MacosPoliciesPayload {
    policies: Vec<ApplicablePolicyJson>,
}

#[derive(Deserialize)]
struct MacosSoftwarePayload {
    software: Vec<ApplicablePolicyJson>,
}

#[derive(Deserialize)]
struct LinuxPoliciesPayload {
    policies: Vec<ApplicablePolicyJson>,
}

#[derive(Deserialize)]
struct LinuxSoftwarePayload {
    software: Vec<ApplicablePolicyJson>,
}

/// **H-2 / H-3 (security review)**: policy/software endpoints now
/// return a `SignedPolicyEnvelope`. The CLI is a diagnostic tool so
/// it only parses — real enforcement happens in the Policy Agents,
/// which pin the node pubkey and verify the signature before
/// dispatch. If `DDS_NODE_PUBKEY` is set, the CLI verifies too.
fn unwrap_envelope(env: dds_core::envelope::SignedPolicyEnvelope, expected_kind: &str) -> Vec<u8> {
    use base64::Engine as _;
    if env.kind != expected_kind {
        eprintln!(
            "warning: envelope kind {:?} does not match expected {:?} — refusing to parse",
            env.kind, expected_kind
        );
        std::process::exit(1);
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64.decode(&env.payload_b64).unwrap_or_else(|e| {
        eprintln!("envelope payload_b64 decode failed: {e}");
        std::process::exit(1);
    });
    if let Ok(pinned_b64) = std::env::var("DDS_NODE_PUBKEY") {
        let pinned = b64.decode(pinned_b64.trim()).unwrap_or_else(|e| {
            eprintln!("DDS_NODE_PUBKEY is not valid base64: {e}");
            std::process::exit(1);
        });
        let pinned: [u8; 32] = pinned.as_slice().try_into().unwrap_or_else(|_| {
            eprintln!("DDS_NODE_PUBKEY must decode to 32 bytes");
            std::process::exit(1);
        });
        let sig = b64.decode(&env.signature_b64).unwrap_or_else(|e| {
            eprintln!("envelope signature_b64 decode failed: {e}");
            std::process::exit(1);
        });
        let sig: [u8; 64] = sig.as_slice().try_into().unwrap_or_else(|_| {
            eprintln!("envelope signature must be 64 bytes");
            std::process::exit(1);
        });
        if dds_core::envelope::verify_envelope(
            &pinned,
            &env.device_urn,
            &env.kind,
            env.issued_at,
            &payload,
            &sig,
        )
        .is_err()
        {
            eprintln!("envelope signature did not verify against DDS_NODE_PUBKEY");
            std::process::exit(1);
        }
    } else {
        eprintln!("note: DDS_NODE_PUBKEY unset — skipping signature verification (dev mode)");
    }
    payload
}

#[derive(Serialize)]
struct ClaimAccountRequest {
    device_urn: String,
    session_token_cbor_b64: String,
}

#[derive(Deserialize)]
struct ClaimAccountResponse {
    subject_urn: String,
    username: String,
    full_name: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize)]
struct AuditEntry {
    action: String,
    node_urn: String,
    timestamp: u64,
    token_cbor_b64: String,
    /// Phase B.2 — full CBOR-encoded signed `AuditLogEntry`. Older
    /// nodes that have not yet shipped the field deserialise to `None`.
    #[serde(default)]
    entry_cbor_b64: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    chain_hash_hex: Option<String>,
    #[serde(default)]
    prev_hash_hex: Option<String>,
}

#[derive(Deserialize)]
struct AuditEntriesResponse {
    entries: Vec<AuditEntry>,
    total: usize,
}
