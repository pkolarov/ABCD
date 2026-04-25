//! DDS command-line interface.
//!
//! Provides subcommands for identity management, group operations,
//! policy evaluation, enrollment, admin bootstrap, platform applier
//! queries, audit-log inspection, and diagnostics.
//!
//! Commands that need a running `dds-node` share the top-level
//! `--node-url` flag (defaults to the loopback API at
//! `http://127.0.0.1:5551`).

mod client;
mod dump;

use clap::{Parser, Subcommand};
use client::{DEFAULT_NODE_URL, get_json, post_json, post_no_body};
use dds_core::identity::Identity;
use dds_store::RedbBackend;
use dds_store::traits::*;
use dump::{DUMP_VERSION, DdsDump};
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
    /// Export the local store to a single `.ddsdump` file for air-gapped sync.
    Export {
        /// Destination path for the dump file.
        #[arg(long)]
        out: PathBuf,
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
        Commands::Export { out } => handle_export(&cli.data_dir, &out),
        Commands::Import {
            input,
            dry_run,
            allow_unsigned,
        } => handle_import(&cli.data_dir, &input, dry_run, allow_unsigned),
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
    }
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

fn handle_export(data_dir: &Path, out: &Path) {
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

    let bytes = dump.to_cbor().unwrap_or_else(|e| {
        eprintln!("Failed to encode dump: {e}");
        std::process::exit(1);
    });

    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create {}: {e}", parent.display());
            std::process::exit(1);
        });
    }
    std::fs::write(out, &bytes).unwrap_or_else(|e| {
        eprintln!("Failed to write {}: {e}", out.display());
        std::process::exit(1);
    });
    // L-5 (security review): restrict dump file to owner-only read.
    // The dump contains revocation/burn lists that can reveal trust
    // graph internals; prior default permissions left it world-readable.
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
    println!("  Size:       {} bytes", bytes.len());
}

fn handle_import(data_dir: &Path, input: &Path, dry_run: bool, allow_unsigned: bool) {
    // Parse dump first — validating the file before opening the store means
    // a bad file never perturbs on-disk state.
    let bytes = std::fs::read(input).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {e}", input.display());
        std::process::exit(1);
    });
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
}

#[derive(Deserialize)]
struct AuditEntriesResponse {
    entries: Vec<AuditEntry>,
    total: usize,
}
