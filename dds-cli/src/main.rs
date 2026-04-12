//! DDS command-line interface.
//!
//! Provides subcommands for identity management, group operations,
//! policy evaluation, and diagnostics.

use clap::{Parser, Subcommand};
use dds_core::identity::Identity;
use dds_store::RedbBackend;
use dds_store::traits::*;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "dds", about = "Decentralized Directory Service CLI")]
struct Cli {
    /// Path to the storage directory.
    #[arg(long, default_value = ".dds")]
    data_dir: PathBuf,

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
    /// Group operations.
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Policy evaluation.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Store diagnostics.
    Status,
    /// Credential Provider operations (requires running dds-node).
    Cp {
        #[command(subcommand)]
        action: CpAction,
        /// dds-node HTTP API base URL.
        #[arg(long, default_value = "http://127.0.0.1:5551")]
        node_url: String,
    },
}

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

#[derive(Subcommand)]
enum GroupAction {
    /// Vouch for a user (add to group).
    Vouch {
        /// Voucher label (your identity).
        #[arg(long)]
        as_label: String,
        /// Target user URN.
        #[arg(long)]
        user: String,
        /// Group/purpose name.
        #[arg(long)]
        purpose: String,
    },
    /// Revoke a vouch by JTI.
    Revoke {
        /// Revoker label.
        #[arg(long)]
        as_label: String,
        /// JTI of the vouch to revoke.
        #[arg(long)]
        jti: String,
    },
}

#[derive(Subcommand)]
enum CpAction {
    /// List enrolled users (calls GET /v1/enrolled-users).
    EnrolledUsers {
        /// Device URN filter (empty = all).
        #[arg(long, default_value = "")]
        device_urn: String,
    },
    /// Issue a session from a FIDO2 assertion (calls POST /v1/session/assert).
    SessionAssert {
        /// FIDO2 credential ID (base64url).
        #[arg(long)]
        credential_id: String,
        /// Base64-encoded authenticatorData.
        #[arg(long)]
        authenticator_data: String,
        /// Base64-encoded SHA-256(clientDataJSON).
        #[arg(long)]
        client_data_hash: String,
        /// Base64-encoded assertion signature.
        #[arg(long)]
        signature: String,
        /// Override subject URN (default: looked up from credential).
        #[arg(long)]
        subject_urn: Option<String>,
        /// Session duration in seconds.
        #[arg(long, default_value = "3600")]
        duration_secs: u64,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Check if a subject can perform an action.
    Check {
        /// Subject identity URN.
        #[arg(long)]
        user: String,
        /// Resource identifier.
        #[arg(long)]
        resource: String,
        /// Action to check.
        #[arg(long)]
        action: String,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Identity { action } => handle_identity(action),
        Commands::Group { action } => handle_group(action, &cli.data_dir),
        Commands::Policy { action } => handle_policy(action),
        Commands::Status => handle_status(&cli.data_dir),
        Commands::Cp { action, node_url } => handle_cp(action, &node_url).await,
    }
}

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

fn handle_policy(action: PolicyAction) {
    match action {
        PolicyAction::Check {
            user,
            resource,
            action,
        } => {
            // Offline policy check (no store needed — just shows the framework)
            let trust_graph = dds_core::trust::TrustGraph::new();
            let engine = dds_core::policy::PolicyEngine::new();
            let roots = std::collections::BTreeSet::new();
            let decision = engine.evaluate(&user, &resource, &action, &trust_graph, &roots);
            println!("Policy decision: {decision}");
        }
    }
}

fn handle_status(data_dir: &Path) {
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

    println!("DDS Store Status");
    println!("  Path:         {}", db_path.display());
    println!("  Tokens:       {total}");
    println!("    Attestations: {attests}");
    println!("    Vouches:      {vouches}");
    println!("  Revocations:  {revoked}");
    println!("  Burns:        {burned}");
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---- Credential Provider commands ----

#[derive(Debug, Serialize)]
struct SessionAssertRequest {
    subject_urn: Option<String>,
    credential_id: String,
    client_data_hash: String,
    authenticator_data: String,
    signature: String,
    duration_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SessionResponse {
    session_id: String,
    token_cbor_b64: String,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct EnrolledUser {
    subject_urn: String,
    display_name: String,
    credential_id: String,
}

#[derive(Debug, Deserialize)]
struct EnrolledUsersResponse {
    users: Vec<EnrolledUser>,
}

async fn handle_cp(action: CpAction, node_url: &str) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    match action {
        CpAction::EnrolledUsers { device_urn } => {
            let url = format!("{node_url}/v1/enrolled-users");
            let resp = client
                .get(&url)
                .query(&[("device_urn", &device_urn)])
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    let body: EnrolledUsersResponse = r.json().await.unwrap();
                    if body.users.is_empty() {
                        println!("No enrolled users.");
                    } else {
                        println!("{} enrolled user(s):", body.users.len());
                        for u in &body.users {
                            println!("  {} ({})", u.display_name, u.subject_urn);
                            println!("    credential_id: {}", u.credential_id);
                        }
                    }
                }
                Ok(r) => {
                    eprintln!(
                        "Error: HTTP {} — {}",
                        r.status(),
                        r.text().await.unwrap_or_default()
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: cannot reach dds-node at {node_url}: {e}");
                    std::process::exit(1);
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
            let url = format!("{node_url}/v1/session/assert");
            let body = SessionAssertRequest {
                subject_urn,
                credential_id,
                client_data_hash,
                authenticator_data,
                signature,
                duration_secs: Some(duration_secs),
            };
            let resp = client.post(&url).json(&body).send().await;
            match resp {
                Ok(r) if r.status().is_success() => {
                    let session: SessionResponse = r.json().await.unwrap();
                    println!("Session issued:");
                    println!("  session_id:  {}", session.session_id);
                    println!("  expires_at:  {}", session.expires_at);
                    println!(
                        "  token (b64): {}...",
                        &session.token_cbor_b64[..64.min(session.token_cbor_b64.len())]
                    );
                }
                Ok(r) => {
                    eprintln!(
                        "Error: HTTP {} — {}",
                        r.status(),
                        r.text().await.unwrap_or_default()
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: cannot reach dds-node at {node_url}: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
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
