//! `dds-fido2` — production FIDO2 ceremony tool for macOS/Linux DDS admin
//! operations. Cross-platform counterpart to Windows' native
//! `DdsEnrollUser.exe`: mirrors its four ceremonies (bare enrollment,
//! bootstrap-admin setup, admin vouch, admin revoke-vouch) using raw
//! CTAP2 (`ctap-hid-fido2`) instead of the Windows WebAuthn API.
//!
//! Exit codes: `0` success, `2` error. (Windows' `DdsEnrollUser.exe` also
//! has a `3` "user cancelled" code sourced from the OS WebAuthn API's
//! explicit Cancel button; raw CTAP2 has no equivalent UI-level
//! cancellation — a key that's never touched just times out as an
//! ordinary error — so that code is not used here.)

mod api;
mod fido2;
mod store;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "dds-fido2",
    about = "FIDO2 ceremony tool for DDS admin operations (macOS/Linux)"
)]
struct Cli {
    /// dds-node HTTP API base URL. macOS/Linux packaged nodes default
    /// `network.api_addr` to a Unix socket with
    /// `trust_loopback_tcp_admin = false` — pass
    /// `--node-url unix:/path/to/dds.sock` for those, or this falls
    /// back to plain loopback TCP (dev/test nodes only).
    #[arg(long, global = true, default_value = api::DEFAULT_NODE_URL)]
    node_url: String,

    /// WebAuthn relying party ID. Must match the rp_id the node's
    /// enrolled credentials were created against.
    #[arg(long, global = true, default_value = "dds.local")]
    rp_id: String,

    /// Path to the admin credential store TOML file. Defaults to the
    /// OS-appropriate location under DDS_ROOT.
    #[arg(long, global = true)]
    credential_store: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register a brand-new person's FIDO2 key (bare enrollment). No
    /// admin credential needed, no UV required. One touch.
    NewUser {
        #[arg(long)]
        label: String,
        #[arg(long)]
        display_name: String,
    },

    /// Bootstrap the very first admin for a freshly-created domain.
    /// Only succeeds once, and only while dds-node's `.bootstrap`
    /// sentinel is present. Subsequent admins go through
    /// `vouch --purpose dds:admin`.
    AdminSetup {
        /// Local credential-store label for this admin (not sent to
        /// the server — purely for `--label` disambiguation on a box
        /// with more than one admin credential).
        #[arg(long, default_value = "admin")]
        label: String,
        /// Overwrite an existing credential-store entry under `--label`.
        #[arg(long)]
        force: bool,
    },

    /// Admin-vouch a subject for a purpose (admin's touch + PIN, UV
    /// required). Used e.g. to approve a person for session login
    /// (`--purpose dds:session`), promote a sub-admin
    /// (`--purpose dds:admin`), or authorize a node to publish policy
    /// (`--purpose dds:policy-publisher-<platform>`).
    Vouch {
        #[arg(long)]
        subject_urn: String,
        #[arg(long)]
        purpose: String,
        /// Which stored admin credential to use — required if the
        /// store holds more than one.
        #[arg(long)]
        label: Option<String>,
        /// Use this credential_id directly instead of the local store
        /// (e.g. an admin whose credential was never registered on
        /// this particular box). Mirrors `DdsEnrollUser.exe`'s
        /// `--credential-id` escape hatch.
        #[arg(long)]
        credential_id: Option<String>,
        /// Read the PIN from one line of stdin instead of prompting
        /// interactively. Scripted/e2e use only — never pass a PIN
        /// through a shell variable that could land in history.
        #[arg(long)]
        pin_stdin: bool,
    },

    /// Offboard a subject: revoke the vouches THIS admin issued for it
    /// (admin's touch + PIN, UV required). Omit `--purpose` to revoke
    /// every vouch this admin issued for the subject (full
    /// offboarding); pass `--purpose dds:admin` to demote a sub-admin.
    RevokeVouch {
        #[arg(long)]
        subject_urn: String,
        #[arg(long)]
        purpose: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        credential_id: Option<String>,
        #[arg(long)]
        pin_stdin: bool,
    },

    /// List admin credentials stored on this box (human inspection
    /// only — labels, truncated credential_id, created_at).
    ListAdmins,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    let store_path = cli
        .credential_store
        .clone()
        .unwrap_or_else(store::default_store_path);

    let result = match cli.command {
        Command::NewUser {
            label,
            display_name,
        } => cmd_new_user(&cli.node_url, &cli.rp_id, &label, &display_name).await,
        Command::AdminSetup { label, force } => {
            cmd_admin_setup(&cli.node_url, &cli.rp_id, &store_path, &label, force).await
        }
        Command::Vouch {
            subject_urn,
            purpose,
            label,
            credential_id,
            pin_stdin,
        } => {
            let auth = AdminAuth {
                store_path: &store_path,
                label: label.as_deref(),
                credential_id_override: credential_id.as_deref(),
                pin_stdin,
            };
            cmd_vouch(&cli.node_url, &cli.rp_id, auth, &subject_urn, &purpose).await
        }
        Command::RevokeVouch {
            subject_urn,
            purpose,
            label,
            credential_id,
            pin_stdin,
        } => {
            let auth = AdminAuth {
                store_path: &store_path,
                label: label.as_deref(),
                credential_id_override: credential_id.as_deref(),
                pin_stdin,
            };
            cmd_revoke_vouch(&cli.node_url, &cli.rp_id, auth, &subject_urn, purpose).await
        }
        Command::ListAdmins => cmd_list_admins(&store_path),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(2);
    }
}

async fn cmd_new_user(
    node_url: &str,
    rp_id: &str,
    label: &str,
    display_name: &str,
) -> Result<(), String> {
    let device = fido2::Device::open()?;
    println!("Touch your FIDO2 key to register {label}...");
    // hmac-secret = true: this person may later log in to a Windows node,
    // whose credential vault is sealed with the assertion-time HMAC output.
    // It cannot be added to the credential afterwards. See
    // `fido2::Device::make_credential`.
    let outcome = device.make_credential(rp_id, label.as_bytes(), label, display_name, true)?;

    let req = api::EnrollUserRequest {
        label: label.to_string(),
        credential_id: fido2::b64url(&outcome.credential_id),
        attestation_object_b64: fido2::b64(&outcome.attestation_object),
        client_data_hash_b64: fido2::b64(&outcome.client_data_hash),
        rp_id: rp_id.to_string(),
        display_name: display_name.to_string(),
        authenticator_type: "cross-platform".to_string(),
        client_data_json_b64: None,
        challenge_id: None,
    };
    let resp: api::EnrollmentResponse = api::post_json(node_url, "/v1/enroll/user", &req).await?;

    println!("Enrolled.");
    println!("  urn:           {}", resp.urn);
    println!("  jti:           {}", resp.jti);
    println!("  credential_id: {}", fido2::b64url(&outcome.credential_id));
    println!("  published:     {}", resp.published);
    Ok(())
}

async fn cmd_admin_setup(
    node_url: &str,
    rp_id: &str,
    store_path: &Path,
    label: &str,
    force: bool,
) -> Result<(), String> {
    let info: api::NodeInfoResponse = api::get_json(node_url, "/v1/node/info").await?;
    if !info.admin_setup_available {
        return Err(
            "Admin Setup is not available — an admin already exists for this domain, \
             or the .bootstrap sentinel is absent."
                .to_string(),
        );
    }

    let device = fido2::Device::open()?;
    ensure_pin_configured(&device)?;

    println!("Touch your FIDO2 key to create the admin credential...");
    // hmac-secret = false: admins vouch, they never unseal a credential
    // vault. Mirrors DdsTrayAgent/AdminFlow.cpp:186.
    let outcome =
        device.make_credential(rp_id, label.as_bytes(), label, "DDS Administrator", false)?;

    let req = api::EnrollUserRequest {
        label: "admin".to_string(),
        credential_id: fido2::b64url(&outcome.credential_id),
        attestation_object_b64: fido2::b64(&outcome.attestation_object),
        client_data_hash_b64: fido2::b64(&outcome.client_data_hash),
        rp_id: rp_id.to_string(),
        display_name: "DDS Administrator".to_string(),
        authenticator_type: "cross-platform".to_string(),
        client_data_json_b64: None,
        challenge_id: None,
    };
    let resp: api::EnrollmentResponse = api::post_json(node_url, "/v1/admin/setup", &req).await?;

    let credential_id_b64url = fido2::b64url(&outcome.credential_id);
    let mut cred_store = store::load(store_path)?;
    store::add(
        &mut cred_store,
        label,
        &credential_id_b64url,
        now_epoch(),
        force,
    )?;
    store::save(store_path, &cred_store)?;

    println!("Admin created.");
    println!("  urn:           {}", resp.urn);
    println!("  jti:           {}", resp.jti);
    println!("  credential_id: {credential_id_b64url}");
    println!("  published:     {}", resp.published);
    println!("  stored under label {label:?} at {}", store_path.display());
    Ok(())
}

/// Which stored admin credential to authenticate with, and how. Shared
/// by `vouch`/`revoke-vouch` and threaded through to
/// `run_admin_assertion_ceremony` — bundled into one struct so neither
/// site carries a long positional-argument list for what is really one
/// "how do we prove we're an admin" concern.
struct AdminAuth<'a> {
    store_path: &'a Path,
    label: Option<&'a str>,
    credential_id_override: Option<&'a str>,
    pin_stdin: bool,
}

async fn cmd_vouch(
    node_url: &str,
    rp_id: &str,
    auth: AdminAuth<'_>,
    subject_urn: &str,
    purpose: &str,
) -> Result<(), String> {
    let c = run_admin_assertion_ceremony(node_url, rp_id, auth, "vouch").await?;

    let req = api::AdminVouchRequest {
        subject_urn: subject_urn.to_string(),
        credential_id: c.credential_id_b64url,
        challenge_id: c.challenge_id,
        authenticator_data: c.authenticator_data_b64,
        client_data_hash: c.client_data_hash_b64,
        client_data_json_b64: None,
        signature: c.signature_b64,
        purpose: Some(purpose.to_string()),
    };
    let resp: api::AdminVouchResponse = api::post_json(node_url, "/v1/admin/vouch", &req).await?;

    println!("Vouch result:");
    println!("  subject_urn: {subject_urn}");
    println!("  purpose:     {purpose}");
    println!("  jti:         {}", resp.vouch_jti);
    println!("  published:   {}", resp.published);
    Ok(())
}

async fn cmd_revoke_vouch(
    node_url: &str,
    rp_id: &str,
    auth: AdminAuth<'_>,
    subject_urn: &str,
    purpose: Option<String>,
) -> Result<(), String> {
    let c = run_admin_assertion_ceremony(node_url, rp_id, auth, "revoke-vouch").await?;

    let req = api::AdminRevokeVouchRequest {
        subject_urn: subject_urn.to_string(),
        credential_id: c.credential_id_b64url,
        challenge_id: c.challenge_id,
        authenticator_data: c.authenticator_data_b64,
        client_data_hash: c.client_data_hash_b64,
        client_data_json_b64: None,
        signature: c.signature_b64,
        purpose,
    };
    let resp: api::AdminRevokeVouchResponse =
        api::post_json(node_url, "/v1/admin/revoke-vouch", &req).await?;

    println!("Revoke-vouch result:");
    for r in &resp.revoked {
        println!(
            "  revoked jti={} target={} purpose={:?}",
            r.revoke_jti, r.target_jti, r.purpose
        );
    }
    for f in &resp.foreign {
        println!(
            "  foreign (ask {} to revoke): target={} purpose={:?}",
            f.issuer, f.target_jti, f.purpose
        );
    }
    println!(
        "  demoted_from_trusted_roots: {}",
        resp.demoted_from_trusted_roots
    );
    println!("  published: {}", resp.published);
    Ok(())
}

fn cmd_list_admins(store_path: &Path) -> Result<(), String> {
    let store = store::load(store_path)?;
    if store.admins.is_empty() {
        println!(
            "No admin credentials stored on this box ({}).",
            store_path.display()
        );
        return Ok(());
    }
    println!("Admin credentials stored at {}:", store_path.display());
    for a in &store.admins {
        let short = if a.credential_id.len() > 16 {
            format!("{}…", &a.credential_id[..16])
        } else {
            a.credential_id.clone()
        };
        println!(
            "  {:<16} credential_id={short} created_at={}",
            a.label, a.created_at
        );
    }
    Ok(())
}

/// Shared read + FIDO2-assertion half of `vouch`/`revoke-vouch` — the
/// only difference between them is which endpoint the resulting
/// signature gets POSTed to and the shape of `purpose`.
struct AssertionCeremony {
    credential_id_b64url: String,
    challenge_id: String,
    authenticator_data_b64: String,
    client_data_hash_b64: String,
    signature_b64: String,
}

async fn run_admin_assertion_ceremony(
    node_url: &str,
    rp_id: &str,
    auth: AdminAuth<'_>,
    action_verb: &str,
) -> Result<AssertionCeremony, String> {
    let credential_id_b64url = match auth.credential_id_override {
        Some(cid) => cid.to_string(),
        None => {
            let store = store::load(auth.store_path)?;
            store::resolve(&store, auth.label)?.credential_id.clone()
        }
    };
    let credential_id_bytes = fido2::b64url_decode(&credential_id_b64url)?;

    let device = fido2::Device::open()?;
    let pin = acquire_pin(auth.pin_stdin, &device)?;
    let pin_ref: Option<&str> = pin.as_ref().map(|z| z.as_str());

    let challenge: api::ChallengeResponse = api::get_json(node_url, "/v1/admin/challenge").await?;

    println!("Touch your FIDO2 key to {action_verb}...");
    let assertion = device.get_assertion(
        rp_id,
        &credential_id_bytes,
        &challenge.challenge_b64url,
        pin_ref,
    )?;

    Ok(AssertionCeremony {
        credential_id_b64url,
        challenge_id: challenge.challenge_id,
        authenticator_data_b64: fido2::b64(&assertion.authenticator_data),
        client_data_hash_b64: fido2::b64(&assertion.client_data_hash),
        signature_b64: fido2::b64(&assertion.signature),
    })
}

/// Acquire the PIN needed for a UV-required assertion. Refuses to
/// proceed silently on an authenticator that has PIN capability but no
/// PIN set (the server would just reject the resulting non-UV
/// assertion with a confusing error) — points the operator at
/// `admin-setup` instead, which offers to set one.
fn acquire_pin(
    pin_stdin: bool,
    device: &fido2::Device,
) -> Result<Option<Zeroizing<String>>, String> {
    match device.pin_status()? {
        fido2::PinStatus::Unsupported => {
            eprintln!(
                "WARN: this authenticator has no PIN capability; the resulting assertion \
                 will lack User Verification and the server will reject it."
            );
            Ok(None)
        }
        fido2::PinStatus::NotSet => Err(
            "this authenticator has PIN capability but no PIN is set — run \
             `dds-fido2 admin-setup` again (it offers to set one), or otherwise set a \
             PIN before vouching"
                .to_string(),
        ),
        fido2::PinStatus::Set => {
            if pin_stdin {
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|e| format!("reading PIN from stdin: {e}"))?;
                Ok(Some(Zeroizing::new(
                    line.trim_end_matches(['\r', '\n']).to_string(),
                )))
            } else {
                let pin = rpassword::prompt_password("FIDO2 PIN: ")
                    .map_err(|e| format!("reading PIN: {e}"))?;
                Ok(Some(Zeroizing::new(pin)))
            }
        }
    }
}

/// Offer to set a PIN on a fresh authenticator during `admin-setup` —
/// without one, `vouch`/`revoke-vouch` (which require UV) could never
/// work for this admin. Registration itself doesn't require UV, so
/// this is advisory, not a hard gate.
fn ensure_pin_configured(device: &fido2::Device) -> Result<(), String> {
    match device.pin_status()? {
        fido2::PinStatus::Set => Ok(()),
        fido2::PinStatus::Unsupported => {
            eprintln!(
                "WARN: this authenticator has no PIN capability; vouch/revoke-vouch \
                 (which require User Verification) will not work with it."
            );
            Ok(())
        }
        fido2::PinStatus::NotSet => {
            eprintln!("This authenticator has no PIN set yet.");
            eprintln!("A PIN is required for future admin approvals (vouch/revoke-vouch).");
            print!("Set a PIN now? [Y/n]: ");
            use std::io::Write;
            std::io::stdout().flush().ok();
            let mut resp = String::new();
            std::io::stdin()
                .read_line(&mut resp)
                .map_err(|e| format!("reading response: {e}"))?;
            let resp = resp.trim().to_ascii_lowercase();
            if resp == "n" || resp == "no" {
                eprintln!(
                    "WARN: proceeding without a PIN; vouch/revoke-vouch will not work \
                     until one is set."
                );
                return Ok(());
            }
            loop {
                let pin1 = rpassword::prompt_password("New FIDO2 PIN: ")
                    .map_err(|e| format!("reading PIN: {e}"))?;
                let pin2 = rpassword::prompt_password("Confirm PIN: ")
                    .map_err(|e| format!("reading PIN: {e}"))?;
                if pin1 != pin2 {
                    eprintln!("PINs did not match, try again.");
                    continue;
                }
                device.set_new_pin(&pin1)?;
                println!("PIN set.");
                break;
            }
            Ok(())
        }
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
