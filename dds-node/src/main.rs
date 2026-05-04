//! DDS node entry point — starts the P2P node, storage, and local API.
//!
//! Subcommands (hand-rolled, no clap dependency):
//!
//! - `dds-node init-domain --name <NAME> --dir <DIR> [--fido2 | --legacy]`
//!   Genesis ceremony. Creates a fresh domain keypair, writes
//!   `<DIR>/domain.toml` (public — share with siblings) and
//!   `<DIR>/domain_key.bin` (secret — keep safe; encrypted with
//!   `DDS_DOMAIN_PASSPHRASE` if set). **Defaults to hybrid** (Ed25519 +
//!   ML-DSA-65 / FIPS 204) so the resulting `Domain` advertises a
//!   `pq_pubkey` and every `AdmissionCert` / `AdmissionRevocation`
//!   minted under it carries a PQ signature alongside the Ed25519 one
//!   (v4/v5 on-disk format). Pass `--legacy` only for benchmark or
//!   regression-test fixtures that explicitly need the v1/v2 Ed25519-only
//!   path; production deployments should never use it. `--fido2` selects
//!   the FIDO2-protected v3 format (Ed25519-only today); v6 hybrid+FIDO2
//!   is a future Phase A-3 follow-up. `--fido2`, `--legacy` are mutually
//!   exclusive.
//!
//! - `dds-node gen-node-key --data-dir <DIR>`
//!   Generates the persistent libp2p keypair and prints the resulting
//!   `PeerId`. Run this on a sibling machine to discover the peer id
//!   that the admin needs in order to issue an admission cert.
//!
//! - `dds-node rotate-identity --data-dir <DIR> [--no-backup]`
//!   Threat-model §2 recommendation #3 / §8 open item #9. Generates a
//!   fresh libp2p Ed25519 keypair, atomically replaces
//!   `<DIR>/p2p_key.bin` with it (encrypted under `DDS_NODE_PASSPHRASE`
//!   if set), backs up the previous file as
//!   `p2p_key.bin.rotated.<unix_seconds>` unless `--no-backup` is
//!   passed, and prints both the old and new PeerIds along with the
//!   admin / operator next-step commands required to resume the node
//!   on its new identity (issue a fresh admission cert against the new
//!   PeerId, optionally revoke the old one, then restart). The
//!   command refuses to run if `<DIR>/p2p_key.bin` is missing — use
//!   `gen-node-key` for first-time provisioning.
//!
//! - `dds-node admit --domain-key <FILE> --domain <FILE> --peer-id <ID> [--out FILE] [--ttl-days N] [--kem-pubkey <HEX> | --kem-pubkey-path <FILE>]`
//!   The admin signs an admission cert for a sibling node's peer id.
//!   Pass `--kem-pubkey <HEX>` (from the peer's `gen-node-key` output) to
//!   embed the peer's hybrid KEM pubkey so enc-v3 encrypted gossip works on
//!   first connect. Ship the resulting cert to the sibling and place it at
//!   `<data_dir>/admission.cbor`.
//!
//! - `dds-node revoke-admission --domain-key <FILE> --domain <FILE> --peer-id <ID> [--reason <STR>] [--out FILE]`
//!   Threat-model §1 / open item #4. The admin issues a domain-signed
//!   admission revocation for `peer_id`. Ship the resulting CBOR file
//!   to every node and import it with `import-revocation`. Each node
//!   then refuses to admit (or, on its own peer id, refuses to start)
//!   the revoked peer.
//!
//! - `dds-node import-revocation --data-dir <DIR> --in <FILE> [--config <PATH>]`
//!   Append a revocation file to the local
//!   `<data_dir>/admission_revocations.cbor`. Idempotent. Restart the
//!   node so the new entry takes effect on the next admission
//!   handshake. Pass `--config <PATH>` to point at the node's
//!   `node.toml` (typical: `/etc/dds/node.toml`); without the flag
//!   the command falls back to `<data_dir>/dds.toml` for back-compat
//!   with older runbooks.
//!
//! - `dds-node list-revocations --data-dir <DIR> [--json] [--config <PATH>]`
//!   Print the current contents of the on-disk admission revocation
//!   list. Useful for verifying that an `import-revocation` (or an
//!   H-12 piggy-back gossip merge — see
//!   `dds_net::admission::AdmissionResponse.revocations`) actually
//!   landed. Read-only; safe to run while a node is live. `--json`
//!   emits one object per entry on stdout for scripting. `--config`
//!   has the same semantics as `import-revocation`.
//!
//! - `dds-node restrict-data-dir-acl --data-dir <DIR>`
//!   Threat-model §3 / open item #8. On Windows, applies an explicit,
//!   non-inherited DACL to `<DIR>` granting `FullControl` only to
//!   `LocalSystem` and `BUILTIN\Administrators`, with `OI`+`CI`
//!   inheritance so files created later (vault, HMAC secret, applied
//!   state, audit logs) pick up the same restriction without per-file
//!   work. Mirrors the L-16 helper in `AppliedStateStore` and the C++
//!   `FileLog::Init` self-heal. The MSI custom action
//!   `CA_RestrictDataDirAcl` invokes this immediately after
//!   `InstallFiles` and before `CA_GenHmacSecret` so the per-install
//!   `node-hmac.key` is created underneath the already-restricted DACL.
//!   No-op on non-Windows: Unix path security is enforced via per-file
//!   `0o600` / per-dir `0o700` modes set elsewhere (L-2/L-3/L-4/M-20).
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

#[cfg(windows)]
mod win_service;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    // Windows Service Control Manager dispatch path. Registered by the
    // MSI as `dds-node.exe service-run --config <path>`. Must NOT be
    // wrapped in a tokio runtime — `service_dispatcher::start` blocks
    // synchronously waiting for SCM and spins up tokio inside the
    // service handler. Using `#[tokio::main]` here would panic when the
    // dispatcher tries to build its own runtime.
    #[cfg(windows)]
    if raw_args.first().map(String::as_str) == Some("service-run") {
        return win_service::run();
    }

    // CLI / interactive path — build a tokio runtime ourselves so the
    // service-mode early-return above can stay synchronous.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(raw_args))
}

async fn async_main(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("run");

    match sub {
        "init-domain" => cmd_init_domain(&args[1..]),
        "gen-node-key" => cmd_gen_node_key(&args[1..]),
        "rotate-identity" => cmd_rotate_identity(&args[1..]),
        "gen-hmac-secret" => cmd_gen_hmac_secret(&args[1..]),
        "admit" => cmd_admit(&args[1..]),
        "revoke-admission" => cmd_revoke_admission(&args[1..]),
        "import-revocation" => cmd_import_revocation(&args[1..]),
        "list-revocations" => cmd_list_revocations(&args[1..]),
        "restrict-data-dir-acl" => cmd_restrict_data_dir_acl(&args[1..]),
        "create-provision-bundle" => cmd_create_bundle(&args[1..]),
        "provision" => cmd_provision(&args[1..]),
        "stamp-agent-pubkey" => cmd_stamp_agent_pubkey(&args[1..]),
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
  dds-node init-domain --name <NAME> --dir <DIR> [--fido2 | --legacy]
  dds-node gen-node-key --data-dir <DIR>
  dds-node rotate-identity --data-dir <DIR> [--no-backup]
  dds-node gen-hmac-secret --out <FILE> [--force] [--keep-existing]
  dds-node admit --domain-key <FILE> --domain <FILE> --peer-id <ID> [--kem-pubkey <HEX> | --kem-pubkey-path <FILE>] [--out <FILE>] [--ttl-days <N>]
  dds-node revoke-admission --domain-key <FILE> --domain <FILE> --peer-id <ID> [--reason <STR>] [--out <FILE>]
  dds-node import-revocation --data-dir <DIR> --in <FILE> [--config <PATH>]
  dds-node list-revocations --data-dir <DIR> [--json] [--config <PATH>]
  dds-node restrict-data-dir-acl --data-dir <DIR>
  dds-node create-provision-bundle --dir <DIR> --org <ORG> [--out <FILE>]
  dds-node provision <BUNDLE.dds> [--data-dir <DIR>] [--no-start]
  dds-node stamp-agent-pubkey --data-dir <DIR> --config-dir <DIR>
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
    // PQ-by-default: hybrid (Ed25519 + ML-DSA-65) is now the default for
    // new domains. `--legacy` opts back into v1/v2 Ed25519-only and is
    // intended only for benchmarks and regression-test fixtures that
    // explicitly need the legacy path. Production deployments should
    // never pass `--legacy`. `--fido2` keeps the v3 path (Ed25519-only
    // today; v6 hybrid+FIDO2 is a future Phase A-3 follow-up).
    let use_legacy = args.iter().any(|a| a == "--legacy");
    if use_legacy && use_fido2 {
        return Err(
            "--legacy and --fido2 are mutually exclusive: --legacy selects v1/v2 plain \
             Ed25519, --fido2 selects v3 FIDO2-protected Ed25519. Pick one or omit both \
             (the default is hybrid v4/v5)."
                .into(),
        );
    }
    let use_hybrid = !use_legacy && !use_fido2;
    std::fs::create_dir_all(&dir)?;

    let mut rng = rand::rngs::OsRng;
    let key = if use_hybrid {
        DomainKey::generate_hybrid(name, &mut rng)
    } else {
        DomainKey::generate(name, &mut rng)
    };
    let domain = key.domain();

    let domain_path = dir.join("domain.toml");
    let key_path = dir.join("domain_key.bin");
    // `save_domain_file` writes the optional `pq_pubkey` automatically
    // when the underlying `Domain` carries one (DomainFile field is
    // `#[serde(default, skip_serializing_if = "Option::is_none")]`).
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
        // `save_domain_key` picks the right on-disk version (v1 plain,
        // v2 encrypted, v4 plain hybrid, v5 encrypted hybrid) based on
        // `key.is_hybrid()` and `DDS_DOMAIN_PASSPHRASE`.
        domain_store::save_domain_key(&key_path, &key)?;
    }

    println!("Domain created:");
    println!("  name:        {}", domain.name);
    println!("  id:          {}", domain.id);
    println!("  pubkey:      {}", to_hex(&domain.pubkey));
    if let Some(pq) = &domain.pq_pubkey {
        println!(
            "  pq_pubkey:   {} ({} bytes ML-DSA-65)",
            to_hex(pq),
            pq.len()
        );
    }
    println!(
        "  domain.toml: {} (share with siblings)",
        domain_path.display()
    );
    println!("  domain_key:  {} (keep secret)", key_path.display());
    if use_hybrid {
        println!(
            "  scheme:      v2 hybrid (Ed25519 + ML-DSA-65) — Z-1 Phase A admission cert path (default)"
        );
    } else if use_legacy {
        println!(
            "  scheme:      v1 legacy (Ed25519 only) — for tests/benchmarks; do NOT use in production"
        );
    }
    if use_fido2 {
        println!("  protection:  FIDO2 hardware key (touch to unlock)");
    }
    Ok(())
}

fn cmd_gen_node_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    std::fs::create_dir_all(&data_dir)?;

    // p2p identity
    let p2p_path = data_dir.join("p2p_key.bin");
    let kp = p2p_identity::load_or_create(&p2p_path)?;
    let peer_id = libp2p::PeerId::from(kp.public());

    // Hybrid KEM keypair — generate (or reload) early so the admin can
    // pass pq_kem_pubkey to `admit` at provisioning time rather than
    // waiting for the node's first run. (PQ-DEFAULT-2 fix.)
    let epoch_keys_path = data_dir.join("epoch_keys.cbor");
    let needs_save = !epoch_keys_path.exists();
    let mut rng = rand::thread_rng();
    let epoch_keys =
        dds_node::epoch_key_store::EpochKeyStore::load_or_create(&epoch_keys_path, &mut rng)
            .map_err(|e| format!("epoch_keys: {e}"))?;
    if needs_save {
        epoch_keys
            .save(&epoch_keys_path)
            .map_err(|e| format!("epoch_keys save: {e}"))?;
    }
    let kem_pubkey_hex = to_hex(&epoch_keys.kem_public().to_bytes());

    println!("Node libp2p identity:");
    println!("  data_dir:       {}", data_dir.display());
    println!("  p2p_key:        {}", p2p_path.display());
    println!("  peer_id:        {peer_id}");
    println!("  kem_pubkey_hex: {kem_pubkey_hex}");
    println!();
    println!("Send the peer_id and kem_pubkey_hex to the domain admin to obtain an");
    println!("admission cert.  The admin should pass --kem-pubkey <HEX> to `admit`");
    println!("so that enc-v3 encrypted gossip is enabled immediately on first connect.");
    Ok(())
}

/// Threat-model §2 recommendation #3 / §8 open item #9: rotate the
/// node's libp2p identity in place.
///
/// Reads the existing `<data_dir>/p2p_key.bin` to record the old
/// PeerId, generates a fresh Ed25519 keypair, atomically replaces the
/// file with the new key (preserving on-disk encryption based on
/// `DDS_NODE_PASSPHRASE`), and — unless `--no-backup` — renames the
/// previous file to `p2p_key.bin.rotated.<unix_seconds>` first so
/// recovery is possible if the operator botches the restart.
///
/// The new PeerId invalidates the existing admission cert (which is
/// bound to the old PeerId via `AdmissionCert.body.peer_id`), so the
/// command prints the explicit follow-up commands the admin and
/// operator must run before the node will start again. The command
/// itself is purely local — it never contacts the admin, never
/// touches the admission cert, and never touches the running node.
///
/// Refuses to run if `<data_dir>/p2p_key.bin` does not exist; first-
/// time provisioning should use `gen-node-key` instead. Refuses to
/// load (and thus refuses to rotate) if the existing file is
/// encrypted but `DDS_NODE_PASSPHRASE` is unset — the operator must
/// supply the passphrase so we can read the old PeerId before
/// overwriting; otherwise the rotation would silently lose track of
/// the cert that needs to be revoked.
fn cmd_rotate_identity(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    let no_backup = args.iter().any(|a| a == "--no-backup");

    if !data_dir.exists() {
        return Err(format!(
            "data_dir {} does not exist — use `gen-node-key` for first-time provisioning",
            data_dir.display()
        )
        .into());
    }

    let p2p_path = data_dir.join("p2p_key.bin");
    if !p2p_path.exists() {
        return Err(format!(
            "no existing p2p_key.bin at {} — use `gen-node-key --data-dir {}` for first-time \
             provisioning (rotate-identity refuses to run without a prior key so the old PeerId \
             can be reported)",
            p2p_path.display(),
            data_dir.display()
        )
        .into());
    }

    // Decrypt + parse the old key so we can report the OLD PeerId. If
    // this fails (wrong passphrase, corrupt blob), abort BEFORE
    // touching the file — the operator needs the old PeerId in order
    // to issue a revocation, so silently rotating without it would be
    // worse than refusing.
    let old_kp = p2p_identity::load(&p2p_path).map_err(|e| {
        format!(
            "failed to load existing p2p_key.bin at {}: {e} — rotate-identity refuses to \
             overwrite a key it cannot read; if the file is encrypted, set DDS_NODE_PASSPHRASE \
             to the same value the running node uses",
            p2p_path.display()
        )
    })?;
    let old_peer_id = libp2p::PeerId::from(old_kp.public());

    let backup_path = if no_backup {
        None
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let candidate = data_dir.join(format!("p2p_key.bin.rotated.{now}"));
        // Refuse to clobber an existing backup at the exact same
        // second. Bumping the suffix is simpler than overwriting a
        // file the operator may need.
        let mut final_path = candidate.clone();
        let mut suffix = 1u32;
        while final_path.exists() {
            final_path = data_dir.join(format!("p2p_key.bin.rotated.{now}.{suffix}"));
            suffix += 1;
        }
        std::fs::rename(&p2p_path, &final_path).map_err(|e| {
            format!(
                "failed to back up existing p2p_key.bin to {}: {e}",
                final_path.display()
            )
        })?;
        Some(final_path)
    };

    // Generate the new keypair via the same path as gen-node-key /
    // load_or_create so the on-disk encryption schema stays
    // consistent (v=3 ChaCha20-Poly1305 + Argon2id under
    // DDS_NODE_PASSPHRASE; v=1 plaintext otherwise). We do NOT use
    // load_or_create here because, if --no-backup left the file in
    // place, load_or_create would return the OLD key.
    let new_kp = libp2p::identity::Keypair::generate_ed25519();
    if let Err(e) = p2p_identity::save(&p2p_path, &new_kp) {
        // Best-effort recovery: if we have a backup, try to put it
        // back. Failure to restore is non-fatal — the operator still
        // has the named backup file and can rename manually.
        if let Some(ref bak) = backup_path
            && let Err(restore_err) = std::fs::rename(bak, &p2p_path)
        {
            return Err(format!(
                "failed to save new p2p_key.bin: {e}; tried to restore backup from {} but \
                 rename failed: {restore_err}. Manually rename {} back to {} to recover.",
                bak.display(),
                bak.display(),
                p2p_path.display()
            )
            .into());
        }
        return Err(format!(
            "failed to save new p2p_key.bin at {}: {e}",
            p2p_path.display()
        )
        .into());
    }
    let new_peer_id = libp2p::PeerId::from(new_kp.public());

    println!("Rotated node libp2p identity:");
    println!("  data_dir:    {}", data_dir.display());
    println!("  p2p_key:     {}", p2p_path.display());
    println!("  old_peer_id: {old_peer_id}");
    println!("  new_peer_id: {new_peer_id}");
    if let Some(ref bak) = backup_path {
        println!("  backup:      {}", bak.display());
    } else {
        println!("  backup:      (skipped — --no-backup)");
    }
    println!();
    println!("The existing admission cert is now invalid (it was bound to the old peer id).");
    println!("Before restarting the node, the admin must:");
    println!();
    println!("  1. Issue a fresh admission cert for the new peer id and ship it to this node:");
    println!(
        "       # The epoch (KEM) key is unchanged by rotation — get kem_pubkey_hex by running:"
    );
    println!(
        "       #   dds-node gen-node-key --data-dir {}", data_dir.display()
    );
    println!(
        "       dds-node admit --domain-key <FILE> --domain <FILE> \\\n         --peer-id {new_peer_id} --kem-pubkey <HEX> --out admission.cbor"
    );
    println!(
        "     Then place admission.cbor at {}.",
        data_dir.join("admission.cbor").display()
    );
    println!();
    println!(
        "  2. (Recommended) Revoke the old peer id so a stolen copy of the old keypair cannot rejoin:"
    );
    println!(
        "       dds-node revoke-admission --domain-key <FILE> --domain <FILE> \\\n         --peer-id {old_peer_id} --reason \"identity rotated\" --out old_revocation.cbor"
    );
    println!(
        "     Distribute old_revocation.cbor to every peer node and import with `import-revocation`,"
    );
    println!("     or rely on H-12 piggy-back gossip once at least one peer has it.");
    println!();
    println!("  3. Restart the node so the new identity takes effect.");
    Ok(())
}

/// **H-6 step-2 (security review)**: generate a 32-byte random HMAC
/// secret suitable for use as `NetworkConfig.api_auth.node_hmac_secret_path`
/// on the node side and as the matching verification key on the C++
/// Auth Bridge side. The MSI installs this at first run so the
/// per-install secret is unique to each deployment and fresh on every
/// clean install.
///
/// By default refuses to overwrite an existing file — pass `--force`
/// to replace. On Unix the file is written via atomic rename with
/// `0o600`. On Windows the default ACL applied by `std::fs::write` is
/// inherited from `ProgramData\DDS`, which the MSI restricts to
/// `LocalSystem` + `BUILTIN\Administrators` via the
/// `CA_RestrictDataDirAcl` custom action (see `restrict-data-dir-acl`,
/// scheduled to run *before* `CA_GenHmacSecret`); we don't re-apply
/// the DACL here to avoid drifting from the MSI-installed permissions.
fn cmd_gen_hmac_secret(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use rand::RngCore;
    let out = PathBuf::from(require_flag(args, "--out")?);
    let force = args.iter().any(|a| a == "--force");
    // The MSI custom action passes --keep-existing so reinstalls/repairs/upgrades
    // do not rotate the secret (which would desynchronise dds-node from the
    // Windows Auth Bridge — see DdsBundle.wxs CA_GenHmacSecret). Humans running
    // the command directly still get the refuse-to-overwrite safety net.
    let keep_existing = args.iter().any(|a| a == "--keep-existing");
    if out.exists() {
        if keep_existing {
            println!(
                "HMAC secret already exists at {} — keeping it (--keep-existing)",
                out.display()
            );
            return Ok(());
        }
        if !force {
            eprintln!(
                "refusing to overwrite existing HMAC secret at {} (pass --force to replace)",
                out.display()
            );
            std::process::exit(1);
        }
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    // Atomic write via tempfile in the target directory so a crash
    // mid-write can't leave a torn file.
    let parent = out.parent().unwrap_or_else(|| std::path::Path::new("."));
    use std::io::Write as _;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&secret)?;
    tmp.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.persist(&out)?;

    println!("Wrote 32-byte HMAC secret to {}", out.display());
    println!("Configure dds-node's network.api_auth.node_hmac_secret_path");
    println!("to this path, and distribute the same file to the Windows");
    println!("Auth Bridge service (it reads it from its HmacSecretPath");
    println!("registry value).");
    Ok(())
}

fn cmd_admit(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let domain_key_path = PathBuf::from(require_flag(args, "--domain-key")?);
    let domain_path = PathBuf::from(require_flag(args, "--domain")?);
    let peer_id = require_flag(args, "--peer-id")?;
    let out = PathBuf::from(flag(args, "--out").unwrap_or("admission.cbor"));
    let ttl_days: Option<u64> = flag(args, "--ttl-days").map(|s| s.parse()).transpose()?;

    // PQ-DEFAULT-2: accept the peer's hybrid KEM pubkey so enc-v3 encrypted
    // gossip can start immediately after admission. The peer obtains the hex
    // from `gen-node-key` output (printed as `kem_pubkey_hex`).
    // `--kem-pubkey-path <FILE>` is an alternative for scripted workflows.
    let kem_pubkey_hex: Option<String> =
        flag(args, "--kem-pubkey")
            .map(|s| s.to_string())
            .or_else(|| {
                flag(args, "--kem-pubkey-path")
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .map(|s| s.trim().to_string())
            });

    let kem_pubkey_bytes: Option<Vec<u8>> = match kem_pubkey_hex.as_deref() {
        Some(hex) if !hex.is_empty() => {
            let bytes =
                dds_domain::domain::from_hex(hex).map_err(|e| format!("--kem-pubkey: {e}"))?;
            if bytes.len() != dds_domain::HYBRID_KEM_PUBKEY_LEN {
                return Err(format!(
                    "--kem-pubkey: expected {} bytes, got {}",
                    dds_domain::HYBRID_KEM_PUBKEY_LEN,
                    bytes.len()
                )
                .into());
            }
            Some(bytes)
        }
        _ => None,
    };

    let key = domain_store::load_domain_key(&domain_key_path)?;
    let domain = domain_store::load_domain_file(&domain_path)?;
    if key.id() != domain.id {
        return Err("domain key does not match domain.toml id".into());
    }

    // Warn when admitting onto a hybrid enc-v3 domain without a KEM pubkey
    // — the peer will fall back to the EpochKeyRequest recovery path and
    // coverage stays at 0% until the cert is re-issued.
    if kem_pubkey_bytes.is_none() && domain.pq_pubkey.is_some() {
        eprintln!("WARNING: domain is hybrid but --kem-pubkey was not supplied.");
        eprintln!("  The peer will still be admitted, but encrypted-gossip (enc-v3) coverage");
        eprintln!("  will be 0% until the admission cert is re-issued with --kem-pubkey.");
        eprintln!("  Run `gen-node-key --data-dir <DIR>` on the peer to get kem_pubkey_hex.");
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let expires_at = ttl_days.map(|d| now + d * 86_400);
    let cert = key.issue_admission_with_kem(peer_id.to_string(), now, expires_at, kem_pubkey_bytes);
    domain_store::save_admission_cert(&out, &cert)?;

    println!("Admission cert issued:");
    println!("  domain:      {} ({})", domain.name, domain.id);
    println!("  peer_id:     {peer_id}");
    println!("  issued_at:   {now}");
    if let Some(exp) = expires_at {
        println!("  expires:     {exp}");
    } else {
        println!("  expires:     never");
    }
    if cert.pq_kem_pubkey.is_some() {
        println!(
            "  kem_pubkey:  set ({} bytes)",
            dds_domain::HYBRID_KEM_PUBKEY_LEN
        );
    } else {
        println!("  kem_pubkey:  not set");
    }
    println!("  out:         {}", out.display());
    Ok(())
}

/// Threat-model §1 / open item #4: issue a domain-signed admission
/// revocation. Ship the resulting CBOR file to every node and import
/// it with `import-revocation`. Revocations are permanent — to
/// re-admit the peer, generate a new libp2p keypair on the target
/// machine and issue a fresh admission cert for the new PeerId.
fn cmd_revoke_admission(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use dds_node::admission_revocation_store;

    let domain_key_path = PathBuf::from(require_flag(args, "--domain-key")?);
    let domain_path = PathBuf::from(require_flag(args, "--domain")?);
    let peer_id = require_flag(args, "--peer-id")?;
    let reason = flag(args, "--reason").map(|s| s.to_string());
    let out = PathBuf::from(flag(args, "--out").unwrap_or("admission_revocation.cbor"));

    let key = domain_store::load_domain_key(&domain_key_path)?;
    let domain = domain_store::load_domain_file(&domain_path)?;
    if key.id() != domain.id {
        return Err("domain key does not match domain.toml id".into());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let rev = key.revoke_admission(peer_id.to_string(), now, reason.clone());
    admission_revocation_store::save_revocation_file(&out, &rev)?;

    println!("Admission revocation issued:");
    println!("  domain:     {} ({})", domain.name, domain.id);
    println!("  peer_id:    {peer_id}");
    println!("  revoked_at: {now}");
    if let Some(r) = reason {
        println!("  reason:     {r}");
    }
    println!("  out:        {}", out.display());
    println!();
    println!("Distribute this file to every node in the domain and run:");
    println!(
        "  dds-node import-revocation --data-dir <DIR> --in {}",
        out.display()
    );
    Ok(())
}

/// Append a revocation file produced by `revoke-admission` into the
/// node's local revocation list at
/// `<data_dir>/admission_revocations.cbor`. Idempotent. The new entry
/// only takes effect at the next node restart, since the H-12
/// admission handshake is a per-connection event and the loaded list
/// is cached for the lifetime of the running process.
/// Locate and load the [`NodeConfig`] for a revocation command. Tries
/// `--config <PATH>` first (operator's explicit override — typical
/// production location is `/etc/dds/node.toml`), then falls back to
/// `<data_dir>/dds.toml` for back-compat with older runbooks. Emits
/// a single error message naming both possibilities so the operator
/// doesn't have to guess.
fn load_revocation_config(
    args: &[String],
    data_dir: &Path,
    cmd: &str,
) -> Result<NodeConfig, Box<dyn std::error::Error>> {
    if let Some(explicit) = flag(args, "--config") {
        let p = PathBuf::from(explicit);
        if !p.exists() {
            return Err(format!("--config {}: file does not exist", p.display()).into());
        }
        return Ok(NodeConfig::from_file(&p)?);
    }
    let fallback = data_dir.join("dds.toml");
    if fallback.exists() {
        return Ok(NodeConfig::from_file(&fallback)?);
    }
    Err(format!(
        "{cmd} needs the node's config to know which domain to verify the \
         revocation against. Pass --config <PATH> (e.g. /etc/dds/node.toml), \
         or place the config at {} so the data-dir fallback finds it.",
        fallback.display()
    )
    .into())
}

fn cmd_import_revocation(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use dds_node::admission_revocation_store;

    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    let in_path = PathBuf::from(require_flag(args, "--in")?);

    // We need the domain pubkey + id to verify the revocation on
    // import. Read them from the node's config — typically
    // `/etc/dds/node.toml` (passed via `--config`); for back-compat
    // we also accept a copy at `<data_dir>/dds.toml`.
    let cfg = load_revocation_config(args, &data_dir, "import-revocation")?;
    let domain_id = dds_domain::DomainId::parse(&cfg.domain.id)?;
    let pk_vec = dds_domain::domain::from_hex(&cfg.domain.pubkey)?;
    if pk_vec.len() != 32 {
        return Err("domain pubkey is not 32 bytes".into());
    }
    let mut domain_pubkey = [0u8; 32];
    domain_pubkey.copy_from_slice(&pk_vec);
    // **Z-1 Phase A** — when the configured domain is v2-hybrid,
    // route through the hybrid-aware import + load so the imported
    // revocation must carry a valid ML-DSA-65 `pq_signature`.
    let pq_pubkey = match cfg.domain.pq_pubkey.as_deref() {
        Some(hex) if !hex.is_empty() => Some(dds_domain::domain::from_hex(hex)?),
        _ => None,
    };

    let list_path = cfg.admission_revocations_path();
    let (added, _) = admission_revocation_store::import_into_with_pq(
        &list_path,
        &in_path,
        domain_id,
        domain_pubkey,
        pq_pubkey.clone(),
    )?;

    let store = admission_revocation_store::load_or_empty_with_pq(
        &list_path,
        domain_id,
        domain_pubkey,
        pq_pubkey,
    )?;
    if added {
        println!("Imported revocation into {}", list_path.display());
    } else {
        println!(
            "Revocation already present in {} (idempotent no-op)",
            list_path.display()
        );
    }
    println!("  total entries: {}", store.len());
    println!();
    println!("Restart the node for the new entry to take effect on the next");
    println!("admission handshake.");
    Ok(())
}

/// Read-only inspection of `<data_dir>/admission_revocations.cbor`.
/// Used by operators to verify which peers have been revoked locally
/// — both via manual `import-revocation` and via H-12 piggy-back gossip
/// (`AdmissionResponse.revocations`). The store is loaded under the
/// same domain-pubkey verification gate as the runtime path, so any
/// entries that fail to verify (corrupt file, foreign-domain
/// contamination) are dropped before they appear in the output.
///
/// Default output is human-readable; `--json` emits one JSON object
/// per revocation on stdout for scripting (e.g. piping into `jq`).
/// Always returns exit 0 if the store loads cleanly, even when empty
/// — callers can branch on `total_entries`.
fn cmd_list_revocations(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use dds_node::admission_revocation_store;

    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    let json = args.iter().any(|a| a == "--json");

    let cfg = load_revocation_config(args, &data_dir, "list-revocations")?;
    let domain_id = dds_domain::DomainId::parse(&cfg.domain.id)?;
    let pk_vec = dds_domain::domain::from_hex(&cfg.domain.pubkey)?;
    if pk_vec.len() != 32 {
        return Err("domain pubkey is not 32 bytes".into());
    }
    let mut domain_pubkey = [0u8; 32];
    domain_pubkey.copy_from_slice(&pk_vec);
    let pq_pubkey = match cfg.domain.pq_pubkey.as_deref() {
        Some(hex) if !hex.is_empty() => Some(dds_domain::domain::from_hex(hex)?),
        _ => None,
    };

    let list_path = cfg.admission_revocations_path();
    let store = admission_revocation_store::load_or_empty_with_pq(
        &list_path,
        domain_id,
        domain_pubkey,
        pq_pubkey,
    )?;
    let entries = store.entries();

    if json {
        for rev in entries {
            // Hand-rolled JSON object so we don't take a serde_json dep
            // for one read-only command. Field order matches the body
            // struct; `reason` is omitted when None to mirror CBOR.
            print!(
                "{{\"peer_id\":\"{peer}\",\"revoked_at\":{at}",
                peer = json_escape(&rev.body.peer_id),
                at = rev.body.revoked_at,
            );
            if let Some(r) = &rev.body.reason {
                print!(",\"reason\":\"{}\"", json_escape(r));
            }
            println!("}}");
        }
    } else {
        println!("Admission revocation list:");
        println!("  data_dir: {}", data_dir.display());
        println!("  file:     {}", list_path.display());
        println!("  domain:   {} ({})", cfg.domain.name, cfg.domain.id);
        println!("  entries:  {}", entries.len());
        if entries.is_empty() {
            println!();
            println!("  (no revocations on file)");
        } else {
            println!();
            for (i, rev) in entries.iter().enumerate() {
                println!("  [{i}] peer_id:    {}", rev.body.peer_id);
                println!("      revoked_at: {}", rev.body.revoked_at);
                if let Some(r) = &rev.body.reason {
                    println!("      reason:     {r}");
                }
            }
        }
    }
    Ok(())
}

/// Threat-model §3 / open item #8: apply a restrictive DACL to the
/// node data directory so child files (vault, HMAC secret, applied
/// state, audit logs) inherit `LocalSystem` + `BUILTIN\Administrators`
/// — only — full control instead of inheriting the wide-open
/// `%ProgramData%` parent ACL (which by default grants `BUILTIN\Users`
/// read on most Windows SKUs).
///
/// Mirrors the L-16 helper in `AppliedStateStore.SetWindowsDacl` and
/// the C++ `FileLog::Init` self-heal. Idempotent — re-applying the
/// same DACL is a no-op. Fails loudly so the MSI custom action
/// (`CA_RestrictDataDirAcl`) aborts the install if the call fails.
///
/// On non-Windows this is a friendly no-op: directory and file
/// security on Unix is enforced via `0o700`/`0o600` modes set in
/// `identity_store`, `domain_store`, and the redb backend (see
/// L-2/L-3/L-4/M-20). The subcommand still exists so the MSI custom
/// action can be exercised on cross-built test hosts.
fn cmd_restrict_data_dir_acl(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    if !data_dir.exists() {
        return Err(format!("data dir does not exist: {}", data_dir.display()).into());
    }
    if !data_dir.is_dir() {
        return Err(format!("not a directory: {}", data_dir.display()).into());
    }

    #[cfg(windows)]
    {
        apply_windows_data_dir_dacl(&data_dir)?;
        println!("Applied restricted DACL to {}", data_dir.display());
        println!(
            "  Grants: NT AUTHORITY\\SYSTEM (FullControl, OI+CI), \
             BUILTIN\\Administrators (FullControl, OI+CI)"
        );
        println!("  Inheritance from parent: disabled (PROTECTED)");
    }
    #[cfg(not(windows))]
    {
        println!(
            "restrict-data-dir-acl is a no-op on non-Windows: {} is \
             secured via per-file 0o600 + per-dir 0o700 modes set in \
             identity_store / domain_store / redb_backend.",
            data_dir.display()
        );
    }

    Ok(())
}

/// Apply the `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` SDDL via
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` +
/// `SetNamedSecurityInfoW` against the supplied directory. Pulls the
/// DACL out of the descriptor and writes it back with
/// `PROTECTED_DACL_SECURITY_INFORMATION` so inheritance from the
/// `%ProgramData%` parent is severed — children of `<data_dir>` then
/// inherit from this DACL only.
#[cfg(windows)]
fn apply_windows_data_dir_dacl(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    // SDDL identical to FileLog::Init (DdsAuthBridge) and
    // AppliedStateStore.SetWindowsDacl (DdsPolicyAgent):
    //   D:PAI               -> protected DACL, auto-inherited (drop parent ACEs)
    //   (A;OICI;FA;;;SY)   -> Allow, ObjectInherit+ContainerInherit, FileAll, LocalSystem
    //   (A;OICI;FA;;;BA)   -> Allow, OI+CI, FileAll, BUILTIN\Administrators
    let sddl: Vec<u16> = std::ffi::OsStr::new("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }

    let mut dacl_present: i32 = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted: i32 = 0;
    let got = unsafe {
        GetSecurityDescriptorDacl(psd, &mut dacl_present, &mut dacl, &mut dacl_defaulted)
    };
    if got == 0 || dacl_present == 0 || dacl.is_null() {
        unsafe { LocalFree(psd as *mut _) };
        return Err("SDDL produced no DACL — refusing to widen ACL".into());
    }

    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };

    unsafe { LocalFree(psd as *mut _) };

    // SetNamedSecurityInfoW returns ERROR_SUCCESS (0) on success.
    if rc != 0 {
        return Err(format!(
            "SetNamedSecurityInfoW failed (Win32 err = {rc}): {}",
            std::io::Error::from_raw_os_error(rc as i32)
        )
        .into());
    }
    Ok(())
}

/// Minimal JSON string escape — covers the characters that can appear
/// in a libp2p peer id (alphanumerics; never a quote or backslash) and
/// in operator-supplied `reason` strings (free-form, so we must escape
/// `"`, `\`, and control chars).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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

    let summary = provision::run_provision(&bundle_path, data_dir.as_deref(), !no_start)?;

    println!();
    println!("============================================================");
    println!("  Node Provisioned");
    println!("============================================================");
    println!();
    println!(
        "  Domain:     {} ({})",
        summary.domain_name, summary.domain_id
    );
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

/// **SC-3-W** — Windows MSI install-time helper. Loads (or creates) the
/// node Ed25519 identity and stamps `PinnedNodePubkeyB64` into the Policy
/// Agent's `appsettings.json` *before* the agent service first starts.
/// The agent fails closed on an empty pubkey (see
/// `platform/windows/DdsPolicyAgent/Program.cs`), so without this stamp
/// the SCM auto-start would crash-loop on a fresh MSI install. Wired
/// from `DdsBundle.wxs`'s `CA_StampAgentPubkey` custom action; safe to
/// run on hosts without the agent installed (returns success with a
/// notice if `appsettings.json` is absent).
fn cmd_stamp_agent_pubkey(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(require_flag(args, "--data-dir")?);
    let config_dir = PathBuf::from(require_flag(args, "--config-dir")?);
    match provision::stamp_pubkey(&data_dir, &config_dir)? {
        true => {
            println!(
                "Stamped Policy Agent PinnedNodePubkeyB64 from {} into appsettings.json (config_dir={})",
                data_dir.join("node_key.bin").display(),
                config_dir.display()
            );
        }
        false => {
            println!(
                "No Policy Agent appsettings.json found under {} (or %ProgramFiles%\\DDS\\config\\); \
                 nothing to stamp",
                config_dir.display()
            );
        }
    }
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

    // Z-3 Phase A.1 (observability-plan.md): hand the same identity
    // to the swarm event loop so gossip-ingest paths can stamp signed
    // audit-log entries on the local chain. `Identity` is not Clone
    // by design (single-copy invariant in security review L-1) — load
    // it a second time from the on-disk identity store. The store is
    // idempotent so we get the same Ed25519 keypair both times.
    let node_identity_for_swarm = identity_store::load_or_create(&identity_path, "dds-node")?;
    node.set_node_identity(node_identity_for_swarm);

    // Start the local HTTP API server alongside the P2P node. Share the
    // trust graph handle (Arc clone) so the swarm event loop and the
    // HTTP service observe the same in-memory state — fixes B5b.
    let api_addr = config.network.api_addr.clone();
    let trusted_roots = config.trusted_roots.iter().cloned().collect();
    let api_store = node.store.clone();
    let api_trust_graph = std::sync::Arc::clone(&node.trust_graph);
    // Seed the in-memory DAG and sync-payload cache from any operations
    // persisted in prior runs. Must run before the HTTP service starts
    // so sync responders can answer requests from the first peer contact.
    node.seed_dag_from_store();
    let mut svc = LocalService::new(node_identity, api_trust_graph, trusted_roots, api_store);
    svc.set_data_dir(config.data_dir.clone());
    svc.set_config_path(config_path.clone());
    // H-8 (security review): restore bootstrap admin identity from
    // durable config so the constraint survives restart.
    svc.set_bootstrap_admin_urn(config.bootstrap_admin_urn.clone());
    // M-7 (security review): apply device-scope vouch enforcement.
    svc.set_enforce_device_scope_vouch(config.domain.enforce_device_scope_vouch);
    // A-1 step-1: opt into unattested-credential enrollment iff the
    // operator set the flag explicitly in node.toml. Default is
    // `false` so production deployments require real attestation.
    svc.set_allow_unattested_credentials(config.domain.allow_unattested_credentials);
    // FIDO2 AAGUID allow-list (Phase 1 of
    // docs/fido2-attestation-allowlist.md). Refuse to start when the
    // operator wrote unparseable entries — silent fallback to "any
    // AAGUID" would be a foot-gun for hardened deployments that meant
    // to restrict enrollment.
    svc.set_fido2_allowed_aaguids(&config.domain.fido2_allowed_aaguids)
        .map_err(|e| format!("invalid fido2_allowed_aaguids: {e}"))?;
    if !config.domain.fido2_allowed_aaguids.is_empty() {
        info!(
            count = config.domain.fido2_allowed_aaguids.len(),
            "FIDO2 AAGUID allow-list enabled — enrollment restricted to listed authenticators"
        );
    }
    // FIDO2 attestation trust roots (Phase 2 of
    // docs/fido2-attestation-allowlist.md). Same fail-closed posture:
    // any I/O or parse error here aborts startup so the operator never
    // ends up with strict-mode silently disabled.
    svc.set_fido2_attestation_roots(&config.domain.fido2_attestation_roots)
        .map_err(|e| format!("invalid fido2_attestation_roots: {e}"))?;
    if !config.domain.fido2_attestation_roots.is_empty() {
        info!(
            count = config.domain.fido2_attestation_roots.len(),
            "FIDO2 attestation roots configured — listed AAGUIDs require chain to vendor CA"
        );
    }
    let shared_svc = Arc::new(tokio::sync::Mutex::new(svc));
    let node_info = http::NodeInfo {
        peer_id: node.peer_id.to_string(),
        // observability-plan.md Phase D.2 — share the swarm's "have we
        // ever connected to a peer" flag with the `/readyz` handler.
        peer_seen: node.peer_seen_handle(),
        bootstrap_empty: config.network.bootstrap_peers.is_empty(),
        // Same snapshot the Prometheus scrape reads for
        // `dds_peers_connected`; lets `/v1/status.connected_peers`
        // report a live count instead of the placeholder 0.
        peer_counts: Some(node.peer_counts_handle()),
    };
    let admin_policy = http::AdminPolicy::from_config(&config.network.api_auth);
    let response_mac_key = match &config.network.api_auth.node_hmac_secret_path {
        Some(path) => {
            let key = http::ResponseMacKey::from_file(path).map_err(|e| {
                format!(
                    "failed to load node HMAC secret from {}: {e}",
                    path.display()
                )
            })?;
            info!(path = %path.display(), "loaded node HMAC secret (H-6)");
            Some(key)
        }
        None => None,
    };
    // M-8: node-local device-caller binding store.
    let binding_path = dds_node::device_binding::DeviceBindingStore::default_path(&config.data_dir);
    let device_binding = Some(Arc::new(
        dds_node::device_binding::DeviceBindingStore::load_or_empty(binding_path.clone()).map_err(
            |e| {
                format!(
                    "failed to load device-binding store at {}: {e}",
                    binding_path.display()
                )
            },
        )?,
    ));
    // observability-plan.md Phase C — install the process-global
    // telemetry handle before any audit emission can fire (admin or
    // gossip). The `record_audit_entry` helper is a no-op until this
    // call lands; calling here keeps test fixtures (which never reach
    // `cmd_run`) telemetry-free.
    let telemetry_handle = dds_node::telemetry::install();
    if let Some(metrics_addr) = config.network.metrics_addr.clone() {
        let svc_for_metrics = Arc::clone(&shared_svc);
        let handle_for_metrics = Arc::clone(&telemetry_handle);
        // observability-plan.md Phase C — share the swarm-task peer
        // count snapshot with the metrics scrape so dds_peers_admitted
        // / dds_peers_connected report live values without reaching
        // into the swarm.
        let peer_counts_for_metrics = Some(node.peer_counts_handle());
        tokio::spawn(async move {
            if let Err(e) = dds_node::telemetry::serve(
                &metrics_addr,
                svc_for_metrics,
                handle_for_metrics,
                peer_counts_for_metrics,
            )
            .await
            {
                tracing::error!(addr = %metrics_addr, "metrics endpoint server error: {e}");
            }
        });
    }
    let manual_rotate = Some(node.manual_rotate.clone());
    tokio::spawn(async move {
        if let Err(e) = http::serve(
            &api_addr,
            shared_svc,
            node_info,
            admin_policy,
            response_mac_key,
            device_binding,
            manual_rotate,
        )
        .await
        {
            tracing::error!("HTTP API server error: {e}");
        }
    });

    info!(peer_id = %node.peer_id, "DDS node running — press Ctrl+C to stop");
    node.run().await
}

// Suppress dead-code warnings for the helper used only in cmd_run path
#[allow(dead_code)]
fn _silence_unused(_p: &Path) {}
