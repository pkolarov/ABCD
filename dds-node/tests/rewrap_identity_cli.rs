//! End-to-end CLI test for `dds-node rewrap-identity`
//! (Admin Guide § "Re-encrypting Node Keys Under a New Passphrase").
//!
//! Verifies the operator round-trip: re-encrypt `node_key.bin` and
//! `p2p_key.bin` with a new passphrase (or write plaintext when no
//! passphrase is set).  The PeerId must be identical after rewrap;
//! backup files must appear by default and be absent with `--no-backup`;
//! and error paths for missing data-dir and missing key files must fail
//! with clear messages.

use std::path::Path;
use std::process::Command;

use dds_core::identity::Identity;
use dds_node::{identity_store, p2p_identity};
use libp2p::{PeerId, identity::Keypair};
use rand::rngs::OsRng;

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn run_capture(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
}

/// Writes both node_key.bin and p2p_key.bin into data_dir (plaintext, no
/// passphrase).  Returns the PeerId so tests can verify it is unchanged.
fn create_node_keys(data_dir: &Path) -> PeerId {
    // p2p identity key (libp2p Ed25519)
    let p2p_path = data_dir.join("p2p_key.bin");
    let kp = Keypair::generate_ed25519();
    p2p_identity::save(&p2p_path, &kp).unwrap();

    // node signing identity key
    let node_path = data_dir.join("node_key.bin");
    let ident = Identity::generate("dds-node", &mut OsRng);
    identity_store::save(&node_path, &ident).unwrap();

    PeerId::from(kp.public())
}

// ──────────────────────────────────────────────────────────────────────────
// Error paths
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn rewrap_identity_missing_data_dir_fails() {
    // Create and immediately drop a tempdir so we have a guaranteed-absent path.
    let absent_path = {
        let tmp = tempfile::tempdir().unwrap();
        tmp.path().to_path_buf()
    };
    // tmp was dropped here, so absent_path no longer exists.
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        absent_path.to_str().unwrap(),
    ]));
    assert!(!ok, "should fail when data_dir does not exist");
    assert!(
        stderr.contains("does not exist") || stderr.contains("No such"),
        "error must mention missing dir; stderr={stderr}"
    );
}

#[test]
fn rewrap_identity_missing_node_key_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    // Only create p2p_key.bin; leave node_key.bin absent.
    let kp = Keypair::generate_ed25519();
    p2p_identity::save(&data_dir.join("p2p_key.bin"), &kp).unwrap();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(!ok, "should fail when node_key.bin is absent");
    assert!(
        stderr.contains("key file not found") || stderr.contains("node_key.bin"),
        "error must mention missing key file; stderr={stderr}"
    );
}

#[test]
fn rewrap_identity_missing_p2p_key_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    // Only create node_key.bin; leave p2p_key.bin absent.
    let ident = Identity::generate("dds-node", &mut OsRng);
    identity_store::save(&data_dir.join("node_key.bin"), &ident).unwrap();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(!ok, "should fail when p2p_key.bin is absent");
    assert!(
        stderr.contains("key file not found") || stderr.contains("p2p_key.bin"),
        "error must mention missing key file; stderr={stderr}"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Success paths
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn rewrap_identity_plaintext_roundtrip_peer_id_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let original_peer_id = create_node_keys(data_dir);

    // Run rewrap without passphrase — plaintext → plaintext.
    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "rewrap-identity must succeed; stderr={stderr}");
    assert!(
        stdout.contains("rewrap-identity complete"),
        "stdout must confirm completion; got: {stdout}"
    );

    // PeerId must be unchanged — the p2p key bytes are only re-saved, not replaced.
    let reloaded_kp = p2p_identity::load(&data_dir.join("p2p_key.bin")).unwrap();
    let new_peer_id = PeerId::from(reloaded_kp.public());
    assert_eq!(
        new_peer_id, original_peer_id,
        "PeerId must be unchanged after rewrap"
    );

    // node_key.bin must still be loadable.
    identity_store::load(&data_dir.join("node_key.bin"))
        .expect("node_key.bin must be loadable after rewrap");
}

#[test]
fn rewrap_identity_backup_created_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    create_node_keys(data_dir);

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "rewrap-identity must succeed; stderr={stderr}");

    assert!(
        data_dir.join("node_key.bin.bak").exists(),
        "node_key.bin.bak must be created by default"
    );
    assert!(
        data_dir.join("p2p_key.bin.bak").exists(),
        "p2p_key.bin.bak must be created by default"
    );
}

#[test]
fn rewrap_identity_no_backup_skips_backup_files() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    create_node_keys(data_dir);

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--no-backup",
    ]));
    assert!(ok, "rewrap-identity --no-backup must succeed; stderr={stderr}");

    assert!(
        !data_dir.join("node_key.bin.bak").exists(),
        "node_key.bin.bak must NOT be created with --no-backup"
    );
    assert!(
        !data_dir.join("p2p_key.bin.bak").exists(),
        "p2p_key.bin.bak must NOT be created with --no-backup"
    );
}

#[test]
fn rewrap_identity_stdout_reports_peer_id_and_encryption_status() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let original_peer_id = create_node_keys(data_dir);

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rewrap-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "rewrap-identity must succeed; stderr={stderr}");

    let peer_id_str = original_peer_id.to_string();
    assert!(
        stdout.contains(&peer_id_str),
        "stdout must include the peer_id ({peer_id_str}); got: {stdout}"
    );
    assert!(
        stdout.contains("PLAINTEXT"),
        "stdout must note plaintext status when no passphrase set; got: {stdout}"
    );
}
