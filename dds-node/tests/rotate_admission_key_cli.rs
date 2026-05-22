//! End-to-end CLI test for `dds-node rotate-admission-key`
//! (Admin Guide § "Hardware-Bound Admission Keys — rotating the software key").
//!
//! Exercises the operator round-trip:
//! 1. `provision-admission-key --backend software` to create the initial key.
//! 2. `rotate-admission-key` to replace it with a fresh Ed25519 key.
//!
//! The new key must differ from the old one; the backup must survive under
//! `admission_key.bin.rotated.<timestamp>` by default and be absent with
//! `--no-backup`; stdout must report both pubkeys; and error paths for
//! missing data-dir and missing admission_key.bin must fail with clear
//! messages naming the remediation step.

use std::path::PathBuf;
use std::process::Command;

use dds_core::key_provider::{AdmissionPublicKey, KeyProvider};
use dds_node::key_provider::SoftwareKeyfile;

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn run_capture(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
}

/// Run `provision-admission-key --backend software` and return the pubkey hex.
fn provision_software_key(data_dir: &std::path::Path) -> String {
    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "software",
    ]));
    assert!(ok, "provision-admission-key must succeed; stderr={stderr}");
    // Extract pubkey_hex from stdout: "  pubkey_hex: <hex>"
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(hex) = line.strip_prefix("pubkey_hex:") {
            return hex.trim().to_string();
        }
    }
    panic!("provision-admission-key stdout did not include pubkey_hex:\n{stdout}");
}

/// Load the current software admission key pubkey from disk.
fn load_pubkey_hex(data_dir: &std::path::Path) -> String {
    let kp = SoftwareKeyfile::load_or_create(&data_dir.join("admission_key.bin")).unwrap();
    match kp.public_key() {
        AdmissionPublicKey::Ed25519(b) => hex::encode(b),
        AdmissionPublicKey::EcdsaP256(b) => hex::encode(b),
    }
}

/// Extract the backup path from a `rotate-admission-key` stdout line
/// `  backup:         <path>` or `  backup:         (skipped …)`.
/// Returns `None` if the backup was skipped.
fn parse_backup_path(stdout: &str, data_dir: &std::path::Path) -> Option<PathBuf> {
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("backup:") {
            let rest = rest.trim();
            if rest.starts_with('(') {
                return None;
            }
            let p = PathBuf::from(rest);
            assert!(
                p.starts_with(data_dir),
                "printed backup path {p:?} must be inside data_dir {data_dir:?}"
            );
            return Some(p);
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────
// Positive paths
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn rotate_admission_key_replaces_key_and_keeps_backup_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let old_pubkey_hex = provision_software_key(data_dir);
    let key_path = data_dir.join("admission_key.bin");
    let old_bytes = std::fs::read(&key_path).unwrap();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "rotate-admission-key must succeed; stderr={stderr}");

    // stdout must report both pubkeys.
    assert!(
        stdout.contains(&old_pubkey_hex),
        "stdout must include old_pubkey_hex ({old_pubkey_hex}); got:\n{stdout}"
    );
    assert!(
        stdout.contains("new_pubkey_hex:"),
        "stdout must include a new_pubkey_hex line; got:\n{stdout}"
    );

    // The on-disk key must differ from the original.
    let new_pubkey_hex = load_pubkey_hex(data_dir);
    assert_ne!(
        new_pubkey_hex, old_pubkey_hex,
        "rotation must produce a different key"
    );

    // A backup file with the `.rotated.` infix must exist and contain
    // the original bytes verbatim so the operator can recover.
    let backup_path = parse_backup_path(&stdout, data_dir)
        .expect("stdout must report a backup path when --no-backup is not set");
    let backup_bytes = std::fs::read(&backup_path).unwrap();
    assert_eq!(
        backup_bytes, old_bytes,
        "backup must be byte-identical to the pre-rotation key"
    );

    // stdout must include follow-up admin instructions.
    assert!(
        stdout.contains("dds-node admit"),
        "stdout must show admit hint; got:\n{stdout}"
    );
    assert!(
        stdout.contains("dds-node revoke-admission"),
        "stdout must show revoke-admission hint; got:\n{stdout}"
    );
}

#[test]
fn rotate_admission_key_no_backup_skips_backup_file() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    provision_software_key(data_dir);

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--no-backup",
    ]));
    assert!(
        ok,
        "rotate-admission-key --no-backup must succeed; stderr={stderr}"
    );
    assert!(
        stdout.contains("(skipped"),
        "stdout must indicate the backup was skipped; got:\n{stdout}"
    );

    // No `.rotated.` sibling files must exist.
    let rotated_siblings: Vec<String> = std::fs::read_dir(data_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("admission_key.bin.rotated"))
        .collect();
    assert!(
        rotated_siblings.is_empty(),
        "--no-backup must not leave any backup files; found {rotated_siblings:?}"
    );

    // New key must still be present and loadable.
    assert!(
        data_dir.join("admission_key.bin").exists(),
        "admission_key.bin must exist after --no-backup rotation"
    );
}

#[test]
fn rotate_admission_key_stdout_reports_old_and_new_pubkey_hex() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let old_hex = provision_software_key(data_dir);

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--no-backup",
    ]));
    assert!(ok, "rotate-admission-key must succeed; stderr={stderr}");

    // The old_pubkey_hex must be a 64-char hex string (32 B Ed25519).
    assert_eq!(old_hex.len(), 64, "old pubkey must be 32 bytes as hex");
    assert!(
        stdout.contains(&old_hex),
        "stdout must include old pubkey: {stdout}"
    );

    // Extract new_pubkey_hex and verify it is also 64 chars.
    let new_hex = load_pubkey_hex(data_dir);
    assert_eq!(new_hex.len(), 64, "new pubkey must be 32 bytes as hex");
    assert!(
        stdout.contains(&new_hex),
        "stdout must include new pubkey: {stdout}"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Error paths
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn rotate_admission_key_fails_when_data_dir_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-admission-key",
        "--data-dir",
        missing.to_str().unwrap(),
    ]));
    assert!(
        !ok,
        "rotate-admission-key must fail when data_dir does not exist"
    );
    assert!(
        stderr.contains("does not exist"),
        "stderr must explain the missing data_dir: {stderr}"
    );
}

#[test]
fn rotate_admission_key_fails_when_admission_key_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    // data_dir exists but no admission_key.bin — operator should be told to
    // run provision-admission-key first.
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(
        !ok,
        "rotate-admission-key must fail when admission_key.bin is absent"
    );
    assert!(
        stderr.contains("provision-admission-key"),
        "stderr must mention provision-admission-key as the remediation step: {stderr}"
    );
    // Must not have created any files.
    assert!(
        !data_dir.join("admission_key.bin").exists(),
        "rotate must not create admission_key.bin when it was missing"
    );
}

#[test]
fn rotate_admission_key_fails_without_data_dir_flag() {
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args(["rotate-admission-key"]));
    assert!(!ok, "must fail when --data-dir is omitted");
    assert!(
        stderr.contains("--data-dir"),
        "stderr must name the missing flag: {stderr}"
    );
}
