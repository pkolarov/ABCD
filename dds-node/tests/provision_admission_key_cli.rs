//! End-to-end CLI test for `dds-node provision-admission-key`
//! (Admin Guide § "Hardware-Bound Admission Keys").
//!
//! Exercises the software backend round-trip and error paths:
//! - Positive: key is created and pubkey hex is printed.
//! - Idempotency: running twice with the same data_dir returns the same pubkey.
//! - Error: `--backend tpm2` returns a Phase A3 pending error.
//! - Error: `--backend <unknown>` is rejected with a clear message.
//! - Error: missing `--data-dir` is caught and named.

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

/// Parse the `pubkey_hex` from `provision-admission-key` stdout.
fn parse_pubkey_hex(stdout: &str) -> String {
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(hex) = line.strip_prefix("pubkey_hex:") {
            return hex.trim().to_string();
        }
    }
    panic!("provision-admission-key stdout did not include pubkey_hex:\n{stdout}");
}

// ──────────────────────────────────────────────────────────────────────────
// Positive paths
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn provision_admission_key_software_creates_key_file() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "software",
    ]));
    assert!(ok, "provision-admission-key --backend software must succeed; stderr={stderr}");

    // admission_key.bin must exist on disk.
    assert!(
        data_dir.join("admission_key.bin").exists(),
        "admission_key.bin must be written after provisioning"
    );

    // The printed pubkey must match what we can read from the file.
    let printed_hex = parse_pubkey_hex(&stdout);
    let kp = SoftwareKeyfile::load_or_create(&data_dir.join("admission_key.bin")).unwrap();
    let disk_hex = match kp.public_key() {
        AdmissionPublicKey::Ed25519(b) => hex::encode(b),
        AdmissionPublicKey::EcdsaP256(b) => hex::encode(b),
    };
    assert_eq!(
        printed_hex, disk_hex,
        "printed pubkey_hex must match the key on disk"
    );
}

#[test]
fn provision_admission_key_software_pubkey_is_32_bytes_hex() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "provision-admission-key must succeed; stderr={stderr}");

    let hex = parse_pubkey_hex(&stdout);
    // Ed25519 pubkey is 32 bytes = 64 hex chars.
    assert_eq!(
        hex.len(),
        64,
        "software Ed25519 pubkey must be 32 bytes (64 hex chars); got len={}: {hex}",
        hex.len()
    );
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "pubkey_hex must be hex digits only; got: {hex}"
    );
}

#[test]
fn provision_admission_key_is_idempotent() {
    // Running provision-admission-key twice on the same data_dir must
    // return the same pubkey both times (load-or-create semantics).
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok1, stdout1, stderr1) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "software",
    ]));
    assert!(ok1, "first provision must succeed; stderr={stderr1}");
    let hex1 = parse_pubkey_hex(&stdout1);

    let (ok2, stdout2, stderr2) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "software",
    ]));
    assert!(ok2, "second provision must succeed; stderr={stderr2}");
    let hex2 = parse_pubkey_hex(&stdout2);

    assert_eq!(
        hex1, hex2,
        "provision-admission-key must be idempotent — same key on repeated calls"
    );
}

#[test]
fn provision_admission_key_stdout_includes_backend_and_data_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "software",
    ]));
    assert!(ok, "provision-admission-key must succeed; stderr={stderr}");

    assert!(
        stdout.contains("backend:"),
        "stdout must include a backend line; got:\n{stdout}"
    );
    assert!(
        stdout.contains("software"),
        "backend line must mention 'software'; got:\n{stdout}"
    );
    assert!(
        stdout.contains(data_dir.to_str().unwrap()),
        "stdout must include the data_dir path; got:\n{stdout}"
    );
    // The admin follow-up command hint must be present.
    assert!(
        stdout.contains("dds-node admit"),
        "stdout must include admit hint for the admin; got:\n{stdout}"
    );
}

#[test]
fn provision_admission_key_default_backend_is_software() {
    // Omitting --backend must behave identically to --backend software.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        // No --backend flag.
    ]));
    assert!(ok, "provision without --backend must succeed; stderr={stderr}");
    assert!(
        data_dir.join("admission_key.bin").exists(),
        "admission_key.bin must be written when --backend is omitted"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Error paths
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn provision_admission_key_tpm2_returns_phase_a3_error() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "tpm2",
    ]));
    assert!(!ok, "provision with --backend tpm2 must fail");
    assert!(
        stderr.contains("Phase A3"),
        "error must mention Phase A3 pending status: {stderr}"
    );
}

#[test]
fn provision_admission_key_unknown_backend_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "provision-admission-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--backend",
        "hsm",
    ]));
    assert!(!ok, "provision with unknown backend must fail");
    assert!(
        stderr.contains("unknown backend") || stderr.contains("hsm"),
        "error must identify the unknown backend: {stderr}"
    );
    assert!(
        stderr.contains("software"),
        "error must list 'software' as a valid option: {stderr}"
    );
}

#[test]
fn provision_admission_key_fails_without_data_dir_flag() {
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args(["provision-admission-key"]));
    assert!(!ok, "must fail when --data-dir is omitted");
    assert!(
        stderr.contains("--data-dir"),
        "stderr must name the missing flag: {stderr}"
    );
}
