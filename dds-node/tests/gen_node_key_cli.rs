//! CLI integration tests for `dds-node gen-node-key`.
//!
//! Covers:
//!  - Creates p2p_key.bin and epoch_keys.cbor in the given data dir
//!  - stdout reports data_dir, p2p_key path, peer_id, kem_pubkey_hex
//!  - peer_id starts with "12D3KooW" (libp2p PeerId prefix)
//!  - kem_pubkey_hex is a non-empty hex string
//!  - Idempotent: second run produces the same peer_id
//!  - --data-dir is required

use std::process::{Command, Stdio};

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn run_capture(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
}

#[test]
fn gen_node_key_creates_key_files() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let status = dds_node_bin()
        .args(["gen-node-key", "--data-dir", data.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "gen-node-key should succeed");
    assert!(data.join("p2p_key.bin").exists(), "p2p_key.bin should be created");
    assert!(data.join("epoch_keys.cbor").exists(), "epoch_keys.cbor should be created");
}

#[test]
fn gen_node_key_stdout_reports_peer_id_and_kem_pubkey() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "gen-node-key", "--data-dir", data.to_str().unwrap(),
    ]));
    assert!(ok, "gen-node-key should succeed");
    assert!(stdout.contains("peer_id:"), "stdout should include peer_id; got: {stdout}");
    assert!(stdout.contains("kem_pubkey_hex:"), "stdout should include kem_pubkey_hex; got: {stdout}");
    assert!(stdout.contains("data_dir:"), "stdout should include data_dir; got: {stdout}");
}

#[test]
fn gen_node_key_peer_id_has_expected_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "gen-node-key", "--data-dir", data.to_str().unwrap(),
    ]));
    assert!(ok);
    // libp2p Ed25519 PeerIds always start with "12D3KooW"
    let peer_line = stdout.lines().find(|l| l.contains("peer_id:")).unwrap_or("");
    assert!(
        peer_line.contains("12D3KooW"),
        "peer_id should start with 12D3KooW; line: {peer_line}",
    );
}

#[test]
fn gen_node_key_kem_pubkey_is_hex() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "gen-node-key", "--data-dir", data.to_str().unwrap(),
    ]));
    assert!(ok);
    let kem_line = stdout.lines().find(|l| l.contains("kem_pubkey_hex:")).unwrap_or("");
    // Extract the hex value (last token on the line after ': ')
    let hex_val = kem_line.split(':').nth(1).unwrap_or("").trim();
    assert!(!hex_val.is_empty(), "kem_pubkey_hex must not be empty; line: {kem_line}");
    assert!(
        hex_val.chars().all(|c| c.is_ascii_hexdigit()),
        "kem_pubkey_hex must be all hex digits; got: {hex_val}",
    );
    // HybridKemPublicKey = 32 (X25519) + 1184 (ML-KEM-768) = 1216 bytes = 2432 hex chars
    assert_eq!(
        hex_val.len(), 2432,
        "kem_pubkey_hex should be 2432 hex chars (HybridKemPublicKey); got {} chars",
        hex_val.len(),
    );
}

#[test]
fn gen_node_key_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path();

    // First run
    let (ok, stdout1, _) = run_capture(dds_node_bin().args([
        "gen-node-key", "--data-dir", data.to_str().unwrap(),
    ]));
    assert!(ok);

    // Second run — same key, same peer_id
    let (ok, stdout2, _) = run_capture(dds_node_bin().args([
        "gen-node-key", "--data-dir", data.to_str().unwrap(),
    ]));
    assert!(ok);

    let peer_id_1 = stdout1.lines().find(|l| l.contains("peer_id:")).unwrap_or("");
    let peer_id_2 = stdout2.lines().find(|l| l.contains("peer_id:")).unwrap_or("");
    assert_eq!(peer_id_1, peer_id_2, "peer_id must be stable across repeated gen-node-key calls");
}

#[test]
fn gen_node_key_requires_data_dir_flag() {
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args(["gen-node-key"]));
    assert!(!ok, "gen-node-key without --data-dir must fail");
    assert!(
        stderr.contains("--data-dir") || stderr.contains("data-dir") || stderr.contains("data_dir"),
        "stderr should mention --data-dir; got: {stderr}",
    );
}

#[test]
fn gen_node_key_creates_data_dir_if_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("new_node_dir");
    assert!(!data.exists(), "test setup: dir must not exist");

    let status = dds_node_bin()
        .args(["gen-node-key", "--data-dir", data.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "gen-node-key should create a missing data dir");
    assert!(data.join("p2p_key.bin").exists());
}
