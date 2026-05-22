//! CLI integration tests for `dds-node stamp-agent-pubkey`.
//!
//! `stamp-agent-pubkey` is the Windows MSI custom action entry point
//! (`CA_StampAgentPubkey` in `DdsBundle.wxs`). It derives the node's
//! Ed25519 public key from `<data_dir>/node_key.bin` (creating the key
//! file if absent) and writes the Base64-encoded pubkey into the
//! `DdsPolicyAgent.PinnedNodePubkeyB64` field of the Policy Agent's
//! `<config_dir>/appsettings.json`.
//!
//! On hosts without the agent installed (or in CI where no
//! `appsettings.json` exists) the command exits 0 with a "nothing to
//! stamp" notice. These tests cover both the stamping path and the
//! no-op path, as well as arg-parse error paths, so that any regression
//! in the MSI custom action contract is caught before a release build.

use std::process::{Command, Stdio};

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

/// Write a minimal `appsettings.json` that the stamping path can parse.
fn write_minimal_appsettings(config_dir: &std::path::Path) {
    let json = r#"{
  "Logging": { "LogLevel": { "Default": "Information" } }
}
"#;
    std::fs::write(config_dir.join("appsettings.json"), json).unwrap();
}

// ---------------------------------------------------------------------------
// No-op path (no appsettings.json)
// ---------------------------------------------------------------------------

#[test]
fn stamp_agent_pubkey_no_appsettings_returns_success() {
    // When `appsettings.json` is absent in config_dir the command must
    // succeed (exit 0) and print the "nothing to stamp" notice. This is
    // the expected outcome on dev/loadtest installs and non-Windows CI.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    let out = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--config-dir",
            config_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stamp-agent-pubkey must exit 0 when appsettings.json is absent; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("nothing to stamp"),
        "stdout must explain that there is nothing to stamp; got: {stdout}"
    );
}

#[test]
fn stamp_agent_pubkey_no_appsettings_creates_node_key() {
    // Even on the no-op path the command must materialise node_key.bin
    // so that subsequent MSI custom actions (provision, restrict-data-dir-acl)
    // find a stable node identity.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    let status = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--config-dir",
            config_dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        data_dir.join("node_key.bin").exists(),
        "node_key.bin must be created in data_dir even when appsettings.json is absent"
    );
}

// ---------------------------------------------------------------------------
// Stamping path (appsettings.json present)
// ---------------------------------------------------------------------------

#[test]
fn stamp_agent_pubkey_writes_pinned_pubkey_into_appsettings() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    write_minimal_appsettings(&config_dir);

    let out = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--config-dir",
            config_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stamp-agent-pubkey must exit 0 when appsettings.json is present; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Stamped Policy Agent PinnedNodePubkeyB64"),
        "stdout must confirm the stamp; got: {stdout}"
    );

    // The pubkey field must now be present in the written JSON.
    let raw = std::fs::read_to_string(config_dir.join("appsettings.json")).unwrap();
    assert!(
        raw.contains("PinnedNodePubkeyB64"),
        "appsettings.json must contain PinnedNodePubkeyB64 after stamp; got: {raw}"
    );
    // Ed25519 pubkey is 32 bytes → 44-char Base64 (with one padding char).
    // Verify the value is 44 characters by checking the JSON field value.
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let pk = v["DdsPolicyAgent"]["PinnedNodePubkeyB64"]
        .as_str()
        .expect("PinnedNodePubkeyB64 must be a string");
    assert_eq!(
        pk.len(),
        44,
        "Base64-encoded Ed25519 pubkey must be 44 chars; got {pk:?}"
    );
}

#[test]
fn stamp_agent_pubkey_preserves_existing_appsettings_fields() {
    // The stamping path must patch only DdsPolicyAgent.PinnedNodePubkeyB64;
    // all other keys must survive unchanged.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();

    let json = r#"{
  "Logging": { "LogLevel": { "Default": "Warning" } },
  "DdsPolicyAgent": { "NodeBaseUrl": "pipe:dds-api", "RequirePackageSignature": true }
}
"#;
    std::fs::write(config_dir.join("appsettings.json"), json).unwrap();

    let status = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--config-dir",
            config_dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let raw = std::fs::read_to_string(config_dir.join("appsettings.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    // Pre-existing fields must be intact.
    assert_eq!(
        v["Logging"]["LogLevel"]["Default"].as_str(),
        Some("Warning"),
        "Logging settings must survive the stamp"
    );
    assert_eq!(
        v["DdsPolicyAgent"]["NodeBaseUrl"].as_str(),
        Some("pipe:dds-api"),
        "NodeBaseUrl must survive the stamp"
    );
    assert_eq!(
        v["DdsPolicyAgent"]["RequirePackageSignature"].as_bool(),
        Some(true),
        "RequirePackageSignature must survive the stamp"
    );
    // New field must be present.
    assert!(
        v["DdsPolicyAgent"]["PinnedNodePubkeyB64"].is_string(),
        "PinnedNodePubkeyB64 must have been added"
    );
}

#[test]
fn stamp_agent_pubkey_is_idempotent() {
    // Re-running stamp-agent-pubkey must produce the same pubkey both
    // times (load_or_create is idempotent) and must not corrupt the JSON.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    write_minimal_appsettings(&config_dir);

    let args = [
        "stamp-agent-pubkey",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--config-dir",
        config_dir.to_str().unwrap(),
    ];

    let out1 = dds_node_bin().args(args).output().unwrap();
    assert!(out1.status.success());
    let raw1 = std::fs::read_to_string(config_dir.join("appsettings.json")).unwrap();
    let v1: serde_json::Value = serde_json::from_str(&raw1).unwrap();
    let pk1 = v1["DdsPolicyAgent"]["PinnedNodePubkeyB64"]
        .as_str()
        .unwrap()
        .to_owned();

    let out2 = dds_node_bin().args(args).output().unwrap();
    assert!(out2.status.success());
    let raw2 = std::fs::read_to_string(config_dir.join("appsettings.json")).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&raw2).unwrap();
    let pk2 = v2["DdsPolicyAgent"]["PinnedNodePubkeyB64"]
        .as_str()
        .unwrap()
        .to_owned();

    assert_eq!(pk1, pk2, "repeated stamp must produce the same pubkey");
}

// ---------------------------------------------------------------------------
// Arg-parse error paths
// ---------------------------------------------------------------------------

#[test]
fn stamp_agent_pubkey_requires_data_dir_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let status = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--config-dir",
            tmp.path().to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "stamp-agent-pubkey must fail when --data-dir is missing"
    );
}

#[test]
fn stamp_agent_pubkey_requires_config_dir_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let status = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--data-dir",
            tmp.path().to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "stamp-agent-pubkey must fail when --config-dir is missing"
    );
}

#[test]
fn stamp_agent_pubkey_missing_data_dir_names_flag_in_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dds_node_bin()
        .args([
            "stamp-agent-pubkey",
            "--config-dir",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--data-dir"),
        "error message must name the missing flag; stderr: {stderr}"
    );
}
