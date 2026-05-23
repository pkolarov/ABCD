//! CLI integration tests for `dds-node create-provision-bundle` and
//! `dds-node provision`.
//!
//! These two commands implement the air-gapped deployment workflow: an
//! admin creates a bundle on the anchor node and carries it (USB/QR) to
//! each worker node to bootstrap without network access.
//!
//! Covers:
//!  - create-provision-bundle: creates a .dds bundle file from a domain dir
//!  - create-provision-bundle: stdout reports "Bundle integrity fingerprint:"
//!  - create-provision-bundle: --legacy domain creates a bundle (v3 wire format)
//!  - create-provision-bundle: --dir is required
//!  - create-provision-bundle: --org is required
//!  - create-provision-bundle: fails when domain dir has no domain.toml
//!  - provision: happy path writes expected files and prints domain + peer_id
//!  - provision: refuses double-provision on the same data_dir
//!  - provision: requires a positional bundle path
//!  - provision: fails with a meaningful error on a nonexistent bundle

use std::path::Path;
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

/// Create a plain (no passphrase) legacy domain in `dir`.
/// Legacy (`--legacy`) is used so all bundle round-trip tests stay
/// deterministic — the passphrase env is always empty, and there is no
/// FIDO2 hardware prompt to worry about.  The hybrid path is exercised
/// by the `create-provision-bundle` hybrid test below.
fn init_legacy_domain(dir: &Path, name: &str) {
    let status = dds_node_bin()
        .env("DDS_DOMAIN_PASSPHRASE", "")
        .args([
            "init-domain",
            "--name",
            name,
            "--dir",
            dir.to_str().unwrap(),
            "--legacy",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "init-domain --legacy should succeed");
}

/// Create a plain hybrid domain in `dir`.
fn init_hybrid_domain(dir: &Path, name: &str) {
    let status = dds_node_bin()
        .env("DDS_DOMAIN_PASSPHRASE", "")
        .args([
            "init-domain",
            "--name",
            name,
            "--dir",
            dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "init-domain should succeed");
}

// ================================================================
// create-provision-bundle tests
// ================================================================

#[test]
fn create_provision_bundle_creates_file() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    std::fs::create_dir_all(&domain_dir).unwrap();
    init_legacy_domain(&domain_dir, "bundle-test.local");

    let bundle_path = tmp.path().join("out.dds");

    let status = dds_node_bin()
        .env("DDS_DOMAIN_PASSPHRASE", "")
        .args([
            "create-provision-bundle",
            "--dir",
            domain_dir.to_str().unwrap(),
            "--org",
            "test-org",
            "--out",
            bundle_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "create-provision-bundle should succeed");
    assert!(bundle_path.exists(), "bundle file should be created");
    assert!(
        std::fs::metadata(&bundle_path).unwrap().len() > 0,
        "bundle file must not be empty"
    );
}

#[test]
fn create_provision_bundle_stdout_includes_fingerprint() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    std::fs::create_dir_all(&domain_dir).unwrap();
    init_legacy_domain(&domain_dir, "fp-test.local");

    let bundle_path = tmp.path().join("fp.dds");

    let (ok, stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .args([
                "create-provision-bundle",
                "--dir",
                domain_dir.to_str().unwrap(),
                "--org",
                "test-org",
                "--out",
                bundle_path.to_str().unwrap(),
            ]),
    );
    assert!(ok, "create-provision-bundle should succeed; stderr={stderr}");
    assert!(
        stdout.contains("Bundle integrity fingerprint:"),
        "stdout must report fingerprint; got: {stdout}"
    );
    assert!(
        stdout.contains("Confirm this fingerprint"),
        "stdout must include confirmation reminder; got: {stdout}"
    );
}

#[test]
fn create_provision_bundle_hybrid_domain_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    std::fs::create_dir_all(&domain_dir).unwrap();
    init_hybrid_domain(&domain_dir, "hybrid-bundle.local");

    let bundle_path = tmp.path().join("hybrid.dds");

    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .args([
                "create-provision-bundle",
                "--dir",
                domain_dir.to_str().unwrap(),
                "--org",
                "hybrid-org",
                "--out",
                bundle_path.to_str().unwrap(),
            ]),
    );
    assert!(
        ok,
        "create-provision-bundle on hybrid domain should succeed; stderr={stderr}"
    );
    assert!(bundle_path.exists(), "hybrid bundle file should exist");
}

#[test]
fn create_provision_bundle_requires_dir_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_path = tmp.path().join("out.dds");

    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .args([
                "create-provision-bundle",
                "--org",
                "test-org",
                "--out",
                bundle_path.to_str().unwrap(),
            ]),
    );
    assert!(!ok, "missing --dir must fail");
    assert!(
        stderr.contains("--dir"),
        "error must mention --dir; got: {stderr}"
    );
}

#[test]
fn create_provision_bundle_requires_org_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    std::fs::create_dir_all(&domain_dir).unwrap();
    init_legacy_domain(&domain_dir, "org-test.local");

    let bundle_path = tmp.path().join("out.dds");

    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .args([
                "create-provision-bundle",
                "--dir",
                domain_dir.to_str().unwrap(),
                "--out",
                bundle_path.to_str().unwrap(),
            ]),
    );
    assert!(!ok, "missing --org must fail");
    assert!(
        stderr.contains("--org"),
        "error must mention --org; got: {stderr}"
    );
}

#[test]
fn create_provision_bundle_fails_on_missing_domain_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let empty_dir = tmp.path().join("empty");
    std::fs::create_dir_all(&empty_dir).unwrap();
    let bundle_path = tmp.path().join("out.dds");

    let (ok, _stdout, _stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .args([
                "create-provision-bundle",
                "--dir",
                empty_dir.to_str().unwrap(),
                "--org",
                "test-org",
                "--out",
                bundle_path.to_str().unwrap(),
            ]),
    );
    assert!(
        !ok,
        "create-provision-bundle must fail when domain.toml is absent"
    );
    assert!(
        !bundle_path.exists(),
        "bundle file must not be created when domain.toml is absent"
    );
}

// ================================================================
// provision tests
// ================================================================

/// Helper: create a domain, build a bundle, return the bundle path.
fn make_bundle(tmp_root: &Path, domain_name: &str) -> std::path::PathBuf {
    let domain_dir = tmp_root.join("domain");
    std::fs::create_dir_all(&domain_dir).unwrap();
    init_legacy_domain(&domain_dir, domain_name);

    let bundle_path = tmp_root.join("node.dds");
    let status = dds_node_bin()
        .env("DDS_DOMAIN_PASSPHRASE", "")
        .args([
            "create-provision-bundle",
            "--dir",
            domain_dir.to_str().unwrap(),
            "--org",
            "test-org",
            "--out",
            bundle_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "create-provision-bundle must succeed in make_bundle helper"
    );
    bundle_path
}

#[test]
fn provision_creates_expected_files() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_path = make_bundle(tmp.path(), "prov-test.local");

    let data_dir = tmp.path().join("node-data");

    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                bundle_path.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(ok, "provision should succeed; stderr={stderr}");

    // Critical files that provision must create.
    for fname in ["admission.cbor", "domain.toml", "p2p_key.bin", "node_key.bin"] {
        assert!(
            data_dir.join(fname).exists(),
            "provision must create {fname}; stderr={stderr}"
        );
    }
    // The domain key must NEVER be written to the data dir.
    assert!(
        !data_dir.join("domain_key.bin").exists(),
        "provision must not write domain_key.bin to the data dir (security invariant)"
    );
}

#[test]
fn provision_stdout_reports_domain_and_peer_id() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_path = make_bundle(tmp.path(), "prov-stdout.local");

    let data_dir = tmp.path().join("node-data");

    let (ok, stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                bundle_path.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(ok, "provision should succeed; stderr={stderr}");
    assert!(
        stdout.contains("Node Provisioned"),
        "stdout must include 'Node Provisioned' banner; got: {stdout}"
    );
    assert!(
        stdout.contains("prov-stdout.local"),
        "stdout must include domain name; got: {stdout}"
    );
    assert!(
        stdout.contains("Peer ID:"),
        "stdout must include 'Peer ID:' line; got: {stdout}"
    );
}

#[test]
fn provision_stdout_peer_id_has_expected_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_path = make_bundle(tmp.path(), "prov-peerid.local");

    let data_dir = tmp.path().join("node-data");

    let (ok, stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                bundle_path.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(ok, "provision should succeed; stderr={stderr}");
    assert!(
        stdout.contains("12D3KooW"),
        "Peer ID must have libp2p Ed25519 PeerId prefix '12D3KooW'; got: {stdout}"
    );
}

#[test]
fn provision_writes_dds_toml_config() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_path = make_bundle(tmp.path(), "prov-config.local");

    let data_dir = tmp.path().join("node-data");

    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                bundle_path.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(ok, "provision should succeed; stderr={stderr}");

    // A sibling dds.toml config must be created next to the data dir.
    // The exact path is data_dir.parent() / "dds.toml" on Unix.
    let config_path = data_dir.parent().unwrap().join("dds.toml");
    assert!(
        config_path.exists(),
        "dds.toml config must be created alongside the data dir; stderr={stderr}"
    );
    let config_text = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        config_text.contains("prov-config.local"),
        "dds.toml must contain the domain name; got: {config_text}"
    );
}

#[test]
fn provision_refuses_double_provision() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle_path = make_bundle(tmp.path(), "prov-double.local");

    let data_dir = tmp.path().join("node-data");

    // First provision must succeed.
    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                bundle_path.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(ok, "first provision should succeed; stderr={stderr}");

    // Second provision on the same data dir must be rejected.
    let (ok2, _stdout2, stderr2) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                bundle_path.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(!ok2, "second provision on the same dir must fail");
    let combined = format!("{_stdout2}{stderr2}");
    assert!(
        combined.to_lowercase().contains("already"),
        "error must mention 'already' (already provisioned); got: {combined}"
    );
}

#[test]
fn provision_requires_bundle_path() {
    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .args(["provision"]),
    );
    assert!(!ok, "provision without bundle path must fail");
    assert!(
        !stderr.is_empty(),
        "error message must be non-empty; got empty stderr"
    );
}

#[test]
fn provision_fails_with_nonexistent_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let missing_bundle = tmp.path().join("does-not-exist.dds");
    let data_dir = tmp.path().join("node-data");

    let (ok, _stdout, stderr) = run_capture(
        dds_node_bin()
            .env("DDS_DOMAIN_PASSPHRASE", "")
            .env_remove("DDS_NODE_PASSPHRASE")
            .args([
                "provision",
                missing_bundle.to_str().unwrap(),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--no-start",
            ]),
    );
    assert!(!ok, "provision with nonexistent bundle must fail");
    assert!(
        !stderr.is_empty(),
        "error message must be non-empty; got empty stderr"
    );
}
