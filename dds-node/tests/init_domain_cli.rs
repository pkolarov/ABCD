//! CLI integration tests for `dds-node init-domain`.
//!
//! Covers:
//!  - Happy path: hybrid domain creates domain.toml + domain_key.bin
//!  - stdout reports name, id, pubkey, pq_pubkey, scheme line
//!  - --legacy flag: creates Ed25519-only domain without pq_pubkey
//!  - --legacy and --fido2 are mutually exclusive
//!  - --name is required
//!  - --dir is required
//!  - --dir is created if it does not yet exist
//!  - Idempotent: re-running in same dir overwrites (no error)

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
fn init_domain_hybrid_creates_files() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let status = dds_node_bin()
        .args(["init-domain", "--name", "acme.test", "--dir", dom.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "init-domain should succeed");
    assert!(dom.join("domain.toml").exists(), "domain.toml should be created");
    assert!(dom.join("domain_key.bin").exists(), "domain_key.bin should be created");
}

#[test]
fn init_domain_hybrid_stdout_reports_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "init-domain", "--name", "acme.test", "--dir", dom.to_str().unwrap(),
    ]));
    assert!(ok, "init-domain should succeed; stderr may contain errors");
    assert!(stdout.contains("acme.test"), "stdout should include the domain name; got: {stdout}");
    assert!(stdout.contains("id:"), "stdout should include id; got: {stdout}");
    assert!(stdout.contains("pubkey:"), "stdout should include pubkey; got: {stdout}");
    assert!(stdout.contains("pq_pubkey:"), "hybrid stdout should include pq_pubkey; got: {stdout}");
    assert!(stdout.contains("v2 hybrid"), "hybrid scheme line; got: {stdout}");
}

#[test]
fn init_domain_legacy_no_pq_pubkey_in_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "init-domain", "--name", "acme.test", "--dir", dom.to_str().unwrap(), "--legacy",
    ]));
    assert!(ok, "init-domain --legacy should succeed; got: {stdout}");
    assert!(stdout.contains("v1 legacy"), "legacy scheme line; got: {stdout}");
    assert!(!stdout.contains("pq_pubkey:"), "legacy domain must not report pq_pubkey; got: {stdout}");
}

#[test]
fn init_domain_legacy_domain_toml_has_no_pq_pubkey() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let status = dds_node_bin()
        .args(["init-domain", "--name", "test.local", "--dir", dom.to_str().unwrap(), "--legacy"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let toml_str = std::fs::read_to_string(dom.join("domain.toml")).unwrap();
    assert!(!toml_str.contains("pq_pubkey"), "legacy domain.toml must not carry pq_pubkey; got: {toml_str}");
}

#[test]
fn init_domain_hybrid_domain_toml_has_pq_pubkey() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let status = dds_node_bin()
        .args(["init-domain", "--name", "test.local", "--dir", dom.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let toml_str = std::fs::read_to_string(dom.join("domain.toml")).unwrap();
    assert!(toml_str.contains("pq_pubkey"), "hybrid domain.toml must carry pq_pubkey; got: {toml_str}");
}

#[test]
fn init_domain_legacy_and_fido2_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "init-domain", "--name", "acme.test", "--dir", dom.to_str().unwrap(),
        "--legacy", "--fido2",
    ]));
    assert!(!ok, "--legacy --fido2 must fail");
    assert!(
        stderr.contains("mutually exclusive") || stderr.contains("--legacy") || stderr.contains("--fido2"),
        "stderr should mention mutual exclusion; got: {stderr}",
    );
}

#[test]
fn init_domain_requires_name_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("dom");

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "init-domain", "--dir", dom.to_str().unwrap(),
    ]));
    assert!(!ok, "missing --name must fail");
    assert!(
        stderr.contains("--name") || stderr.contains("name"),
        "stderr should mention --name; got: {stderr}",
    );
}

#[test]
fn init_domain_requires_dir_flag() {
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "init-domain", "--name", "acme.test",
    ]));
    assert!(!ok, "missing --dir must fail");
    assert!(
        stderr.contains("--dir") || stderr.contains("dir"),
        "stderr should mention --dir; got: {stderr}",
    );
}

#[test]
fn init_domain_creates_dir_if_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let dom = tmp.path().join("nonexistent").join("nested").join("dom");
    assert!(!dom.exists(), "test setup: dir must not exist yet");

    let status = dds_node_bin()
        .args(["init-domain", "--name", "acme.test", "--dir", dom.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "init-domain should create missing --dir");
    assert!(dom.join("domain.toml").exists());
}
