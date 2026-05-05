//! CLI integration tests for `dds-node self-admit`.
//!
//! Covers:
//!  - Happy path on a hybrid domain (gen-node-key first, then self-admit)
//!  - Happy path on a legacy domain
//!  - Refuses to overwrite an existing admission.cbor without --force
//!  - Overwrites when --force is passed
//!  - Fails when p2p_key.bin is missing (gen-node-key not run)
//!  - Prints a warning on hybrid domain when epoch_keys.cbor is absent

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

fn init_hybrid_domain(dir: &std::path::Path) {
    let status = dds_node_bin()
        .args(["init-domain", "--name", "test.local", "--dir", dir.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "init-domain should succeed");
}

fn init_legacy_domain(dir: &std::path::Path) {
    let status = dds_node_bin()
        .args([
            "init-domain",
            "--name",
            "test.local",
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

fn gen_node_key(data_dir: &std::path::Path) {
    let status = dds_node_bin()
        .args(["gen-node-key", "--data-dir", data_dir.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "gen-node-key should succeed");
}

/// Happy path on a hybrid domain: domain key + node key in the same dir.
/// self-admit should produce admission.cbor with kem_pubkey set.
#[test]
fn self_admit_hybrid_domain_success() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    init_hybrid_domain(dir);
    gen_node_key(dir);

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(ok, "self-admit should succeed on hybrid domain; stderr={stderr}");

    assert!(
        dir.join("admission.cbor").exists(),
        "admission.cbor must be written"
    );
    assert!(
        stdout.contains("Self-admission cert issued"),
        "stdout should confirm cert issued; got:\n{stdout}"
    );
    assert!(
        stdout.contains("kem_pubkey: set"),
        "kem_pubkey should be set on hybrid domain; got:\n{stdout}"
    );
}

/// Happy path on a legacy domain: cert is issued successfully.
/// gen-node-key always creates epoch_keys.cbor so kem_pubkey is embedded
/// even on legacy domains (harmless extra field; domain cert verifies clean).
#[test]
fn self_admit_legacy_domain_success() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    init_legacy_domain(dir);
    gen_node_key(dir);

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(ok, "self-admit should succeed on legacy domain; stderr={stderr}");
    assert!(
        dir.join("admission.cbor").exists(),
        "admission.cbor must be written"
    );
    assert!(
        stdout.contains("Self-admission cert issued"),
        "stdout should confirm cert issued; got:\n{stdout}"
    );
}

/// self-admit refuses to overwrite an existing admission.cbor without --force.
#[test]
fn self_admit_refuses_to_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    init_hybrid_domain(dir);
    gen_node_key(dir);

    // First run — succeeds.
    let (ok, _, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(ok, "first self-admit should succeed; stderr={stderr}");

    // Second run without --force — must fail.
    let (ok, _, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(!ok, "second self-admit without --force must fail");
    assert!(
        stderr.contains("--force"),
        "error message should mention --force; got:\n{stderr}"
    );
}

/// --force allows overwriting an existing admission.cbor.
#[test]
fn self_admit_force_overwrites_existing_cert() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    init_hybrid_domain(dir);
    gen_node_key(dir);

    // First run.
    let (ok, _, _) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(ok);

    // Second run with --force.
    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
        "--force",
    ]));
    assert!(
        ok,
        "self-admit --force should succeed on second run; stderr={stderr}"
    );
    assert!(stdout.contains("Self-admission cert issued"), "{stdout}");
}

/// self-admit fails gracefully when gen-node-key hasn't been run yet.
#[test]
fn self_admit_fails_without_p2p_key() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    init_hybrid_domain(dir);
    // Deliberately skip gen-node-key.

    let (ok, _, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(!ok, "self-admit without p2p key must fail");
    assert!(
        stderr.contains("gen-node-key"),
        "error message should mention gen-node-key; got:\n{stderr}"
    );
}

/// On a hybrid domain with epoch_keys.cbor missing, self-admit should warn
/// but still succeed (produces cert without kem_pubkey).
#[test]
fn self_admit_warns_on_hybrid_domain_without_epoch_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    init_hybrid_domain(dir);
    gen_node_key(dir);

    // Remove epoch_keys.cbor to simulate the missing-KEM scenario.
    std::fs::remove_file(dir.join("epoch_keys.cbor")).unwrap();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "self-admit",
        "--data-dir",
        dir.to_str().unwrap(),
    ]));
    assert!(ok, "self-admit should still succeed without epoch_keys; stderr={stderr}");
    assert!(
        stderr.contains("WARNING"),
        "should print a warning to stderr; got:\n{stderr}"
    );
    assert!(
        stdout.contains("kem_pubkey: not set"),
        "kem_pubkey should be not set; got:\n{stdout}"
    );
}
