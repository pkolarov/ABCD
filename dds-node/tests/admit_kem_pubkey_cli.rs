//! End-to-end CLI tests for `dds-node admit --kem-pubkey` and the matching
//! `gen-node-key` KEM pubkey output (PQ-DEFAULT-2).
//!
//! Covers:
//!  - `gen-node-key` writes `epoch_keys.cbor` and prints `kem_pubkey_hex`
//!  - `admit --kem-pubkey` embeds the pubkey in the issued cert
//!  - `admit` on a hybrid domain without `--kem-pubkey` prints a warning
//!  - `admit` on a legacy domain without `--kem-pubkey` succeeds silently

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

fn init_hybrid_domain(dir: &std::path::Path, name: &str) {
    let status = dds_node_bin()
        .args(["init-domain", "--name", name, "--dir", dir.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "init-domain should succeed");
}

fn init_legacy_domain(dir: &std::path::Path, name: &str) {
    let status = dds_node_bin()
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

/// **PQ-DEFAULT-2** — `gen-node-key` must write `epoch_keys.cbor` and
/// print the `kem_pubkey_hex` field so the admin can pass it to `admit`.
#[test]
fn gen_node_key_creates_epoch_keys_and_prints_kem_pubkey_hex() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "gen-node-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "gen-node-key must succeed; stderr={stderr}");

    // epoch_keys.cbor must be written.
    assert!(
        data_dir.join("epoch_keys.cbor").exists(),
        "gen-node-key must create epoch_keys.cbor"
    );

    // stdout must contain kem_pubkey_hex with a non-empty hex value.
    assert!(
        stdout.contains("kem_pubkey_hex:"),
        "gen-node-key stdout must include kem_pubkey_hex; got:\n{stdout}"
    );
    let kem_hex = stdout
        .lines()
        .find(|l| l.contains("kem_pubkey_hex:"))
        .and_then(|l| l.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("");
    assert!(
        !kem_hex.is_empty() && kem_hex.len() > 16,
        "kem_pubkey_hex must be a non-trivial hex string; got: {kem_hex}"
    );

    // Running gen-node-key a second time must be idempotent (same pubkey).
    let (ok2, stdout2, _) = run_capture(dds_node_bin().args([
        "gen-node-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok2, "second gen-node-key must also succeed");
    let kem_hex2 = stdout2
        .lines()
        .find(|l| l.contains("kem_pubkey_hex:"))
        .and_then(|l| l.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("");
    assert_eq!(
        kem_hex, kem_hex2,
        "kem_pubkey_hex must be stable across re-runs (idempotent)"
    );
}

/// **PQ-DEFAULT-2** — `admit --kem-pubkey <HEX>` on a hybrid domain must
/// produce an admission cert whose `pq_kem_pubkey` field is populated.
#[test]
fn admit_with_kem_pubkey_embeds_pubkey_in_cert() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&domain_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    init_hybrid_domain(&domain_dir, "kem-test");

    // Generate a peer id + KEM pubkey.
    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "gen-node-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "gen-node-key failed: {stderr}");

    let peer_id = stdout
        .lines()
        .find(|l| l.contains("peer_id:"))
        .and_then(|l| l.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    let kem_hex = stdout
        .lines()
        .find(|l| l.contains("kem_pubkey_hex:"))
        .and_then(|l| l.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    assert!(!peer_id.is_empty(), "peer_id missing from gen-node-key output");
    assert!(!kem_hex.is_empty(), "kem_pubkey_hex missing from gen-node-key output");

    let cert_path = tmp.path().join("admission.cbor");
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "admit",
        "--domain-key",
        domain_dir.join("domain_key.bin").to_str().unwrap(),
        "--domain",
        domain_dir.join("domain.toml").to_str().unwrap(),
        "--peer-id",
        &peer_id,
        "--kem-pubkey",
        &kem_hex,
        "--out",
        cert_path.to_str().unwrap(),
    ]));
    assert!(ok, "admit --kem-pubkey must succeed; stderr={stderr}");
    assert!(cert_path.exists(), "admission cert must be written");

    // Verify the cert carries pq_kem_pubkey.
    let cert = dds_node::domain_store::load_admission_cert(&cert_path).unwrap();
    assert!(
        cert.pq_kem_pubkey.is_some(),
        "admission cert must contain pq_kem_pubkey when --kem-pubkey is passed"
    );
    assert_eq!(
        cert.pq_kem_pubkey.as_ref().unwrap().len(),
        dds_domain::HYBRID_KEM_PUBKEY_LEN,
        "pq_kem_pubkey length must be HYBRID_KEM_PUBKEY_LEN"
    );
}

/// **PQ-DEFAULT-2** — `admit` on a hybrid domain *without* `--kem-pubkey`
/// must succeed but print a warning to stderr about 0% enc-v3 coverage.
#[test]
fn admit_without_kem_pubkey_on_hybrid_domain_warns() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&domain_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    init_hybrid_domain(&domain_dir, "warn-test");

    let (ok, stdout, _) = run_capture(dds_node_bin().args([
        "gen-node-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok);
    let peer_id = stdout
        .lines()
        .find(|l| l.contains("peer_id:"))
        .and_then(|l| l.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    let cert_path = tmp.path().join("admission.cbor");
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "admit",
        "--domain-key",
        domain_dir.join("domain_key.bin").to_str().unwrap(),
        "--domain",
        domain_dir.join("domain.toml").to_str().unwrap(),
        "--peer-id",
        &peer_id,
        "--out",
        cert_path.to_str().unwrap(),
    ]));
    assert!(ok, "admit without --kem-pubkey must still succeed");

    assert!(
        stderr.contains("WARNING") || stderr.contains("hybrid"),
        "admit on hybrid domain without --kem-pubkey must warn; stderr={stderr}"
    );

    // cert should exist but not carry kem pubkey.
    let cert = dds_node::domain_store::load_admission_cert(&cert_path).unwrap();
    assert!(
        cert.pq_kem_pubkey.is_none(),
        "cert must not carry kem pubkey when --kem-pubkey was not supplied"
    );
}

/// **PQ-DEFAULT-2** — `admit` on a legacy (Ed25519-only) domain without
/// `--kem-pubkey` must succeed silently (no warning expected).
#[test]
fn admit_legacy_domain_without_kem_pubkey_succeeds_silently() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("domain");
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&domain_dir).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();

    init_legacy_domain(&domain_dir, "legacy-test");

    let (ok, stdout, _) = run_capture(dds_node_bin().args([
        "gen-node-key",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok);
    let peer_id = stdout
        .lines()
        .find(|l| l.contains("peer_id:"))
        .and_then(|l| l.split(':').nth(1))
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    let cert_path = tmp.path().join("admission.cbor");
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "admit",
        "--domain-key",
        domain_dir.join("domain_key.bin").to_str().unwrap(),
        "--domain",
        domain_dir.join("domain.toml").to_str().unwrap(),
        "--peer-id",
        &peer_id,
        "--out",
        cert_path.to_str().unwrap(),
    ]));
    assert!(ok, "admit on legacy domain must succeed; stderr={stderr}");
    assert!(
        !stderr.contains("WARNING"),
        "admit on legacy domain must not warn about kem-pubkey; stderr={stderr}"
    );

    let cert = dds_node::domain_store::load_admission_cert(&cert_path).unwrap();
    assert!(
        cert.pq_kem_pubkey.is_none(),
        "legacy domain cert must not carry kem pubkey"
    );
}
