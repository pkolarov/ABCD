//! End-to-end CLI test for the admission-revocation flow
//! (threat-model §1, open item #4).
//!
//! Exercises the full operator round-trip: an admin issues a
//! revocation against a peer id with `dds-node revoke-admission`, the
//! operator imports it into a node's data dir with
//! `dds-node import-revocation`, and the on-disk store ends up with
//! exactly the entries we expect. Re-importing the same file is a
//! no-op (idempotent). Importing a revocation issued under a foreign
//! domain is rejected — without that property, an attacker who landed
//! a revocation file on disk could DoS the local node by revoking its
//! own peer id.

use std::process::{Command, Stdio};

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn init_domain_via_cli(dir: &std::path::Path, name: &str) {
    let status = dds_node_bin()
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

fn write_minimal_node_config(data_dir: &std::path::Path, domain_dir: &std::path::Path) {
    // import-revocation needs the node's dds.toml to know which
    // domain pubkey to verify against. Build a minimal one referencing
    // the domain we just created.
    let domain_toml = std::fs::read_to_string(domain_dir.join("domain.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&domain_toml).unwrap();
    let id = parsed["id"].as_str().unwrap().to_string();
    let pubkey = parsed["pubkey"].as_str().unwrap().to_string();
    let name = parsed["name"].as_str().unwrap().to_string();

    let cfg = format!(
        r#"
data_dir = "{data}"
org_hash = "test.org"

[network]
listen_addr = "/ip4/127.0.0.1/tcp/0"
api_addr = "127.0.0.1:0"

[domain]
name = "{name}"
id = "{id}"
pubkey = "{pubkey}"
"#,
        data = data_dir.display()
    );
    std::fs::write(data_dir.join("dds.toml"), cfg).unwrap();
}

#[test]
fn revoke_admission_cli_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("dom");
    std::fs::create_dir_all(&domain_dir).unwrap();
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&data_dir).unwrap();

    init_domain_via_cli(&domain_dir, "acme.test");
    write_minimal_node_config(&data_dir, &domain_dir);

    // 1. Admin issues a revocation.
    let rev_out = tmp.path().join("rev.cbor");
    let status = dds_node_bin()
        .args([
            "revoke-admission",
            "--domain-key",
            domain_dir.join("domain_key.bin").to_str().unwrap(),
            "--domain",
            domain_dir.join("domain.toml").to_str().unwrap(),
            "--peer-id",
            "12D3KooWRevokedPeer",
            "--reason",
            "key compromise drill",
            "--out",
            rev_out.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "revoke-admission should succeed");
    assert!(rev_out.exists(), "revocation file should be written");

    // 2. Operator imports into the local node.
    let status = dds_node_bin()
        .args([
            "import-revocation",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--in",
            rev_out.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "import-revocation should succeed");
    assert!(
        data_dir.join("admission_revocations.cbor").exists(),
        "revocation list file should be created"
    );

    // 3. Re-import is idempotent.
    let status = dds_node_bin()
        .args([
            "import-revocation",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--in",
            rev_out.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "re-import should succeed (idempotent)");

    // 4. Read back the on-disk store and check it has exactly one
    //    entry against our peer id.
    let toml_str = std::fs::read_to_string(data_dir.join("dds.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&toml_str).unwrap();
    let domain_id = dds_domain::DomainId::parse(parsed["domain"]["id"].as_str().unwrap()).unwrap();
    let pk_hex = parsed["domain"]["pubkey"].as_str().unwrap();
    let pk_vec = dds_domain::domain::from_hex(pk_hex).unwrap();
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pk_vec);

    let store = dds_node::admission_revocation_store::load_or_empty(
        &data_dir.join("admission_revocations.cbor"),
        domain_id,
        pubkey,
    )
    .unwrap();
    assert_eq!(store.len(), 1, "exactly one entry after two imports");
    assert!(store.is_revoked("12D3KooWRevokedPeer"));
}

#[test]
fn import_rejects_revocation_signed_by_foreign_domain() {
    let tmp = tempfile::tempdir().unwrap();
    let our_dir = tmp.path().join("ours");
    let foreign_dir = tmp.path().join("foreign");
    std::fs::create_dir_all(&our_dir).unwrap();
    std::fs::create_dir_all(&foreign_dir).unwrap();
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&data_dir).unwrap();

    init_domain_via_cli(&our_dir, "acme.test");
    init_domain_via_cli(&foreign_dir, "evil.test");
    write_minimal_node_config(&data_dir, &our_dir);

    // Issue a revocation under the foreign domain key.
    let foreign_rev = tmp.path().join("foreign_rev.cbor");
    let status = dds_node_bin()
        .args([
            "revoke-admission",
            "--domain-key",
            foreign_dir.join("domain_key.bin").to_str().unwrap(),
            "--domain",
            foreign_dir.join("domain.toml").to_str().unwrap(),
            "--peer-id",
            "12D3KooWVictim",
            "--out",
            foreign_rev.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    // Try to import it into our node — must fail.
    let status = dds_node_bin()
        .args([
            "import-revocation",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--in",
            foreign_rev.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "import-revocation must reject a revocation signed by a different domain"
    );
    // And nothing should have landed on disk for our store.
    assert!(
        !data_dir.join("admission_revocations.cbor").exists()
            || std::fs::metadata(data_dir.join("admission_revocations.cbor"))
                .unwrap()
                .len()
                <= 16, // schema overhead only — empty list at most
        "no foreign revocations should have been persisted"
    );
}
