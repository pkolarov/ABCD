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

fn run_capture(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
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

    // **Windows path escaping** — TOML basic strings (double-quoted)
    // interpret backslashes as escape sequences, so a Windows path
    // like `C:\Users\...` is read as a malformed `\U` Unicode escape.
    // Single-quoted TOML literal strings take the bytes verbatim, and
    // path values never contain a single quote on either platform.
    let cfg = format!(
        r#"
data_dir = '{data}'
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

#[test]
fn list_revocations_empty_store_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("dom");
    std::fs::create_dir_all(&domain_dir).unwrap();
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&data_dir).unwrap();

    init_domain_via_cli(&domain_dir, "acme.test");
    write_minimal_node_config(&data_dir, &domain_dir);

    // No revocations have been imported and no file exists on disk.
    // list-revocations must succeed and report zero entries.
    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "list-revocations",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "list-revocations on empty store must exit 0");
    assert!(stdout.contains("entries:  0"), "stdout was: {stdout}");
    assert!(
        stdout.contains("(no revocations on file)"),
        "stdout was: {stdout}",
    );
}

#[test]
fn list_revocations_human_and_json_outputs() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("dom");
    std::fs::create_dir_all(&domain_dir).unwrap();
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&data_dir).unwrap();

    init_domain_via_cli(&domain_dir, "acme.test");
    write_minimal_node_config(&data_dir, &domain_dir);

    // Issue + import two revocations with distinct peer ids.
    for (peer, reason) in [
        ("12D3KooWPeerOne", Some("key compromise")),
        ("12D3KooWPeerTwo", None),
    ] {
        let rev_out = tmp.path().join(format!("{peer}.cbor"));
        let mut cmd = dds_node_bin();
        cmd.args([
            "revoke-admission",
            "--domain-key",
            domain_dir.join("domain_key.bin").to_str().unwrap(),
            "--domain",
            domain_dir.join("domain.toml").to_str().unwrap(),
            "--peer-id",
            peer,
            "--out",
            rev_out.to_str().unwrap(),
        ]);
        if let Some(r) = reason {
            cmd.args(["--reason", r]);
        }
        let status = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

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
        assert!(status.success());
    }

    // Human-readable output mentions both peer ids and the reason
    // string we attached to the first.
    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "list-revocations",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok);
    assert!(stdout.contains("entries:  2"), "stdout was: {stdout}");
    assert!(stdout.contains("12D3KooWPeerOne"), "stdout was: {stdout}");
    assert!(stdout.contains("12D3KooWPeerTwo"), "stdout was: {stdout}");
    assert!(stdout.contains("key compromise"), "stdout was: {stdout}");

    // JSON output is one object per line, parseable by hand.
    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "list-revocations",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--json",
    ]));
    assert!(ok);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected 2 JSON lines, got: {stdout}");
    for line in &lines {
        assert!(line.starts_with('{') && line.ends_with('}'), "line: {line}");
        assert!(line.contains("\"peer_id\":"), "line: {line}");
        assert!(line.contains("\"revoked_at\":"), "line: {line}");
    }
    // The line for peer-one carries the reason; peer-two does not.
    let one = lines
        .iter()
        .find(|l| l.contains("12D3KooWPeerOne"))
        .unwrap();
    assert!(one.contains("\"reason\":\"key compromise\""), "line: {one}");
    let two = lines
        .iter()
        .find(|l| l.contains("12D3KooWPeerTwo"))
        .unwrap();
    assert!(!two.contains("\"reason\""), "line: {two}");
}

#[test]
fn list_revocations_json_escapes_special_chars_in_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let domain_dir = tmp.path().join("dom");
    std::fs::create_dir_all(&domain_dir).unwrap();
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&data_dir).unwrap();

    init_domain_via_cli(&domain_dir, "acme.test");
    write_minimal_node_config(&data_dir, &domain_dir);

    // Reason contains a quote, a backslash, and a newline — all of
    // which must be escaped in the JSON output for the line to remain
    // valid one-object-per-line JSON.
    let nasty = "trip\\1: he said \"go\"\nand left";
    let rev_out = tmp.path().join("rev.cbor");
    let status = dds_node_bin()
        .args([
            "revoke-admission",
            "--domain-key",
            domain_dir.join("domain_key.bin").to_str().unwrap(),
            "--domain",
            domain_dir.join("domain.toml").to_str().unwrap(),
            "--peer-id",
            "12D3KooWPeerNasty",
            "--reason",
            nasty,
            "--out",
            rev_out.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
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
    assert!(status.success());

    let (ok, stdout, _stderr) = run_capture(dds_node_bin().args([
        "list-revocations",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--json",
    ]));
    assert!(ok);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // Exactly one line — the embedded newline must be escaped, not
    // emitted as a real LF that would split the record in two.
    assert_eq!(
        lines.len(),
        1,
        "embedded newline must be escaped, got lines: {lines:?}"
    );
    let line = lines[0];
    // Quote and backslash escaped per RFC 8259.
    assert!(line.contains("\\\""), "line: {line}");
    assert!(line.contains("\\\\"), "line: {line}");
    assert!(line.contains("\\n"), "line: {line}");
}

#[test]
fn list_revocations_without_dds_toml_fails_loudly() {
    // No dds.toml in the data dir — the command needs the domain
    // pubkey to verify entries, so it must refuse rather than silently
    // print whatever happens to be on disk.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("node");
    std::fs::create_dir_all(&data_dir).unwrap();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "list-revocations",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(!ok, "list-revocations without dds.toml must exit non-zero");
    assert!(
        stderr.contains("dds.toml") || stderr.contains("config"),
        "stderr should mention the missing config; got: {stderr}",
    );
}
