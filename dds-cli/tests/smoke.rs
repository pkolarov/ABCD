//! CLI smoke tests — build and run the binary with various subcommands.

use std::process::Command;

fn dds_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds"))
}

#[test]
fn test_help() {
    let output = dds_cli().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Decentralized Directory Service CLI"));
    // All top-level subcommands should be advertised in --help.
    for cmd in [
        "identity", "group", "policy", "status", "enroll", "admin", "audit", "platform", "cp",
        "debug", "stats", "health", "export", "import", "pq",
    ] {
        assert!(stdout.contains(cmd), "help missing {cmd}: {stdout}");
    }
}

#[test]
fn test_subcommand_help() {
    // Every new subcommand tree must have its own --help without crashing.
    for tree in [
        vec!["audit", "--help"],
        vec!["audit", "list", "--help"],
        vec!["admin", "--help"],
        vec!["admin", "setup", "--help"],
        vec!["admin", "vouch", "--help"],
        vec!["enroll", "--help"],
        vec!["enroll", "user", "--help"],
        vec!["enroll", "device", "--help"],
        vec!["platform", "--help"],
        vec!["platform", "windows", "--help"],
        vec!["platform", "windows", "policies", "--help"],
        vec!["platform", "windows", "applied", "--help"],
        vec!["platform", "windows", "claim-account", "--help"],
        vec!["platform", "macos", "--help"],
        vec!["debug", "--help"],
        vec!["debug", "ping", "--help"],
        vec!["debug", "stats", "--help"],
        vec!["debug", "config", "--help"],
        vec!["stats", "--help"],
        vec!["health", "--help"],
        vec!["audit", "export", "--help"],
        vec!["export", "--help"],
        vec!["import", "--help"],
        vec!["pq", "--help"],
        vec!["pq", "status", "--help"],
        vec!["pq", "list-pubkeys", "--help"],
    ] {
        let out = dds_cli().args(&tree).output().unwrap();
        assert!(
            out.status.success(),
            "help failed for {tree:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn test_remote_commands_fail_when_node_absent() {
    // Use an unreachable node URL (an unassigned loopback port on a reserved
    // 127.x range) so the CLI is forced to report the reach error cleanly.
    let bad_url = "http://127.0.0.1:1"; // port 1 won't accept connections
    for tree in [
        vec!["--node-url", bad_url, "status", "--remote"],
        vec!["--node-url", bad_url, "audit", "list"],
        vec!["--node-url", bad_url, "debug", "ping"],
        vec!["--node-url", bad_url, "debug", "stats"],
        vec!["--node-url", bad_url, "stats"],
        vec!["--node-url", bad_url, "health"],
        vec!["--node-url", bad_url, "audit", "export"],
    ] {
        let out = dds_cli().args(&tree).output().unwrap();
        assert!(!out.status.success(), "expected failure for {tree:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("cannot reach dds-node"),
            "unexpected stderr for {tree:?}: {stderr}"
        );
    }
}

#[test]
fn test_audit_export_rejects_unknown_format() {
    // Format check happens before any HTTP call, so an unreachable
    // node-url is fine — the CLI must exit non-zero with a clear
    // message naming the unsupported format and the supported set.
    // `xml` is intentionally unsupported (jsonl / cef / syslog all
    // ship); historically this test guarded `cef` rejection but those
    // formats now ship under the Phase B.1 follow-up.
    let bad_url = "http://127.0.0.1:1";
    let out = dds_cli()
        .args(["--node-url", bad_url, "audit", "export", "--format", "xml"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unsupported audit format"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains("jsonl, cef, syslog"),
        "expected supported-format hint, got: {stderr}"
    );
}

#[test]
fn test_audit_export_accepts_cef_and_syslog_format_args() {
    // Negative test: CEF and syslog must NOT be rejected at format
    // parse time — only the HTTP reach failure should surface.
    let bad_url = "http://127.0.0.1:1";
    for fmt in ["cef", "syslog"] {
        let out = dds_cli()
            .args(["--node-url", bad_url, "audit", "export", "--format", fmt])
            .output()
            .unwrap();
        assert!(!out.status.success(), "expected failure for {fmt}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("cannot reach dds-node"),
            "{fmt}: expected reach failure, got: {stderr}"
        );
        assert!(
            !stderr.contains("unsupported"),
            "{fmt}: format should have parsed: {stderr}"
        );
    }
}

#[test]
fn test_health_rejects_unknown_format_after_reach_failure() {
    // `health` parses --format only after the HTTP call returns, so an
    // unreachable URL fails earlier with the standard reach error —
    // matching the test_remote_commands_fail_when_node_absent posture.
    let bad_url = "http://127.0.0.1:1";
    let out = dds_cli()
        .args(["--node-url", bad_url, "health", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot reach dds-node"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn test_debug_config_parses_toml() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cfg_path = tmp.path().join("test-config.toml");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    writeln!(
        f,
        "[domain]\nmax_delegation_depth = 7\naudit_log_enabled = true\naudit_log_max_entries = 500\n"
    )
    .unwrap();
    let out = dds_cli()
        .args(["debug", "config", cfg_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "debug config failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("max_delegation_depth: 7"));
    assert!(stdout.contains("audit_log_enabled: true"));
    assert!(stdout.contains("audit_log_max_entries: 500"));
}

#[test]
fn test_debug_config_rejects_invalid_toml() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let cfg_path = tmp.path().join("broken.toml");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    writeln!(f, "[domain\nthis is = not = valid").unwrap();
    let out = dds_cli()
        .args(["debug", "config", cfg_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Invalid TOML"));
}

#[test]
fn test_identity_create_classical() {
    let output = dds_cli()
        .args(["identity", "create", "smoke-test-alice"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("urn:vouchsafe:smoke-test-alice."));
    assert!(stdout.contains("Ed25519"));
    assert!(stdout.contains("32 bytes"));
}

#[test]
fn test_identity_create_hybrid() {
    let output = dds_cli()
        .args(["identity", "create", "smoke-quantum", "--hybrid"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("urn:vouchsafe:smoke-quantum."));
    assert!(stdout.contains("hybrid"));
    assert!(stdout.contains("1984 bytes"));
}

#[test]
fn test_identity_show_valid() {
    let output = dds_cli()
        .args(["identity", "show", "urn:vouchsafe:alice.abcdef123"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Label: alice"));
    assert!(stdout.contains("Hash:  abcdef123"));
}

#[test]
fn test_identity_show_invalid() {
    let output = dds_cli()
        .args(["identity", "show", "not-a-urn"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid URN"));
}

#[test]
fn test_policy_check() {
    let output = dds_cli()
        .args([
            "policy",
            "check",
            "--user",
            "urn:vouchsafe:bob.hash",
            "--resource",
            "repo:main",
            "--action",
            "read",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // No rules loaded → should deny
    assert!(stdout.contains("DENY"));
}

#[test]
fn test_status_no_store() {
    let tmp = tempfile::tempdir().unwrap();
    let output = dds_cli()
        .args(["--data-dir", tmp.path().to_str().unwrap(), "status"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No store found"));
}

#[test]
fn test_group_vouch_and_status() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_str().unwrap();

    // Vouch
    let output = dds_cli()
        .args([
            "--data-dir",
            data_dir,
            "group",
            "vouch",
            "--as-label",
            "admin",
            "--user",
            "urn:vouchsafe:bob.fakehash",
            "--purpose",
            "group:backend",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "vouch failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Vouch created"));
    assert!(stdout.contains("group:backend"));

    // Status should now show 1 token
    let output = dds_cli()
        .args(["--data-dir", data_dir, "status"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Tokens:       1"));
}

// ================================================================
// export / import (air-gapped sync)
// ================================================================

/// Write a minimal `domain.toml` + `domain_key.bin` next to the
/// store so the export path (which now signs the dump with the
/// domain key per M-16) has a real key to unwrap. The `id` arg is
/// ignored for v2 signed dumps — the id is derived from the
/// generated key so the fixture must use whatever that yields. Kept
/// as `_id` for source-compat with the legacy callers.
#[allow(dead_code)]
fn seed_domain(dir: &std::path::Path, _id: &str) {
    use dds_domain::DomainKey;
    use rand::rngs::OsRng;
    // Plain-mode domain key (no passphrase) so tests don't need to
    // juggle env state. Matches the existing `provision_with_plain_domain_key`
    // convention.
    // SAFETY: set_var is required because the signing path reads
    // DDS_DOMAIN_PASSPHRASE from the environment; an empty value
    // keeps tests deterministic under parallel execution.
    unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "") };
    let key = DomainKey::generate("test.example", &mut OsRng);
    let domain = key.domain();
    dds_node::domain_store::save_domain_file(&dir.join("domain.toml"), &domain).unwrap();
    dds_node::domain_store::save_domain_key(&dir.join("domain_key.bin"), &key).unwrap();
}

/// Helper: the real domain id the test fixture will have, derived
/// from the key generated in `seed_domain`. Tests that compare
/// domain ids should call `seed_domain_returning_id` instead.
#[allow(dead_code)]
fn seed_domain_returning_id(dir: &std::path::Path) -> String {
    use dds_domain::DomainKey;
    use rand::rngs::OsRng;
    unsafe { std::env::set_var("DDS_DOMAIN_PASSPHRASE", "") };
    let key = DomainKey::generate("test.example", &mut OsRng);
    let domain = key.domain();
    dds_node::domain_store::save_domain_file(&dir.join("domain.toml"), &domain).unwrap();
    dds_node::domain_store::save_domain_key(&dir.join("domain_key.bin"), &key).unwrap();
    domain.id.to_string()
}

#[test]
fn test_export_import_round_trip() {
    // Node A: create a vouch + revocation + burn, export.
    let src = tempfile::tempdir().unwrap();
    let src_dir = src.path().to_str().unwrap();
    let domain_id = seed_domain_returning_id(src.path());

    // Populate with a vouch.
    let out = dds_cli()
        .args([
            "--data-dir",
            src_dir,
            "group",
            "vouch",
            "--as-label",
            "admin",
            "--user",
            "urn:vouchsafe:bob.fakehash",
            "--purpose",
            "group:backend",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Export.
    let dump_path = src.path().join("sync.ddsdump");
    let out = dds_cli()
        .args([
            "--data-dir",
            src_dir,
            "export",
            "--out",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Tokens:     1"));
    assert!(dump_path.exists());

    // L-5 (security review) — the dump carries every signed token plus
    // the revoked / burned sets, so the writer must restrict the file
    // to owner-only. Pin the 0o600 mode on Unix so a regression that
    // drops the `set_permissions` call surfaces here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dump_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "dump file mode must be 0o600");
    }

    // Z-5 (security review) — the dump is signed for integrity but is
    // NOT encrypted. The CLI must surface that confidentiality posture
    // explicitly so an operator who pipes the dump into a courier flow
    // does not silently ship plaintext directory state.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("WARNING") && stderr.contains("NOT encrypted"),
        "export must warn that the dump is not encrypted; stderr was: {stderr}"
    );

    // Node B: empty, same domain. Clone the src's domain files so
    // the signed dump verifies against dst's copy of the pubkey.
    let dst = tempfile::tempdir().unwrap();
    let dst_dir = dst.path().to_str().unwrap();
    std::fs::copy(
        src.path().join("domain.toml"),
        dst.path().join("domain.toml"),
    )
    .unwrap();
    // dst intentionally does NOT have domain_key.bin — it's an
    // importer, not a signer.
    let _ = domain_id; // same domain by construction

    let out = dds_cli()
        .args([
            "--data-dir",
            dst_dir,
            "import",
            "--in",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Tokens:     1 new"));

    // Node B's status should now show 1 token.
    let out = dds_cli()
        .args(["--data-dir", dst_dir, "status"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Tokens:       1"));

    // Second import is idempotent — everything duplicated.
    let out = dds_cli()
        .args([
            "--data-dir",
            dst_dir,
            "import",
            "--in",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0 new, 1 already present"));
}

#[test]
fn test_import_rejects_domain_mismatch() {
    let src = tempfile::tempdir().unwrap();
    let _src_id = seed_domain_returning_id(src.path());
    // Populate something exportable.
    let out = dds_cli()
        .args([
            "--data-dir",
            src.path().to_str().unwrap(),
            "group",
            "vouch",
            "--as-label",
            "a",
            "--user",
            "urn:vouchsafe:x.h",
            "--purpose",
            "group:x",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let dump_path = src.path().join("alpha.ddsdump");
    let out = dds_cli()
        .args([
            "--data-dir",
            src.path().to_str().unwrap(),
            "export",
            "--out",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Destination node on a different domain.
    let dst = tempfile::tempdir().unwrap();
    let _ = seed_domain_returning_id(dst.path());
    let out = dds_cli()
        .args([
            "--data-dir",
            dst.path().to_str().unwrap(),
            "import",
            "--in",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "import should have been rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("domain mismatch"));
}

#[test]
fn test_import_dry_run_makes_no_writes() {
    let src = tempfile::tempdir().unwrap();
    let _ = seed_domain_returning_id(src.path());
    let out = dds_cli()
        .args([
            "--data-dir",
            src.path().to_str().unwrap(),
            "group",
            "vouch",
            "--as-label",
            "a",
            "--user",
            "urn:vouchsafe:x.h",
            "--purpose",
            "group:x",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let dump_path = src.path().join("dry.ddsdump");
    let out = dds_cli()
        .args([
            "--data-dir",
            src.path().to_str().unwrap(),
            "export",
            "--out",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Empty dest — dry-run should print summary but not create a store.
    // Clone src's domain so signature verification passes.
    let dst = tempfile::tempdir().unwrap();
    std::fs::copy(
        src.path().join("domain.toml"),
        dst.path().join("domain.toml"),
    )
    .unwrap();
    let out = dds_cli()
        .args([
            "--data-dir",
            dst.path().to_str().unwrap(),
            "import",
            "--in",
            dump_path.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("(dry run"));
    assert!(!dst.path().join("directory.redb").exists());
}

#[test]
fn test_group_vouch_then_revoke() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().to_str().unwrap();

    // Vouch first
    let output = dds_cli()
        .args([
            "--data-dir",
            data_dir,
            "group",
            "vouch",
            "--as-label",
            "admin",
            "--user",
            "urn:vouchsafe:carol.hash",
            "--purpose",
            "group:dev",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    // Extract JTI from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let jti_line = stdout.lines().find(|l| l.contains("JTI:")).unwrap();
    let jti = jti_line.split_whitespace().last().unwrap();

    // Revoke
    let output = dds_cli()
        .args([
            "--data-dir",
            data_dir,
            "group",
            "revoke",
            "--as-label",
            "admin",
            "--jti",
            jti,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Revoked JTI:"));

    // Status should show revocation
    let output = dds_cli()
        .args(["--data-dir", data_dir, "status"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Revocations:  1"));
}

// ================================================================
// pq (Z-1 Phase B operator surface)
// ================================================================

#[test]
fn test_pq_status_no_state() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dds_cli()
        .args(["--data-dir", tmp.path().to_str().unwrap(), "pq", "status"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DDS PQ Status"), "stdout: {stdout}");
    assert!(stdout.contains("Epoch key store:          not initialized"));
    assert!(stdout.contains("Peer cert cache:          not initialized"));
}

/// Z-5 — encrypted export/import round-trip using hybrid-KEM envelope.
///
/// The destination's KEM keypair is created ahead of time via
/// `EpochKeyStore::new`. The source exports with `--encrypt-to <hex>` and the
/// destination imports transparently (auto-loading `epoch_keys.cbor` to decap).
#[test]
fn test_export_import_encrypted_round_trip() {
    use dds_node::epoch_key_store::EpochKeyStore;
    use rand::rngs::OsRng;

    // ---- Source node: seed domain + one vouch ----
    let src = tempfile::tempdir().unwrap();
    let src_dir = src.path().to_str().unwrap();
    let _domain_id = seed_domain_returning_id(src.path());
    let out = dds_cli()
        .args([
            "--data-dir",
            src_dir,
            "group",
            "vouch",
            "--as-label",
            "admin",
            "--user",
            "urn:vouchsafe:encrypted.fakehash",
            "--purpose",
            "group:backend",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "vouch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ---- Destination node: create epoch key store ----
    let dst = tempfile::tempdir().unwrap();
    let dst_dir = dst.path().to_str().unwrap();
    let mut rng = OsRng;
    let dst_store = EpochKeyStore::new(&mut rng);
    let epoch_path = dst.path().join("epoch_keys.cbor");
    dst_store.save(&epoch_path).unwrap();
    let kem_pubkey_hex = hex::encode(dst_store.kem_public().to_bytes());

    // ---- Export from source with --encrypt-to ----
    let dump_path = src.path().join("encrypted.ddsdump");
    let out = dds_cli()
        .args([
            "--data-dir",
            src_dir,
            "export",
            "--out",
            dump_path.to_str().unwrap(),
            "--encrypt-to",
            &kem_pubkey_hex,
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Should NOT warn about plaintext since we encrypted.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("NOT encrypted"),
        "encrypted export must not warn about plaintext; stderr was: {stderr}"
    );
    assert!(
        stderr.contains("hybrid-KEM encrypted"),
        "encrypted export must confirm encryption; stderr was: {stderr}"
    );

    // Verify the file has the MAGIC prefix.
    let raw = std::fs::read(&dump_path).unwrap();
    assert!(
        raw.starts_with(b"DDSDUMP_ENC_V1\0"),
        "encrypted dump must start with DDSDUMP_ENC_V1\\0 magic"
    );

    // ---- Destination node: copy domain.toml so signature verifies ----
    std::fs::copy(
        src.path().join("domain.toml"),
        dst.path().join("domain.toml"),
    )
    .unwrap();

    let out = dds_cli()
        .args([
            "--data-dir",
            dst_dir,
            "import",
            "--in",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Decrypted hybrid-KEM-encrypted dump"),
        "import must confirm decryption; stderr was: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Tokens:     1 new"),
        "import must report 1 new token; stdout was: {stdout}"
    );

    // Second import is idempotent.
    let out = dds_cli()
        .args([
            "--data-dir",
            dst_dir,
            "import",
            "--in",
            dump_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0 new, 1 already present"),
        "second encrypted import must be idempotent; stdout was: {stdout}"
    );
}

#[test]
fn test_pq_list_pubkeys_no_state() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dds_cli()
        .args([
            "--data-dir",
            tmp.path().to_str().unwrap(),
            "pq",
            "list-pubkeys",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No peer cert cache"), "stdout: {stdout}");
}

#[test]
fn test_pq_status_reports_initialized_store() {
    use rand::rngs::OsRng;
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    // Seed a fresh epoch_keys.cbor by constructing the store and saving.
    let mut rng = OsRng;
    let store = dds_node::epoch_key_store::EpochKeyStore::new(&mut rng);
    store.save(&data_dir.join("epoch_keys.cbor")).unwrap();

    let out = dds_cli()
        .args(["--data-dir", data_dir.to_str().unwrap(), "pq", "status"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("KEM pubkey hash"), "stdout: {stdout}");
    // Fresh store seeds epoch_id = 1 (B.6 contract).
    assert!(
        stdout.contains("Current epoch_id:         1"),
        "stdout: {stdout}"
    );
    // Fresh store has no cached peer releases yet.
    assert!(
        stdout.contains("Cached peer releases:     0"),
        "stdout: {stdout}"
    );
    // Peer cert cache file still missing.
    assert!(
        stdout.contains("Peer cert cache:          not initialized"),
        "stdout: {stdout}"
    );
}
