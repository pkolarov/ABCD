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
        "debug",
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
