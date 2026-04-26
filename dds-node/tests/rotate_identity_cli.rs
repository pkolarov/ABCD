//! End-to-end CLI test for `dds-node rotate-identity`
//! (threat-model §2 recommendation #3 / §8 open item #9).
//!
//! Exercises the round-trip: an operator runs `gen-node-key` to create
//! a fresh `p2p_key.bin`, then `rotate-identity` to replace it with a
//! new keypair. The on-disk file must end up with a different PeerId,
//! the previous file must survive at the printed backup path (unless
//! `--no-backup`), and the new file must be loadable by the same code
//! path the running node uses (`p2p_identity::load`). Negative tests
//! cover missing-data-dir / missing-key-file, the encrypted-blob
//! refuse-without-passphrase guard (so we never silently overwrite a
//! key we cannot read), and the `--no-backup` short-circuit.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use dds_node::p2p_identity;
use libp2p::PeerId;

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn run_capture(cmd: &mut Command) -> (bool, String, String) {
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (out.status.success(), stdout, stderr)
}

fn gen_initial_key(data_dir: &std::path::Path) -> PeerId {
    let status = dds_node_bin()
        .args(["gen-node-key", "--data-dir", data_dir.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "gen-node-key should succeed");
    let kp = p2p_identity::load(&data_dir.join("p2p_key.bin")).unwrap();
    PeerId::from(kp.public())
}

#[test]
fn rotate_identity_replaces_keypair_and_keeps_backup_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let p2p_path = data_dir.join("p2p_key.bin");

    let old_id = gen_initial_key(data_dir);

    // Snapshot the file bytes so we can verify the backup is the
    // exact pre-rotation blob (atomic-rename semantics).
    let old_bytes = std::fs::read(&p2p_path).unwrap();

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(ok, "rotate-identity must succeed; stderr={stderr}");

    let old_str = old_id.to_string();
    assert!(
        stdout.contains(&old_str),
        "stdout must report the old peer id ({old_str}); got: {stdout}"
    );
    assert!(
        stdout.contains("new_peer_id:"),
        "stdout must include a new_peer_id line; got: {stdout}"
    );

    // The on-disk file must now decode to a different PeerId.
    let new_kp = p2p_identity::load(&p2p_path).unwrap();
    let new_id = PeerId::from(new_kp.public());
    assert_ne!(new_id, old_id, "rotation must produce a different PeerId");

    // The backup must exist and contain the original bytes verbatim.
    let backup_path = parse_backup_path(&stdout, data_dir).expect("stdout must report backup path");
    let backup_bytes = std::fs::read(&backup_path).unwrap();
    assert_eq!(
        backup_bytes, old_bytes,
        "backup must be byte-identical to the pre-rotation key"
    );

    // The backup is still loadable as the OLD peer id, so an operator
    // who needs to recover (e.g. revoke the new key after a botched
    // restart) can.
    let backup_kp = p2p_identity::load(&backup_path).unwrap();
    assert_eq!(
        PeerId::from(backup_kp.public()),
        old_id,
        "backup must still load to the old peer id"
    );

    // The follow-up instructions must reference both peer ids and
    // both `admit` and `revoke-admission` so the operator knows the
    // full sequence.
    assert!(
        stdout.contains("dds-node admit"),
        "stdout must show admit hint: {stdout}"
    );
    assert!(
        stdout.contains("dds-node revoke-admission"),
        "stdout must show revoke-admission hint: {stdout}"
    );
    assert!(
        stdout.contains(&new_id.to_string()),
        "stdout must include the new peer id in the admit hint: {stdout}"
    );
}

#[test]
fn rotate_identity_no_backup_skips_backup_file() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let _old_id = gen_initial_key(data_dir);

    let entries_before: Vec<_> = std::fs::read_dir(data_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        entries_before.iter().any(|n| n == "p2p_key.bin"),
        "p2p_key.bin must exist before rotate"
    );

    let (ok, stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--no-backup",
    ]));
    assert!(
        ok,
        "rotate-identity --no-backup must succeed; stderr={stderr}"
    );
    assert!(
        stdout.contains("backup:      (skipped"),
        "stdout must indicate the backup was skipped; got: {stdout}"
    );

    // After --no-backup there must be exactly one p2p_key file in the
    // directory (the new one), with no `p2p_key.bin.rotated.*`
    // siblings.
    let entries_after: Vec<String> = std::fs::read_dir(data_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let rotated_siblings: Vec<&String> = entries_after
        .iter()
        .filter(|n| n.starts_with("p2p_key.bin.rotated"))
        .collect();
    assert!(
        rotated_siblings.is_empty(),
        "--no-backup must not leave any backup files; found {rotated_siblings:?}"
    );
}

#[test]
fn rotate_identity_fails_when_data_dir_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-identity",
        "--data-dir",
        missing.to_str().unwrap(),
    ]));
    assert!(
        !ok,
        "rotate-identity must fail when data_dir does not exist"
    );
    assert!(
        stderr.contains("does not exist"),
        "stderr must explain the missing data_dir: {stderr}"
    );
}

#[test]
fn rotate_identity_fails_when_p2p_key_missing() {
    // data_dir exists but no prior p2p_key.bin — the operator should
    // be redirected to `gen-node-key` rather than getting a fresh key
    // they didn't ask for.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args([
        "rotate-identity",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]));
    assert!(!ok, "rotate-identity must fail when p2p_key.bin is absent");
    assert!(
        stderr.contains("gen-node-key"),
        "stderr must mention gen-node-key as the recovery action: {stderr}"
    );
    // The directory must NOT have been written into.
    assert!(
        !data_dir.join("p2p_key.bin").exists(),
        "rotate-identity must not create p2p_key.bin when it was missing"
    );
}

#[test]
fn rotate_identity_refuses_to_overwrite_unreadable_encrypted_blob() {
    // Write an encrypted p2p_key.bin but invoke rotate-identity in a
    // subprocess WITHOUT DDS_NODE_PASSPHRASE. The command must refuse,
    // because rotating without first decrypting the prior key would
    // silently lose the old PeerId — the operator needs that to issue
    // a revocation. This is the safety guarantee documented in the
    // command's docstring.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let p2p_path = data_dir.join("p2p_key.bin");

    // Save the initial key WITH a passphrase by setting it in the
    // child's env. Subsequent rotate-identity is invoked without it.
    let status = dds_node_bin()
        .args(["gen-node-key", "--data-dir", data_dir.to_str().unwrap()])
        .env("DDS_NODE_PASSPHRASE", "rotate-test-passphrase")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let original_bytes = std::fs::read(&p2p_path).unwrap();

    // Now invoke rotate-identity with NO passphrase. Must fail before
    // touching anything.
    let mut cmd = dds_node_bin();
    cmd.args(["rotate-identity", "--data-dir", data_dir.to_str().unwrap()])
        .env_remove("DDS_NODE_PASSPHRASE");
    let (ok, _stdout, stderr) = run_capture(&mut cmd);
    assert!(
        !ok,
        "rotate-identity without passphrase must refuse to overwrite an encrypted key"
    );
    assert!(
        stderr.contains("DDS_NODE_PASSPHRASE")
            || stderr.contains("encrypted")
            || stderr.contains("PASSPHRASE"),
        "stderr must explain the passphrase requirement: {stderr}"
    );

    // The file must be byte-identical to the pre-rotate state.
    let after_bytes = std::fs::read(&p2p_path).unwrap();
    assert_eq!(
        after_bytes, original_bytes,
        "p2p_key.bin must be untouched when rotate refused"
    );

    // No `*.rotated.*` siblings should have been created either.
    let rotated_siblings: Vec<String> = std::fs::read_dir(data_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("p2p_key.bin.rotated"))
        .collect();
    assert!(
        rotated_siblings.is_empty(),
        "no backup files should exist after a refused rotation; found {rotated_siblings:?}"
    );
}

#[test]
fn rotate_identity_requires_no_flag_other_than_data_dir() {
    // Exercise the `require_flag("--data-dir")` path explicitly: no
    // `--data-dir` ⇒ Err, and the error must name the missing flag.
    let (ok, _stdout, stderr) = run_capture(dds_node_bin().args(["rotate-identity"]));
    assert!(!ok);
    assert!(
        stderr.contains("--data-dir"),
        "missing --data-dir must be named in stderr: {stderr}"
    );
}

/// Extract the absolute backup path from the `backup:` line in
/// `rotate-identity` stdout. Returns None if not found.
fn parse_backup_path(stdout: &str, data_dir: &std::path::Path) -> Option<PathBuf> {
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("backup:") {
            let path = rest.trim();
            if path.starts_with('(') {
                return None;
            }
            let p = PathBuf::from(path);
            // Sanity-check: the printed backup must live under the
            // operator-supplied data_dir.
            assert!(
                p.starts_with(data_dir),
                "printed backup path {p:?} must be inside data_dir {data_dir:?}"
            );
            return Some(p);
        }
    }
    None
}
