//! Threat-model §3 / open item #8: integration tests for
//! `dds-node restrict-data-dir-acl`.
//!
//! The Windows path (which actually applies the SDDL via
//! `SetNamedSecurityInfoW`) requires Windows host CI to verify
//! end-to-end. These tests cover the cross-platform contract: arg
//! parsing, error paths, and the friendly no-op behaviour on
//! non-Windows. The MSI custom action `CA_RestrictDataDirAcl` calls
//! the same binary with `--data-dir [CommonAppDataFolder]DDS`, so any
//! regression in arg parsing or exit codes here would break the
//! installer.

use std::process::{Command, Stdio};

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

#[test]
fn restrict_data_dir_acl_succeeds_on_existing_dir() {
    // On Windows this actually applies the DACL; on macOS / Linux it
    // is a no-op that prints a friendly explanation. Either way, the
    // binary must exit 0 and the directory must remain readable to
    // the calling process (so subsequent CA steps can write into it).
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    let status = dds_node_bin()
        .args([
            "restrict-data-dir-acl",
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "restrict-data-dir-acl must succeed on a freshly-created directory"
    );
    assert!(
        data_dir.exists() && data_dir.is_dir(),
        "data dir must still be a usable directory after the ACL pass"
    );
}

#[test]
fn restrict_data_dir_acl_fails_when_dir_missing() {
    // The MSI sequence guarantees `[CommonAppDataFolder]DDS` exists
    // before this CA runs (CG_AppData / <CreateFolder/>). If that
    // invariant ever breaks we want the install to fail loudly rather
    // than silently leaving the directory unprotected.
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("does-not-exist");

    let status = dds_node_bin()
        .args([
            "restrict-data-dir-acl",
            "--data-dir",
            missing.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "restrict-data-dir-acl must fail closed when the data dir does not exist"
    );
}

#[test]
fn restrict_data_dir_acl_rejects_non_directory_path() {
    let tmp = tempfile::tempdir().unwrap();
    let file_path = tmp.path().join("a-regular-file");
    std::fs::write(&file_path, b"not a directory").unwrap();

    let status = dds_node_bin()
        .args([
            "restrict-data-dir-acl",
            "--data-dir",
            file_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "restrict-data-dir-acl must refuse to ACL a non-directory target"
    );
}

#[test]
fn restrict_data_dir_acl_requires_data_dir_flag() {
    // Mirror gen-hmac-secret's contract: missing required flag exits
    // non-zero so the MSI custom action surfaces the failure rather
    // than silently no-op'ing.
    let status = dds_node_bin()
        .args(["restrict-data-dir-acl"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "restrict-data-dir-acl must require --data-dir"
    );
}

#[test]
fn restrict_data_dir_acl_is_idempotent() {
    // The CA may run on every install / repair; re-applying the same
    // DACL must succeed. (On non-Windows this is trivially true since
    // we only print; on Windows SetNamedSecurityInfoW with the same
    // SDDL is a documented no-op.)
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    for _ in 0..3 {
        let status = dds_node_bin()
            .args([
                "restrict-data-dir-acl",
                "--data-dir",
                data_dir.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "repeat invocation must succeed");
    }
}
