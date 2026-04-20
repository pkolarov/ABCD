//! H-6 step-2: integration test for `dds-node gen-hmac-secret`.
//!
//! Exercises the subcommand against the compiled binary. Pins the
//! behaviour operators (and the MSI custom action) will rely on:
//!   - 32 random bytes written to the target path, `0o600` on Unix
//!   - refuse to overwrite an existing file without `--force`
//!   - replace the file when `--force` is passed, with a different
//!     32-byte value (i.e., the generator is actually random).
//!   - parent directory is created if missing.

use std::process::{Command, Stdio};

fn dds_node_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dds-node"))
}

fn file_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("read secret file")
}

#[test]
fn gen_hmac_secret_writes_32_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("node-hmac.key");

    let status = dds_node_bin()
        .args(["gen-hmac-secret", "--out", out.to_str().unwrap()])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "gen-hmac-secret should succeed on fresh out");
    let bytes = file_bytes(&out);
    assert_eq!(bytes.len(), 32, "HMAC secret must be exactly 32 bytes");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "HMAC secret file must be 0o600 on Unix");
    }
}

#[test]
fn gen_hmac_secret_refuses_overwrite_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("node-hmac.key");

    assert!(
        dds_node_bin()
            .args(["gen-hmac-secret", "--out", out.to_str().unwrap()])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let first = file_bytes(&out);

    let status = dds_node_bin()
        .args(["gen-hmac-secret", "--out", out.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "gen-hmac-secret must fail when --force is not set and file exists"
    );
    let after_second = file_bytes(&out);
    assert_eq!(
        first, after_second,
        "file must NOT have been overwritten without --force"
    );
}

#[test]
fn gen_hmac_secret_force_replaces_file() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("node-hmac.key");

    assert!(
        dds_node_bin()
            .args(["gen-hmac-secret", "--out", out.to_str().unwrap()])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let first = file_bytes(&out);

    assert!(
        dds_node_bin()
            .args([
                "gen-hmac-secret",
                "--out",
                out.to_str().unwrap(),
                "--force",
            ])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let second = file_bytes(&out);
    assert_eq!(second.len(), 32);
    assert_ne!(
        first, second,
        "rotated secret must differ from the previous one"
    );
}

#[test]
fn gen_hmac_secret_creates_missing_parent_dir() {
    let tmp = tempfile::tempdir().unwrap();
    // Path with a parent directory that does not yet exist. The MSI
    // custom action relies on this: on a clean install, ProgramData\DDS
    // exists (created by CG_AppData), but tests lean on the fallback
    // anyway to avoid a separate `mkdir` step.
    let out = tmp.path().join("sub/dir/node-hmac.key");
    assert!(!out.parent().unwrap().exists());

    assert!(
        dds_node_bin()
            .args(["gen-hmac-secret", "--out", out.to_str().unwrap()])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(file_bytes(&out).len(), 32);
}
