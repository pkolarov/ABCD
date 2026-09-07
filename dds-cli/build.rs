//! Inject the application release version from the repo-root VERSION file
//! so `env!("DDS_VERSION")` resolves to e.g. "1.6.2" at compile time.
//! The workspace Cargo version stays 0.1.0 and must not leak into
//! `dds --version`; operators use that output (and `dds-node version`)
//! to confirm which release an install is running. Mirrors the VERSION
//! handling in dds-node/build.rs. Falls back to "0.0.0" if the file is
//! missing (sandbox / tarball builds).

fn main() {
    let dds_version = std::fs::read_to_string("../VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    println!("cargo:rustc-env=DDS_VERSION={}", dds_version.trim());
    println!("cargo:rerun-if-changed=../VERSION");
}
