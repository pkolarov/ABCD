//! Build-time fingerprint capture for the `dds_build_info` Prometheus
//! gauge (observability-plan.md Phase C). Captures two values from the
//! build environment and emits them as `cargo:rustc-env=...` so
//! `env!("DDS_GIT_SHA")` and `env!("DDS_RUST_VERSION")` resolve at
//! compile time:
//!
//! - `DDS_GIT_SHA` — short hash from `git rev-parse --short HEAD` if a
//!   git tree is present, otherwise the literal string `unknown`. This
//!   matches the catalog row's "static fingerprint" framing — the SHA
//!   that built this binary, not the SHA running on the host.
//! - `DDS_RUST_VERSION` — `rustc --version` output, e.g.
//!   `rustc 1.85.0 (4d91de4e4 2025-02-17)`. Falls back to `unknown` if
//!   the rustc invocation fails (sandboxed CI without /usr/bin/env, etc.).
//!
//! `cargo:rerun-if-changed=` directives on `.git/HEAD` and the packed
//! refs file ensure a checkout that switches branches re-runs the
//! script; otherwise cargo would happily reuse a stale build cache and
//! the `dds_build_info{git_sha=...}` label would lie.

use std::process::Command;

fn main() {
    let git_sha = run("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=DDS_GIT_SHA={git_sha}");

    let rust_version = run("rustc", &["--version"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=DDS_RUST_VERSION={rust_version}");

    // Re-run if the working-tree HEAD moves. We watch HEAD itself (so a
    // branch switch / checkout fires) and the packed-refs file (so a
    // commit that does not move HEAD still busts the cache when refs
    // are repacked). Missing files are tolerated — a tarball build
    // outside a git tree skips this without erroring.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/packed-refs");
    println!("cargo:rerun-if-env-changed=DDS_GIT_SHA");
    println!("cargo:rerun-if-env-changed=DDS_RUST_VERSION");
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
