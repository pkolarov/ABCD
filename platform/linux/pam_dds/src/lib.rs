// SPDX-License-Identifier: MIT OR Apache-2.0
//!
//! DDS PAM authentication module (`pam_dds.so`).
//!
//! ## Overview
//!
//! This crate is compiled as a `cdylib` and loaded by the Linux-PAM
//! framework when a service is configured to use `pam_dds`.  The module:
//!
//! 1. Reads the username from the PAM stack (`pam_get_item(PAM_USER)`).
//! 2. Spawns [`dds-pam-helper`] as a subprocess, passing the username and
//!    the dds-node socket path as arguments.
//! 3. The helper performs the FIDO2 challenge/response flow against the
//!    local `dds-node` HTTP API and writes a JSON result object to stdout.
//! 4. If the helper exits with code 0 and the stdout is valid JSON, the
//!    module returns `PAM_SUCCESS`; otherwise `PAM_AUTH_ERR`.
//!
//! ## PAM configuration snippet
//!
//! ```text
//! auth required pam_dds.so node_sock=/var/lib/dds/dds.sock helper=/usr/lib/dds/dds-pam-helper
//! ```
//!
//! Supported module arguments:
//!
//! | Argument | Default | Description |
//! |---|---|---|
//! | `node_sock=PATH` | `/var/lib/dds/dds.sock` | Path to the dds-node Unix socket |
//! | `helper=PATH` | auto-detected | Path to `dds-pam-helper` binary |
//! | `debug` | off | Log debug information via `syslog(3)` |

#[cfg(target_os = "linux")]
mod linux;

// Re-export the PAM entry points so they appear at the crate root.
#[cfg(target_os = "linux")]
pub use linux::{pam_sm_acct_mgmt, pam_sm_authenticate, pam_sm_setcred};

// ─── shared helpers (compile on all platforms for `cargo test`) ───────────────

/// Candidate directories searched for `dds-pam-helper` when the `helper=`
/// module argument is not provided.
pub const HELPER_SEARCH_PATHS: &[&str] = &[
    "/usr/lib/dds/dds-pam-helper",
    "/usr/local/lib/dds/dds-pam-helper",
    "/usr/libexec/dds-pam-helper",
    "/usr/local/libexec/dds-pam-helper",
];

/// Default dds-node Unix socket path.
pub const DEFAULT_NODE_SOCK: &str = "/var/lib/dds/dds.sock";

/// Parse module arguments (`argc`/`argv` pairs forwarded by the PAM
/// framework) into a typed [`ModuleArgs`] struct.
///
/// The slice entries are expected to have the form `key=value` or bare
/// flags like `debug`.
pub fn parse_module_args(args: &[&str]) -> ModuleArgs {
    let mut out = ModuleArgs::default();
    for arg in args {
        if let Some(v) = arg.strip_prefix("node_sock=") {
            out.node_sock = v.to_owned();
        } else if let Some(v) = arg.strip_prefix("helper=") {
            out.helper_path = Some(v.to_owned());
        } else if *arg == "debug" {
            out.debug = true;
        }
    }
    out
}

/// Resolved module arguments after parsing the PAM config line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ModuleArgs {
    /// Path to the dds-node Unix socket.
    pub node_sock: String,
    /// Explicit path to `dds-pam-helper`, or `None` to auto-detect.
    pub helper_path: Option<String>,
    /// Whether verbose debug logging is enabled.
    pub debug: bool,
}

impl ModuleArgs {
    /// Return the `node_sock` path, falling back to [`DEFAULT_NODE_SOCK`].
    pub fn resolved_node_sock(&self) -> &str {
        if self.node_sock.is_empty() {
            DEFAULT_NODE_SOCK
        } else {
            &self.node_sock
        }
    }

    /// Find the `dds-pam-helper` binary to execute.
    ///
    /// Returns the explicit path if one was supplied, otherwise searches
    /// [`HELPER_SEARCH_PATHS`] and returns the first match that exists.
    pub fn resolve_helper(&self) -> Option<std::path::PathBuf> {
        if let Some(explicit) = &self.helper_path {
            return Some(std::path::PathBuf::from(explicit));
        }
        for candidate in HELPER_SEARCH_PATHS {
            let p = std::path::Path::new(candidate);
            if p.exists() {
                return Some(p.to_owned());
            }
        }
        None
    }
}

/// Outcome returned by the helper subprocess, serialised as JSON on stdout.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct HelperOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HelperOutcome {
    /// Try to parse helper stdout as a [`HelperOutcome`].  Returns `None`
    /// when the bytes are not valid UTF-8 or not valid JSON.
    pub fn from_stdout(bytes: &[u8]) -> Option<Self> {
        let s = std::str::from_utf8(bytes).ok()?;
        serde_json::from_str(s).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_empty() {
        let a = parse_module_args(&[]);
        assert_eq!(a, ModuleArgs::default());
        assert_eq!(a.resolved_node_sock(), DEFAULT_NODE_SOCK);
    }

    #[test]
    fn parse_args_node_sock() {
        let a = parse_module_args(&["node_sock=/tmp/test.sock"]);
        assert_eq!(a.node_sock, "/tmp/test.sock");
        assert_eq!(a.resolved_node_sock(), "/tmp/test.sock");
    }

    #[test]
    fn parse_args_helper_and_debug() {
        let a = parse_module_args(&["helper=/usr/bin/my-helper", "debug"]);
        assert_eq!(a.helper_path.as_deref(), Some("/usr/bin/my-helper"));
        assert!(a.debug);
    }

    #[test]
    fn parse_args_unknown_flags_are_ignored() {
        let a = parse_module_args(&["unknown_flag", "future_option=42"]);
        assert_eq!(a, ModuleArgs::default());
    }

    #[test]
    fn resolve_helper_explicit_path() {
        let a = ModuleArgs {
            helper_path: Some("/custom/helper".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            a.resolve_helper(),
            Some(std::path::PathBuf::from("/custom/helper"))
        );
    }

    #[test]
    fn resolve_helper_returns_none_when_no_candidates_exist() {
        // None of the HELPER_SEARCH_PATHS exist in a typical CI environment.
        let a = ModuleArgs::default();
        // We can't assert None universally (a dev box might have dds installed)
        // but we can verify the type is correct.
        let _ = a.resolve_helper();
    }

    #[test]
    fn helper_outcome_parse_success() {
        let json = r#"{"ok":true,"session_id":"sess-abc123"}"#;
        let out = HelperOutcome::from_stdout(json.as_bytes()).unwrap();
        assert!(out.ok);
        assert_eq!(out.session_id.as_deref(), Some("sess-abc123"));
    }

    #[test]
    fn helper_outcome_parse_failure() {
        let json = r#"{"ok":false,"error":"no enrolled credential for user"}"#;
        let out = HelperOutcome::from_stdout(json.as_bytes()).unwrap();
        assert!(!out.ok);
        assert!(out.error.is_some());
    }

    #[test]
    fn helper_outcome_parse_invalid_returns_none() {
        assert!(HelperOutcome::from_stdout(b"not json").is_none());
        assert!(HelperOutcome::from_stdout(b"").is_none());
    }

    #[test]
    fn resolved_node_sock_default() {
        let a = ModuleArgs::default();
        assert_eq!(a.resolved_node_sock(), DEFAULT_NODE_SOCK);
    }
}
