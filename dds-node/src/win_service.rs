//! Windows Service Control Manager (SCM) integration.
//!
//! When dds-node is registered as a Windows service, SCM launches the
//! binary and expects it to:
//!   1. Call `StartServiceCtrlDispatcher` within ~30s (otherwise SCM
//!      times out and reports "service failed to start" while the
//!      orphan process keeps running).
//!   2. Register a control handler for Stop / Shutdown.
//!   3. Transition state: StartPending → Running → Stopped.
//!
//! Without this, dds-node ran fine as a CLI but every Start-Service
//! call ended in SCM error 1920 and a dangling redb-locked process.
//!
//! Entrypoint: `main.rs` dispatches the `service-run` subcommand to
//! [`run`], which blocks inside `service_dispatcher::start` and is
//! eventually invoked back via [`service_main`]. Inside
//! [`service_main`] we build a tokio runtime, call [`crate_run_node`]
//! (the same code path as `dds-node run <config>`), and toggle
//! SERVICE_RUNNING / SERVICE_STOPPED around it.
//!
//! ## Sealed passphrase
//!
//! If the service was registered with `--unseal-passphrase-from <path>`,
//! [`run`] reads the DPAPI-sealed blob at `<path>`, calls
//! `CryptUnprotectData`, and sets `DDS_NODE_PASSPHRASE` in-process
//! **before** `service_dispatcher::start`. This ensures the node runtime
//! sees the passphrase before it loads any identity files.
//!
//! The MSI registers the service with:
//!   `service-run --config <path> --unseal-passphrase-from %ProgramData%\DDS\node-passphrase.dpapi`
//!
//! The Bootstrap-DdsDomain.ps1 script creates and seals the blob before
//! provisioning, so the keys land encrypted. On re-install over an
//! existing encrypted node, the sealed blob is already present and the
//! keys remain encrypted at rest.

#![cfg(windows)]

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "DdsNode";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Flag name for the sealed-passphrase path.
const UNSEAL_FLAG: &str = "--unseal-passphrase-from";

/// Block on the SCM dispatcher. Called from `main()` when argv[1] is
/// `service-run`. Returns when SCM tells us to stop or on dispatcher
/// failure.
///
/// Parses `--unseal-passphrase-from <path>` from argv, unseals the DPAPI
/// blob, and sets `DDS_NODE_PASSPHRASE` before entering the dispatcher.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // argv: [dds-node.exe, service-run, ...flags...]
    let args: Vec<String> = std::env::args().skip(2).collect();
    try_unseal_passphrase_from_args(&args)?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

/// If `--unseal-passphrase-from <path>` is present in `args`, read the
/// DPAPI blob at `<path>`, decrypt it, and set `DDS_NODE_PASSPHRASE`.
///
/// Logs a warning but does NOT fail if the file is absent (allows
/// running without a sealed passphrase on dev/test machines).
fn try_unseal_passphrase_from_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let Some(blob_path) = flag_value(args, UNSEAL_FLAG) else {
        return Ok(());
    };
    match std::fs::read(blob_path) {
        Ok(blob) => {
            let plaintext = crate::win_dpapi::unseal(&blob)
                .map_err(|e| format!("DPAPI unseal of {blob_path:?} failed: {e}"))?;
            let passphrase = String::from_utf8(plaintext.to_vec())
                .map_err(|_| "DPAPI blob is not valid UTF-8")?;
            // SAFETY: service-run executes as the SCM dispatch thread before
            // tokio is started; no other thread observes the env var yet.
            unsafe {
                std::env::set_var(crate::identity_store::PASSPHRASE_ENV, passphrase.trim());
            }
            tracing::info!(
                path = blob_path,
                "DDS_NODE_PASSPHRASE unsealed from DPAPI blob"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No sealed blob — fall through to plaintext mode. This is
            // normal on first install before provisioning or on dev boxes.
            tracing::warn!(
                path = blob_path,
                "sealed passphrase blob not found — \
                 starting without DDS_NODE_PASSPHRASE (keys plaintext)"
            );
        }
        Err(e) => {
            return Err(
                format!("failed to read sealed passphrase from {blob_path:?}: {e}").into(),
            );
        }
    }
    Ok(())
}

/// Return the value of `--flag <value>` from `args`, or `None`.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).map(String::as_str)
}

/// Remove `--unseal-passphrase-from <path>` from `args` so the remaining
/// args can be forwarded to `cmd_run` without it mistaking the path for
/// the config file.
fn strip_unseal_flag(mut args: Vec<String>) -> Vec<String> {
    if let Some(pos) = args.iter().position(|a| a == UNSEAL_FLAG) {
        // Remove the flag and its value (two elements).
        if pos + 1 < args.len() {
            args.remove(pos + 1);
        }
        args.remove(pos);
    }
    args
}

/// Invoked by the SCM dispatcher with whatever args
/// `lpServiceArgVectors` carried (typically empty — the binary picks
/// its own args from `std::env::args()`).
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // Dispatcher writes its own log on failure, but tracing init
        // may already be running — duplicate to stderr just in case.
        eprintln!("[dds-node service] fatal: {e:?}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    // Channel the SCM control handler uses to nudge the main thread.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // 1. Tell SCM we're starting.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(60),
        process_id: None,
    })?;

    // The original argv lives on; we stripped only the `service-run`
    // subcommand verb in main(). Strip the unseal flag too so `cmd_run`
    // doesn't mistake the blob path for the config file.
    let cli_args = strip_unseal_flag(std::env::args().skip(2).collect());

    // Build a multi-thread tokio runtime — the swarm + HTTP server
    // pair both demand it.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Run the node inside the runtime. We spawn it as a task so the
    // main thread stays free to listen for SCM Stop and to report
    // SERVICE_RUNNING the moment node init signals readiness.
    let node_handle = runtime.spawn(async move {
        // Same code path as `dds-node run <config>` — `cmd_run` is the
        // existing main.rs entry that loads the config, brings up the
        // P2P node + HTTP API, and blocks on `node.run()`.
        if let Err(e) = crate::cmd_run(&cli_args).await {
            tracing::error!(error = %e, "dds-node service exited with error");
        }
    });

    // 2. Tell SCM we're up. We do this immediately after kicking off
    //    the spawn — the actual readiness gate is the named pipe
    //    appearing in the filesystem, but SCM only cares that we
    //    answered StartPending → Running within wait_hint. Operator
    //    health checks (via DDS Console / DdsAuthBridge) wait for
    //    the pipe.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    // 3. Block until SCM Stop / Shutdown.
    let _ = shutdown_rx.recv();
    tracing::info!("SCM Stop received — shutting down dds-node");

    // Cancel the node task and let the runtime wind down. tokio's
    // Drop on the runtime gives us a 10s grace period.
    node_handle.abort();
    drop(runtime);

    // 4. Tell SCM we're stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_unseal_flag_removes_flag_and_value() {
        let args = vec![
            "--config".to_string(),
            "node.toml".to_string(),
            "--unseal-passphrase-from".to_string(),
            r"C:\ProgramData\DDS\node-passphrase.dpapi".to_string(),
        ];
        let stripped = strip_unseal_flag(args);
        assert_eq!(stripped, vec!["--config", "node.toml"]);
    }

    #[test]
    fn strip_unseal_flag_noop_when_absent() {
        let args = vec!["--config".to_string(), "node.toml".to_string()];
        let stripped = strip_unseal_flag(args.clone());
        assert_eq!(stripped, args);
    }

    #[test]
    fn strip_unseal_flag_handles_flag_at_end_with_no_value() {
        // Malformed invocation: flag present but no following value.
        // Should remove only the flag itself and not panic.
        let args = vec!["--config".to_string(), "--unseal-passphrase-from".to_string()];
        let stripped = strip_unseal_flag(args);
        assert_eq!(stripped, vec!["--config"]);
    }

    #[test]
    fn flag_value_finds_value() {
        let args = vec![
            "--config".to_string(),
            "node.toml".to_string(),
            "--unseal-passphrase-from".to_string(),
            "blob.dpapi".to_string(),
        ];
        assert_eq!(flag_value(&args, "--unseal-passphrase-from"), Some("blob.dpapi"));
    }

    #[test]
    fn flag_value_returns_none_when_absent() {
        let args = vec!["--config".to_string(), "node.toml".to_string()];
        assert_eq!(flag_value(&args, "--unseal-passphrase-from"), None);
    }
}
