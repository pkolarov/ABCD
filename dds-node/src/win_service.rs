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
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "DdsNode";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// Upper bound on how long [`run_service`] waits for the node's API pipe to
/// be bound before reporting SERVICE_RUNNING anyway. Comfortably inside the
/// 60s StartPending `wait_hint` below so SCM never times the start out, yet
/// long enough to cover a cold-boot node init (redb open, identity load,
/// swarm bring-up).
const PIPE_READY_TIMEOUT_SECS: u64 = 30;
/// Poll cadence while waiting for the API pipe to appear.
const PIPE_POLL_INTERVAL_MS: u64 = 100;

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
            return Err(format!("failed to read sealed passphrase from {blob_path:?}: {e}").into());
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

    // If the node serves its HTTP API over a named pipe, resolve the full
    // pipe path now (before `cli_args` is moved into the task below). We use
    // it to gate the StartPending → Running transition on the pipe actually
    // being bound. `None` for non-pipe transports (loopback TCP, dev configs)
    // or if the config can't be read — both fall through to reporting Running
    // immediately, exactly as before.
    let ready_pipe = pipe_ready_target(&cli_args);

    // Build a multi-thread tokio runtime — the swarm + HTTP server
    // pair both demand it.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // Run the node inside the runtime. We spawn it as a task so the
    // main thread stays free to listen for SCM Stop and to gate the
    // SERVICE_RUNNING report on the API pipe coming up.
    let node_handle = runtime.spawn(async move {
        // Same code path as `dds-node run <config>` — `cmd_run` is the
        // existing main.rs entry that loads the config, brings up the
        // P2P node + HTTP API, and blocks on `node.run()`.
        if let Err(e) = crate::cmd_run(&cli_args).await {
            tracing::error!(error = %e, "dds-node service exited with error");
        }
    });

    // 2. Gate SERVICE_RUNNING on the API pipe being bound.
    //
    //    SCM starts DdsAuthBridge only after we report Running (it declares
    //    `<ServiceDependency Id="DdsNode" />` in DdsBundle.wxs). If we report
    //    Running the instant after `spawn` — before the spawned task has
    //    created `\\.\pipe\dds-api` — the bridge's first `GET
    //    /v1/enrolled-users` hits ERROR_FILE_NOT_FOUND, falls back to
    //    synthesizing the user list from the local vault, and LogonUI renders
    //    duplicate / SID-only credential tiles. Holding Running until the pipe
    //    exists makes the SCM dependency mean what it says: "dds-node is ready
    //    to serve."
    //
    //    Bounded by PIPE_READY_TIMEOUT_SECS so a node that never binds
    //    (mis-config, crash in init) still surfaces as Running (degraded)
    //    rather than pinning SCM at StartPending until the 60s wait_hint
    //    lapses. We pump StartPending checkpoints while waiting, and bail to
    //    the shutdown path if SCM asks us to stop before the API comes up.
    if let Some(pipe_path) = ready_pipe.as_deref() {
        let deadline = Instant::now() + Duration::from_secs(PIPE_READY_TIMEOUT_SECS);
        let mut checkpoint = 0u32;
        loop {
            if named_pipe_exists(pipe_path) {
                tracing::info!(pipe = pipe_path, "API pipe bound — reporting SERVICE_RUNNING");
                break;
            }
            if shutdown_rx.try_recv().is_ok() {
                tracing::warn!(
                    "SCM Stop received during startup — shutting down before API came up"
                );
                node_handle.abort();
                drop(runtime);
                status_handle.set_service_status(ServiceStatus {
                    service_type: SERVICE_TYPE,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 0,
                    wait_hint: Duration::ZERO,
                    process_id: None,
                })?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                tracing::warn!(
                    pipe = pipe_path,
                    timeout_secs = PIPE_READY_TIMEOUT_SECS,
                    "API pipe not bound within timeout — reporting SERVICE_RUNNING anyway (degraded)"
                );
                break;
            }
            checkpoint = checkpoint.wrapping_add(1);
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::StartPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })?;
            std::thread::sleep(Duration::from_millis(PIPE_POLL_INTERVAL_MS));
        }
    }

    // 3. Tell SCM we're up.
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    // 4. Block until SCM Stop / Shutdown.
    let _ = shutdown_rx.recv();
    tracing::info!("SCM Stop received — shutting down dds-node");

    // Cancel the node task and let the runtime wind down. tokio's
    // Drop on the runtime gives us a 10s grace period.
    node_handle.abort();
    drop(runtime);

    // 5. Tell SCM we're stopped.
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

/// If the node will serve its HTTP API over a Windows named pipe, return the
/// full pipe path (`\\.\pipe\<name>`); otherwise `None`.
///
/// Best-effort: any failure to locate or parse the config yields `None`, which
/// makes [`run_service`] skip the readiness gate and report Running
/// immediately — the pre-existing behaviour. We never want a config-read quirk
/// here to block the service from starting; `cmd_run` is the authority on
/// config validity and will fail loudly on the task side if it's broken.
fn pipe_ready_target(cli_args: &[String]) -> Option<String> {
    // Mirror cmd_run's config-path resolution: first non-flag arg, else the
    // conventional dds.toml in the working directory.
    let config_path = cli_args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("dds.toml"));
    let config = dds_node::config::NodeConfig::from_file(&config_path).ok()?;
    let spec = config.network.api_addr.strip_prefix("pipe:")?;
    Some(normalize_pipe_path(spec))
}

/// Expand a bare pipe name to its full `\\.\pipe\<name>` path; pass an
/// already-qualified path through unchanged. Mirrors
/// `http::normalize_pipe_name` so the path we probe is byte-identical to the
/// one the server binds.
fn normalize_pipe_path(spec: &str) -> String {
    if spec.starts_with(r"\\") {
        spec.to_string()
    } else {
        format!(r"\\.\pipe\{spec}")
    }
}

/// Return `true` once a named pipe with this path exists. An available
/// instance returns immediately; if all instances are momentarily busy the
/// 1ms wait lapses with `ERROR_SEM_TIMEOUT` — both mean the server has bound
/// the name, so we treat them as ready. Only `ERROR_FILE_NOT_FOUND` means the
/// name has not been created yet.
fn named_pipe_exists(pipe_path: &str) -> bool {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, GetLastError};
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    let wide: Vec<u16> = OsStr::new(pipe_path).encode_wide().chain(once(0)).collect();
    // 1ms: long enough to distinguish "name missing" (returns instantly with
    // ERROR_FILE_NOT_FOUND) from "name exists but busy" (ERROR_SEM_TIMEOUT).
    if unsafe { WaitNamedPipeW(wide.as_ptr(), 1) } != 0 {
        return true;
    }
    unsafe { GetLastError() != ERROR_FILE_NOT_FOUND }
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
        let args = vec![
            "--config".to_string(),
            "--unseal-passphrase-from".to_string(),
        ];
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
        assert_eq!(
            flag_value(&args, "--unseal-passphrase-from"),
            Some("blob.dpapi")
        );
    }

    #[test]
    fn flag_value_returns_none_when_absent() {
        let args = vec!["--config".to_string(), "node.toml".to_string()];
        assert_eq!(flag_value(&args, "--unseal-passphrase-from"), None);
    }

    #[test]
    fn normalize_pipe_path_expands_bare_name() {
        assert_eq!(normalize_pipe_path("dds-api"), r"\\.\pipe\dds-api");
    }

    #[test]
    fn normalize_pipe_path_passes_through_full_path() {
        assert_eq!(
            normalize_pipe_path(r"\\.\pipe\dds-api"),
            r"\\.\pipe\dds-api"
        );
    }

    #[test]
    fn pipe_ready_target_none_when_config_missing() {
        // No config file at the resolved path → best-effort returns None so
        // the readiness gate is skipped rather than blocking startup.
        let args = vec![r"C:\does\not\exist\nope.toml".to_string()];
        assert_eq!(pipe_ready_target(&args), None);
    }
}
