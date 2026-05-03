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

#![cfg(windows)]

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "DdsNode";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Block on the SCM dispatcher. Called from `main()` when argv[1] is
/// `service-run`. Returns when SCM tells us to stop or on dispatcher
/// failure.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
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
    // subcommand verb in main(). Anything after it is handed to the
    // node as if it were a plain `dds-node run <args>` invocation.
    let cli_args: Vec<String> = std::env::args().skip(2).collect();

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
