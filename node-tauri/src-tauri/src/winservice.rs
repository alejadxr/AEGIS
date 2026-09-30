//! Windows service host (`--service`, `--install-service`, `--uninstall-service`).
//!
//! The service is the headless sensor run under the Service Control Manager
//! as LocalSystem. Compiled on Windows only.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::cli;
use crate::headless;

const SERVICE_NAME: &str = "AEGISNode";
const SERVICE_DISPLAY: &str = "AEGIS Node";
const SERVICE_DESCRIPTION: &str = "AEGIS endpoint sensor";
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// A GUI-subsystem exe has no console. For the CLI modes, attach to the
/// parent's so `--install-service` errors and `--headless` output are visible.
pub fn attach_parent_console() {
    use std::os::windows::io::IntoRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{
        AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return; // no parent console (or already attached)
        }
        for (which, name) in [(STD_OUTPUT_HANDLE, "CONOUT$"), (STD_ERROR_HANDLE, "CONOUT$")] {
            let missing = match GetStdHandle(which) {
                Ok(h) => h.is_invalid() || h.0.is_null(),
                Err(_) => true,
            };
            if missing {
                if let Ok(f) = std::fs::OpenOptions::new().write(true).open(name) {
                    let _ = SetStdHandle(which, HANDLE(f.into_raw_handle() as _));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

fn describe(e: windows_service::Error, action: &str) -> String {
    if let windows_service::Error::Winapi(io) = &e {
        match io.raw_os_error() {
            Some(ERROR_ACCESS_DENIED) => {
                return format!(
                    "cannot {} the service: access denied. Run this from an elevated \
                     (Administrator) prompt.",
                    action
                )
            }
            Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                return format!("cannot {} the service: {} is not installed.", action, SERVICE_NAME)
            }
            _ => {}
        }
    }
    format!("cannot {} the service: {}", action, e)
}

pub fn install() -> Result<(), String> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| describe(e, "install"))?;

    let exe = std::env::current_exe().map_err(|e| format!("current exe: {}", e))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| describe(e, "install"))?;
    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| describe(e, "describe"))?;

    // Restart on crash: 3 attempts 60 s apart, counter reset after a day.
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(60),
    };
    let failure = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart; 3]),
    };
    if let Err(e) = service.update_failure_actions(failure) {
        eprintln!("warning: service installed but failure actions not set: {}", e);
    }

    println!(
        "Service {} installed (LocalSystem, automatic start). Start it with: sc start {}",
        SERVICE_NAME, SERVICE_NAME
    );
    println!(
        "Data and logs: %ProgramData%\\aegis-node\\ (config.json, logs\\aegis-node.log)"
    );
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| describe(e, "uninstall"))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| describe(e, "uninstall"))?;

    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
            for _ in 0..20 {
                std::thread::sleep(Duration::from_millis(500));
                match service.query_status() {
                    Ok(s) if s.current_state != ServiceState::Stopped => continue,
                    _ => break,
                }
            }
        }
    }
    service.delete().map_err(|e| describe(e, "uninstall"))?;
    println!("Service {} removed.", SERVICE_NAME);
    Ok(())
}

// ---------------------------------------------------------------------------
// Service entry
// ---------------------------------------------------------------------------

define_windows_service!(ffi_service_main, service_main);

/// `--service`: hand the thread to the SCM dispatcher.
pub fn run_dispatcher() -> Result<(), String> {
    cli::set_run_mode(cli::RunMode::Service);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("service dispatcher: {} (was --service run outside the SCM?)", e))
}

fn service_main(_args: Vec<OsString>) {
    // The exit code is reported to the SCM inside run_service.
    if let Err(e) = run_service() {
        log::error!("service failed: {}", e);
    }
}

fn status(state: ServiceState, accepted: ServiceControlAccept, exit: u32, wait_secs: u64) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(wait_secs),
        process_id: None,
    }
}

fn run_service() -> Result<(), String> {
    let stop = Arc::new(Notify::new());
    let stop_for_handler = stop.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |ctl| match ctl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_for_handler.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| format!("register control handler: {}", e))?;

    let _ = handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        0,
        10,
    ));
    let _ = handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
        0,
    ));

    let stop_wait = stop.clone();
    let res = headless::run_sensor(async move {
        stop_wait.notified().await;
        // The SCM sees StopPending while the runtime winds down.
        let _ = handle.set_service_status(status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            0,
            5,
        ));
    });

    let exit = if res.is_ok() { 0 } else { 1 };
    let _ = handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
        0,
    ));
    res
}
