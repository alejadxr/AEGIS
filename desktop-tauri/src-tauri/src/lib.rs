use aegis_agent::{discovery, monitor};
use std::collections::HashSet;
use std::sync::Arc;
use sysinfo::System;
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;
use tokio::time::Duration;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct AgentState {
    monitoring: bool,
    fim_running: bool,
    events: Vec<serde_json::Value>,
    known_pids: HashSet<u32>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            monitoring: false,
            fim_running: false,
            events: Vec::new(),
            known_pids: HashSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri commands — called directly from the frontend via invoke()
// ---------------------------------------------------------------------------

#[tauri::command]
async fn agent_status(
    state: tauri::State<'_, Arc<Mutex<AgentState>>>,
) -> Result<serde_json::Value, String> {
    let s = state.lock().await;
    Ok(serde_json::json!({
        "type": "status",
        "monitoring": s.monitoring,
        "fim_running": s.fim_running,
        "events_count": s.events.len(),
        "known_pids": s.known_pids.len(),
    }))
}

#[tauri::command]
async fn agent_system_info() -> Result<serde_json::Value, String> {
    let info = monitor::collect_system_info();
    Ok(serde_json::to_value(&info).unwrap_or_default())
}

#[tauri::command]
async fn agent_processes(
    state: tauri::State<'_, Arc<Mutex<AgentState>>>,
) -> Result<serde_json::Value, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let mut s = state.lock().await;
    let procs = monitor::monitor_processes(&sys, &mut s.known_pids);
    Ok(serde_json::json!({
        "type": "processes",
        "data": procs,
        "total": procs.len(),
    }))
}

#[tauri::command]
async fn agent_discover(target: Option<String>) -> Result<serde_json::Value, String> {
    let targets = if let Some(t) = target {
        vec![t]
    } else {
        let local_ip = discovery::get_local_ip();
        discovery::generate_subnet_targets(&local_ip)
    };

    let ports: Vec<u16> = vec![22, 80, 443, 3306, 5432, 8080, 8443, 3389, 11434];
    let result = discovery::scan_network(&targets, &ports, 500).await;
    Ok(serde_json::json!({
        "type": "discovery_result",
        "services": result.services,
        "scan_duration_ms": result.scan_duration_ms,
        "hosts_scanned": targets.len(),
    }))
}

#[tauri::command]
async fn agent_scan_host(
    target: String,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
) -> Result<serde_json::Value, String> {
    let ports = ports.unwrap_or_else(|| {
        vec![
            21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521,
            2222, 3000, 3001, 3306, 3389, 5000, 5432, 5900, 6379, 8000,
            8080, 8443, 8888, 9090, 9100, 9200, 27017,
        ]
    });
    let timeout = timeout_ms.unwrap_or(500);
    let services = discovery::scan_host(&target, &ports, timeout).await;
    Ok(serde_json::json!({
        "type": "scan_result",
        "target": target,
        "services": services,
        "ports_scanned": ports.len(),
    }))
}

#[tauri::command]
async fn agent_local_ip() -> Result<serde_json::Value, String> {
    let ip = discovery::get_local_ip();
    Ok(serde_json::json!({
        "type": "local_ip",
        "ip": ip,
    }))
}

#[tauri::command]
async fn agent_get_events(
    state: tauri::State<'_, Arc<Mutex<AgentState>>>,
) -> Result<serde_json::Value, String> {
    let s = state.lock().await;
    Ok(serde_json::json!({
        "type": "events",
        "data": s.events,
        "count": s.events.len(),
    }))
}

#[tauri::command]
async fn agent_is_running() -> Result<bool, String> {
    // The agent is always running — it is embedded in the process.
    Ok(true)
}

#[tauri::command]
async fn agent_start_monitoring(
    state: tauri::State<'_, Arc<Mutex<AgentState>>>,
    app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let mut s = state.lock().await;
    if s.monitoring {
        return Ok(serde_json::json!({"status": "already_running"}));
    }
    s.monitoring = true;
    drop(s);

    let state_ref = state.inner().clone();
    let handle = app_handle.clone();

    tauri::async_runtime::spawn(async move {
        loop {
            {
                let s = state_ref.lock().await;
                if !s.monitoring {
                    break;
                }
            }

            let mut sys = System::new_all();
            sys.refresh_all();

            let suspicious: Vec<monitor::ProcessInfo>;
            {
                let mut s = state_ref.lock().await;
                let procs = monitor::monitor_processes(&sys, &mut s.known_pids);
                suspicious = procs
                    .into_iter()
                    .filter(|p| p.severity != "info")
                    .collect();

                // Store events
                for proc in &suspicious {
                    if let Ok(val) = serde_json::to_value(proc) {
                        s.events.push(val);
                    }
                }
            }

            if !suspicious.is_empty() {
                let _ = handle.emit(
                    "agent-event",
                    serde_json::json!({
                        "type": "suspicious_processes",
                        "data": suspicious,
                    }),
                );
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    Ok(serde_json::json!({"status": "monitoring_started"}))
}

#[tauri::command]
async fn agent_stop_monitoring(
    state: tauri::State<'_, Arc<Mutex<AgentState>>>,
) -> Result<serde_json::Value, String> {
    let mut s = state.lock().await;
    s.monitoring = false;
    Ok(serde_json::json!({"status": "monitoring_stopped"}))
}

// ---------------------------------------------------------------------------
// Tauri entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(Arc::new(Mutex::new(AgentState::default())))
        .setup(|app| {
            let handle = app.handle().clone();
            let state = app.state::<Arc<Mutex<AgentState>>>().inner().clone();

            // Auto-start background process monitoring on launch
            tauri::async_runtime::spawn(async move {
                // Initial snapshot: populate known_pids so only NEW processes trigger alerts
                {
                    let mut sys = System::new_all();
                    sys.refresh_all();
                    let mut s = state.lock().await;
                    let _ = monitor::monitor_processes(&sys, &mut s.known_pids);
                    s.monitoring = true;
                    log::info!(
                        "Agent embedded — initial snapshot: {} known PIDs",
                        s.known_pids.len()
                    );
                }

                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;

                    {
                        let s = state.lock().await;
                        if !s.monitoring {
                            continue; // paused, but keep the loop alive
                        }
                    }

                    let mut sys = System::new_all();
                    sys.refresh_all();

                    let suspicious: Vec<monitor::ProcessInfo>;
                    {
                        let mut s = state.lock().await;
                        let procs = monitor::monitor_processes(&sys, &mut s.known_pids);
                        suspicious = procs
                            .into_iter()
                            .filter(|p| p.severity != "info")
                            .collect();

                        for proc in &suspicious {
                            if let Ok(val) = serde_json::to_value(proc) {
                                s.events.push(val);
                            }
                        }
                    }

                    if !suspicious.is_empty() {
                        let _ = handle.emit(
                            "agent-event",
                            serde_json::json!({
                                "type": "suspicious_processes",
                                "data": suspicious,
                            }),
                        );
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            agent_status,
            agent_system_info,
            agent_processes,
            agent_discover,
            agent_scan_host,
            agent_local_ip,
            agent_get_events,
            agent_is_running,
            agent_start_monitoring,
            agent_stop_monitoring,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
