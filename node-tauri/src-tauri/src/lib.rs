use aegis_agent::{discovery, fim, monitor};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use sysinfo::System;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager, WindowEvent,
};
use tokio::sync::Mutex;
use tokio::time::Duration;

// Task #2: Ransomware protection module
mod ransomware;
use ransomware::RansomwareState;

// Task #5: EDR/XDR core
mod edr;
use edr::EdrState;

// Task #6: Antivirus engine
mod antivirus;
use antivirus::AntivirusState;

// ---------------------------------------------------------------------------
// Hidden subprocess helper — prevents visible CMD windows on Windows
// ---------------------------------------------------------------------------

/// Create a Command that runs hidden on Windows (no visible CMD window)
fn hidden_command(program: &str) -> std::process::Command {
    let mut cmd = hidden_command(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

// ---------------------------------------------------------------------------
// Enroll code generation
// ---------------------------------------------------------------------------

fn generate_enroll_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let part1: String = (0..4).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    let part2: String = (0..4).map(|_| chars[rng.gen_range(0..chars.len())]).collect();
    format!("C6-{}-{}", part1, part2)
}

// ---------------------------------------------------------------------------
// Task #1: Persistent config — save/load to disk
// ---------------------------------------------------------------------------

/// Config file that gets persisted to disk.
/// Windows: %APPDATA%/aegis-node/config.json
/// macOS:   ~/.config/aegis-node/config.json
/// Linux:   ~/.config/aegis-node/config.json
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedConfig {
    server_url: String,
    client_id: Option<String>,
    client_name: Option<String>,
    node_id: Option<String>,
}

fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("aegis-node");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".config").join("aegis-node");
        }
    }
    PathBuf::from(".").join("aegis-node")
}

fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

fn save_config(config: &NodeConfig) {
    let persisted = PersistedConfig {
        server_url: config.server_url.clone(),
        client_id: config.client_id.clone(),
        client_name: config.client_name.clone(),
        node_id: config.node_id.clone(),
    };
    let dir = config_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::error!("Failed to create config dir {:?}: {}", dir, e);
        return;
    }
    let path = config_path();
    match serde_json::to_string_pretty(&persisted) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                log::error!("Failed to write config to {:?}: {}", path, e);
            } else {
                log::info!("Config saved to {:?}", path);
            }
        }
        Err(e) => log::error!("Failed to serialize config: {}", e),
    }
}

fn load_config() -> Option<PersistedConfig> {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(json) => match serde_json::from_str::<PersistedConfig>(&json) {
            Ok(c) => {
                log::info!("Loaded persisted config from {:?}", path);
                Some(c)
            }
            Err(e) => {
                log::warn!("Failed to parse config {:?}: {}", path, e);
                None
            }
        },
        Err(_) => None,
    }
}

fn clear_config() {
    let path = config_path();
    let _ = std::fs::remove_file(&path);
    log::info!("Cleared persisted config");
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeConfig {
    server_url: String,
    enroll_code: String,
    enroll_expires_at: String,
    client_id: Option<String>,
    client_name: Option<String>,
    node_id: Option<String>,
    status: String, // "waiting", "connected", "error"
}

struct NodeState {
    config: NodeConfig,
    known_pids: HashSet<u32>,
    monitoring: bool,
    events_count: u64,
    #[allow(dead_code)]
    fim_watcher: Option<notify::RecommendedWatcher>,
}

impl NodeState {
    fn new() -> Self {
        let code = generate_enroll_code();
        let expires = (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();

        // Task #1: Try loading persisted config
        if let Some(persisted) = load_config() {
            if persisted.node_id.is_some() {
                log::info!("Restoring enrolled session from disk");
                return Self {
                    config: NodeConfig {
                        server_url: persisted.server_url,
                        enroll_code: code,
                        enroll_expires_at: expires,
                        client_id: persisted.client_id,
                        client_name: persisted.client_name,
                        node_id: persisted.node_id,
                        status: "connected".to_string(),
                    },
                    known_pids: HashSet::new(),
                    monitoring: true,
                    events_count: 0,
                    fim_watcher: None,
                };
            }
        }

        Self {
            config: NodeConfig {
                server_url: "http://localhost:8000/api/v1".to_string(),
                enroll_code: code,
                enroll_expires_at: expires,
                client_id: None,
                client_name: None,
                node_id: None,
                status: "waiting".to_string(),
            },
            known_pids: HashSet::new(),
            monitoring: false,
            events_count: 0,
            fim_watcher: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
async fn get_node_config(
    state: tauri::State<'_, Arc<Mutex<NodeState>>>,
) -> Result<NodeConfig, String> {
    let s = state.lock().await;
    Ok(s.config.clone())
}

#[tauri::command]
async fn get_system_info() -> Result<serde_json::Value, String> {
    let info = monitor::collect_system_info();
    Ok(serde_json::to_value(&info).unwrap_or_default())
}

#[tauri::command]
async fn get_process_stats(
    state: tauri::State<'_, Arc<Mutex<NodeState>>>,
) -> Result<serde_json::Value, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let mut s = state.lock().await;
    let procs = monitor::monitor_processes(&sys, &mut s.known_pids);
    let suspicious: Vec<_> = procs.iter().filter(|p| p.severity != "info").collect();
    Ok(serde_json::json!({
        "total": sys.processes().len(),
        "new": procs.len(),
        "suspicious": suspicious.len(),
        "events_sent": s.events_count,
    }))
}

#[tauri::command]
async fn regenerate_code(
    state: tauri::State<'_, Arc<Mutex<NodeState>>>,
) -> Result<NodeConfig, String> {
    let mut s = state.lock().await;
    s.config.enroll_code = generate_enroll_code();
    s.config.enroll_expires_at = (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
    s.config.status = "waiting".to_string();
    s.config.client_id = None;
    s.config.client_name = None;
    s.config.node_id = None;
    Ok(s.config.clone())
}

#[tauri::command]
async fn set_server_url(
    url: String,
    state: tauri::State<'_, Arc<Mutex<NodeState>>>,
) -> Result<NodeConfig, String> {
    let mut s = state.lock().await;
    s.config.server_url = url;
    save_config(&s.config);
    Ok(s.config.clone())
}

#[tauri::command]
async fn hide_to_tray(window: tauri::WebviewWindow) -> Result<(), String> {
    window.hide().map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    window.set_skip_taskbar(true).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn scan_local_ports() -> Result<serde_json::Value, String> {
    let ports: Vec<u16> = vec![22, 80, 443, 3306, 3389, 5432, 8080, 8443];
    let services = discovery::scan_host("127.0.0.1", &ports, 500).await;
    Ok(serde_json::json!({
        "services": services,
        "local_ip": discovery::get_local_ip(),
    }))
}

/// Task #1: Disconnect — clear saved config and reset to enrollment wizard
#[tauri::command]
async fn disconnect_node(
    state: tauri::State<'_, Arc<Mutex<NodeState>>>,
) -> Result<NodeConfig, String> {
    let mut s = state.lock().await;
    clear_config();
    s.config.enroll_code = generate_enroll_code();
    s.config.enroll_expires_at = (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
    s.config.status = "waiting".to_string();
    s.config.client_id = None;
    s.config.client_name = None;
    s.config.node_id = None;
    s.monitoring = false;
    // Disable autostart on disconnect
    #[cfg(target_os = "windows")]
    { let _ = remove_autostart_registry(); }
    Ok(s.config.clone())
}

// ---------------------------------------------------------------------------
// Task #5: Windows auto-start via registry
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
const AUTOSTART_REG_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(target_os = "windows")]
const AUTOSTART_REG_VALUE: &str = "AegisNode";

#[cfg(target_os = "windows")]
fn set_autostart_registry() -> Result<(), String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let exe_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(AUTOSTART_REG_KEY)
        .map_err(|e| e.to_string())?;
    key.set_value(AUTOSTART_REG_VALUE, &exe_path.to_string_lossy().to_string())
        .map_err(|e| e.to_string())?;
    log::info!("Auto-start enabled in registry");
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_autostart_registry() -> Result<(), String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(AUTOSTART_REG_KEY, KEY_WRITE) {
        let _ = key.delete_value(AUTOSTART_REG_VALUE);
    }
    log::info!("Auto-start disabled in registry");
    Ok(())
}

#[cfg(target_os = "windows")]
fn check_autostart_registry() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(AUTOSTART_REG_KEY, KEY_READ) {
        key.get_value::<String, _>(AUTOSTART_REG_VALUE).is_ok()
    } else {
        false
    }
}

#[tauri::command]
async fn enable_autostart() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        set_autostart_registry()?;
        return Ok(true);
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

#[tauri::command]
async fn disable_autostart() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        remove_autostart_registry()?;
        return Ok(true);
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

#[tauri::command]
async fn is_autostart_enabled() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        return Ok(check_autostart_registry());
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Task #3: Auto-scan assets and report to backend
// ---------------------------------------------------------------------------

#[tauri::command]
async fn auto_scan_assets(
    state: tauri::State<'_, Arc<Mutex<NodeState>>>,
) -> Result<serde_json::Value, String> {
    let (server_url, node_id) = {
        let s = state.lock().await;
        (s.config.server_url.clone(), s.config.node_id.clone())
    };

    let node_id = node_id.ok_or("Not enrolled")?;

    // Scan local ports
    let common_ports: Vec<u16> = vec![
        21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 1521, 2222, 3306, 3389, 5000, 5432, 5900,
        6379, 8000, 8080, 8443, 8888, 9090, 9100, 9200, 27017,
    ];
    let local_ip = discovery::get_local_ip();
    let services = discovery::scan_host("127.0.0.1", &common_ports, 500).await;
    let info = monitor::collect_system_info();

    let report = serde_json::json!({
        "node_id": node_id,
        "hostname": info.hostname,
        "os_name": info.os_name,
        "os_version": info.os_version,
        "local_ip": local_ip,
        "cpu_brand": info.cpu_brand,
        "cpu_count": info.cpu_count,
        "ram_total_mb": info.ram_total_mb,
        "disk_total_gb": info.disk_total_gb,
        "open_services": services,
        "scan_timestamp": Utc::now().to_rfc3339(),
    });

    // POST to backend
    let client = reqwest::Client::new();
    match client
        .post(format!("{}/nodes/report-assets", server_url))
        .json(&report)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let server_body: serde_json::Value = resp.json().await.unwrap_or_default();
            log::info!("Asset report sent, server responded: {}", status);
            Ok(serde_json::json!({
                "status": "sent",
                "services_found": services.len(),
                "services": services,
                "server_response": status,
                "assets_created": server_body.get("assets_created").and_then(|v| v.as_u64()).unwrap_or(0),
                "assets_updated": server_body.get("assets_updated").and_then(|v| v.as_u64()).unwrap_or(0),
            }))
        }
        Err(e) => {
            log::error!("Failed to send asset report: {}", e);
            Ok(serde_json::json!({
                "status": "error",
                "services_found": services.len(),
                "services": services,
                "error": e.to_string(),
            }))
        }
    }
}

/// Background auto-scan: runs after enrollment, then every hour
async fn auto_scan_loop(state: Arc<Mutex<NodeState>>) {
    // Wait 10s after startup for enrollment to settle
    tokio::time::sleep(Duration::from_secs(10)).await;

    loop {
        let (server_url, node_id, connected) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.node_id.clone(),
                s.config.status == "connected",
            )
        };

        if connected {
            if let Some(nid) = node_id {
                let common_ports: Vec<u16> = vec![
                    21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                    1433, 1521, 2222, 3306, 3389, 5000, 5432, 5900,
                    6379, 8000, 8080, 8443, 8888, 9090, 9100, 9200, 27017,
                ];
                let local_ip = discovery::get_local_ip();
                let services = discovery::scan_host("127.0.0.1", &common_ports, 500).await;
                let info = monitor::collect_system_info();

                let report = serde_json::json!({
                    "node_id": nid,
                    "hostname": info.hostname,
                    "os_name": info.os_name,
                    "os_version": info.os_version,
                    "local_ip": local_ip,
                    "cpu_brand": info.cpu_brand,
                    "cpu_count": info.cpu_count,
                    "ram_total_mb": info.ram_total_mb,
                    "disk_total_gb": info.disk_total_gb,
                    "open_services": services,
                    "scan_timestamp": Utc::now().to_rfc3339(),
                });

                let client = reqwest::Client::new();
                match client
                    .post(format!("{}/nodes/report-assets", server_url))
                    .json(&report)
                    .send()
                    .await
                {
                    Ok(resp) => log::info!("Auto-scan report sent: {}", resp.status()),
                    Err(e) => log::warn!("Auto-scan report failed: {}", e),
                }
            }
        }

        // Repeat every hour
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

// ---------------------------------------------------------------------------
// Background: poll enrollment status (with Task #1 persistence)
// ---------------------------------------------------------------------------

async fn poll_enrollment(state: Arc<Mutex<NodeState>>, handle: tauri::AppHandle) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let (server_url, code, status) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.enroll_code.clone(),
                s.config.status.clone(),
            )
        };

        if status == "connected" {
            continue;
        }

        // POST announce (register as pending node)
        let client = reqwest::Client::new();
        let info = monitor::collect_system_info();
        let local_ip = discovery::get_local_ip();

        let announce_body = serde_json::json!({
            "enroll_code": code,
            "hostname": info.hostname,
            "os_name": info.os_name,
            "os_version": info.os_version,
            "local_ip": local_ip,
            "agent_version": "0.1.0",
        });

        let _ = client
            .post(format!("{}/nodes/announce", server_url))
            .json(&announce_body)
            .send()
            .await;

        // GET status (check if manager enrolled us)
        if let Ok(resp) = client
            .get(format!("{}/nodes/status/{}", server_url, code))
            .send()
            .await
        {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if body.get("status").and_then(|s| s.as_str()) == Some("active") {
                    let mut s = state.lock().await;
                    s.config.status = "connected".to_string();
                    s.config.client_id =
                        body.get("client_id").and_then(|v| v.as_str()).map(String::from);
                    s.config.client_name =
                        body.get("client_name").and_then(|v| v.as_str()).map(String::from);
                    s.config.node_id =
                        body.get("node_id").and_then(|v| v.as_str()).map(String::from);
                    s.monitoring = true;

                    // Task #1: Persist config immediately after enrollment
                    save_config(&s.config);

                    // Task #5: Auto-enable autostart on first enrollment
                    #[cfg(target_os = "windows")]
                    {
                        if let Err(e) = set_autostart_registry() {
                            log::warn!("Failed to set autostart: {}", e);
                        }
                    }

                    let _ = handle.emit("node-enrolled", &s.config);
                    log::info!(
                        "Node enrolled to {} (node_id={})",
                        s.config.client_name.as_deref().unwrap_or("unknown"),
                        s.config.node_id.as_deref().unwrap_or("unknown")
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Task #4: Persistent heartbeat with exponential backoff + auto-reconnect
// ---------------------------------------------------------------------------

async fn heartbeat_loop(state: Arc<Mutex<NodeState>>, handle: tauri::AppHandle) {
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut interval_secs: u64 = 30;
    let mut consecutive_failures: u32 = 0;

    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        let (server_url, node_id, connected) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.node_id.clone(),
                s.config.status == "connected",
            )
        };

        if !connected {
            // Reset backoff when not connected (waiting for enrollment)
            interval_secs = 30;
            consecutive_failures = 0;
            continue;
        }

        let node_id = match node_id {
            Some(id) => id,
            None => continue,
        };

        sys.refresh_all();

        let info = monitor::collect_system_info();
        let suspicious: Vec<monitor::ProcessInfo>;
        {
            let mut s = state.lock().await;
            let procs = monitor::monitor_processes(&sys, &mut s.known_pids);
            suspicious = procs.into_iter().filter(|p| p.severity != "info").collect();
            s.events_count += suspicious.len() as u64;
        }

        let heartbeat = serde_json::json!({
            "node_id": node_id,
            "hostname": info.hostname,
            "cpu_usage": info.cpu_usage_percent,
            "ram_usage": info.ram_usage_percent,
            "disk_usage": info.disk_usage_percent,
            "process_count": info.process_count,
            "uptime_seconds": info.uptime_seconds,
            "suspicious_processes": suspicious,
            "timestamp": Utc::now().to_rfc3339(),
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        match client
            .post(format!("{}/nodes/heartbeat", server_url))
            .json(&heartbeat)
            .send()
            .await
        {
            Ok(resp) => {
                let status_code = resp.status().as_u16();

                if status_code == 404 {
                    // Node was deleted on the server — clear config, show enrollment
                    log::warn!("Heartbeat got 404 — node deleted on server. Resetting...");
                    let mut s = state.lock().await;
                    clear_config();
                    s.config.enroll_code = generate_enroll_code();
                    s.config.enroll_expires_at =
                        (Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();
                    s.config.status = "waiting".to_string();
                    s.config.client_id = None;
                    s.config.client_name = None;
                    s.config.node_id = None;
                    s.monitoring = false;
                    let _ = handle.emit("node-disconnected", &s.config);
                    interval_secs = 30;
                    consecutive_failures = 0;
                    continue;
                }

                // Success — reset backoff
                if consecutive_failures > 0 {
                    log::info!("Heartbeat recovered after {} failures", consecutive_failures);
                    let _ = handle.emit("heartbeat-status", "connected");
                }
                consecutive_failures = 0;
                interval_secs = 30;
            }
            Err(e) => {
                consecutive_failures += 1;
                // Exponential backoff: 5s, 10s, 30s, 60s, max 300s (5min)
                interval_secs = match consecutive_failures {
                    1 => 5,
                    2 => 10,
                    3 => 30,
                    4 => 60,
                    _ => 300,
                };
                log::warn!(
                    "Heartbeat failed (attempt {}): {}. Next retry in {}s",
                    consecutive_failures,
                    e,
                    interval_secs
                );
                let _ = handle.emit(
                    "heartbeat-status",
                    serde_json::json!({
                        "status": "error",
                        "failures": consecutive_failures,
                        "next_retry_secs": interval_secs,
                    }),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Task #6: Real-time event reporting — suspicious processes + FIM
// ---------------------------------------------------------------------------

/// Background loop: watch for suspicious processes and send events
async fn event_reporter_loop(state: Arc<Mutex<NodeState>>) {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Separate known_pids for event reporting (don't share with heartbeat)
    let mut reporter_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let (server_url, node_id, connected) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.node_id.clone(),
                s.config.status == "connected",
            )
        };

        if !connected {
            continue;
        }
        let node_id = match node_id {
            Some(id) => id,
            None => continue,
        };

        sys.refresh_all();
        let procs = monitor::monitor_processes(&sys, &mut reporter_pids);
        let suspicious: Vec<&monitor::ProcessInfo> =
            procs.iter().filter(|p| p.severity != "info").collect();

        if suspicious.is_empty() {
            continue;
        }

        let events: Vec<serde_json::Value> = suspicious
            .iter()
            .map(|p| {
                serde_json::json!({
                    "node_id": node_id,
                    "event_type": "suspicious_process",
                    "severity": p.severity,
                    "details": {
                        "pid": p.pid,
                        "name": p.name,
                        "cmd": p.cmd,
                        "cpu_usage": p.cpu_usage,
                        "memory_kb": p.memory_kb,
                        "reasons": p.reasons,
                    },
                    "timestamp": Utc::now().to_rfc3339(),
                })
            })
            .collect();

        let client = reqwest::Client::new();
        for event in &events {
            match client
                .post(format!("{}/nodes/events", server_url))
                .json(event)
                .send()
                .await
            {
                Ok(resp) => log::info!(
                    "Suspicious process event sent: {} ({})",
                    event["details"]["name"],
                    resp.status()
                ),
                Err(e) => log::warn!("Failed to send process event: {}", e),
            }
        }

        // Update events count in shared state
        {
            let mut s = state.lock().await;
            s.events_count += events.len() as u64;
        }
    }
}

/// Background: FIM watcher — monitors sensitive directories and reports changes
async fn fim_reporter_loop(state: Arc<Mutex<NodeState>>) {
    // Wait for enrollment
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = state.lock().await;
        if s.config.status == "connected" && s.config.node_id.is_some() {
            break;
        }
    }

    // Determine paths to watch based on OS
    #[cfg(target_os = "windows")]
    let watch_paths: Vec<&str> = {
        let mut paths = vec!["C:\\Windows\\System32\\drivers\\etc"];
        // Watch user .ssh if it exists
        if let Ok(home) = std::env::var("USERPROFILE") {
            let ssh_path = format!("{}/.ssh", home);
            if std::path::Path::new(&ssh_path).exists() {
                // We'll add it below after the vec is created
                paths.push("C:\\Windows\\System32\\drivers\\etc");
            }
        }
        paths
    };

    #[cfg(not(target_os = "windows"))]
    let watch_paths: Vec<&str> = vec![
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
    ];

    // Also watch user's .ssh directory
    let home_ssh = {
        #[cfg(target_os = "windows")]
        {
            std::env::var("USERPROFILE")
                .map(|h| format!("{}\\.ssh", h))
                .unwrap_or_default()
        }
        #[cfg(not(target_os = "windows"))]
        {
            std::env::var("HOME")
                .map(|h| format!("{}/.ssh", h))
                .unwrap_or_default()
        }
    };

    let mut all_paths: Vec<&str> = watch_paths;
    let home_ssh_ref: &str = &home_ssh;
    if !home_ssh.is_empty() && std::path::Path::new(&home_ssh).exists() {
        all_paths.push(home_ssh_ref);
    }

    log::info!("Starting FIM on paths: {:?}", all_paths);

    let breadcrumbs: Vec<&str> = vec![];
    let (rx, _watcher) = match fim::start_fim(&all_paths, &breadcrumbs) {
        Ok(pair) => pair,
        Err(e) => {
            log::error!("Failed to start FIM: {}", e);
            return;
        }
    };

    // Store watcher in state so it doesn't get dropped
    {
        let mut s = state.lock().await;
        s.fim_watcher = Some(_watcher);
    }

    // Process FIM events
    loop {
        // Check for FIM events (non-blocking with timeout)
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(fim_event) => {
                let (server_url, node_id, connected) = {
                    let s = state.lock().await;
                    (
                        s.config.server_url.clone(),
                        s.config.node_id.clone(),
                        s.config.status == "connected",
                    )
                };

                if !connected {
                    continue;
                }
                let node_id = match node_id {
                    Some(id) => id,
                    None => continue,
                };

                let event = serde_json::json!({
                    "node_id": node_id,
                    "event_type": "fim_change",
                    "severity": fim_event.severity,
                    "details": {
                        "path": fim_event.path,
                        "change_type": fim_event.event_type,
                        "hash_before": fim_event.hash_before,
                        "hash_after": fim_event.hash_after,
                        "is_breadcrumb": fim_event.is_breadcrumb,
                    },
                    "timestamp": fim_event.timestamp,
                });

                let client = reqwest::Client::new();
                match client
                    .post(format!("{}/nodes/events", server_url))
                    .json(&event)
                    .send()
                    .await
                {
                    Ok(resp) => log::info!(
                        "FIM event sent: {} {} ({})",
                        fim_event.event_type,
                        fim_event.path,
                        resp.status()
                    ),
                    Err(e) => log::warn!("Failed to send FIM event: {}", e),
                }

                {
                    let mut s = state.lock().await;
                    s.events_count += 1;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // No events, keep looping
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                log::error!("FIM channel disconnected");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EDR: Windows Event Log monitoring
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
async fn windows_eventlog_loop(state: Arc<Mutex<NodeState>>) {
    use std::collections::HashMap;
    use std::time::Instant;

    // Wait for enrollment
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = state.lock().await;
        if s.config.status == "connected" && s.config.node_id.is_some() {
            break;
        }
    }

    log::info!("EDR: Windows Event Log monitor started");

    // Track failed logon attempts: IP -> (count, first_seen)
    let mut failed_logons: HashMap<String, (u32, Instant)> = HashMap::new();

    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;

        let (server_url, node_id, connected) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.node_id.clone(),
                s.config.status == "connected",
            )
        };
        if !connected {
            continue;
        }
        let node_id = match node_id {
            Some(id) => id,
            None => continue,
        };

        let client = reqwest::Client::new();
        let mut alerts: Vec<serde_json::Value> = Vec::new();

        // --- Security Event Log: process creation (4688), failed logon (4625), service install (4697) ---
        if let Ok(output) = hidden_command("wevtutil")
            .args(["qe", "Security", "/c:50", "/rd:true", "/f:text"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut current_event_id = String::new();
            let mut current_data = HashMap::<String, String>::new();

            for line in text.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("Event[") {
                    // Process previous event
                    if !current_event_id.is_empty() {
                        if let Some(alert) = process_security_event(
                            &current_event_id,
                            &current_data,
                            &node_id,
                            &mut failed_logons,
                        ) {
                            alerts.push(alert);
                        }
                    }
                    current_event_id.clear();
                    current_data.clear();
                } else if let Some(rest) = trimmed.strip_prefix("Event ID: ") {
                    current_event_id = rest.trim().to_string();
                } else if let Some((key, val)) = trimmed.split_once(": ") {
                    current_data.insert(key.trim().to_string(), val.trim().to_string());
                }
            }
            // Process last event
            if !current_event_id.is_empty() {
                if let Some(alert) = process_security_event(
                    &current_event_id,
                    &current_data,
                    &node_id,
                    &mut failed_logons,
                ) {
                    alerts.push(alert);
                }
            }
        }

        // --- PowerShell Script Block Logging ---
        if let Ok(output) = hidden_command("wevtutil")
            .args(["qe", "Microsoft-Windows-PowerShell/Operational", "/c:20", "/rd:true", "/f:text"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let lower = line.to_lowercase();
                if lower.contains("-encodedcommand")
                    || lower.contains("-enc ")
                    || lower.contains("invoke-expression")
                    || lower.contains("downloadstring")
                    || lower.contains("invoke-webrequest")
                    || lower.contains("net.webclient")
                {
                    alerts.push(serde_json::json!({
                        "node_id": node_id,
                        "event_type": "suspicious_powershell",
                        "severity": "high",
                        "details": {
                            "source": "PowerShell/Operational",
                            "snippet": line.trim().chars().take(500).collect::<String>(),
                        },
                        "timestamp": Utc::now().to_rfc3339(),
                    }));
                    break; // One alert per cycle to avoid flooding
                }
            }
        }

        // Clean up old failed logon entries (older than 60s)
        let now = Instant::now();
        failed_logons.retain(|_, (_, first)| now.duration_since(*first).as_secs() < 120);

        // Send alerts
        for alert in &alerts {
            match client
                .post(format!("{}/nodes/events", server_url))
                .json(alert)
                .send()
                .await
            {
                Ok(resp) => log::info!(
                    "EDR event sent: {} [{}]",
                    alert["event_type"],
                    resp.status()
                ),
                Err(e) => log::warn!("EDR event send failed: {}", e),
            }
        }

        if !alerts.is_empty() {
            let mut s = state.lock().await;
            s.events_count += alerts.len() as u64;
        }
    }
}

#[cfg(target_os = "windows")]
fn process_security_event(
    event_id: &str,
    data: &std::collections::HashMap<String, String>,
    node_id: &str,
    failed_logons: &mut std::collections::HashMap<String, (u32, std::time::Instant)>,
) -> Option<serde_json::Value> {
    match event_id {
        // Process Creation
        "4688" => {
            let cmd = data.get("Process Command Line")
                .or_else(|| data.get("New Process Name"))
                .cloned()
                .unwrap_or_default();
            let lower = cmd.to_lowercase();

            // Check for suspicious LOTL patterns
            let suspicious = lower.contains("powershell") && (lower.contains("-enc") || lower.contains("-encodedcommand"))
                || lower.contains("certutil") && (lower.contains("-decode") || lower.contains("-urlcache"))
                || lower.contains("bitsadmin") && lower.contains("/transfer")
                || lower.contains("mshta.exe")
                || lower.contains("regsvr32") && lower.contains("/s")
                || lower.contains("wmic") && lower.contains("process call create")
                || lower.contains("rundll32") && lower.contains("javascript");

            if suspicious {
                Some(serde_json::json!({
                    "node_id": node_id,
                    "event_type": "lotl_process_creation",
                    "severity": "high",
                    "details": {
                        "event_id": 4688,
                        "command_line": cmd.chars().take(500).collect::<String>(),
                        "source": "Security",
                    },
                    "timestamp": Utc::now().to_rfc3339(),
                }))
            } else {
                None
            }
        }
        // Failed Logon
        "4625" => {
            let source_ip = data.get("Source Network Address")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let entry = failed_logons
                .entry(source_ip.clone())
                .or_insert((0, std::time::Instant::now()));
            entry.0 += 1;

            if entry.0 >= 5 {
                // Reset counter after alerting
                entry.0 = 0;
                entry.1 = std::time::Instant::now();
                Some(serde_json::json!({
                    "node_id": node_id,
                    "event_type": "brute_force_attempt",
                    "severity": "high",
                    "details": {
                        "event_id": 4625,
                        "source_ip": source_ip,
                        "failures": "5+ in 60s",
                        "source": "Security",
                    },
                    "timestamp": Utc::now().to_rfc3339(),
                }))
            } else {
                None
            }
        }
        // Service Install
        "4697" => {
            let svc_name = data.get("Service Name")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let svc_path = data.get("Service File Name")
                .cloned()
                .unwrap_or_default();
            Some(serde_json::json!({
                "node_id": node_id,
                "event_type": "new_service_installed",
                "severity": "medium",
                "details": {
                    "event_id": 4697,
                    "service_name": svc_name,
                    "service_path": svc_path.chars().take(500).collect::<String>(),
                    "source": "Security",
                },
                "timestamp": Utc::now().to_rfc3339(),
            }))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// EDR: Network connection monitoring
// ---------------------------------------------------------------------------

async fn network_monitor_loop(state: Arc<Mutex<NodeState>>) {
    // Wait for enrollment
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = state.lock().await;
        if s.config.status == "connected" && s.config.node_id.is_some() {
            break;
        }
    }

    log::info!("EDR: Network connection monitor started");

    let suspicious_ports: HashSet<u16> = [4444, 5555, 31337, 1234, 6666, 6667, 9999, 12345]
        .iter()
        .cloned()
        .collect();

    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;

        let (server_url, node_id, connected) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.node_id.clone(),
                s.config.status == "connected",
            )
        };
        if !connected {
            continue;
        }
        let node_id = match node_id {
            Some(id) => id,
            None => continue,
        };

        // Run netstat
        let netstat_output = {
            #[cfg(target_os = "windows")]
            {
                hidden_command("netstat")
                    .args(["-ano"])
                    .output()
            }
            #[cfg(not(target_os = "windows"))]
            {
                hidden_command("netstat")
                    .args(["-tunap"])
                    .output()
            }
        };

        let connections = match netstat_output {
            Ok(output) => parse_netstat(&String::from_utf8_lossy(&output.stdout)),
            Err(_) => continue,
        };

        // Build a PID->process name map from sysinfo
        let mut sys = System::new_all();
        sys.refresh_all();
        let pid_names: std::collections::HashMap<u32, String> = sys
            .processes()
            .iter()
            .map(|(pid, proc_)| (pid.as_u32(), proc_.name().to_string_lossy().to_string()))
            .collect();

        let lotl_binaries: HashSet<&str> = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
            "bitsadmin.exe", "wmic.exe",
        ]
        .iter()
        .cloned()
        .collect();

        let client = reqwest::Client::new();
        let mut alerts: Vec<serde_json::Value> = Vec::new();

        for conn in &connections {
            let remote_port = conn.remote_port;
            let pid = conn.pid;
            let proc_name = pid_names
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| format!("PID:{}", pid));
            let proc_lower = proc_name.to_lowercase();

            // Flag: connection to suspicious ports
            if suspicious_ports.contains(&remote_port) {
                alerts.push(serde_json::json!({
                    "node_id": node_id,
                    "event_type": "suspicious_network_connection",
                    "severity": "high",
                    "details": {
                        "remote_addr": conn.remote_addr,
                        "remote_port": remote_port,
                        "local_port": conn.local_port,
                        "pid": pid,
                        "process": proc_name,
                        "state": conn.state,
                    },
                    "timestamp": Utc::now().to_rfc3339(),
                }));
            }

            // Flag: LOTL binary with outbound network activity
            if lotl_binaries.contains(proc_lower.as_str())
                && conn.state == "ESTABLISHED"
                && !conn.remote_addr.starts_with("127.")
                && !conn.remote_addr.starts_with("::1")
            {
                alerts.push(serde_json::json!({
                    "node_id": node_id,
                    "event_type": "lotl_network_activity",
                    "severity": "high",
                    "details": {
                        "remote_addr": conn.remote_addr,
                        "remote_port": remote_port,
                        "pid": pid,
                        "process": proc_name,
                        "state": conn.state,
                    },
                    "timestamp": Utc::now().to_rfc3339(),
                }));
            }
        }

        // Send alerts (max 10 per cycle)
        for alert in alerts.iter().take(10) {
            let _ = client
                .post(format!("{}/nodes/events", server_url))
                .json(alert)
                .send()
                .await;
        }

        if !alerts.is_empty() {
            let count = alerts.len().min(10);
            let mut s = state.lock().await;
            s.events_count += count as u64;
            log::info!("EDR: {} network alerts sent", count);
        }
    }
}

#[derive(Debug)]
struct NetConnection {
    #[allow(dead_code)]
    proto: String,
    #[allow(dead_code)]
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
    pid: u32,
}

fn parse_netstat(output: &str) -> Vec<NetConnection> {
    let mut connections = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Windows netstat -ano: TCP  0.0.0.0:135  0.0.0.0:0  LISTENING  1234
        if parts.len() >= 5 && (parts[0] == "TCP" || parts[0] == "UDP") {
            let proto = parts[0].to_string();
            let (local_addr, local_port) = parse_addr_port(parts[1]);
            let (remote_addr, remote_port) = parse_addr_port(parts[2]);

            let (state, pid_str) = if parts[0] == "TCP" && parts.len() >= 5 {
                (parts[3].to_string(), parts[4])
            } else if parts[0] == "UDP" && parts.len() >= 4 {
                ("UDP".to_string(), parts[3])
            } else {
                continue;
            };

            let pid: u32 = pid_str.parse().unwrap_or(0);

            connections.push(NetConnection {
                proto,
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                pid,
            });
        }
    }
    connections
}

fn parse_addr_port(s: &str) -> (String, u16) {
    // Handle IPv6 [::]:port and IPv4 0.0.0.0:port
    if let Some(idx) = s.rfind(':') {
        let addr = s[..idx].to_string();
        let port: u16 = s[idx + 1..].parse().unwrap_or(0);
        (addr, port)
    } else {
        (s.to_string(), 0)
    }
}

/// Tauri command: get current network connections
#[tauri::command]
async fn get_network_connections() -> Result<serde_json::Value, String> {
    let output = {
        #[cfg(target_os = "windows")]
        {
            hidden_command("netstat")
                .args(["-ano"])
                .output()
        }
        #[cfg(not(target_os = "windows"))]
        {
            hidden_command("netstat")
                .args(["-tunap"])
                .output()
        }
    };

    match output {
        Ok(out) => {
            let connections = parse_netstat(&String::from_utf8_lossy(&out.stdout));
            let mut sys = System::new_all();
            sys.refresh_all();

            let result: Vec<serde_json::Value> = connections
                .iter()
                .filter(|c| c.state == "ESTABLISHED")
                .take(100)
                .map(|c| {
                    let proc_name = sys
                        .process(sysinfo::Pid::from_u32(c.pid))
                        .map(|p| p.name().to_string_lossy().to_string())
                        .unwrap_or_else(|| format!("PID:{}", c.pid));
                    serde_json::json!({
                        "proto": c.proto,
                        "local_port": c.local_port,
                        "remote_addr": c.remote_addr,
                        "remote_port": c.remote_port,
                        "state": c.state,
                        "pid": c.pid,
                        "process": proc_name,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "connections": result, "total": connections.len() }))
        }
        Err(e) => Err(format!("netstat failed: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// EDR: Registry persistence detection
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
async fn registry_persistence_loop(state: Arc<Mutex<NodeState>>) {
    use std::collections::HashMap;
    use winreg::enums::*;
    use winreg::RegKey;

    // Wait for enrollment
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let s = state.lock().await;
        if s.config.status == "connected" && s.config.node_id.is_some() {
            break;
        }
    }

    log::info!("EDR: Registry persistence monitor started");

    let run_keys = [
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];

    // Build initial baseline
    let mut baseline: HashMap<String, String> = HashMap::new();
    for (hive, path) in &run_keys {
        let hkey = RegKey::predef(*hive);
        if let Ok(key) = hkey.open_subkey_with_flags(path, KEY_READ) {
            for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
                let val_str = format!("{:?}", value);
                let full_key = format!("{}\\{}", path, name);
                baseline.insert(full_key, val_str);
            }
        }
    }
    log::info!("EDR: Registry baseline captured, {} entries", baseline.len());

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;

        let (server_url, node_id, connected) = {
            let s = state.lock().await;
            (
                s.config.server_url.clone(),
                s.config.node_id.clone(),
                s.config.status == "connected",
            )
        };
        if !connected {
            continue;
        }
        let node_id = match node_id {
            Some(id) => id,
            None => continue,
        };

        let client = reqwest::Client::new();
        let mut alerts: Vec<serde_json::Value> = Vec::new();

        for (hive, path) in &run_keys {
            let hkey = RegKey::predef(*hive);
            if let Ok(key) = hkey.open_subkey_with_flags(path, KEY_READ) {
                for (name, value) in key.enum_values().filter_map(|r| r.ok()) {
                    let val_str = format!("{:?}", value);
                    let full_key = format!("{}\\{}", path, name);

                    if !baseline.contains_key(&full_key) {
                        // New entry detected!
                        log::warn!("EDR: New registry persistence: {} = {}", full_key, val_str);
                        alerts.push(serde_json::json!({
                            "node_id": node_id,
                            "event_type": "registry_persistence_new",
                            "severity": "high",
                            "details": {
                                "key": full_key,
                                "value": val_str.chars().take(500).collect::<String>(),
                                "hive": if *hive == HKEY_CURRENT_USER { "HKCU" } else { "HKLM" },
                            },
                            "timestamp": Utc::now().to_rfc3339(),
                        }));
                        // Add to baseline to avoid repeat alerts
                        baseline.insert(full_key, val_str);
                    }
                }
            }
        }

        // Also check process command lines for LOTL abuse
        let mut sys = System::new_all();
        sys.refresh_all();
        for (_pid, proc_) in sys.processes() {
            let cmd_parts: Vec<String> = proc_.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
            let cmd = cmd_parts.join(" ");
            let lower = cmd.to_lowercase();

            let is_lotl =
                (lower.contains("certutil") && (lower.contains("-decode") || lower.contains("-urlcache")))
                || (lower.contains("bitsadmin") && lower.contains("/transfer"))
                || (lower.contains("powershell") && (lower.contains("-enc ") || lower.contains("-encodedcommand")))
                || lower.contains("mshta.exe")
                || (lower.contains("regsvr32") && lower.contains("/s") && lower.contains("/u") && lower.contains("/i:"));

            if is_lotl {
                alerts.push(serde_json::json!({
                    "node_id": node_id,
                    "event_type": "lotl_command_detected",
                    "severity": "critical",
                    "details": {
                        "pid": _pid.as_u32(),
                        "process": proc_.name().to_string_lossy().to_string(),
                        "command_line": cmd.chars().take(500).collect::<String>(),
                    },
                    "timestamp": Utc::now().to_rfc3339(),
                }));
            }
        }

        // Send alerts
        for alert in alerts.iter().take(10) {
            match client
                .post(format!("{}/nodes/events", server_url))
                .json(alert)
                .send()
                .await
            {
                Ok(resp) => log::info!(
                    "EDR registry/LOTL alert sent: {} [{}]",
                    alert["event_type"],
                    resp.status()
                ),
                Err(e) => log::warn!("EDR alert send failed: {}", e),
            }
        }

        if !alerts.is_empty() {
            let count = alerts.len().min(10);
            let mut s = state.lock().await;
            s.events_count += count as u64;
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
        .manage(Arc::new(Mutex::new(NodeState::new())))
        .setup(|app| {
            let state = app.state::<Arc<Mutex<NodeState>>>().inner().clone();
            let handle = app.handle().clone();

            // --- System tray ---
            let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let tray_icon = app.default_window_icon().cloned().expect("No default icon");
            let _tray = TrayIconBuilder::new()
                .icon(tray_icon)
                .menu(&menu)
                .tooltip("AEGIS Node")
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            #[cfg(target_os = "windows")]
                            let _ = window.set_skip_taskbar(false);
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(event, tauri::tray::TrayIconEvent::DoubleClick { .. }) {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            #[cfg(target_os = "windows")]
                            let _ = window.set_skip_taskbar(false);
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            // --- Intercept close: hide to tray instead of quitting ---
            let main_window = app.get_webview_window("main").unwrap();
            let win_handle = main_window.clone();
            main_window.on_window_event(move |event| {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = win_handle.hide();
                    #[cfg(target_os = "windows")]
                    let _ = win_handle.set_skip_taskbar(true);
                }
            });

            // --- Show window and inject IPC readiness check ---
            {
                let win = app.get_webview_window("main").unwrap();
                let _ = win.show();
                let _ = win.set_focus();
                // Give the WebView a moment then trigger bootstrap from Rust side
                let win2 = win.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let _ = win2.eval("if(typeof bootstrap==='function' && !invoke){bootstrap();}");
                });
            }

            // --- Initial PID snapshot ---
            let state_clone = state.clone();
            tauri::async_runtime::spawn(async move {
                let mut sys = System::new_all();
                sys.refresh_all();
                let mut s = state_clone.lock().await;
                let _ = monitor::monitor_processes(&sys, &mut s.known_pids);
                log::info!(
                    "Node agent started -- {} known PIDs, code: {}, status: {}",
                    s.known_pids.len(),
                    s.config.enroll_code,
                    s.config.status
                );
            });

            // --- Background: enrollment polling ---
            let state_enroll = state.clone();
            let handle_enroll = handle.clone();
            tauri::async_runtime::spawn(async move {
                poll_enrollment(state_enroll, handle_enroll).await;
            });

            // --- Background: heartbeat with backoff (Task #4) ---
            let state_hb = state.clone();
            let handle_hb = handle.clone();
            tauri::async_runtime::spawn(async move {
                heartbeat_loop(state_hb, handle_hb).await;
            });

            // --- Background: auto-scan assets (Task #3) ---
            let state_scan = state.clone();
            tauri::async_runtime::spawn(async move {
                auto_scan_loop(state_scan).await;
            });

            // --- Background: event reporter for suspicious processes (Task #6) ---
            let state_events = state.clone();
            tauri::async_runtime::spawn(async move {
                event_reporter_loop(state_events).await;
            });

            // --- Background: FIM reporter (Task #6) ---
            let state_fim = state.clone();
            tauri::async_runtime::spawn(async move {
                fim_reporter_loop(state_fim).await;
            });

            // --- Background: Windows Event Log monitor ---
            #[cfg(target_os = "windows")]
            {
                let state_evtlog = state.clone();
                tauri::async_runtime::spawn(async move {
                    windows_eventlog_loop(state_evtlog).await;
                });
            }

            // --- Background: Network connection monitor ---
            let state_netmon = state.clone();
            tauri::async_runtime::spawn(async move {
                network_monitor_loop(state_netmon).await;
            });

            // --- Background: Registry persistence detection ---
            #[cfg(target_os = "windows")]
            {
                let state_reg = state.clone();
                tauri::async_runtime::spawn(async move {
                    registry_persistence_loop(state_reg).await;
                });
            }

            // --- Task #2: Ransomware protection module ---
            let state_ransom_seed = state.clone();
            tauri::async_runtime::spawn(async move {
                // Wait for enrollment to resolve server_url/node_id
                tokio::time::sleep(Duration::from_secs(15)).await;
                let (server_url, node_id) = {
                    let s = state_ransom_seed.lock().await;
                    (s.config.server_url.clone(), s.config.node_id.clone())
                };
                let rstate = Arc::new(Mutex::new(RansomwareState::new(server_url)));
                {
                    let mut r = rstate.lock().await;
                    r.node_id = node_id;
                }
                ransomware::start(rstate).await;
            });

            // --- Task #5: EDR/XDR core ---
            let state_edr_seed = state.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let (server_url, node_id) = {
                    let s = state_edr_seed.lock().await;
                    (s.config.server_url.clone(), s.config.node_id.clone())
                };
                let estate = Arc::new(Mutex::new(EdrState::new(server_url, node_id)));
                edr::start(estate).await;
            });

            // --- Task #6: Antivirus engine ---
            let state_av_seed = state.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(20)).await;
                let (server_url, node_id) = {
                    let s = state_av_seed.lock().await;
                    (s.config.server_url.clone(), s.config.node_id.clone())
                };
                match AntivirusState::new(server_url, node_id) {
                    Ok(av) => {
                        let av_state = Arc::new(Mutex::new(av));
                        antivirus::start(av_state).await;
                    }
                    Err(e) => log::error!("[av] failed to initialize: {}", e),
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_node_config,
            get_system_info,
            get_process_stats,
            regenerate_code,
            set_server_url,
            scan_local_ports,
            hide_to_tray,
            disconnect_node,
            enable_autostart,
            disable_autostart,
            is_autostart_enabled,
            auto_scan_assets,
            get_network_connections,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
