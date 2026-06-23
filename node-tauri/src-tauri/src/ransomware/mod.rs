// ---------------------------------------------------------------------------
// Ransomware Protection Module (Task #2)
//
// Detects encryption activity via multiple correlated signals and executes
// automated response: kill the process tree, roll back affected files, and
// post a forensic chain to the AEGIS backend with severity=critical.
//
// Detection signals (need 2+ within 2s to trigger):
//   1. Canary file modified          (canary.rs)
//   2. Mass file extension changes   (detector.rs)
//   3. Entropy spike on writes       (entropy.rs)
//   4. Shadow Copy deletion          (Windows only)
//   5. Backup tool process killed    (detector.rs)
//   6. Known ransom note filenames   (canary.rs)
//
// Response chain:
//   1. killer::terminate_process_tree
//   2. rollback::restore_affected_files
//   3. POST /api/v1/agents/events with severity=critical
// ---------------------------------------------------------------------------

pub mod canary;
pub mod detector;
pub mod entropy;
pub mod killer;

#[cfg(target_os = "windows")]
pub mod rollback_windows;

#[cfg(target_os = "linux")]
pub mod rollback_linux;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ransomware::detector::{Detector, Signal, SignalKind};

/// Shared state for the ransomware module.
#[derive(Debug)]
pub struct RansomwareState {
    pub detector: Detector,
    pub canary_paths: Vec<PathBuf>,
    pub enabled: bool,
    pub server_url: String,
    pub node_id: Option<String>,
    pub incidents_reported: u64,
}

impl RansomwareState {
    pub fn new(server_url: String) -> Self {
        Self {
            detector: Detector::new(),
            canary_paths: Vec::new(),
            enabled: true,
            server_url,
            node_id: None,
            incidents_reported: 0,
        }
    }
}

/// Forensic chain reported to backend on a ransomware incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareIncident {
    pub node_id: Option<String>,
    pub detected_at: String,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub signals: Vec<SignalReport>,
    pub affected_files: Vec<String>,
    pub killed_pids: Vec<u32>,
    pub rollback_status: String,
    pub rollback_files_restored: u64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalReport {
    pub kind: String,
    pub detail: String,
    pub at: String,
}

impl From<&Signal> for SignalReport {
    fn from(s: &Signal) -> Self {
        SignalReport {
            kind: match s.kind {
                SignalKind::CanaryModified => "canary_modified".into(),
                SignalKind::MassExtensionChange => "mass_extension_change".into(),
                SignalKind::EntropySpike => "entropy_spike".into(),
                SignalKind::ShadowCopyDeletion => "shadow_copy_deletion".into(),
                SignalKind::BackupToolKilled => "backup_tool_killed".into(),
                SignalKind::RansomNoteDropped => "ransom_note_dropped".into(),
            },
            detail: s.detail.clone(),
            at: s.at.to_rfc3339(),
        }
    }
}

/// Start the ransomware module. Spawns background tasks:
///   - canary file watcher
///   - detector correlation loop
///   - incident reporter
pub async fn start(state: Arc<Mutex<RansomwareState>>) {
    log::info!("[ransomware] starting module");

    // Seed canary files in user directories
    match canary::seed_canaries() {
        Ok(paths) => {
            let n = paths.len();
            {
                let mut s = state.lock().await;
                s.canary_paths = paths;
            }
            log::info!("[ransomware] seeded {} canary files", n);
        }
        Err(e) => {
            log::warn!("[ransomware] failed to seed canaries: {}", e);
        }
    }

    // Spawn the canary watcher
    let state_w = state.clone();
    tokio::spawn(async move {
        if let Err(e) = canary::watch_canaries(state_w).await {
            log::error!("[ransomware] canary watcher stopped: {}", e);
        }
    });

    // Spawn the detector correlation loop
    let state_d = state.clone();
    tokio::spawn(async move {
        detector::run_correlator(state_d).await;
    });

    // Spawn the Shadow Copy monitor on Windows
    #[cfg(target_os = "windows")]
    {
        let state_vss = state.clone();
        tokio::spawn(async move {
            rollback_windows::monitor_shadow_copy_deletion(state_vss).await;
        });
    }
}

/// Called by the detector when 2+ signals correlate. Runs the response chain.
pub async fn handle_incident(
    state: Arc<Mutex<RansomwareState>>,
    pid: Option<u32>,
    signals: Vec<Signal>,
    affected_files: Vec<PathBuf>,
) {
    log::warn!(
        "[ransomware] INCIDENT DETECTED pid={:?} signals={} files={}",
        pid,
        signals.len(),
        affected_files.len(),
    );

    // 1. Kill the process tree
    let mut killed_pids: Vec<u32> = Vec::new();
    let mut process_name: Option<String> = None;
    let mut process_path: Option<String> = None;

    if let Some(pid) = pid {
        match killer::terminate_process_tree(pid) {
            Ok(result) => {
                killed_pids = result.killed_pids;
                process_name = result.process_name;
                process_path = result.process_path;
                log::warn!("[ransomware] killed {} PIDs", killed_pids.len());
            }
            Err(e) => log::error!("[ransomware] kill failed: {}", e),
        }
    }

    // 2. Roll back affected files
    let file_strs: Vec<String> = affected_files
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let (rollback_status, rollback_restored) = rollback_files(&affected_files).await;

    // 3. Post forensic chain to backend
    let now = chrono::Utc::now().to_rfc3339();
    let (server_url, node_id) = {
        let mut s = state.lock().await;
        s.incidents_reported += 1;
        (s.server_url.clone(), s.node_id.clone())
    };

    let incident = RansomwareIncident {
        node_id: node_id.clone(),
        detected_at: now,
        process_pid: pid,
        process_name,
        process_path,
        signals: signals.iter().map(SignalReport::from).collect(),
        affected_files: file_strs,
        killed_pids,
        rollback_status,
        rollback_files_restored: rollback_restored,
        severity: "critical".into(),
    };

    if let Err(e) = post_incident(&server_url, &incident).await {
        log::error!("[ransomware] failed to report incident: {}", e);
    } else {
        log::info!("[ransomware] incident reported to backend");
    }
}

async fn rollback_files(affected: &[PathBuf]) -> (String, u64) {
    #[cfg(target_os = "windows")]
    {
        match rollback_windows::restore_from_shadow_copy(affected).await {
            Ok(n) => ("vss_restored".into(), n),
            Err(e) => {
                log::warn!("[ransomware] VSS rollback failed: {}", e);
                ("vss_failed".into(), 0)
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        match rollback_linux::restore_from_snapshot(affected).await {
            Ok(n) => ("snapshot_restored".into(), n),
            Err(e) => {
                log::warn!("[ransomware] Linux rollback failed: {}", e);
                ("snapshot_failed".into(), 0)
            }
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = affected;
        ("unsupported_platform".into(), 0)
    }
}

async fn post_incident(
    server_url: &str,
    incident: &RansomwareIncident,
) -> Result<(), String> {
    // Wrap in the standard AgentEvent batch shape expected by backend
    let body = serde_json::json!({
        "agent_id": incident.node_id.clone().unwrap_or_default(),
        "events": [{
            "category": "forensic",
            "severity": "critical",
            "title": format!(
                "Ransomware activity detected (pid={:?}, {} signals)",
                incident.process_pid,
                incident.signals.len()
            ),
            "details": incident,
            "timestamp": incident.detected_at,
        }]
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .post(format!("{}/agents/events", server_url))
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("server responded with {}", resp.status()));
    }
    Ok(())
}
