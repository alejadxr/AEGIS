// ---------------------------------------------------------------------------
// EDR/XDR Core (Task #5)
//
// Streams kernel-level telemetry from the endpoint to the AEGIS backend:
//   - Process events  (start, stop, image load)
//   - Network events  (connect, accept)
//   - File events     (create, write, delete)
//   - Registry events (set, delete) — Windows only
//   - AMSI events     — Windows only
//
// Collection is tiered:
//   - Tier 1 (no admin): sysinfo/procfs polling (works everywhere)
//   - Tier 2 (admin):    ETW on Windows (ferrisetw), eBPF on Linux (aya)
//
// Everything funnels into a single `EdrEvent` ring buffer that the uploader
// drains every second and POSTs (gzipped JSON) to /api/v1/edr/events.
// ---------------------------------------------------------------------------

pub mod event_buffer;
pub mod uploader;

#[cfg(target_os = "windows")]
pub mod etw_windows;

#[cfg(target_os = "linux")]
pub mod ebpf_linux;

// Tier-1 polling fallback — always built.
pub mod poller;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use event_buffer::EventBuffer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdrEventKind {
    ProcessStart,
    ProcessStop,
    ImageLoad,
    TcpConnect,
    TcpAccept,
    FileCreate,
    FileWrite,
    FileDelete,
    RegistrySet,
    RegistryDelete,
    AmsiScan,
    DnsQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEvent {
    pub kind: EdrEventKind,
    pub at: DateTime<Utc>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub target: Option<String>,
    pub extra: serde_json::Value,
}

impl EdrEvent {
    pub fn new(kind: EdrEventKind) -> Self {
        Self {
            kind,
            at: Utc::now(),
            pid: None,
            ppid: None,
            process_name: None,
            process_path: None,
            command_line: None,
            user: None,
            target: None,
            extra: serde_json::Value::Null,
        }
    }
}

#[derive(Debug)]
pub struct EdrState {
    pub buffer: EventBuffer,
    pub enabled: bool,
    pub server_url: String,
    pub node_id: Option<String>,
    pub agent_id: Option<String>,
    pub events_sent: u64,
    pub events_dropped: u64,
    pub tier2_active: bool, // true when ETW/eBPF is running
}

impl EdrState {
    pub fn new(server_url: String, agent_id: Option<String>) -> Self {
        Self {
            buffer: EventBuffer::with_capacity(16_384),
            enabled: true,
            server_url,
            node_id: agent_id.clone(),
            agent_id,
            events_sent: 0,
            events_dropped: 0,
            tier2_active: false,
        }
    }
}

/// Start the EDR module. Spawns collectors + the uploader.
pub async fn start(state: Arc<Mutex<EdrState>>) {
    log::info!("[edr] starting module");

    // Try Tier 2 (ETW / eBPF) first — fall back to Tier 1 polling.
    #[cfg(target_os = "windows")]
    {
        let state_etw = state.clone();
        tokio::spawn(async move {
            match etw_windows::run(state_etw).await {
                Ok(()) => log::info!("[edr] ETW collector exited cleanly"),
                Err(e) => log::warn!(
                    "[edr] ETW collector failed ({}); falling back to Tier 1",
                    e
                ),
            }
        });
    }

    #[cfg(target_os = "linux")]
    {
        let state_ebpf = state.clone();
        tokio::spawn(async move {
            match ebpf_linux::run(state_ebpf).await {
                Ok(()) => log::info!("[edr] eBPF collector exited cleanly"),
                Err(e) => log::warn!(
                    "[edr] eBPF collector failed ({}); falling back to Tier 1",
                    e
                ),
            }
        });
    }

    // Tier 1 poller is always running as a safety net — it dedupes against
    // whatever Tier 2 already pushed.
    let state_poll = state.clone();
    tokio::spawn(async move {
        poller::run(state_poll).await;
    });

    // Uploader: drain buffer every 1s, gzip, POST to backend
    let state_up = state.clone();
    tokio::spawn(async move {
        uploader::run(state_up).await;
    });
}
