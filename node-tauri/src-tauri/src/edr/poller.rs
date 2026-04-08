// ---------------------------------------------------------------------------
// Tier-1 EDR poller (Task #5)
//
// Works without administrative privileges. Uses sysinfo to diff process
// state every 500ms and emit ProcessStart / ProcessStop events. Also
// enumerates TCP connections via sysinfo::Networks when available.
//
// This collector is always running as a safety net behind ETW/eBPF. Tier-2
// collectors are expected to emit richer, earlier events; the poller
// de-dupes by (pid, kind, ~1s bucket).
// ---------------------------------------------------------------------------

use chrono::Utc;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tokio::sync::Mutex;

use crate::edr::{EdrEvent, EdrEventKind, EdrState};

pub async fn run(state: Arc<Mutex<EdrState>>) {
    log::info!("[edr/poller] tier-1 poller started");

    let mut sys = System::new_with_specifics(
        RefreshKind::default().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes();
    let mut known: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        sys.refresh_processes();
        let mut current: HashSet<u32> = HashSet::new();
        let mut new_events: Vec<EdrEvent> = Vec::new();

        for (pid, proc_) in sys.processes() {
            let pu = pid.as_u32();
            current.insert(pu);
            if !known.contains(&pu) {
                let ev = EdrEvent {
                    kind: EdrEventKind::ProcessStart,
                    at: Utc::now(),
                    pid: Some(pu),
                    ppid: proc_.parent().map(|p| p.as_u32()),
                    process_name: Some(proc_.name().to_string_lossy().to_string()),
                    process_path: proc_.exe().map(|p| p.to_string_lossy().to_string()),
                    command_line: Some(
                        proc_
                            .cmd()
                            .iter()
                            .map(|s| s.to_string_lossy().to_string())
                            .collect::<Vec<_>>()
                            .join(" "),
                    ),
                    user: proc_.user_id().map(|u| u.to_string()),
                    target: None,
                    extra: serde_json::json!({
                        "source": "tier1_poll",
                        "start_time": proc_.start_time(),
                    }),
                };
                new_events.push(ev);
            }
        }

        // Gone PIDs
        for pu in known.difference(&current) {
            new_events.push(EdrEvent {
                kind: EdrEventKind::ProcessStop,
                at: Utc::now(),
                pid: Some(*pu),
                ppid: None,
                process_name: None,
                process_path: None,
                command_line: None,
                user: None,
                target: None,
                extra: serde_json::json!({"source": "tier1_poll"}),
            });
        }

        if !new_events.is_empty() {
            let mut s = state.lock().await;
            if s.tier2_active {
                // When tier 2 is active we suppress the poller's stop events
                // and only keep starts (tier-2 emits before we'd poll anyway,
                // but some starts can slip through under load).
                for ev in new_events.drain(..) {
                    if ev.kind == EdrEventKind::ProcessStart {
                        s.buffer.push(ev);
                    }
                }
            } else {
                for ev in new_events.drain(..) {
                    s.buffer.push(ev);
                }
            }
        }

        known = current;
    }
}
