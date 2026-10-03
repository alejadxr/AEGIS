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
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tokio::sync::Mutex;

use crate::edr::{EdrEvent, EdrEventKind, EdrState};

/// What to load for every process we see. `refresh_processes` (no specifics)
/// uses `ProcessRefreshKind::nothing()` in sysinfo 0.34, so newly spawned
/// processes come back with no cmd / exe / user unless we ask for them here.
/// `OnlyIfNotSet` keeps the cost to one lookup per process lifetime.
fn refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_user(UpdateKind::OnlyIfNotSet)
        .with_cwd(UpdateKind::OnlyIfNotSet)
}

fn refresh(sys: &mut System) {
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh_kind());
}

/// Refresh once and diff against `known`. Returns the events and the new
/// set of live PIDs.
fn poll_once(sys: &mut System, known: &HashSet<u32>) -> (Vec<EdrEvent>, HashSet<u32>) {
    refresh(sys);
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
                    // Lets the server judge the lineage of a process whose
                    // parent started before the agent (never seen starting).
                    "parent_path": proc_
                        .parent()
                        .and_then(|pp| sys.process(pp))
                        .and_then(|pp| pp.exe())
                        .map(|p| p.to_string_lossy().to_string()),
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

    (new_events, current)
}

pub async fn run(state: Arc<Mutex<EdrState>>) {
    log::info!("[edr/poller] tier-1 poller started");

    let mut sys = System::new();
    refresh(&mut sys);
    let mut known: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;

        let (mut new_events, current) = poll_once(&mut sys, &known);

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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn new_process_start_carries_command_line() {
        let mut sys = System::new();
        refresh(&mut sys);
        let known: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();

        let mut child = std::process::Command::new("sleep")
            .arg("30.123")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();

        let mut found = None;
        for _ in 0..20 {
            let (events, _) = poll_once(&mut sys, &known);
            found = events
                .into_iter()
                .find(|e| e.kind == EdrEventKind::ProcessStart && e.pid == Some(pid));
            if found.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();

        let ev = found.expect("child process start event");
        let cmd = ev.command_line.unwrap_or_default();
        assert!(cmd.contains("30.123"), "command_line was {cmd:?}");
        assert!(ev.process_path.is_some(), "exe missing");
        assert!(ev.user.is_some(), "user missing");
        let me = std::env::current_exe().unwrap().to_string_lossy().to_string();
        assert_eq!(
            ev.extra["parent_path"].as_str(),
            Some(me.as_str()),
            "parent_path should be this test binary"
        );
    }
}
