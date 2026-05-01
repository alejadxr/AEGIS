//! Process killer with forensic chain capture — Phase R-E
//!
//! Terminates the offending process and its entire process chain (parents +
//! children). Before killing, captures a [`ProcessChainSnapshot`] for forensic
//! analysis.
//!
//! Open-files and network-connections fields are stubs — sysinfo does not
//! expose these at this abstraction level. They are reserved for future
//! platform-specific enrichment (lsof/netstat on Unix, NtQuerySystemInformation
//! on Windows).

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessesToUpdate, System};

/// A lightweight process entry captured for forensics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub cmdline: Vec<String>,
}

/// Forensic snapshot of the process chain taken before killing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChainSnapshot {
    /// All processes in the chain (target + parents + children).
    pub tree: Vec<ProcessEntry>,
    /// Flat map pid → command line (convenience accessor).
    pub command_lines: HashMap<u32, Vec<String>>,
    /// Open file handles — stub, populated when platform data is available.
    pub open_files: Vec<String>,
    /// Active network connections — stub, populated when platform data is available.
    pub network_connections: Vec<String>,
    /// UTC timestamp when the snapshot was captured.
    pub captured_at: u64,
}

/// Errors produced by the killer subsystem.
#[derive(Debug, thiserror::Error)]
pub enum KillerError {
    #[error("sysinfo refresh failed")]
    SysinfoRefresh,
    #[error("kill failed for pid {pid}: {reason}")]
    KillFailed { pid: u32, reason: String },
}

/// Orchestrates forensic capture and process-chain termination.
pub struct Killer {
    capture_forensics: bool,
}

impl Killer {
    pub fn new(capture_forensics: bool) -> Self {
        Self { capture_forensics }
    }

    /// Capture forensics, then kill the process chain rooted at `target_pid`.
    /// Idempotent: if a PID is already dead, the call succeeds.
    pub async fn kill_chain(
        &self,
        target_pid: u32,
    ) -> Result<ProcessChainSnapshot, KillerError> {
        // Run the blocking sysinfo work on a dedicated thread to avoid
        // blocking the async executor.
        let capture = self.capture_forensics;
        tokio::task::spawn_blocking(move || kill_chain_sync(target_pid, capture))
            .await
            .map_err(|_| KillerError::SysinfoRefresh)?
    }
}

/// Synchronous (blocking) implementation — safe to call from spawn_blocking.
fn kill_chain_sync(
    target_pid: u32,
    capture_forensics: bool,
) -> Result<ProcessChainSnapshot, KillerError> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let target = Pid::from_u32(target_pid);

    // Collect the full chain: target + all ancestors + all descendants.
    let chain_pids = collect_chain(&sys, target);

    // --- Forensic snapshot (before kill) ---
    let snapshot = if capture_forensics {
        build_snapshot(&sys, &chain_pids)
    } else {
        empty_snapshot()
    };

    // --- Kill ---
    for &pid in &chain_pids {
        kill_pid(&sys, pid);
    }

    Ok(snapshot)
}

/// Collect target PID + all ancestors + all descendants.
fn collect_chain(sys: &System, target: Pid) -> Vec<Pid> {
    let mut pids: Vec<Pid> = Vec::new();

    // Walk ancestors.
    let mut current = Some(target);
    while let Some(pid) = current {
        pids.push(pid);
        current = sys
            .process(pid)
            .and_then(|p| p.parent())
    }

    // Walk descendants (all processes whose ancestor chain includes target).
    for pid in sys.processes().keys() {
        if pids.contains(pid) {
            continue;
        }
        if is_descendant_of(sys, *pid, target) {
            pids.push(*pid);
        }
    }

    pids.sort_unstable_by_key(|p| p.as_u32());
    pids.dedup();
    pids
}

fn is_descendant_of(sys: &System, pid: Pid, ancestor: Pid) -> bool {
    let mut current = sys.process(pid).and_then(|p| p.parent());
    while let Some(parent) = current {
        if parent == ancestor {
            return true;
        }
        current = sys.process(parent).and_then(|p| p.parent());
    }
    false
}

fn build_snapshot(sys: &System, pids: &[Pid]) -> ProcessChainSnapshot {
    let captured_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut tree = Vec::with_capacity(pids.len());
    let mut command_lines: HashMap<u32, Vec<String>> = HashMap::new();

    for &pid in pids {
        if let Some(proc_) = sys.process(pid) {
            let cmdline: Vec<String> = proc_.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect();
            let entry = ProcessEntry {
                pid: pid.as_u32(),
                parent_pid: proc_.parent().map(|p| p.as_u32()),
                name: proc_.name().to_string_lossy().to_string(),
                cmdline: cmdline.clone(),
            };
            command_lines.insert(pid.as_u32(), cmdline);
            tree.push(entry);
        }
    }

    ProcessChainSnapshot {
        tree,
        command_lines,
        // Stubs — platform enrichment deferred to future phase.
        open_files: vec![],
        network_connections: vec![],
        captured_at,
    }
}

fn empty_snapshot() -> ProcessChainSnapshot {
    ProcessChainSnapshot {
        tree: vec![],
        command_lines: HashMap::new(),
        open_files: vec![],
        network_connections: vec![],
        captured_at: 0,
    }
}

/// Kill a single PID. Idempotent — returns silently if PID not found.
fn kill_pid(sys: &System, pid: Pid) {
    if let Some(proc_) = sys.process(pid) {
        #[cfg(unix)]
        {
            let _ = proc_.kill_with(Signal::Kill);
        }
        #[cfg(windows)]
        {
            // sysinfo maps kill() to TerminateProcess on Windows.
            let _ = proc_.kill();
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = proc_.kill();
        }
    }
    // If the process is already dead (not found), we do nothing — idempotent.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_chain_snapshot_serde_round_trip() {
        let mut cmd_map = HashMap::new();
        cmd_map.insert(42u32, vec!["evil.exe".to_string(), "--encrypt".to_string()]);

        let snap = ProcessChainSnapshot {
            tree: vec![ProcessEntry {
                pid: 42,
                parent_pid: Some(1),
                name: "evil.exe".to_string(),
                cmdline: vec!["evil.exe".to_string(), "--encrypt".to_string()],
            }],
            command_lines: cmd_map,
            open_files: vec!["/tmp/victim.txt".to_string()],
            network_connections: vec!["192.0.2.1:443".to_string()],
            captured_at: 1_700_000_000,
        };

        let json = serde_json::to_string(&snap).expect("serialize");
        let back: ProcessChainSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.tree.len(), 1);
        assert_eq!(back.tree[0].pid, 42);
        assert_eq!(back.tree[0].parent_pid, Some(1));
        assert_eq!(back.tree[0].name, "evil.exe");
        assert_eq!(back.command_lines[&42], vec!["evil.exe", "--encrypt"]);
        assert_eq!(back.open_files, vec!["/tmp/victim.txt"]);
        assert_eq!(back.network_connections, vec!["192.0.2.1:443"]);
        assert_eq!(back.captured_at, 1_700_000_000);
    }

    #[test]
    fn process_entry_serde_round_trip() {
        let entry = ProcessEntry {
            pid: 100,
            parent_pid: None,
            name: "init".to_string(),
            cmdline: vec!["/sbin/init".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProcessEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pid, 100);
        assert!(back.parent_pid.is_none());
    }
}
