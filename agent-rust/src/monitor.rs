//! Process and system monitoring module.
//!
//! Mirrors the Python agent's process_monitor_loop and system info collection.

use serde::{Deserialize, Serialize};
use sysinfo::{Disks, Pid, System};
use std::collections::HashSet;

/// Suspicious process names — mirrors config.py SUSPICIOUS_PROCESS_NAMES
const SUSPICIOUS_NAMES: &[&str] = &[
    "ncat", "nc", "netcat", "socat",
    "msfconsole", "msfvenom", "meterpreter",
    "mimikatz", "lazagne", "hashcat", "john",
    "hydra", "medusa", "ncrack",
    "chisel", "ligolo", "frp", "ngrok",
    "rclone", "mega-cmd",
    "xmrig", "cpuminer", "bfgminer",
    "crackmapexec", "impacket", "responder",
    "bloodhound", "sharphound",
    "cobaltstrike", "beacon",
    "reverse_tcp", "bind_tcp",
];

/// Reverse-shell command patterns
const SHELL_PATTERNS: &[&str] = &[
    "/bin/sh -i",
    "/bin/bash -i",
    "bash -c 'sh -i",
    "python -c 'import socket",
    "powershell -enc",
    "powershell -nop",
    "powershell -w hidden",
    "cmd /c powershell",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmd: String,
    pub cpu_usage: f32,
    pub memory_kb: u64,
    pub severity: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub cpu_count: usize,
    pub cpu_brand: String,
    pub cpu_usage_percent: f32,
    pub ram_total_mb: u64,
    pub ram_used_mb: u64,
    pub ram_usage_percent: f64,
    pub disk_total_gb: f64,
    pub disk_free_gb: f64,
    pub disk_usage_percent: f64,
    pub process_count: usize,
    pub uptime_seconds: u64,
}

/// Collect a full system information snapshot.
pub fn collect_system_info() -> SystemInfo {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_usage: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>()
        / sys.cpus().len().max(1) as f32;

    let cpu_brand = sys
        .cpus()
        .first()
        .map(|c| c.brand().to_string())
        .unwrap_or_default();

    let ram_total = sys.total_memory();
    let ram_used = sys.used_memory();
    let ram_pct = if ram_total > 0 {
        (ram_used as f64 / ram_total as f64) * 100.0
    } else {
        0.0
    };

    let disks = Disks::new_with_refreshed_list();
    let (disk_total, disk_free) = disks.iter().fold((0u64, 0u64), |(t, f), d| {
        (t + d.total_space(), f + d.available_space())
    });

    SystemInfo {
        hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
        os_name: System::name().unwrap_or_else(|| "unknown".into()),
        os_version: System::os_version().unwrap_or_else(|| "unknown".into()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".into()),
        cpu_count: sys.cpus().len(),
        cpu_brand,
        cpu_usage_percent: cpu_usage,
        ram_total_mb: ram_total / (1024 * 1024),
        ram_used_mb: ram_used / (1024 * 1024),
        ram_usage_percent: ram_pct,
        disk_total_gb: disk_total as f64 / (1024.0 * 1024.0 * 1024.0),
        disk_free_gb: disk_free as f64 / (1024.0 * 1024.0 * 1024.0),
        disk_usage_percent: if disk_total > 0 {
            ((disk_total - disk_free) as f64 / disk_total as f64) * 100.0
        } else {
            0.0
        },
        process_count: sys.processes().len(),
        uptime_seconds: System::uptime(),
    }
}

/// Monitor processes: detect new PIDs since last call, flag suspicious ones.
pub fn monitor_processes(sys: &System, known_pids: &mut HashSet<u32>) -> Vec<ProcessInfo> {
    let current_pids: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
    let new_pids: Vec<u32> = current_pids.difference(known_pids).copied().collect();

    let mut results = Vec::new();

    for pid in &new_pids {
        let pid_key = Pid::from_u32(*pid);
        if let Some(process) = sys.process(pid_key) {
            let name = process.name().to_string_lossy().to_string();
            let cmd: String = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            let name_lower = name.to_lowercase();
            let cmd_lower = cmd.to_lowercase();

            let mut severity = "info".to_string();
            let mut reasons: Vec<String> = Vec::new();

            // Check against suspicious names.
            // Use exact match on the process name to avoid false positives
            // (e.g. "nc" matching NotificationCenter, financed, etc.)
            // but allow substring match on the full command line.
            for bad in SUSPICIOUS_NAMES {
                let name_match = name_lower == *bad;
                // For cmd, use word-boundary-like matching: the suspicious
                // name must appear as a standalone token (preceded/followed
                // by whitespace, path separator, or string boundary).
                let cmd_match = cmd_lower
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .any(|token| token == *bad);
                if name_match || cmd_match {
                    severity = "high".to_string();
                    reasons.push(format!("matches suspicious name '{}'", bad));
                    break;
                }
            }

            // Check for reverse shell patterns
            for pat in SHELL_PATTERNS {
                if cmd_lower.contains(pat) {
                    severity = "critical".to_string();
                    reasons.push("possible reverse shell".to_string());
                    break;
                }
            }

            results.push(ProcessInfo {
                pid: *pid,
                name,
                cmd,
                cpu_usage: process.cpu_usage(),
                memory_kb: process.memory() / 1024,
                severity,
                reasons,
            });
        }
    }

    // Update known set
    *known_pids = current_pids;

    results
}

/// Convert system info to a serde_json::Value for IPC output.
pub fn system_info_to_json(info: &SystemInfo) -> serde_json::Value {
    serde_json::to_value(info).unwrap_or(serde_json::Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_system_info() {
        let info = collect_system_info();
        assert!(info.cpu_count > 0);
        assert!(info.ram_total_mb > 0);
        assert!(!info.hostname.is_empty());
    }

    #[test]
    fn test_monitor_processes() {
        let mut sys = System::new_all();
        sys.refresh_all();
        let mut known = HashSet::new();
        // First call: everything is "new"
        let procs = monitor_processes(&sys, &mut known);
        assert!(!procs.is_empty());
        // Second call: nothing new
        let procs2 = monitor_processes(&sys, &mut known);
        assert!(procs2.is_empty());
    }
}
