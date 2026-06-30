//! AEGIS EDR-lite Endpoint Agent — Rust Prototype
//! =================================================
//!
//! Minimal Rust implementation proving core agent capabilities:
//!   - System information collection
//!   - Process monitoring (new processes, suspicious name detection)
//!   - Network discovery (async TCP port scanning)
//!   - File Integrity Monitoring (FIM) via notify
//!   - IPC mode (stdin/stdout JSON communication)
//!
//! This prototype mirrors the Python agent's architecture while
//! demonstrating the performance and resource advantages of Rust.

mod discovery;
mod fim;
mod monitor;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{self, BufRead, Write};
use sysinfo::System;
use tokio::time::{self, Duration};

// ---------------------------------------------------------------------------
// IPC message types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct IpcRequest {
    command: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct IpcResponse {
    status: String,
    command: String,
    data: serde_json::Value,
    timestamp: String,
}

impl IpcResponse {
    fn success(command: &str, data: serde_json::Value) -> Self {
        Self {
            status: "ok".to_string(),
            command: command.to_string(),
            data,
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    fn error(command: &str, message: &str) -> Self {
        Self {
            status: "error".to_string(),
            command: command.to_string(),
            data: serde_json::json!({ "error": message }),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

// ---------------------------------------------------------------------------
// Agent event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct AgentEvent {
    category: String,
    severity: String,
    title: String,
    details: serde_json::Value,
    timestamp: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "ipc" => run_ipc_mode().await,
            "demo" => run_demo().await,
            "scan" => {
                let target = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1");
                run_scan(target).await;
            }
            "sysinfo" => run_sysinfo(),
            "monitor" => run_monitor().await,
            "fim" => {
                let path = args.get(2).map(|s| s.as_str()).unwrap_or("/tmp");
                run_fim(path).await;
            }
            "help" | "--help" | "-h" => print_usage(),
            _ => {
                eprintln!("Unknown command: {}", args[1]);
                print_usage();
            }
        }
    } else {
        // Default: run demo mode
        run_demo().await;
    }
}

fn print_usage() {
    println!(
        r#"AEGIS Agent (Rust Prototype) v0.1.0

USAGE:
    aegis-agent-rust <COMMAND> [OPTIONS]

COMMANDS:
    demo        Run all capabilities once and display results (default)
    sysinfo     Collect and display system information
    monitor     Start process monitoring loop
    scan [IP]   Scan common ports on target IP (default: 127.0.0.1)
    fim [PATH]  Start file integrity monitoring on a path (default: /tmp)
    ipc         Start IPC mode (stdin/stdout JSON)
    help        Show this help message
"#
    );
}

// ---------------------------------------------------------------------------
// Demo mode: exercise all capabilities
// ---------------------------------------------------------------------------

async fn run_demo() {
    println!("=== AEGIS Agent (Rust Prototype) v0.1.0 ===\n");

    // 1. System info
    println!("[1/4] Collecting system information...");
    let sys_info = monitor::collect_system_info();
    println!(
        "  Host    : {}",
        sys_info.hostname
    );
    println!(
        "  OS      : {} {} (kernel {})",
        sys_info.os_name, sys_info.os_version, sys_info.kernel_version
    );
    println!(
        "  CPU     : {} ({} cores, {:.1}% usage)",
        sys_info.cpu_brand, sys_info.cpu_count, sys_info.cpu_usage_percent
    );
    println!(
        "  RAM     : {} MB / {} MB ({:.1}%)",
        sys_info.ram_used_mb, sys_info.ram_total_mb, sys_info.ram_usage_percent
    );
    println!(
        "  Disk    : {:.1} GB free / {:.1} GB total ({:.1}%)",
        sys_info.disk_free_gb, sys_info.disk_total_gb, sys_info.disk_usage_percent
    );
    println!(
        "  Procs   : {}",
        sys_info.process_count
    );
    println!(
        "  Uptime  : {} seconds\n",
        sys_info.uptime_seconds
    );

    // 2. Process monitoring snapshot
    println!("[2/4] Scanning processes...");
    let mut sys = System::new_all();
    sys.refresh_all();
    let mut known_pids = HashSet::new();
    let new_procs = monitor::monitor_processes(&sys, &mut known_pids);
    let suspicious: Vec<_> = new_procs
        .iter()
        .filter(|p| p.severity != "info")
        .collect();
    println!(
        "  Found {} processes ({} suspicious)\n",
        new_procs.len(),
        suspicious.len()
    );
    for proc in &suspicious {
        println!(
            "  [{}] PID {} - {} : {}",
            proc.severity.to_uppercase(),
            proc.pid,
            proc.name,
            proc.reasons.join(", ")
        );
    }

    // 3. Network discovery (scan localhost)
    println!("[3/4] Port scanning localhost...");
    let common_ports: Vec<u16> = vec![
        22, 80, 443, 3000, 3001, 3306, 5432, 6379, 8000, 8080, 8443, 9200, 27017,
    ];
    let start = std::time::Instant::now();
    let services = discovery::scan_host("127.0.0.1", &common_ports, 500).await;
    let elapsed = start.elapsed();
    println!(
        "  Scanned {} ports in {:.1}ms",
        common_ports.len(),
        elapsed.as_secs_f64() * 1000.0
    );
    for svc in &services {
        println!(
            "  OPEN: :{} ({}) - {}ms",
            svc.port, svc.service, svc.latency_ms
        );
    }
    println!();

    // 4. Local IP and subnet info
    println!("[4/4] Network info:");
    let local_ip = discovery::get_local_ip();
    println!("  Local IP: {}", local_ip);
    let subnet_targets = discovery::generate_subnet_targets(&local_ip);
    println!("  Subnet targets: {} hosts in /24\n", subnet_targets.len());

    println!("=== Demo complete ===");
    println!("Run with 'ipc' mode for Tauri integration.");
}

// ---------------------------------------------------------------------------
// IPC mode: stdin/stdout JSON
// ---------------------------------------------------------------------------

async fn run_ipc_mode() {
    // Write ready message
    let ready = serde_json::json!({
        "status": "ready",
        "agent": "aegis-agent-rust",
        "version": "0.1.0",
        "pid": std::process::id(),
        "timestamp": Utc::now().to_rfc3339(),
    });
    println!("{}", serde_json::to_string(&ready).unwrap());
    io::stdout().flush().unwrap();

    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l.trim().to_string(),
            Err(_) => break,
        };

        if line.is_empty() {
            continue;
        }

        let request: IpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = IpcResponse::error("unknown", &format!("Invalid JSON: {}", e));
                println!("{}", serde_json::to_string(&resp).unwrap());
                io::stdout().flush().unwrap();
                continue;
            }
        };

        let response = handle_ipc_command(&request).await;
        println!("{}", serde_json::to_string(&response).unwrap());
        io::stdout().flush().unwrap();
    }
}

async fn handle_ipc_command(req: &IpcRequest) -> IpcResponse {
    match req.command.as_str() {
        "sysinfo" => {
            let info = monitor::collect_system_info();
            IpcResponse::success("sysinfo", monitor::system_info_to_json(&info))
        }

        "processes" => {
            let mut sys = System::new_all();
            sys.refresh_all();
            let mut known = HashSet::new();
            let procs = monitor::monitor_processes(&sys, &mut known);
            IpcResponse::success(
                "processes",
                serde_json::to_value(&procs).unwrap_or_default(),
            )
        }

        "scan" => {
            let target = req.params.get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1");
            let ports: Vec<u16> = req.params.get("ports")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_else(|| vec![22, 80, 443, 3306, 5432, 8080, 8443]);
            let timeout = req.params.get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(500);

            let services = discovery::scan_host(target, &ports, timeout).await;
            IpcResponse::success(
                "scan",
                serde_json::to_value(&services).unwrap_or_default(),
            )
        }

        "scan_network" => {
            let local_ip = discovery::get_local_ip();
            let targets = discovery::generate_subnet_targets(&local_ip);
            let ports: Vec<u16> = req.params.get("ports")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_else(|| vec![22, 80, 443, 8080]);
            let timeout = req.params.get("timeout_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(500);

            let result = discovery::scan_network(&targets, &ports, timeout).await;
            IpcResponse::success(
                "scan_network",
                serde_json::to_value(&result).unwrap_or_default(),
            )
        }

        "local_ip" => {
            let ip = discovery::get_local_ip();
            IpcResponse::success("local_ip", serde_json::json!({ "ip": ip }))
        }

        "ping" => {
            IpcResponse::success("ping", serde_json::json!({ "pong": true }))
        }

        "shutdown" => {
            IpcResponse::success("shutdown", serde_json::json!({ "message": "shutting down" }))
            // The main loop will end when stdin closes
        }

        _ => IpcResponse::error(&req.command, "Unknown command"),
    }
}

// ---------------------------------------------------------------------------
// Standalone subcommands
// ---------------------------------------------------------------------------

fn run_sysinfo() {
    let info = monitor::collect_system_info();
    let json = serde_json::to_string_pretty(&info).unwrap();
    println!("{}", json);
}

async fn run_scan(target: &str) {
    println!("Scanning {} ...", target);
    let ports: Vec<u16> = vec![
        21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
        1433, 1521, 2222, 3000, 3001, 3306, 3389, 5000, 5432,
        5900, 6379, 8000, 8080, 8443, 8888, 9090, 9100, 9200, 27017,
    ];
    let start = std::time::Instant::now();
    let services = discovery::scan_host(target, &ports, 500).await;
    let elapsed = start.elapsed();

    println!(
        "\nScan complete: {} ports in {:.1}ms\n",
        ports.len(),
        elapsed.as_secs_f64() * 1000.0
    );

    if services.is_empty() {
        println!("No open ports found.");
    } else {
        println!("{:<8} {:<20} {}", "PORT", "SERVICE", "LATENCY");
        println!("{}", "-".repeat(40));
        for svc in &services {
            println!("{:<8} {:<20} {}ms", svc.port, svc.service, svc.latency_ms);
        }
    }
}

async fn run_monitor() {
    println!("Starting process monitor (Ctrl+C to stop)...\n");
    let mut sys = System::new_all();
    sys.refresh_all();
    let mut known_pids = HashSet::new();

    // Initial snapshot
    let _ = monitor::monitor_processes(&sys, &mut known_pids);
    println!("Initial snapshot: {} known processes", known_pids.len());

    let mut interval = time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        sys.refresh_all();
        let new_procs = monitor::monitor_processes(&sys, &mut known_pids);

        for proc in &new_procs {
            let marker = match proc.severity.as_str() {
                "critical" => "!!!",
                "high" => "!! ",
                "medium" => "!  ",
                _ => "   ",
            };
            println!(
                "{} [{}] New PID {} : {} (CPU: {:.1}%, MEM: {} KB)",
                marker,
                Utc::now().format("%H:%M:%S"),
                proc.pid,
                proc.name,
                proc.cpu_usage,
                proc.memory_kb,
            );
            if !proc.reasons.is_empty() {
                println!("     Reasons: {}", proc.reasons.join(", "));
            }
        }
    }
}

async fn run_fim(path: &str) {
    println!("Starting FIM on: {} (Ctrl+C to stop)\n", path);

    match fim::start_fim(&[path], &[]) {
        Ok((rx, _watcher)) => {
            println!("FIM watcher active. Waiting for file changes...\n");
            // Keep watcher alive and process events
            loop {
                match rx.recv() {
                    Ok(event) => {
                        println!(
                            "[{}] {} {} (severity: {})",
                            event.timestamp, event.event_type, event.path, event.severity
                        );
                        if !event.hash_before.is_empty() || !event.hash_after.is_empty() {
                            println!(
                                "  Hash: {} -> {}",
                                if event.hash_before.is_empty() {
                                    "(none)"
                                } else {
                                    &event.hash_before
                                },
                                if event.hash_after.is_empty() {
                                    "(none)"
                                } else {
                                    &event.hash_after
                                }
                            );
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to start FIM: {}", e);
        }
    }
}
