//! Network discovery module.
//!
//! Provides async TCP port scanning and local network host detection.
//! Mirrors the Python agent's network_discovery.py capabilities.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use tokio::task;

/// Well-known service names by port number.
fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2222 => "ssh-alt",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "http-dev",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8000 => "http-dev",
        8080 => "http-alt",
        8443 => "https-alt",
        8888 => "http-dev",
        9090 => "prometheus",
        9100 => "node-exporter",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredService {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub open: bool,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub services: Vec<DiscoveredService>,
    pub scan_duration_ms: u64,
}

/// Scan a single TCP port on a given IP. Uses blocking connect_timeout
/// executed on a Tokio blocking thread.
pub async fn scan_port(ip: &str, port: u16, timeout_ms: u64) -> DiscoveredService {
    let addr_str = format!("{}:{}", ip, port);
    let ip_owned = ip.to_string();
    let timeout = Duration::from_millis(timeout_ms);

    let (open, latency) = task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        match addr_str.parse::<SocketAddr>() {
            Ok(addr) => match TcpStream::connect_timeout(&addr, timeout) {
                Ok(_stream) => (true, start.elapsed().as_millis() as u64),
                Err(_) => (false, start.elapsed().as_millis() as u64),
            },
            Err(_) => (false, 0u64),
        }
    })
    .await
    .unwrap_or((false, 0));

    DiscoveredService {
        ip: ip_owned,
        port,
        service: service_name(port).to_string(),
        open,
        latency_ms: latency,
    }
}

/// Scan multiple ports on a single host concurrently.
pub async fn scan_host(ip: &str, ports: &[u16], timeout_ms: u64) -> Vec<DiscoveredService> {
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let ip_owned = ip.to_string();
        handles.push(tokio::spawn(async move {
            scan_port(&ip_owned, port, timeout_ms).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(svc) = handle.await {
            if svc.open {
                results.push(svc);
            }
        }
    }

    results
}

/// Full network scan: scan a list of target IPs across a set of ports.
/// Returns a ScanResult with all discovered open services.
pub async fn scan_network(
    targets: &[String],
    ports: &[u16],
    timeout_ms: u64,
) -> ScanResult {
    let start = std::time::Instant::now();
    let mut all_handles = Vec::new();

    for target in targets {
        let ip = target.clone();
        let ports = ports.to_vec();
        all_handles.push(tokio::spawn(async move {
            scan_host(&ip, &ports, timeout_ms).await
        }));
    }

    let mut services = Vec::new();
    for handle in all_handles {
        if let Ok(host_services) = handle.await {
            services.extend(host_services);
        }
    }

    let duration = start.elapsed().as_millis() as u64;

    ScanResult {
        target: format!("{} hosts", targets.len()),
        services,
        scan_duration_ms: duration,
    }
}

/// Get the local machine's primary IPv4 address by opening a UDP socket.
/// Does not actually send traffic.
pub fn get_local_ip() -> String {
    match local_ip_address::local_ip() {
        Ok(IpAddr::V4(ip)) => ip.to_string(),
        Ok(IpAddr::V6(ip)) => ip.to_string(),
        Err(_) => "127.0.0.1".to_string(),
    }
}

/// Generate a list of IPs on the same /24 subnet as the local machine.
/// Excludes the local IP itself and .0/.255 addresses.
pub fn generate_subnet_targets(local_ip: &str) -> Vec<String> {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return Vec::new();
    }

    let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    let self_octet: u8 = parts[3].parse().unwrap_or(0);

    (1..255u8)
        .filter(|&o| o != self_octet)
        .map(|o| format!("{}.{}", prefix, o))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_local_ip() {
        let ip = get_local_ip();
        assert!(!ip.is_empty());
        // Should be a valid IP (not necessarily non-loopback in CI)
    }

    #[test]
    fn test_generate_subnet_targets() {
        let targets = generate_subnet_targets("192.168.1.100");
        assert_eq!(targets.len(), 253); // 1-254 minus self
        assert!(!targets.contains(&"192.168.1.100".to_string()));
        assert!(targets.contains(&"192.168.1.1".to_string()));
        assert!(!targets.contains(&"192.168.1.0".to_string()));
    }

    #[test]
    fn test_service_name_known() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(12345), "unknown");
    }

    #[tokio::test]
    async fn test_scan_port_closed() {
        // Scanning a port that is almost certainly closed
        let result = scan_port("127.0.0.1", 59999, 200).await;
        assert!(!result.open);
    }
}
