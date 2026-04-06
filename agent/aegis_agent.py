#!/usr/bin/env python3
"""
AEGIS EDR-lite Endpoint Agent
================================
Lightweight endpoint detection & response agent that monitors a host and
reports events to the AEGIS API.

Capabilities:
  - Process monitoring (new processes, suspicious names, port listeners)
  - Network monitoring (new connections, new listening ports)
  - File integrity monitoring (FIM) via watchdog
  - Deception breadcrumbs (canary files that trigger CRITICAL alerts)
  - Forensic snapshot capture on demand
  - Local network discovery (hosts, services, banners)
  - System information collection
  - Opt-in anonymized data sharing

Usage:
  AEGIS_API_URL=http://server:8000/api/v1 AEGIS_API_KEY=c6_xxx python aegis_agent.py
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import platform
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config as cfg
from network_discovery import (
    discover_local_network,
    collect_system_info,
    anonymize_discovery_data,
    DATA_SHARING_PROMPT,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, cfg.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [aegis-agent] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("aegis-agent")

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
_event_queue: list[dict] = []
_queue_lock = asyncio.Lock()
_thread_lock = threading.Lock()  # for watchdog thread-safe enqueue
_known_pids: set[int] = set()
_known_connections: set[tuple] = set()
_known_listeners: set[tuple] = set()
_file_hashes: dict[str, str] = {}
_discovered_services: list[dict] = []
_system_info: dict = {}
_shutdown = asyncio.Event()


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
def _build_client() -> httpx.AsyncClient:
    headers = {}
    if cfg.AEGIS_API_KEY:
        headers["X-API-Key"] = cfg.AEGIS_API_KEY
    return httpx.AsyncClient(
        base_url=cfg.AEGIS_API_URL,
        headers=headers,
        timeout=15.0,
    )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_sha256(path: str) -> str:
    """Compute SHA-256 hash of a file. Returns empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


async def _enqueue(category: str, severity: str, title: str, details: dict):
    async with _queue_lock:
        _event_queue.append({
            "category": category,
            "severity": severity,
            "title": title,
            "details": details,
            "timestamp": _now_iso(),
        })


def _enqueue_sync(category: str, severity: str, title: str, details: dict):
    """Thread-safe enqueue for watchdog callbacks (runs outside asyncio)."""
    with _thread_lock:
        _event_queue.append({
            "category": category,
            "severity": severity,
            "title": title,
            "details": details,
            "timestamp": _now_iso(),
        })


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
async def register(client: httpx.AsyncClient) -> bool:
    payload = {
        "agent_id": cfg.AGENT_ID,
        "hostname": cfg.HOSTNAME,
        "os_info": cfg.OS_INFO,
        "ip_address": _get_primary_ip(),
        "agent_version": cfg.AGENT_VERSION,
        "tags": [],
        "system_info": _system_info,
        "discovered_services": _discovered_services,
        "data_sharing": {
            "enabled": cfg.DATA_SHARING_ENABLED,
            "level": cfg.DATA_SHARING_LEVEL if cfg.DATA_SHARING_ENABLED else "none",
        },
    }
    for attempt in range(5):
        try:
            resp = await client.post("/agents/register", json=payload)
            if resp.status_code in (200, 201):
                data = resp.json()
                log.info("Registered: %s (status=%s)", data.get("message"), data.get("status"))
                return True
            log.warning("Registration failed (%d): %s", resp.status_code, resp.text)
        except httpx.RequestError as exc:
            log.warning("Registration attempt %d failed: %s", attempt + 1, exc)
        await asyncio.sleep(min(2 ** attempt, 30))
    return False


def _get_primary_ip() -> str:
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Heartbeat loop
# ---------------------------------------------------------------------------
async def heartbeat_loop(client: httpx.AsyncClient):
    start_time = time.monotonic()
    while not _shutdown.is_set():
        try:
            payload = {
                "agent_id": cfg.AGENT_ID,
                "uptime_seconds": int(time.monotonic() - start_time),
                "process_count": len(psutil.pids()),
                "connection_count": len(psutil.net_connections(kind="inet")),
            }
            resp = await client.post("/agents/heartbeat", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                commands = data.get("commands", [])
                for cmd in commands:
                    await _handle_command(cmd, client)
            else:
                log.warning("Heartbeat failed (%d)", resp.status_code)
        except httpx.RequestError as exc:
            log.warning("Heartbeat error: %s", exc)
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=cfg.HEARTBEAT_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass


async def _handle_command(cmd: dict, client: httpx.AsyncClient):
    command = cmd.get("command", "")
    log.info("Received command: %s", command)
    if command == "capture_forensic":
        snapshot = capture_forensic_snapshot()
        await _upload_forensic(client, snapshot, trigger="remote_command")
    elif command == "update_config":
        params = cmd.get("params", {})
        log.info("Config update requested: %s", params)
        # Could dynamically update intervals, paths, etc.
    elif command == "restart":
        log.info("Restart requested. Exiting for supervisor to restart.")
        _shutdown.set()


# ---------------------------------------------------------------------------
# Event flush loop
# ---------------------------------------------------------------------------
async def event_flush_loop(client: httpx.AsyncClient):
    while not _shutdown.is_set():
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=cfg.EVENT_FLUSH_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        async with _queue_lock:
            if not _event_queue:
                continue
            batch = list(_event_queue)
            _event_queue.clear()

        if batch:
            payload = {"agent_id": cfg.AGENT_ID, "events": batch}
            try:
                resp = await client.post("/agents/events", json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    log.debug("Flushed %d events (accepted=%d)", len(batch), data.get("accepted", 0))
                else:
                    log.warning("Event flush failed (%d): %s", resp.status_code, resp.text)
                    # Re-queue on failure
                    async with _queue_lock:
                        _event_queue.extend(batch)
            except httpx.RequestError as exc:
                log.warning("Event flush error: %s", exc)
                async with _queue_lock:
                    _event_queue.extend(batch)

    # Final flush
    async with _queue_lock:
        batch = list(_event_queue)
        _event_queue.clear()
    if batch:
        try:
            await client.post("/agents/events", json={"agent_id": cfg.AGENT_ID, "events": batch})
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Process monitor
# ---------------------------------------------------------------------------
async def process_monitor_loop():
    global _known_pids
    log.info("Process monitor started (interval=%ds)", cfg.PROCESS_INTERVAL)

    # Initial snapshot
    _known_pids = set(psutil.pids())

    while not _shutdown.is_set():
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=cfg.PROCESS_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - _known_pids
            _known_pids = current_pids

            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    info = proc.as_dict(attrs=[
                        "pid", "name", "cmdline", "username",
                        "cpu_percent", "memory_percent",
                        "create_time", "ppid",
                    ])

                    # Check connections
                    try:
                        conns = proc.net_connections(kind="inet")
                        info["connections"] = [
                            {
                                "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                                "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                                "status": c.status,
                            }
                            for c in conns
                        ]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        info["connections"] = []

                    # Determine severity
                    severity = "info"
                    title = f"New process: {info.get('name', 'unknown')} (PID {pid})"
                    reasons = []

                    proc_name = (info.get("name") or "").lower()
                    cmdline_str = " ".join(info.get("cmdline") or []).lower()

                    # Check known-bad names
                    for bad in cfg.SUSPICIOUS_PROCESS_NAMES:
                        if bad in proc_name or bad in cmdline_str:
                            severity = "high"
                            reasons.append(f"matches suspicious name '{bad}'")
                            break

                    # Check if listening on a port
                    if info["connections"]:
                        listening = [c for c in info["connections"] if c["status"] == "LISTEN"]
                        if listening:
                            severity = max(severity, "medium") if severity == "info" else severity
                            reasons.append(f"listening on {len(listening)} port(s)")

                    # Check for reverse shells (common patterns)
                    shell_patterns = ["/bin/sh -i", "/bin/bash -i", "bash -c 'sh -i", "python -c 'import socket"]
                    # Windows-specific shell indicators
                    if platform.system() == "Windows":
                        shell_patterns.extend([
                            "powershell -enc", "powershell -nop",
                            "powershell -w hidden", "cmd /c powershell",
                            "certutil -urlcache", "bitsadmin /transfer",
                            "mshta", "regsvr32 /s /n /u /i:",
                            "rundll32.exe javascript:",
                        ])
                    for pat in shell_patterns:
                        if pat in cmdline_str:
                            severity = "critical"
                            reasons.append("possible reverse shell")
                            break

                    if reasons:
                        title = f"Suspicious process: {info.get('name', 'unknown')} (PID {pid}) - {', '.join(reasons)}"

                    info["cmdline"] = " ".join(info.get("cmdline") or [])
                    await _enqueue("process", severity, title, info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except Exception as exc:
            log.error("Process monitor error: %s", exc)


# ---------------------------------------------------------------------------
# Network monitor
# ---------------------------------------------------------------------------
async def network_monitor_loop():
    global _known_connections, _known_listeners
    log.info("Network monitor started (interval=%ds)", cfg.NETWORK_INTERVAL)

    # Initial snapshot
    try:
        for c in psutil.net_connections(kind="inet"):
            key = _conn_key(c)
            if c.status == "LISTEN":
                _known_listeners.add(key)
            elif c.raddr and c.status == "ESTABLISHED":
                _known_connections.add(key)
    except (psutil.AccessDenied, OSError):
        pass

    while not _shutdown.is_set():
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=cfg.NETWORK_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        try:
            current_listeners: set[tuple] = set()
            current_connections: set[tuple] = set()

            for c in psutil.net_connections(kind="inet"):
                key = _conn_key(c)
                if c.status == "LISTEN":
                    current_listeners.add(key)
                elif c.raddr and c.status == "ESTABLISHED":
                    current_connections.add(key)

            # New listeners
            new_listeners = current_listeners - _known_listeners
            for lkey in new_listeners:
                pid = lkey[2]
                proc_name = _pid_name(pid)
                details = {
                    "local_addr": f"{lkey[0]}:{lkey[1]}",
                    "pid": pid,
                    "process_name": proc_name,
                    "status": "LISTEN",
                }
                await _enqueue(
                    "network", "medium",
                    f"New listening port: {lkey[0]}:{lkey[1]} ({proc_name})",
                    details,
                )

            # New outbound connections
            new_conns = current_connections - _known_connections
            for ckey in new_conns:
                pid = ckey[2]
                proc_name = _pid_name(pid)
                remote = f"{ckey[3]}:{ckey[4]}" if len(ckey) > 4 else "unknown"

                # Skip private IPs for noise reduction
                if len(ckey) > 3 and _is_private(ckey[3]):
                    continue

                details = {
                    "local_addr": f"{ckey[0]}:{ckey[1]}",
                    "remote_addr": remote,
                    "pid": pid,
                    "process_name": proc_name,
                    "status": "ESTABLISHED",
                }
                await _enqueue(
                    "network", "info",
                    f"New outbound connection: {proc_name} -> {remote}",
                    details,
                )

            _known_listeners = current_listeners
            _known_connections = current_connections

        except (psutil.AccessDenied, OSError) as exc:
            log.debug("Network monitor: %s", exc)
        except Exception as exc:
            log.error("Network monitor error: %s", exc)


def _conn_key(c) -> tuple:
    local_ip = c.laddr.ip if c.laddr else ""
    local_port = c.laddr.port if c.laddr else 0
    remote_ip = c.raddr.ip if c.raddr else ""
    remote_port = c.raddr.port if c.raddr else 0
    pid = c.pid or 0
    return (local_ip, local_port, pid, remote_ip, remote_port)


def _pid_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def _is_private(ip: str) -> bool:
    """Check if IP is RFC1918 / loopback."""
    if ip.startswith("127.") or ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            pass
    if ip == "::1" or ip.startswith("fe80"):
        return True
    return False


# ---------------------------------------------------------------------------
# File Integrity Monitoring (FIM)
# ---------------------------------------------------------------------------
class FIMHandler(FileSystemEventHandler):
    """Watchdog event handler that queues FIM events.

    Watchdog callbacks run in a background thread, so we use the thread-safe
    _enqueue_sync helper that acquires a threading lock instead of the async
    version.
    """

    def __init__(self, is_breadcrumb: bool = False):
        super().__init__()
        self.is_breadcrumb = is_breadcrumb

    def on_any_event(self, event: FileSystemEvent):
        if event.is_directory:
            return
        if event.event_type in ("created", "modified", "deleted", "moved"):
            self._handle_sync(event)

    def _handle_sync(self, event: FileSystemEvent):
        path = event.src_path

        if self.is_breadcrumb:
            details = {
                "file_path": path,
                "event_type": event.event_type,
                "breadcrumb": True,
                "message": "Canary file accessed -- possible attacker reconnaissance",
            }
            _enqueue_sync(
                "breadcrumb", "critical",
                f"BREADCRUMB TRIGGERED: {path} ({event.event_type})",
                details,
            )
            return

        old_hash = _file_hashes.get(path, "")
        new_hash = ""
        if event.event_type != "deleted":
            new_hash = _file_sha256(path)

        details = {
            "file_path": path,
            "event_type": event.event_type,
            "hash_before": old_hash,
            "hash_after": new_hash,
        }

        if new_hash:
            _file_hashes[path] = new_hash

        severity = "low"
        # Platform-aware sensitive file patterns
        sensitive = ["authorized_keys", "id_rsa", "id_ed25519", "known_hosts"]
        if platform.system() == "Windows":
            from config_windows import WINDOWS_SENSITIVE_PATTERNS
            sensitive.extend(WINDOWS_SENSITIVE_PATTERNS)
        else:
            sensitive.extend(["/etc/passwd", "/etc/shadow", "/etc/sudoers", "crontab"])
        if any(s in path for s in sensitive):
            severity = "high"

        _enqueue_sync(
            "fim", severity,
            f"File {event.event_type}: {path}",
            details,
        )


def _start_fim_watcher() -> Optional[Observer]:
    """Start watchdog observer for FIM paths."""
    observer = Observer()
    handler = FIMHandler(is_breadcrumb=False)
    watched = 0

    all_paths = cfg.FIM_PATHS + cfg.FIM_USER_PATHS
    for path in all_paths:
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            is_dir = os.path.isdir(expanded)
            observer.schedule(handler, expanded, recursive=is_dir)
            watched += 1
            log.info("FIM watching: %s (recursive=%s)", expanded, is_dir)

    if watched == 0:
        log.warning("No FIM paths found to watch")
        return None

    observer.start()
    log.info("FIM observer started (%d paths)", watched)
    return observer


# ---------------------------------------------------------------------------
# Deception breadcrumbs
# ---------------------------------------------------------------------------
_BREADCRUMB_CANARY_TOKEN = cfg.AGENT_ID[:8]

_BREADCRUMB_CONTENTS = {
    "credentials": (
        "[default]\n"
        f"aws_access_key_id = AKIA{'CANARY' + _BREADCRUMB_CANARY_TOKEN.upper()[:14]}\n"
        f"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY{'_CANARY_' + _BREADCRUMB_CANARY_TOKEN}\n"
        "region = us-east-1\n"
    ),
    "passwords.txt": (
        "# Internal Service Credentials - DO NOT SHARE\n"
        f"admin portal: admin / Sup3rS3cret_{_BREADCRUMB_CANARY_TOKEN}!2024\n"
        f"database: root / Db_M@ster_{_BREADCRUMB_CANARY_TOKEN}\n"
        f"vpn: sysadmin / VPN_Acc3ss_{_BREADCRUMB_CANARY_TOKEN}\n"
        f"ssh root: R00t_SSH_{_BREADCRUMB_CANARY_TOKEN}#key\n"
    ),
    ".env.production": (
        f"DATABASE_URL=postgresql://admin:Pr0d_DB_{_BREADCRUMB_CANARY_TOKEN}@db.internal:5432/production\n"
        f"STRIPE_SECRET_KEY=sk_live_CANARY{_BREADCRUMB_CANARY_TOKEN}xxxxxxxxxxxx\n"
        f"JWT_SECRET=canary_{_BREADCRUMB_CANARY_TOKEN}_jwt_secret_key\n"
        f"AWS_SECRET_ACCESS_KEY=canary_{_BREADCRUMB_CANARY_TOKEN}_aws_key\n"
        "REDIS_URL=redis://cache.internal:6379\n"
    ),
}


def _deploy_breadcrumbs() -> Optional[Observer]:
    """Create canary files and set up monitoring."""
    if not cfg.BREADCRUMBS_ENABLED:
        log.info("Breadcrumbs disabled")
        return None

    observer = Observer()
    handler = FIMHandler(is_breadcrumb=True)
    deployed = 0

    for bpath in cfg.BREADCRUMB_PATHS:
        expanded = os.path.expanduser(bpath)
        basename = os.path.basename(expanded)

        # Pick content template
        if "credentials" in basename:
            content = _BREADCRUMB_CONTENTS["credentials"]
        elif "password" in basename.lower():
            content = _BREADCRUMB_CONTENTS["passwords.txt"]
        elif ".env" in basename:
            content = _BREADCRUMB_CONTENTS[".env.production"]
        else:
            content = _BREADCRUMB_CONTENTS["passwords.txt"]

        try:
            parent = os.path.dirname(expanded)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, mode=0o700, exist_ok=True)

            # Only create if doesn't exist (don't overwrite real files)
            if not os.path.exists(expanded):
                with open(expanded, "w") as f:
                    f.write(content)
                os.chmod(expanded, 0o644)
                log.info("Breadcrumb deployed: %s", expanded)
            else:
                log.info("Breadcrumb file exists, monitoring: %s", expanded)

            # Watch the parent directory for events on this file
            observer.schedule(handler, parent, recursive=False)
            deployed += 1

        except (OSError, PermissionError) as exc:
            log.warning("Could not deploy breadcrumb %s: %s", expanded, exc)

    if deployed == 0:
        return None

    observer.start()
    log.info("Breadcrumb observer started (%d files)", deployed)
    return observer


# ---------------------------------------------------------------------------
# Forensic capture
# ---------------------------------------------------------------------------
def capture_forensic_snapshot() -> dict:
    """
    Capture a full forensic snapshot of the current machine state.
    Returns a dict suitable for JSON serialization.
    """
    log.info("Capturing forensic snapshot...")
    snapshot: dict = {
        "captured_at": _now_iso(),
        "hostname": cfg.HOSTNAME,
        "os_info": cfg.OS_INFO,
    }

    # 1) All processes (ps aux equivalent)
    processes = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_percent", "status"]):
        try:
            info = proc.info
            info["cmdline"] = " ".join(info.get("cmdline") or [])
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    snapshot["processes"] = processes

    # 2) All network connections (ss -tulpn equivalent)
    connections = []
    try:
        for c in psutil.net_connections(kind="inet"):
            connections.append({
                "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
                "pid": c.pid,
                "process_name": _pid_name(c.pid) if c.pid else "",
            })
    except (psutil.AccessDenied, OSError):
        pass
    snapshot["connections"] = connections

    # 3) Shell history (last 100 lines) - platform aware
    history_lines = []
    if platform.system() == "Windows":
        # PowerShell history
        ps_history = os.path.join(
            os.environ.get("APPDATA", ""),
            "Microsoft", "Windows", "PowerShell", "PSReadLine",
            "ConsoleHost_history.txt"
        )
        history_files = [ps_history]
    else:
        history_files = [
            os.path.expanduser("~/.bash_history"),
            os.path.expanduser("~/.zsh_history"),
        ]
    for hfile in history_files:
        if os.path.exists(hfile):
            try:
                with open(hfile, "r", errors="replace") as f:
                    lines = f.readlines()
                    history_lines.extend(lines[-100:])
            except (OSError, PermissionError):
                pass
    snapshot["shell_history"] = [l.strip() for l in history_lines[-100:]]

    # 4) Scheduled jobs (crontab on Unix, Task Scheduler on Windows)
    if platform.system() == "Windows":
        try:
            from config_windows import get_scheduled_tasks_summary
            snapshot["scheduled_tasks"] = get_scheduled_tasks_summary()
        except Exception:
            snapshot["scheduled_tasks"] = []
        snapshot["crontab"] = ""
    else:
        crontab = ""
        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=5,
            )
            crontab = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        snapshot["crontab"] = crontab
        snapshot["scheduled_tasks"] = []

    # 5) System info
    if platform.system() == "Windows":
        try:
            disk_pct = psutil.disk_usage("C:\\").percent
        except Exception:
            disk_pct = 0
    else:
        disk_pct = psutil.disk_usage("/").percent

    snapshot["system"] = {
        "boot_time": datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc).isoformat(),
        "cpu_count": psutil.cpu_count(),
        "memory_total_mb": round(psutil.virtual_memory().total / (1024 * 1024)),
        "memory_used_pct": psutil.virtual_memory().percent,
        "disk_usage_pct": disk_pct,
        "users_logged_in": [
            {"name": u.name, "terminal": u.terminal or "", "host": u.host}
            for u in psutil.users()
        ],
        "platform": platform.system(),
    }

    # 5b) Windows-specific: Defender status and RDP sessions
    if platform.system() == "Windows":
        try:
            from config_windows import get_defender_status, get_rdp_sessions
            snapshot["windows_defender"] = get_defender_status()
            snapshot["rdp_sessions"] = get_rdp_sessions()
        except Exception:
            snapshot["windows_defender"] = {}
            snapshot["rdp_sessions"] = []

    log.info(
        "Forensic snapshot captured: %d processes, %d connections",
        len(processes), len(connections),
    )
    return snapshot


async def _upload_forensic(client: httpx.AsyncClient, snapshot: dict, trigger: str = "manual"):
    payload = {
        "agent_id": cfg.AGENT_ID,
        "trigger": trigger,
        "data": snapshot,
    }
    try:
        resp = await client.post("/agents/forensic", json=payload)
        if resp.status_code in (200, 201):
            log.info("Forensic snapshot uploaded successfully")
        else:
            log.warning("Forensic upload failed (%d): %s", resp.status_code, resp.text)
    except httpx.RequestError as exc:
        log.warning("Forensic upload error: %s", exc)


# ---------------------------------------------------------------------------
# Windows Event Log Monitor
# ---------------------------------------------------------------------------
async def windows_eventlog_monitor_loop():
    """
    Monitor Windows Security Event Log for suspicious events.
    Only runs on Windows. Requires pywin32.
    """
    if platform.system() != "Windows":
        return

    try:
        import win32evtlog
        import win32evtlogutil
    except ImportError:
        log.warning("pywin32 not installed -- Windows Event Log monitoring disabled.")
        log.warning("Install with: pip install pywin32")
        return

    from config_windows import WINDOWS_SECURITY_EVENTS, LOGON_TYPES

    log.info("Windows Event Log monitor started (interval=30s)")

    # Track the last record we read
    server = "localhost"
    logtype = "Security"
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    # Get initial position to avoid flooding with old events
    handle = win32evtlog.OpenEventLog(server, logtype)
    total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
    win32evtlog.CloseEventLog(handle)
    last_record_number = total_records

    while not _shutdown.is_set():
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=30)
            break
        except asyncio.TimeoutError:
            pass

        try:
            handle = win32evtlog.OpenEventLog(server, logtype)
            current_total = win32evtlog.GetNumberOfEventLogRecords(handle)

            if current_total <= last_record_number:
                win32evtlog.CloseEventLog(handle)
                continue

            # Read new events
            events = []
            while True:
                batch = win32evtlog.ReadEventLog(handle, flags, 0)
                if not batch:
                    break
                for event in batch:
                    if event.RecordNumber <= last_record_number:
                        break
                    event_id = event.EventID & 0xFFFF  # Mask to get base event ID
                    if event_id in WINDOWS_SECURITY_EVENTS:
                        event_info = WINDOWS_SECURITY_EVENTS[event_id]
                        details = {
                            "event_id": event_id,
                            "event_name": event_info["name"],
                            "time_generated": str(event.TimeGenerated),
                            "source": event.SourceName,
                            "computer": event.ComputerName,
                            "strings": list(event.StringInserts) if event.StringInserts else [],
                        }

                        # Extract logon type for 4624/4625
                        if event_id in (4624, 4625) and event.StringInserts:
                            try:
                                logon_type_idx = 8 if event_id == 4624 else 10
                                if len(event.StringInserts) > logon_type_idx:
                                    lt = int(event.StringInserts[logon_type_idx])
                                    details["logon_type"] = LOGON_TYPES.get(lt, f"Unknown({lt})")
                                    # RDP logon is more noteworthy
                                    if lt == 10:
                                        details["rdp_logon"] = True
                            except (ValueError, IndexError):
                                pass

                        await _enqueue(
                            "windows_event", event_info["severity"],
                            f"Windows Event {event_id}: {event_info['name']}",
                            details,
                        )
                else:
                    continue
                break

            last_record_number = current_total
            win32evtlog.CloseEventLog(handle)

        except Exception as exc:
            log.debug("Windows Event Log monitor error: %s", exc)


# ---------------------------------------------------------------------------
# Network Discovery Loop
# ---------------------------------------------------------------------------
async def discovery_loop(client: httpx.AsyncClient):
    """
    Run network discovery on startup and then periodically (default: every 6h).
    Reports discovered assets to the API as events with category="discovery".
    """
    global _discovered_services

    if not cfg.DISCOVERY_ENABLED:
        log.info("Network discovery disabled")
        return

    log.info(
        "Network discovery started (interval=%ds, ports=%s)",
        cfg.DISCOVERY_INTERVAL,
        cfg.DISCOVERY_SCAN_PORTS,
    )

    while not _shutdown.is_set():
        try:
            log.info("Running network discovery scan...")
            services = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: discover_local_network(
                    ports=cfg.DISCOVERY_SCAN_PORTS,
                    timeout=cfg.DISCOVERY_TIMEOUT,
                    max_threads=cfg.DISCOVERY_MAX_THREADS,
                ),
            )
            _discovered_services = services

            if services:
                await _enqueue(
                    "discovery", "info",
                    f"Network discovery: {len(services)} services found",
                    {
                        "services": services,
                        "scan_ports": cfg.DISCOVERY_SCAN_PORTS,
                    },
                )
                log.info("Discovery reported %d services to API", len(services))
            else:
                log.info("Discovery found no services on local network")

        except Exception as exc:
            log.error("Network discovery error: %s", exc)

        # Wait for next interval or shutdown
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=cfg.DISCOVERY_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass


# ---------------------------------------------------------------------------
# System Info Collection
# ---------------------------------------------------------------------------
async def collect_system_info_async() -> dict:
    """Collect system info in a thread executor to avoid blocking."""
    return await asyncio.get_event_loop().run_in_executor(
        None, collect_system_info,
    )


# ---------------------------------------------------------------------------
# Data Sharing Loop
# ---------------------------------------------------------------------------
async def data_sharing_loop(client: httpx.AsyncClient):
    """
    Periodically send anonymized data to the intel hub if sharing is enabled.
    """
    if not cfg.DATA_SHARING_ENABLED:
        return

    log.info(
        "Data sharing enabled (level=%s, interval=%ds)",
        cfg.DATA_SHARING_LEVEL, cfg.DATA_SHARING_INTERVAL,
    )

    while not _shutdown.is_set():
        # Wait first, then share (give discovery time to run)
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=cfg.DATA_SHARING_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass

        try:
            shared_data = anonymize_discovery_data(
                _discovered_services,
                _system_info,
                level=cfg.DATA_SHARING_LEVEL,
            )
            shared_data["agent_id_hash"] = hashlib.sha256(
                cfg.AGENT_ID.encode()
            ).hexdigest()[:16]

            resp = await client.post("/intel/hub/submit", json=shared_data)
            if resp.status_code in (200, 201):
                log.debug("Data sharing: submitted anonymized data")
            else:
                log.debug("Data sharing: submission returned %d", resp.status_code)

        except httpx.RequestError as exc:
            log.debug("Data sharing error: %s", exc)
        except Exception as exc:
            log.error("Data sharing unexpected error: %s", exc)


# ---------------------------------------------------------------------------
# IPC Mode (stdin/stdout JSON-lines for Tauri sidecar)
# ---------------------------------------------------------------------------
_ipc_mode = False
_start_time = time.monotonic()


async def handle_ipc_command(cmd: dict) -> dict:
    """Handle a JSON command from the Tauri host and return a response."""
    global _discovered_services
    command = cmd.get("cmd", "")

    if command == "status":
        uptime = int(time.monotonic() - _start_time)
        try:
            conn_count = len(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, OSError):
            conn_count = -1
        return {
            "type": "status",
            "data": {
                "agent_id": cfg.AGENT_ID,
                "hostname": cfg.HOSTNAME,
                "os_info": cfg.OS_INFO,
                "version": cfg.AGENT_VERSION,
                "uptime_seconds": uptime,
                "process_count": len(psutil.pids()),
                "connection_count": conn_count,
                "event_queue_size": len(_event_queue),
                "known_pids": len(_known_pids),
                "known_connections": len(_known_connections),
                "known_listeners": len(_known_listeners),
                "discovered_services": len(_discovered_services),
            },
        }

    elif command == "discover":
        try:
            services = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: discover_local_network(
                    ports=cfg.DISCOVERY_SCAN_PORTS,
                    timeout=cfg.DISCOVERY_TIMEOUT,
                    max_threads=cfg.DISCOVERY_MAX_THREADS,
                ),
            )
            _discovered_services = services
            return {
                "type": "discovery_result",
                "data": services,
            }
        except Exception as exc:
            return {"type": "error", "data": {"message": str(exc)}}

    elif command == "start_monitoring":
        # Monitoring loops are already running; acknowledge
        return {
            "type": "status",
            "data": {"message": "Monitoring is active", "monitors": [
                "process", "network", "fim", "breadcrumbs",
            ]},
        }

    elif command == "stop":
        log.info("IPC: stop command received")
        _shutdown.set()
        return {"type": "status", "data": {"message": "Shutting down"}}

    elif command == "get_system_info":
        info = await collect_system_info_async()
        return {"type": "system_info", "data": info}

    elif command == "get_events":
        # Return recent events from the queue (non-destructive peek)
        async with _queue_lock:
            events = list(_event_queue)
        return {"type": "events", "data": events}

    elif command == "forensic_snapshot":
        snapshot = capture_forensic_snapshot()
        return {"type": "forensic", "data": snapshot}

    else:
        return {"type": "error", "data": {"message": f"Unknown command: {command}"}}


def _ipc_write(data: dict):
    """Write a JSON line to stdout for the Tauri host to read."""
    try:
        line = json.dumps(data, default=str) + "\n"
        sys.stdout.write(line)
        sys.stdout.flush()
    except (BrokenPipeError, OSError):
        _shutdown.set()


async def ipc_stdin_loop():
    """Read JSON commands from stdin and write responses to stdout."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )

    # Send a ready signal so Tauri knows the agent is up
    _ipc_write({"type": "ready", "data": {
        "agent_id": cfg.AGENT_ID,
        "hostname": cfg.HOSTNAME,
        "version": cfg.AGENT_VERSION,
    }})

    while not _shutdown.is_set():
        try:
            line = await reader.readline()
            if not line:
                log.info("IPC: stdin closed, shutting down")
                _shutdown.set()
                break
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue
            try:
                cmd = json.loads(line_str)
            except json.JSONDecodeError:
                _ipc_write({"type": "error", "data": {"message": "Invalid JSON"}})
                continue
            response = await handle_ipc_command(cmd)
            _ipc_write(response)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("IPC loop error: %s", exc)
            _ipc_write({"type": "error", "data": {"message": str(exc)}})

    transport.close()


async def ipc_event_forwarder():
    """In IPC mode, forward queued events to stdout as they arrive."""
    while not _shutdown.is_set():
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=2.0)
            break
        except asyncio.TimeoutError:
            pass

        async with _queue_lock:
            if _event_queue:
                events = list(_event_queue)
                # Don't clear -- let the normal flush loop handle API submission
                # Just forward copies to Tauri for real-time display
            else:
                events = []

        for event in events:
            _ipc_write({"type": "event", "data": event})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main(ipc: bool = False):
    global _ipc_mode
    _ipc_mode = ipc

    # In IPC mode, redirect logging to stderr so stdout stays clean for JSON
    if _ipc_mode:
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(logging.Formatter(
            "%(asctime)s [aegis-agent] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logging.root.addHandler(stderr_handler)

    log.info("=" * 60)
    log.info("AEGIS EDR-lite Agent v%s", cfg.AGENT_VERSION)
    log.info("Agent ID : %s", cfg.AGENT_ID)
    log.info("Hostname : %s", cfg.HOSTNAME)
    log.info("OS       : %s", cfg.OS_INFO)
    log.info("Mode     : %s", "IPC (Tauri sidecar)" if _ipc_mode else "HTTP (standalone)")
    log.info("API URL  : %s", cfg.AEGIS_API_URL)
    log.info("=" * 60)

    # In IPC mode, API key is optional (agent may run without server connection)
    if not _ipc_mode and not cfg.AEGIS_API_KEY:
        log.error("AEGIS_API_KEY is not set. Exiting.")
        sys.exit(1)

    # Show data sharing prompt on first run (skip in IPC mode)
    if not _ipc_mode and not cfg.DATA_SHARING_ENABLED:
        print("\n" + DATA_SHARING_PROMPT + "\n")

    # Collect system information before registration
    global _system_info, _discovered_services
    log.info("Collecting system information...")
    _system_info = await collect_system_info_async()
    log.info(
        "System info: %s %s, %d CPUs, %d MB RAM",
        _system_info.get("os", {}).get("system", "?"),
        _system_info.get("os", {}).get("release", "?"),
        _system_info.get("cpu", {}).get("count_logical", 0),
        _system_info.get("ram", {}).get("total_mb", 0),
    )

    # Run initial network discovery before registration (so results are included)
    if cfg.DISCOVERY_ENABLED:
        log.info("Running initial network discovery...")
        try:
            _discovered_services = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: discover_local_network(
                    ports=cfg.DISCOVERY_SCAN_PORTS,
                    timeout=cfg.DISCOVERY_TIMEOUT,
                    max_threads=cfg.DISCOVERY_MAX_THREADS,
                ),
            )
            log.info("Initial discovery found %d services", len(_discovered_services))
        except Exception as exc:
            log.warning("Initial discovery failed: %s", exc)

    client = _build_client()

    # Register with backend (includes system_info and discovered_services)
    # In IPC mode, registration failure is non-fatal (agent can still serve local data)
    if cfg.AEGIS_API_KEY:
        registered = await register(client)
        if not registered and not _ipc_mode:
            log.error("Failed to register with AEGIS API after retries. Exiting.")
            sys.exit(1)
        elif not registered:
            log.warning("Could not register with API, running in local-only IPC mode")
    elif _ipc_mode:
        log.info("No API key set, running in local-only IPC mode")

    # Start FIM watcher
    fim_observer = _start_fim_watcher()

    # Deploy and monitor breadcrumbs
    breadcrumb_observer = _deploy_breadcrumbs()

    # Hash initial state of FIM paths
    for path in cfg.FIM_PATHS + cfg.FIM_USER_PATHS:
        expanded = os.path.expanduser(path)
        if os.path.isfile(expanded):
            _file_hashes[expanded] = _file_sha256(expanded)
        elif os.path.isdir(expanded):
            try:
                for entry in os.scandir(expanded):
                    if entry.is_file():
                        _file_hashes[entry.path] = _file_sha256(entry.path)
            except (OSError, PermissionError):
                pass

    # Signal handlers (SIGTERM not available on Windows)
    def _signal_handler(signum, frame):
        log.info("Signal %s received, shutting down...", signum)
        _shutdown.set()

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    # Launch coroutines
    tasks = [
        asyncio.create_task(heartbeat_loop(client), name="heartbeat"),
        asyncio.create_task(event_flush_loop(client), name="event_flush"),
        asyncio.create_task(process_monitor_loop(), name="process_monitor"),
        asyncio.create_task(network_monitor_loop(), name="network_monitor"),
    ]

    # Network discovery loop (periodic re-scan)
    if cfg.DISCOVERY_ENABLED:
        tasks.append(
            asyncio.create_task(discovery_loop(client), name="discovery"),
        )

    # Data sharing loop (opt-in)
    if cfg.DATA_SHARING_ENABLED:
        tasks.append(
            asyncio.create_task(data_sharing_loop(client), name="data_sharing"),
        )

    # Windows-only: Event Log monitor
    if platform.system() == "Windows":
        tasks.append(
            asyncio.create_task(windows_eventlog_monitor_loop(), name="win_eventlog"),
        )

    # IPC mode: listen for commands on stdin and forward events to stdout
    if _ipc_mode:
        tasks.append(
            asyncio.create_task(ipc_stdin_loop(), name="ipc_stdin"),
        )
        tasks.append(
            asyncio.create_task(ipc_event_forwarder(), name="ipc_events"),
        )

    log.info("All monitors started. Waiting for shutdown signal...")
    await _shutdown.wait()

    log.info("Shutting down monitors...")
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    # Stop observers
    if fim_observer:
        fim_observer.stop()
        fim_observer.join(timeout=5)
    if breadcrumb_observer:
        breadcrumb_observer.stop()
        breadcrumb_observer.join(timeout=5)

    await client.aclose()
    log.info("AEGIS agent stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS EDR-lite Agent")
    parser.add_argument(
        "--ipc",
        action="store_true",
        help="Run in IPC mode: read JSON commands from stdin, write JSON responses to stdout. "
             "Used when launched as a Tauri sidecar.",
    )
    args = parser.parse_args()
    asyncio.run(main(ipc=args.ipc))
