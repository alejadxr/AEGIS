"""
Host self-monitoring service for EDR.

Uses psutil to collect process and network telemetry from the host
AEGIS runs on, feeding data into the same agent_events pipeline as
external Rust agents. This means the host is auto-protected without
needing any external agent installation.

Includes:
  - Process start/stop tracking
  - Suspicious process flagging (nc, nmap, hydra, mimikatz, etc.)
  - File Integrity Monitoring (FIM) via watchdog
  - Network anomaly detection (C2/scanner beaconing)
  - Event bus publishing for WebSocket streaming
"""

import asyncio
import logging
import os
import platform
import socket
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil
from sqlalchemy import select
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from app.database import async_session
from app.core.events import event_bus
from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, AgentStatus,
    EventCategory, EventSeverity,
)
from app.models.client import Client

logger = logging.getLogger("aegis.host_monitor")

import socket as _socket
AGENT_ID = f"aegis-{_socket.gethostname().lower().replace('.local','').replace(' ','-')}"
INTERVAL_SECONDS = 30

# Processes that are suspicious when seen on a production host
SUSPICIOUS_PROCESSES: dict[str, str] = {
    "nc": "high",
    "ncat": "high",
    "socat": "high",
    "nmap": "medium",
    "masscan": "medium",
    "hydra": "high",
    "sqlmap": "high",
    "mimikatz": "critical",
    "base64": "medium",
    "msfconsole": "critical",
    "msfvenom": "critical",
    "john": "high",
    "hashcat": "high",
    "responder": "high",
    "ettercap": "high",
    "tcpdump": "medium",
    "xmrig": "critical",
    "minerd": "critical",
    "cgminer": "critical",
    "cryptonight": "critical",
}

# Directories to monitor for file integrity
FIM_PATHS = ["/etc/", os.path.expanduser("~/.ssh/"), "/tmp/", "/var/log/"]

# Network anomaly: max outbound connections per process per window
NET_ANOMALY_WINDOW_SECS = 30
NET_ANOMALY_THRESHOLD = 20


# -----------------------------------------------------------------------
# FIM handler (watchdog -> asyncio bridge)
# -----------------------------------------------------------------------

class _FIMHandler(FileSystemEventHandler):
    """Watchdog handler that pushes file events into an asyncio queue."""

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self._queue = queue
        self._loop = loop

    def _push(self, event: FileSystemEvent, kind: str):
        try:
            self._loop.call_soon_threadsafe(
                self._queue.put_nowait,
                {"kind": kind, "path": event.src_path, "is_dir": event.is_directory},
            )
        except Exception:
            pass

    def on_created(self, event: FileSystemEvent):
        self._push(event, "file_create")

    def on_modified(self, event: FileSystemEvent):
        self._push(event, "file_modify")

    def on_deleted(self, event: FileSystemEvent):
        self._push(event, "file_delete")


class HostMonitor:
    """Collects local host telemetry via psutil and writes AgentEvents."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._fim_task: Optional[asyncio.Task] = None
        self._running = False
        # Track known PIDs so we can detect new/terminated processes
        self._known_pids: set[int] = set()
        # FIM
        self._fim_observer: Optional[Observer] = None
        self._fim_queue: Optional[asyncio.Queue] = None
        # Network anomaly tracking: pid -> list of timestamps
        self._conn_tracker: dict[int, list[float]] = defaultdict(list)

    async def start(self):
        if self._running:
            return
        self._running = True
        await self._ensure_agent_registered()
        self._task = asyncio.create_task(self._loop())
        self._start_fim()
        logger.info("Host monitor started (interval=%ds, FIM active)", INTERVAL_SECONDS)

    async def stop(self):
        self._running = False
        if self._fim_observer:
            self._fim_observer.stop()
            self._fim_observer.join(timeout=2)
            self._fim_observer = None
        if self._fim_task:
            self._fim_task.cancel()
            try:
                await self._fim_task
            except asyncio.CancelledError:
                pass
            self._fim_task = None
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Host monitor stopped")

    # ------------------------------------------------------------------
    # FIM (File Integrity Monitoring)
    # ------------------------------------------------------------------

    def _start_fim(self):
        """Start watchdog observer on sensitive directories."""
        loop = asyncio.get_running_loop()
        self._fim_queue = asyncio.Queue()
        handler = _FIMHandler(self._fim_queue, loop)
        self._fim_observer = Observer()
        for path in FIM_PATHS:
            if os.path.isdir(path):
                try:
                    self._fim_observer.schedule(handler, path, recursive=True)
                    logger.info("FIM watching: %s", path)
                except Exception as e:
                    logger.warning("FIM cannot watch %s: %s", path, e)
        self._fim_observer.daemon = True
        self._fim_observer.start()
        self._fim_task = asyncio.create_task(self._fim_consumer())

    async def _fim_consumer(self):
        """Drain the FIM queue and persist events + publish to event_bus."""
        while self._running:
            try:
                item = await asyncio.wait_for(self._fim_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            kind = item["kind"]
            file_path = item["path"]

            severity = EventSeverity.medium
            if "ssh" in file_path.lower():
                severity = EventSeverity.high
            elif file_path.startswith("/etc/"):
                severity = EventSeverity.high
            elif file_path.startswith("/tmp/"):
                severity = EventSeverity.low

            now = datetime.utcnow()
            client_id = await self._get_client_id()
            if not client_id:
                continue

            ev = AgentEvent(
                agent_id=AGENT_ID,
                client_id=client_id,
                category=EventCategory.fim,
                severity=severity,
                title=f"{kind}: {file_path}",
                details={
                    "kind": kind,
                    "path": file_path,
                    "is_directory": item.get("is_dir", False),
                },
                timestamp=now,
            )

            async with async_session() as db:
                db.add(ev)
                await db.commit()

            # Publish to event_bus for WebSocket
            try:
                await event_bus.publish("edr.event", {
                    "type": "fim",
                    "kind": kind,
                    "path": file_path,
                    "severity": severity.value,
                    "agent_id": AGENT_ID,
                    "timestamp": now.isoformat(),
                })
            except Exception as e:
                logger.debug("FIM event_bus publish failed: %s", e)

    async def _get_client_id(self) -> Optional[str]:
        async with async_session() as db:
            result = await db.execute(
                select(EndpointAgent).where(EndpointAgent.id == AGENT_ID)
            )
            agent = result.scalar_one_or_none()
            return agent.client_id if agent else None

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def _ensure_agent_registered(self):
        """Create or update the virtual endpoint_agent row."""
        hostname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()}"

        async with async_session() as db:
            result = await db.execute(
                select(EndpointAgent).where(EndpointAgent.id == AGENT_ID)
            )
            agent = result.scalar_one_or_none()

            # Find the first client to associate with
            client_result = await db.execute(select(Client).limit(1))
            client = client_result.scalar_one_or_none()
            if not client:
                logger.error("No client found — cannot register host monitor agent")
                return

            if agent:
                agent.hostname = hostname
                agent.os_info = os_info
                agent.status = AgentStatus.online
                agent.last_heartbeat = datetime.utcnow()
                agent.agent_version = "host-monitor-1.0"
                agent.node_type = "server"
            else:
                agent = EndpointAgent(
                    id=AGENT_ID,
                    client_id=client.id,
                    hostname=hostname,
                    os_info=os_info,
                    ip_address="127.0.0.1",
                    agent_version="host-monitor-1.0",
                    status=AgentStatus.online,
                    last_heartbeat=datetime.utcnow(),
                    config={},
                    node_type="server",
                    tags=["host-monitor", "auto"],
                )
                db.add(agent)

            await db.commit()
            logger.info(
                "Host monitor agent registered: id=%s hostname=%s client=%s",
                AGENT_ID, hostname, client.id,
            )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def _loop(self):
        # Seed known PIDs on first run to avoid a flood of "new process" events
        self._known_pids = set(psutil.pids())
        logger.info("Seeded %d known PIDs", len(self._known_pids))

        while self._running:
            try:
                await self._collect()
            except Exception as e:
                logger.error("Host monitor collection error: %s", e)
            await asyncio.sleep(INTERVAL_SECONDS)

    async def _collect(self):
        """Enumerate processes and network connections, write events."""
        current_pids = set(psutil.pids())
        new_pids = current_pids - self._known_pids
        gone_pids = self._known_pids - current_pids

        events: list[AgentEvent] = []
        suspicious_events: list[dict] = []

        # Get client_id from the registered agent
        async with async_session() as db:
            result = await db.execute(
                select(EndpointAgent).where(EndpointAgent.id == AGENT_ID)
            )
            agent = result.scalar_one_or_none()
            if not agent:
                return
            client_id = agent.client_id

            # Update heartbeat
            agent.status = AgentStatus.online
            agent.last_heartbeat = datetime.utcnow()
            await db.commit()

        now = datetime.utcnow()

        # --- New processes ---
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                info = proc.as_dict(attrs=[
                    "pid", "ppid", "name", "exe", "cmdline", "username",
                    "cpu_percent", "memory_percent",
                ])
                proc_name = info.get("name") or "?"
                cmdline = " ".join(info.get("cmdline") or []) or None

                # Check if this is a suspicious process
                proc_name_lower = proc_name.lower()
                severity = EventSeverity.info
                is_suspicious = False
                if proc_name_lower in SUSPICIOUS_PROCESSES:
                    sev_str = SUSPICIOUS_PROCESSES[proc_name_lower]
                    severity = EventSeverity[sev_str]
                    is_suspicious = True

                details = {
                    "kind": "process_start",
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "process_name": proc_name,
                    "process_path": info.get("exe"),
                    "command_line": cmdline,
                    "user": info.get("username"),
                    "cpu_percent": info.get("cpu_percent"),
                    "memory_percent": round(info.get("memory_percent") or 0, 2),
                }

                if is_suspicious:
                    details["suspicious"] = True
                    details["reason"] = f"Known offensive tool: {proc_name_lower}"

                events.append(AgentEvent(
                    agent_id=AGENT_ID,
                    client_id=client_id,
                    category=EventCategory.process,
                    severity=severity,
                    title=f"proc_start: {proc_name} (pid={pid})",
                    details=details,
                    timestamp=now,
                ))

                # Publish process start to event_bus (for chain detector + WebSocket)
                bus_payload = {
                    "type": "process_start",
                    "agent_id": AGENT_ID,
                    "client_id": client_id,
                    "timestamp": now.isoformat(),
                    **details,
                }
                try:
                    await event_bus.publish("edr.process_start", bus_payload)
                    await event_bus.publish("edr.event", bus_payload)
                except Exception as e:
                    logger.debug("event_bus publish failed: %s", e)

                if is_suspicious:
                    susp_payload = {
                        **bus_payload,
                        "severity": severity.value,
                        "reason": details["reason"],
                    }
                    suspicious_events.append(susp_payload)
                    try:
                        await event_bus.publish_high("edr.suspicious_process", susp_payload)
                    except Exception as e:
                        logger.debug("suspicious event_bus publish failed: %s", e)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # --- Terminated processes ---
        for pid in gone_pids:
            details = {"kind": "process_stop", "pid": pid}
            events.append(AgentEvent(
                agent_id=AGENT_ID,
                client_id=client_id,
                category=EventCategory.process,
                severity=EventSeverity.info,
                title=f"proc_stop: pid={pid}",
                details=details,
                timestamp=now,
            ))
            try:
                await event_bus.publish("edr.event", {
                    "type": "process_stop",
                    "agent_id": AGENT_ID,
                    "pid": pid,
                    "timestamp": now.isoformat(),
                })
            except Exception:
                pass

        # --- Network connections (outbound) + anomaly detection ---
        now_ts = time.monotonic()
        try:
            connections = psutil.net_connections(kind="inet")
            for conn in connections[:50]:
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0
                target = f"{remote_ip}:{remote_port}"

                proc_name = None
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    # Track for anomaly detection
                    tracker = self._conn_tracker[conn.pid]
                    tracker.append(now_ts)
                    # Prune old entries
                    cutoff = now_ts - NET_ANOMALY_WINDOW_SECS
                    self._conn_tracker[conn.pid] = [t for t in tracker if t > cutoff]

                    # Check threshold
                    if len(self._conn_tracker[conn.pid]) > NET_ANOMALY_THRESHOLD:
                        anomaly_details = {
                            "kind": "network_anomaly",
                            "pid": conn.pid,
                            "process_name": proc_name,
                            "connections_in_window": len(self._conn_tracker[conn.pid]),
                            "window_seconds": NET_ANOMALY_WINDOW_SECS,
                            "reason": "Excessive outbound connections (possible C2/scanner)",
                        }
                        events.append(AgentEvent(
                            agent_id=AGENT_ID,
                            client_id=client_id,
                            category=EventCategory.network,
                            severity=EventSeverity.high,
                            title=f"net_anomaly: {proc_name or '?'} pid={conn.pid} ({len(self._conn_tracker[conn.pid])} conns/{NET_ANOMALY_WINDOW_SECS}s)",
                            details=anomaly_details,
                            timestamp=now,
                        ))
                        try:
                            await event_bus.publish_high("edr.suspicious_process", {
                                "type": "network_anomaly",
                                "agent_id": AGENT_ID,
                                "severity": "high",
                                "timestamp": now.isoformat(),
                                **anomaly_details,
                            })
                        except Exception:
                            pass
                        # Reset to avoid repeated alerts every cycle
                        self._conn_tracker[conn.pid] = []

                events.append(AgentEvent(
                    agent_id=AGENT_ID,
                    client_id=client_id,
                    category=EventCategory.network,
                    severity=EventSeverity.info,
                    title=f"tcp_connect: {proc_name or '?'} -> {target}",
                    details={
                        "kind": "tcp_connect",
                        "pid": conn.pid,
                        "process_name": proc_name,
                        "target": target,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                    },
                    timestamp=now,
                ))
        except (psutil.AccessDenied, OSError) as e:
            logger.debug("net_connections skipped: %s", e)

        # Update known PIDs
        self._known_pids = current_pids

        # Persist events
        if events:
            async with async_session() as db:
                for ev in events:
                    db.add(ev)
                await db.commit()
            logger.info(
                "Host monitor: %d events (new=%d, gone=%d, suspicious=%d)",
                len(events), len(new_pids), len(gone_pids),
                len(suspicious_events),
            )


host_monitor = HostMonitor()
