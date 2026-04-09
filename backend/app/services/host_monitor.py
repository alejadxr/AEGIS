"""
Host self-monitoring service for EDR.

Uses psutil to collect process and network telemetry from the host
AEGIS runs on, feeding data into the same agent_events pipeline as
external Rust agents. This means the host is auto-protected without
needing any external agent installation.
"""

import asyncio
import logging
import platform
import socket
from datetime import datetime
from typing import Optional

import psutil
from sqlalchemy import select

from app.database import async_session
from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, AgentStatus,
    EventCategory, EventSeverity,
)
from app.models.client import Client

logger = logging.getLogger("aegis.host_monitor")

AGENT_ID = "aegis-host-monitor"
INTERVAL_SECONDS = 30


class HostMonitor:
    """Collects local host telemetry via psutil and writes AgentEvents."""

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._running = False
        # Track known PIDs so we can detect new/terminated processes
        self._known_pids: set[int] = set()

    async def start(self):
        if self._running:
            return
        self._running = True
        await self._ensure_agent_registered()
        self._task = asyncio.create_task(self._loop())
        logger.info("Host monitor started (interval=%ds)", INTERVAL_SECONDS)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Host monitor stopped")

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
                cmdline = " ".join(info.get("cmdline") or []) or None
                events.append(AgentEvent(
                    agent_id=AGENT_ID,
                    client_id=client_id,
                    category=EventCategory.process,
                    severity=EventSeverity.info,
                    title=f"proc_start: {info.get('name', '?')} (pid={pid})",
                    details={
                        "kind": "process_start",
                        "pid": pid,
                        "ppid": info.get("ppid"),
                        "process_name": info.get("name"),
                        "process_path": info.get("exe"),
                        "command_line": cmdline,
                        "user": info.get("username"),
                        "cpu_percent": info.get("cpu_percent"),
                        "memory_percent": round(info.get("memory_percent") or 0, 2),
                    },
                    timestamp=now,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # --- Terminated processes ---
        for pid in gone_pids:
            events.append(AgentEvent(
                agent_id=AGENT_ID,
                client_id=client_id,
                category=EventCategory.process,
                severity=EventSeverity.info,
                title=f"proc_stop: pid={pid}",
                details={
                    "kind": "process_stop",
                    "pid": pid,
                },
                timestamp=now,
            ))

        # --- Network connections (new outbound) ---
        try:
            connections = psutil.net_connections(kind="inet")
            # Only track ESTABLISHED outbound connections
            for conn in connections[:50]:  # cap to avoid event flood
                if conn.status != "ESTABLISHED" or not conn.raddr:
                    continue
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_port = conn.laddr.port if conn.laddr else 0
                target = f"{remote_ip}:{remote_port}"

                # Get process name if available
                proc_name = None
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

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
                "Host monitor: %d events (new=%d, gone=%d, net=%d)",
                len(events), len(new_pids), len(gone_pids),
                len(events) - len(new_pids) - len(gone_pids),
            )


host_monitor = HostMonitor()
