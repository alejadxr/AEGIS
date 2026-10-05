"""
IOC connection monitor — the one piece of network telemetry AEGIS can honestly
collect on this deployment, and the only detection path for a callback that
never reaches a log file.

WHY THIS EXISTS (and why it is not ndr_lite)
--------------------------------------------
`ndr_lite` and `dns_monitor` in this package are both inert on the Mac Pro:

  * ndr_lite's only data source is `psutil.net_connections()`, which on macOS
    requires root. cayde6-api runs under PM2 as an unprivileged user (uid 501), so both
    the `kind="inet"` call and its `kind="tcp"` fallback raise AccessDenied and
    `_snapshot_connections()` returns before taking a sample — every 5s,
    forever. Verified against prod. `host_monitor`'s own network section
    (tcp_connect / network_anomaly, host_monitor.py:516) dies on the same call
    and swallows it into `logger.debug`.
  * dns_monitor tails a DNS query log; all six paths it probes
    (/var/log/syslog, messages, dnsmasq.log, pihole.log, named/queries.log,
    unbound.log) are Linux-only and absent on macOS, so it falls into
    `_periodic_check()`, which only reloads threat intel and emits nothing.

Neither can be "wired up" — there is nothing at the other end of the wire.
This module therefore uses `netstat -an`, which works unprivileged on macOS
(and is the tool CLAUDE.md mandates on the Mac Pro, where lsof is banned for
hanging), and psutil on Linux where it is permitted.

WHAT IT PUBLISHES, AND WHAT IT DELIBERATELY DOES NOT
----------------------------------------------------
It publishes an event **only** when the remote peer of a connection is a known
indicator of compromise. Generic traffic is never published, for two reasons:

  1. Blast radius. AEGIS blocks autonomously. `sigma_exfil_uncommon_port`
     matches `protocol=tls, target_type=external` with a threshold of 5 in
     300s grouped by source_ip — feeding it ordinary outbound HTTPS would open
     an incident against, and potentially firewall off, OpenRouter, Cloudflare
     or a Tailscale DERP relay. A detection platform that blocks its own
     dependencies is worse than one that misses a beacon.
  2. The sliding window. correlation_engine keeps 10 000 events. A busy host
     holds >100 connections; emitting one event per connection per poll would
     evict real attack telemetry within minutes.

The IOC set is read from the loaded rules themselves (every `source_ip` /
`destination_ip` equality list on a `network_connection` or `connection` rule)
plus the `ip` rows of `threat_intel`. It is deliberately NOT a second hardcoded
copy of the indicator list: this codebase has already shipped an alias table
whose second half was missing and a safelist read from the wrong source, and a
duplicated IOC list is the same failure waiting to happen. Add an indicator to
a rule and this collector starts watching for it.

KNOWN LIMITATION, stated plainly: this is a sampler, not a packet capture. A
single-shot callback that opens and closes between two polls is not seen. It
catches sustained or repeated connections — which is what beaconing is — and
misses one-shot exfil. `pcap` on the Pi gateway is the honest fix for that and
is not attempted here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import re
import subprocess
import time
from datetime import datetime
from typing import Iterable, Optional

logger = logging.getLogger("aegis.connection_monitor")

# Bus topic. Deliberately NOT the bare "network_connection" rule type: that
# topic is auto-subscribed by correlation_engine._collect_subscribed_types() to
# the UNGATED _on_event handler. Publishing here instead binds to the safelist-
# gated _on_connection_event, mirroring the dos.* convention.
TOPIC = "network.connection"

# Seconds a given (peer_ip, peer_port, direction) stays deduped. One callback is
# one event, not one per poll.
DEFAULT_COOLDOWN_SECONDS = 300

# macOS netstat renders addresses as `1.2.3.4.443` / `fe80::1%lo0.443` — the
# port is joined by a dot, not a colon.
_NETSTAT_ROW = re.compile(
    r"^(?P<proto>tcp[46]?|udp[46]?)\s+\S+\s+\S+\s+"
    r"(?P<local>\S+)\s+(?P<remote>\S+)(?:\s+(?P<state>\S+))?\s*$"
)


def _split_host_port(token: str) -> tuple[Optional[str], Optional[int]]:
    """Split a netstat address token into (host, port).

    Handles `1.2.3.4.443`, `*.8000`, `fe80::1%lo0.443` and `*.*`.
    """
    if not token or token == "*.*":
        return (None, None)
    host, _, port = token.rpartition(".")
    if not host:
        return (None, None)
    if port == "*":
        return (host if host != "*" else None, None)
    try:
        return (host if host != "*" else None, int(port))
    except ValueError:
        return (host if host != "*" else None, None)


# Tailscale / RFC6598 shared address space. Checked explicitly because
# ipaddress.is_private does NOT cover it on Python 3.13+ (CPython reclassified
# 100.64.0.0/10 as non-private), and the entire wilab estate — Mac Pro, Pi, Mac
# Mini, MacBook Pro, Kali — lives in this range. Mirrors the same explicit check
# in correlation_engine._is_internal_ip.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _is_routable_peer(ip: Optional[str]) -> bool:
    """True for a peer worth checking against the IOC set.

    Loopback/private/link-local/CGNAT peers are estate-internal; an IOC will
    never legitimately live there, and matching one would mean the IOC list is
    wrong rather than that we found a C2.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast:
        return False
    if addr.is_unspecified or addr.is_reserved:
        return False
    if addr.version == 4 and addr in _CGNAT_V4:
        return False
    return True


class ConnectionMonitor:
    """Polls established connections and reports IOC peers only."""

    def __init__(self, event_bus=None):
        self._event_bus = event_bus
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._cooldown_seconds = DEFAULT_COOLDOWN_SECONDS
        self._last_emit: dict[tuple, float] = {}
        self._ioc_ips: set[str] = set()
        self._stats = {
            "polls": 0,
            "poll_errors": 0,
            "connections_sampled": 0,
            "ioc_hits": 0,
            "events_published": 0,
            "ioc_set_size": 0,
            "collector": None,
            "started_at": None,
            "last_poll_at": None,
            "unavailable_reason": None,
        }

    def register_event_bus(self, bus) -> None:
        self._event_bus = bus

    # ------------------------------------------------------------------
    # IOC set — derived from the rules, never a second hardcoded copy
    # ------------------------------------------------------------------

    def load_ioc_ips(self, rules: Optional[Iterable[dict]] = None) -> set[str]:
        """Collect every literal IP an enabled rule matches on source/destination.

        Only equality clauses are read (`source_ip: [...]`, `destination_ip:
        "..."`). Substring and numeric operators describe shapes, not
        indicators, so they are ignored.
        """
        ips: set[str] = set()
        if rules is None:
            try:
                from app.services.correlation_engine import correlation_engine
                rules = correlation_engine._rules
            except Exception as exc:
                logger.warning(f"connection_monitor could not read rules: {exc}")
                rules = []
        for rule in rules or []:
            if not rule.get("enabled", True):
                continue
            cond = rule.get("condition") or {}
            if cond.get("event_type") not in ("network_connection", "connection"):
                continue
            filt = cond.get("filter") or {}
            for field in ("source_ip", "destination_ip", "remote_ip"):
                value = filt.get(field)
                if value is None:
                    continue
                candidates = value if isinstance(value, (list, tuple)) else [value]
                for candidate in candidates:
                    if not isinstance(candidate, str):
                        continue
                    try:
                        ipaddress.ip_address(candidate)
                    except ValueError:
                        continue  # a hostname or shape, not an indicator
                    ips.add(candidate)
        self._ioc_ips = ips
        self._stats["ioc_set_size"] = len(ips)
        return ips

    async def load_threat_intel_ips(self) -> int:
        """Fold the `ip` rows of threat_intel into the IOC set. Best effort."""
        added = 0
        try:
            from sqlalchemy import select

            from app.database import async_session
            from app.models.threat_intel import ThreatIntel

            async with async_session() as db:
                result = await db.execute(
                    select(ThreatIntel).where(ThreatIntel.ioc_type == "ip")
                )
                for ioc in result.scalars().all():
                    value = (ioc.ioc_value or "").strip()
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    if value not in self._ioc_ips:
                        self._ioc_ips.add(value)
                        added += 1
        except Exception as exc:
            logger.info(f"connection_monitor threat_intel unavailable: {exc}")
        self._stats["ioc_set_size"] = len(self._ioc_ips)
        return added

    # ------------------------------------------------------------------
    # Collectors
    # ------------------------------------------------------------------

    def collect(self) -> list[dict]:
        """Return the current connection list as dicts, or [] if unavailable.

        Each entry: local_ip, local_port, remote_ip, remote_port, protocol,
        state, direction, process.
        """
        system = platform.system()
        if system == "Darwin":
            self._stats["collector"] = "netstat"
            return self._collect_netstat()
        self._stats["collector"] = "psutil"
        conns = self._collect_psutil()
        if conns is None:
            # Linux without permission — netstat/ss is no more privileged, but
            # /proc based netstat often still works for our own sockets.
            self._stats["collector"] = "netstat"
            return self._collect_netstat()
        return conns

    def _collect_netstat(self) -> list[dict]:
        try:
            proc = subprocess.run(
                ["netstat", "-an"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._stats["poll_errors"] += 1
            self._stats["unavailable_reason"] = f"netstat failed: {exc}"
            return []
        if proc.returncode != 0 and not proc.stdout:
            self._stats["poll_errors"] += 1
            self._stats["unavailable_reason"] = (
                f"netstat rc={proc.returncode}: {(proc.stderr or '').strip()[:120]}"
            )
            return []
        return self._parse_netstat(proc.stdout)

    def _parse_netstat(self, output: str) -> list[dict]:
        """Parse `netstat -an` output. Two passes: listeners, then peers.

        netstat does not say which side opened a connection. A local port that
        also appears as a LISTEN socket means the peer dialled us (inbound);
        otherwise the local port is ephemeral and we dialled out (outbound).
        """
        rows = []
        listen_ports: set[int] = set()
        for line in output.splitlines():
            match = _NETSTAT_ROW.match(line.strip())
            if not match:
                continue
            state = (match.group("state") or "").upper()
            local_ip, local_port = _split_host_port(match.group("local"))
            remote_ip, remote_port = _split_host_port(match.group("remote"))
            if state == "LISTEN":
                if local_port:
                    listen_ports.add(local_port)
                continue
            # No peer address: an unconnected UDP socket (`*.*`) or a bound
            # listener netstat did not label LISTEN. Not a connection.
            if not remote_ip:
                if local_port:
                    listen_ports.add(local_port)
                continue
            rows.append(
                {
                    "protocol": "tcp" if match.group("proto").startswith("tcp") else "udp",
                    "state": state or "NONE",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process": None,
                }
            )
        for row in rows:
            row["direction"] = (
                "inbound" if row["local_port"] in listen_ports else "outbound"
            )
        return rows

    def _collect_psutil(self) -> Optional[list[dict]]:
        """psutil collector for Linux. Returns None when not permitted."""
        try:
            import psutil
        except ImportError:
            self._stats["unavailable_reason"] = "psutil not installed"
            return None
        try:
            raw = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            self._stats["unavailable_reason"] = f"psutil AccessDenied: {exc}"
            return None
        except Exception as exc:
            self._stats["poll_errors"] += 1
            self._stats["unavailable_reason"] = f"psutil error: {exc}"
            return None

        listen_ports = {
            c.laddr.port
            for c in raw
            if c.status == "LISTEN" and c.laddr
        }
        rows = []
        for conn in raw:
            if conn.status == "LISTEN" or not conn.raddr:
                continue
            local_port = conn.laddr.port if conn.laddr else None
            process = None
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid).name()
                except Exception:
                    process = None
            rows.append(
                {
                    "protocol": "tcp" if conn.type == 1 else "udp",
                    "state": conn.status or "NONE",
                    "local_ip": conn.laddr.ip if conn.laddr else None,
                    "local_port": local_port,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "process": process,
                    "direction": "inbound" if local_port in listen_ports else "outbound",
                }
            )
        return rows

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def match_iocs(self, connections: Iterable[dict]) -> list[dict]:
        """Return the subset of connections whose remote peer is an IOC."""
        hits = []
        for conn in connections:
            remote_ip = conn.get("remote_ip")
            if not _is_routable_peer(remote_ip):
                continue
            if remote_ip in self._ioc_ips:
                hits.append(conn)
        return hits

    def build_event(self, conn: dict) -> dict:
        """Translate a connection row into an event the rules actually read.

        On `source_ip`: for an OUTBOUND callback the peer did not initiate the
        connection, yet it is set to the peer here. That is deliberate, and it
        is the whole reason this path produces an incident at all:

          * correlation_engine._on_rule_triggered drops any firing whose
            source_ip is internal (`if not source_ip or _is_internal_ip(...)`),
            unconditionally and before confidence factors. The source of an
            outbound callback is always our own host, so naming it as source_ip
            would make every outbound C2 rule silently unfireable.
          * source_ip is also what the incident is opened against and what the
            responder blocks. For a confirmed C2 callback the entity to name
            and to firewall is the C2 server — not the victim host.

        `destination_ip` carries the same peer so the outbound IOC rules
        (`sigma_supply_axios_sfrclak_c2` et al) match on their own terms, and
        `local_ip`/`local_port` preserve which of our hosts and services was
        talking so the incident is still actionable.

        `target_type` is deliberately absent. Setting it to "internal" for an
        inbound connection is semantically right but would make
        `lateral_movement` (threshold 10, group_by source_ip, filter
        target_type=internal) fire on any busy external client. A field is only
        populated here when this collector can state it truthfully AND the
        rules that read it mean what this event means.
        """
        peer = conn.get("remote_ip")
        return {
            "event_type": "network_connection",
            "source_ip": peer,
            "destination_ip": peer,
            "destination_port": conn.get("remote_port"),
            "remote_ip": peer,
            "remote_port": conn.get("remote_port"),
            "direction": conn.get("direction", "outbound"),
            "protocol": conn.get("protocol", "tcp"),
            "connection_state": conn.get("state"),
            "local_ip": conn.get("local_ip"),
            "local_port": conn.get("local_port"),
            "process_name": conn.get("process"),
            "severity": "critical",
            "source": "connection_monitor",
            "detection": "ioc_peer_match",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _should_emit(self, conn: dict, now: Optional[float] = None) -> bool:
        if now is None:
            now = time.monotonic()
        key = (
            conn.get("remote_ip"),
            conn.get("remote_port"),
            conn.get("direction"),
        )
        last = self._last_emit.get(key)
        if last is not None and now - last < self._cooldown_seconds:
            return False
        self._last_emit[key] = now
        return True

    async def poll_once(self) -> list[dict]:
        """One sample. Returns the events published."""
        self._stats["polls"] += 1
        self._stats["last_poll_at"] = datetime.utcnow().isoformat()
        connections = self.collect()
        self._stats["connections_sampled"] += len(connections)
        published = []
        for conn in self.match_iocs(connections):
            self._stats["ioc_hits"] += 1
            if not self._should_emit(conn):
                continue
            event = self.build_event(conn)
            published.append(event)
            self._stats["events_published"] += 1
            logger.warning(
                "IOC connection observed: %s %s:%s (local %s:%s, proc=%s)",
                event["direction"],
                event["destination_ip"],
                event["destination_port"],
                event["local_ip"],
                event["local_port"],
                event["process_name"],
            )
            if self._event_bus:
                try:
                    await self._event_bus.publish(TOPIC, event, priority=0)
                except Exception as exc:
                    logger.error(f"connection_monitor publish failed: {exc}")
        return published

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, interval_seconds: int = 5) -> None:
        if self._running:
            logger.warning("connection_monitor already running")
            return
        self.load_ioc_ips()
        await self.load_threat_intel_ips()
        if not self._ioc_ips:
            logger.warning(
                "connection_monitor started with an empty IOC set — nothing to match"
            )
        probe = self.collect()
        if not probe and self._stats["unavailable_reason"]:
            logger.error(
                "connection_monitor cannot read connections on this host (%s); "
                "not starting the poll loop",
                self._stats["unavailable_reason"],
            )
            return
        self._running = True
        self._stats["started_at"] = datetime.utcnow().isoformat()
        self._task = asyncio.create_task(
            self._loop(interval_seconds), name="connection_monitor"
        )
        logger.info(
            "connection_monitor started (collector=%s, interval=%ss, %d IOC IPs)",
            self._stats["collector"],
            interval_seconds,
            len(self._ioc_ips),
        )

    async def _loop(self, interval_seconds: int) -> None:
        reload_every = 60  # polls between IOC-set refreshes
        counter = 0
        try:
            while self._running:
                try:
                    await self.poll_once()
                except Exception as exc:
                    self._stats["poll_errors"] += 1
                    logger.error(f"connection_monitor poll error: {exc}")
                counter += 1
                if counter >= reload_every:
                    counter = 0
                    self.load_ioc_ips()
                    await self.load_threat_intel_ips()
                await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None
        logger.info("connection_monitor stopped")

    def get_stats(self) -> dict:
        return {**self._stats, "is_running": self._running}


# Singleton
connection_monitor = ConnectionMonitor()
