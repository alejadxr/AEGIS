"""MikroTik switch health monitor + device inventory.

DIAGNOSTIC ONLY. This module raises *network-health* incidents (a bad cable, a
port stuck at half duplex, a new device on the wire). It must never block an
IP, touch ``firewall_client`` / ``firewall_local`` / guardrails, or trigger any
automatic response: a cabling problem is not an attacker. Its incidents carry
no ``source_ip`` on purpose, so nothing downstream has an address to act on.

Opt-in: with ``AEGIS_SWITCH_URL`` unset, ``start()`` returns without creating a
task and nothing is ever logged or polled (same contract as firewall_sync).

Counters from RouterOS are cumulative since the switch booted, so a large
absolute value is not a new problem. Error/drop conditions therefore look at
the DELTA between two polls; a counter that goes backwards (switch reboot)
resets the baseline instead of producing a negative or huge delta.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from sqlalchemy import select

from app.core import switch_client as sc
from app.database import async_session
from app.models.client import Client
from app.models.incident import Incident

logger = logging.getLogger("aegis.switch_monitor")

POLL_INTERVAL_SECONDS = 60
STARTUP_DELAY_SECONDS = 20

SOURCE = "switch_monitor"

# Thresholds (see module docstring: deltas between polls, not absolute values).
FLAP_WINDOW_SECONDS = 3600
FLAP_LINK_DOWNS = 3          # >= this many new link-downs inside the window
ERRORS_DELTA = 100           # > this between two polls
DROPS_DELTA = 1000           # > this between two polls
GIGABIT_MBPS = 1000
DEGRADED_MBPS = 100          # <= this, after having run at >= 1 Gbps
DEDUP_WINDOW_SECONDS = 6 * 3600
PROBLEM_TTL_SECONDS = 3600   # how long a delta-type problem stays listed after it last fired
HOSTS_SAVE_EVERY_SECONDS = 600
# Inventory hygiene. Phones rotate randomised MACs, so "one incident per new
# MAC, forever" floods the incident table and the inventory file never stops
# growing. A burst of new devices becomes ONE incident, and a device that has
# not been seen for a long time is forgotten.
NEW_DEVICE_INDIVIDUAL_MAX = 3            # more than this in a cycle => one summary incident
INVENTORY_TTL_SECONDS = 30 * 24 * 3600   # forget hosts unseen for this long
INVENTORY_MAX_HOSTS = 5000

OPEN_STATUSES = ("open", "investigating")

# reason -> (severity, human title). State reasons stay listed while true;
# delta reasons expire PROBLEM_TTL_SECONDS after they last fired.
REASONS: dict[str, tuple[str, str]] = {
    "link_flapping": ("high", "link flapping"),
    "half_duplex": ("high", "half duplex"),
    "errors_rising": ("medium", "errors rising"),
    "drops_rising": ("medium", "drops rising"),
    "speed_degraded": ("medium", "speed degraded"),
    "port_down": ("low", "port down"),
}
STATE_REASONS = {"half_duplex", "speed_degraded", "port_down"}

# --- offline OUI -> vendor table ---------------------------------------------
# Best-effort, intentionally small. To extend: add "AA:BB:CC": "Vendor" here
# (uppercase, colon separated, first 3 octets). No network lookups, ever.
OUI_VENDORS: dict[str, str] = {
    "00:00:5E": "IANA (documentacion)",
    "00:15:5D": "Microsoft (Hyper-V)",
    "08:00:27": "VirtualBox",
    # Raspberry Pi Foundation / Trading
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi", "2C:CF:67": "Raspberry Pi",
    # Espressif
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "7C:9E:BD": "Espressif",
    "A4:CF:12": "Espressif", "84:CC:A8": "Espressif", "24:6F:28": "Espressif",
    "3C:71:BF": "Espressif", "5C:CF:7F": "Espressif", "80:7D:3A": "Espressif",
    # MikroTik
    "4C:5E:0C": "MikroTik", "64:D1:54": "MikroTik", "6C:3B:6B": "MikroTik",
    "74:4D:28": "MikroTik", "78:9A:18": "MikroTik", "B8:69:F4": "MikroTik",
    "CC:2D:E0": "MikroTik", "D4:01:C3": "MikroTik", "E4:8D:8C": "MikroTik",
    "2C:C8:1B": "MikroTik", "48:8F:5A": "MikroTik", "DC:2C:6E": "MikroTik",
    # Apple
    "00:03:93": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple", "00:11:24": "Apple",
    "00:16:CB": "Apple", "00:17:F2": "Apple", "00:1B:63": "Apple", "00:1C:B3": "Apple",
    "00:1E:C2": "Apple", "00:1F:5B": "Apple", "3C:07:54": "Apple", "40:6C:8F": "Apple",
    "68:5B:35": "Apple", "78:7B:8A": "Apple", "A4:83:E7": "Apple", "BC:52:B7": "Apple",
    "F0:18:98": "Apple", "F0:99:BF": "Apple", "14:98:77": "Apple", "28:CF:E9": "Apple",
    # Intel
    "00:1B:21": "Intel", "00:1E:64": "Intel", "3C:97:0E": "Intel", "48:51:B7": "Intel",
    "8C:8D:28": "Intel", "A4:4E:31": "Intel", "B4:96:91": "Intel", "34:13:E8": "Intel",
    "7C:5C:F8": "Intel", "F8:63:3F": "Intel",
    # TP-Link
    "50:C7:BF": "TP-Link", "14:CC:20": "TP-Link", "98:DA:C4": "TP-Link",
    "F4:F2:6D": "TP-Link", "EC:08:6B": "TP-Link", "60:E3:27": "TP-Link",
    "18:D6:C7": "TP-Link", "C0:06:C3": "TP-Link",
    # Hewlett Packard
    "00:0B:CD": "Hewlett Packard", "00:1B:78": "Hewlett Packard", "3C:D9:2B": "Hewlett Packard",
    "98:E7:F4": "Hewlett Packard", "10:60:4B": "Hewlett Packard", "94:57:A5": "Hewlett Packard",
    "00:25:B3": "Hewlett Packard",
}
UNKNOWN_VENDOR = "desconocido"


def lookup_vendor(mac: Optional[str]) -> str:
    if not mac:
        return UNKNOWN_VENDOR
    return OUI_VENDORS.get(mac.upper().replace("-", ":")[:8], UNKNOWN_VENDOR)


def hosts_file() -> Path:
    # Env override mirrors BLOCKED_IPS_FILE / SAFELIST_FILE.
    return Path(os.environ.get("AEGIS_SWITCH_HOSTS_FILE")
                or Path.home() / ".aegis" / "switch_hosts.json")


def _atomic_write(path: Path, content: str) -> None:
    """tempfile in the same dir + os.replace: readers never see a torn file.
    (Same technique as ip_blocker.atomic_write_text, kept local so this module
    stays decoupled from the blocking stack.)"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _sum(*vals: Optional[int]) -> Optional[int]:
    present = [v for v in vals if v is not None]
    return sum(present) if present else None


@dataclass
class PortState:
    """What we remember about a port between polls (memory only)."""
    running: Optional[bool] = None
    err_total: Optional[int] = None
    drop_total: Optional[int] = None
    link_downs: Optional[int] = None
    rate_mbps: Optional[int] = None
    full_duplex: Optional[bool] = None
    was_gigabit: bool = False
    down_flag: bool = False
    link_samples: deque = field(default_factory=deque)  # (ts, link_downs)
    view: dict = field(default_factory=dict)             # last public snapshot


@dataclass
class Problem:
    port: str
    reason: str
    severity: str
    detail: str
    first_seen: float
    last_seen: float


class SwitchMonitor:
    def __init__(self, session_factory: Callable = None, client: sc.SwitchClient = None):
        self._session_factory = session_factory or async_session
        self._client = client or sc.switch_client
        self._task: Optional[asyncio.Task] = None
        self._running = False

        self._ports: dict[str, PortState] = {}
        self._problems: dict[tuple[str, str], Problem] = {}
        self._raised_at: dict[tuple[str, str], float] = {}   # (port, reason) -> ts of last incident

        self._hosts: dict[str, dict] = {}        # MAC -> {port, first_seen, last_seen}
        self._visible: set[str] = set()          # MACs in the latest bridge-host poll
        self._inventory_primed = False           # see _update_inventory
        self._last_hosts_save = 0.0

        self.resource: Optional[dict] = None
        self.reachable: Optional[bool] = None
        self.last_poll: Optional[float] = None
        self._loaded = False   # inventory file is read lazily, only when enabled

    # ------------------------------------------------------------ lifecycle
    async def start(self):
        if not sc.is_enabled():
            return  # total no-op: no task, no log
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Switch monitor started (interval: %ss)", POLL_INTERVAL_SECONDS)

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self):
        await asyncio.sleep(STARTUP_DELAY_SECONDS)
        while self._running:
            try:
                await self.run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # a monitor bug must never take the API down
                logger.error("Switch monitor cycle failed: %s", e, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    # ------------------------------------------------------------ one cycle
    async def run_cycle(self, now: Optional[float] = None) -> None:
        if not sc.is_enabled():
            return
        now = time.time() if now is None else now
        if not self._loaded:
            self._loaded = True
            self._load_inventory()

        ifaces = await self._client.get_interfaces()
        if ifaces is None:  # switch unreachable / auth failed: keep old state untouched
            self.reachable = False
            return
        self.reachable = True
        self.last_poll = now

        eth_rows = await self._client.get_ethernet() or []
        eth = {r["name"]: r for r in eth_rows if r.get("name")}
        ports = [i for i in ifaces if i.get("type") == "ether" and i.get("name")]
        monitors = await asyncio.gather(*(self._client.monitor_port(p["name"]) for p in ports))

        for iface, mon in zip(ports, monitors):
            await self._check_port(iface, eth.get(iface["name"], {}), mon, now)

        self.resource = await self._client.get_resource() or self.resource
        self._expire_problems(now)

        hosts = await self._client.get_bridge_hosts()
        if hosts is not None:
            await self._update_inventory(hosts, now)

    # ------------------------------------------------------------ health
    async def _check_port(self, iface: dict, eth: dict, mon: Optional[dict], now: float):
        name = iface["name"]
        st = self._ports.setdefault(name, PortState())
        prev_seen = st.running is not None   # False on the very first sample

        running = iface.get("running")
        disabled = bool(iface.get("disabled"))
        link_downs = iface.get("link_downs")
        err_total = _sum(iface.get("rx_error"), iface.get("tx_error"),
                         eth.get("rx_fcs_error"), eth.get("rx_align_error"))
        drop_total = _sum(iface.get("rx_drop"), iface.get("tx_drop"), iface.get("tx_queue_drop"))
        # Only trust the monitor call when it answered; a failed call must not
        # erase the last known speed/duplex.
        rate = mon.get("rate_mbps") if mon else st.rate_mbps
        full_duplex = mon.get("full_duplex") if mon else st.full_duplex
        if mon and mon.get("status") == "no-link":
            rate, full_duplex = None, None

        true_now: dict[str, str] = {}

        # link_flapping: link-downs gained inside the last hour.
        if link_downs is not None:
            if st.link_samples and link_downs < st.link_samples[-1][1]:
                st.link_samples.clear()  # switch rebooted: counters restarted
            st.link_samples.append((now, link_downs))
            cutoff = now - FLAP_WINDOW_SECONDS
            while len(st.link_samples) > 1 and st.link_samples[1][0] <= cutoff:
                st.link_samples.popleft()
            gained = link_downs - st.link_samples[0][1]
            if gained >= FLAP_LINK_DOWNS:
                true_now["link_flapping"] = f"link-downs +{gained} in the last hour"

        # half_duplex: a live link that is not full duplex.
        if running and full_duplex is False:
            true_now["half_duplex"] = f"negotiated {rate or '?'} Mbps half duplex"

        # errors / drops: deltas between two polls (skipped on a counter reset).
        if prev_seen and err_total is not None and st.err_total is not None \
                and err_total >= st.err_total:
            d = err_total - st.err_total
            if d > ERRORS_DELTA:
                true_now["errors_rising"] = f"+{d} errors since the previous poll"
        if prev_seen and drop_total is not None and st.drop_total is not None \
                and drop_total >= st.drop_total:
            d = drop_total - st.drop_total
            if d > DROPS_DELTA:
                true_now["drops_rising"] = f"+{d} drops since the previous poll"

        # speed_degraded: a port that has run at >= 1 Gbps now at <= 100 Mbps.
        if rate is not None:
            if rate >= GIGABIT_MBPS:
                st.was_gigabit = True
            elif rate <= DEGRADED_MBPS and st.was_gigabit and running:
                true_now["speed_degraded"] = f"was {GIGABIT_MBPS} Mbps, now {rate} Mbps"

        # port_down: it was running, now it is not, and nobody disabled it.
        if st.running is True and running is False and not disabled:
            st.down_flag = True
        if running or disabled:
            st.down_flag = False
        if st.down_flag:
            true_now["port_down"] = "link lost"

        # commit sample
        st.running = running
        st.link_downs = link_downs
        if err_total is not None:
            st.err_total = err_total
        if drop_total is not None:
            st.drop_total = drop_total
        st.rate_mbps, st.full_duplex = rate, full_duplex
        st.view = {
            "name": name, "running": running, "disabled": disabled, "rate": (mon or {}).get("rate"),
            "rate_mbps": rate, "full_duplex": full_duplex, "link_downs": link_downs,
            "errors": err_total, "drops": drop_total,
        }

        # state-type problems vanish as soon as the condition stops holding
        for reason in STATE_REASONS:
            if reason not in true_now:
                self._problems.pop((name, reason), None)

        for reason, detail in true_now.items():
            sev = REASONS[reason][0]
            key = (name, reason)
            p = self._problems.get(key)
            if p:
                p.last_seen, p.detail = now, detail
            else:
                self._problems[key] = Problem(name, reason, sev, detail, now, now)
            await self._raise(name, reason, sev, detail, now)

    def _expire_problems(self, now: float):
        for key, p in list(self._problems.items()):
            if p.reason not in STATE_REASONS and now - p.last_seen > PROBLEM_TTL_SECONDS:
                del self._problems[key]

    # ------------------------------------------------------------ incidents
    async def _raise(self, port: str, reason: str, severity: str, detail: str, now: float):
        key = (port, reason)
        last = self._raised_at.get(key)
        if last is not None and now - last < DEDUP_WINDOW_SECONDS:
            return
        title = f"Switch {port}: {REASONS[reason][1]}"
        description = (f"Network health issue on switch port {port}: {detail}. "
                       "This is a diagnostic (cabling/negotiation), not an attack; "
                       "no automatic response is taken.")
        ok = await self._open_incident(
            title, description, severity,
            {"kind": "switch_health", "port": port, "reason": reason, "detail": detail},
            dedup_open=True)
        if ok is not None:  # created, or an open incident already exists
            self._raised_at[key] = now

    async def _open_incident(self, title: str, description: str, severity: str,
                             raw: dict, dedup_open: bool) -> Optional[bool]:
        """Returns True if created, False if an open duplicate exists, None on failure."""
        try:
            async with self._session_factory() as db:
                if dedup_open:
                    dup = await db.execute(
                        select(Incident.id).where(
                            Incident.source == SOURCE, Incident.title == title,
                            Incident.status.in_(OPEN_STATUSES)).limit(1))
                    if dup.first() is not None:
                        return False
                from app.core.tenancy import primary_client
                client = await primary_client(db)
                if client is None:
                    return None
                db.add(Incident(
                    client_id=client.id, title=title, description=description,
                    severity=severity, status="open", source=SOURCE,
                    ai_analysis={"switch": raw}, raw_alert=raw,
                    detected_at=datetime.utcnow()))
                await db.commit()
                return True
        except Exception as e:
            logger.warning("Switch incident not stored (%s): %s", title, e)
            return None

    # ------------------------------------------------------------ inventory
    def _load_inventory(self):
        try:
            data = json.loads(hosts_file().read_text())
            hosts = data["hosts"]
            if not isinstance(hosts, dict):
                raise ValueError("hosts is not a mapping")
            self._hosts = {m.upper(): h for m, h in hosts.items() if isinstance(h, dict)}
            self._inventory_primed = True
        except FileNotFoundError:
            pass
        except Exception as e:  # corrupt file == no state: re-seed rather than flood
            logger.warning("Switch inventory unreadable, re-seeding silently: %s", e)

    def _prune_inventory(self, now: float, keep: set) -> int:
        """Forget hosts unseen for INVENTORY_TTL_SECONDS and cap the table.

        Timestamps are fixed-format UTC ISO strings, so they compare as text.
        Hosts visible right now are never dropped.
        """
        cutoff = _iso(now - INVENTORY_TTL_SECONDS)
        stale = [m for m, h in self._hosts.items()
                 if m not in keep and str(h.get("last_seen") or "") < cutoff]
        for mac in stale:
            del self._hosts[mac]
        dropped = len(stale)
        overflow = len(self._hosts) - INVENTORY_MAX_HOSTS
        if overflow > 0:
            oldest = sorted((m for m in self._hosts if m not in keep),
                            key=lambda m: str(self._hosts[m].get("last_seen") or ""))[:overflow]
            for mac in oldest:
                del self._hosts[mac]
            dropped += len(oldest)
        if dropped:
            logger.info("Switch inventory: forgot %d stale device(s)", dropped)
        return dropped

    def _save_inventory(self, now: float):
        try:
            _atomic_write(hosts_file(), json.dumps(
                {"version": 1, "hosts": self._hosts}, indent=1, sort_keys=True))
            self._last_hosts_save = now
        except Exception as e:
            logger.warning("Switch inventory not saved: %s", e)

    async def _update_inventory(self, hosts: list[dict], now: float):
        # FIRST-CYCLE RULE (easy to break, do not "simplify"): when there is no
        # persisted inventory (clean first boot, deleted or corrupt file) the
        # bridge table is SEEDED SILENTLY, otherwise every one of the ~70 devices
        # already on the network would fire a "new device" alert at once. Alerts
        # start from the next cycle. An empty first poll does not count as
        # seeded (the bridge table is probably not populated yet).
        seeding = not self._inventory_primed
        seen_now: set[str] = set()
        changed = False
        new_macs: list[tuple[str, str]] = []

        for h in hosts:
            mac, port = h.get("mac"), h.get("port")
            if not mac or h.get("local") is True:   # local=true: the switch's own MACs
                continue
            seen_now.add(mac)
            rec = self._hosts.get(mac)
            if rec is None:
                self._hosts[mac] = {"port": port, "first_seen": _iso(now), "last_seen": _iso(now)}
                changed = True
                if not seeding:
                    new_macs.append((mac, port))
            else:
                rec["last_seen"] = _iso(now)
                if port and rec.get("port") != port:
                    rec["port"] = port
                    changed = True
        self._visible = seen_now

        if seeding and self._hosts:
            self._inventory_primed = True
            changed = True
            logger.info("Switch inventory seeded silently with %d devices", len(self._hosts))

        if len(new_macs) > NEW_DEVICE_INDIVIDUAL_MAX:
            listed = new_macs[:25]
            lines = ", ".join(f"{mac} on {port} ({lookup_vendor(mac)})" for mac, port in listed)
            more = len(new_macs) - len(listed)
            await self._open_incident(
                f"Switch: {len(new_macs)} new devices",
                f"{len(new_macs)} devices appeared on the switch in one poll, first seen {_iso(now)}: "
                f"{lines}{f' and {more} more' if more else ''}. Informational inventory event.",
                "low",
                {"kind": "switch_new_devices", "count": len(new_macs),
                 "devices": [{"mac": mac, "port": port} for mac, port in listed],
                 "seen_at": _iso(now)},
                dedup_open=False)
            new_macs = []
        for mac, port in new_macs:
            vendor = lookup_vendor(mac)
            await self._open_incident(
                f"Switch: new device {mac} on {port}",
                f"New device seen on the switch: MAC {mac} on port {port}, vendor {vendor}, "
                f"first seen {_iso(now)}. Informational inventory event.",
                "low",
                {"kind": "switch_new_device", "mac": mac, "port": port,
                 "vendor": vendor, "seen_at": _iso(now)},
                dedup_open=False)

        if self._prune_inventory(now, keep=seen_now):
            changed = True

        if changed or now - self._last_hosts_save >= HOSTS_SAVE_EVERY_SECONDS:
            self._save_inventory(now)

    # ------------------------------------------------------------ API views
    def status_view(self) -> dict:
        if not sc.is_enabled():
            return {"enabled": False}
        r = self.resource or {}
        total, free = r.get("total_memory"), r.get("free_memory")
        return {
            "enabled": True, "reachable": self.reachable,
            "last_poll": _iso(self.last_poll) if self.last_poll else None,
            "board": r.get("board"), "version": r.get("version"), "uptime": r.get("uptime"),
            "cpu_load": r.get("cpu_load"),
            "memory": {"total": total, "free": free,
                       "used_pct": round(100 * (total - free) / total, 1) if total and free is not None else None},
        }

    def ports_view(self) -> dict:
        if not sc.is_enabled():
            return {"enabled": False}
        counts: dict[str, int] = {}
        for mac in self._visible:
            p = (self._hosts.get(mac) or {}).get("port")
            if p:
                counts[p] = counts.get(p, 0) + 1
        out = []
        for name, st in sorted(self._ports.items()):
            v = dict(st.view)
            v["devices"] = counts.get(name, 0)
            v["problems"] = [
                {"reason": p.reason, "severity": p.severity, "detail": p.detail,
                 "first_seen": _iso(p.first_seen), "last_seen": _iso(p.last_seen)}
                for (pn, _), p in self._problems.items() if pn == name]
            out.append(v)
        return {"enabled": True, "ports": out}

    def devices_view(self) -> dict:
        if not sc.is_enabled():
            return {"enabled": False}
        devs = [{"mac": mac, "port": h.get("port"), "vendor": lookup_vendor(mac),
                 "first_seen": h.get("first_seen"), "last_seen": h.get("last_seen"),
                 "online": mac in self._visible}
                for mac, h in sorted(self._hosts.items())]
        return {"enabled": True, "count": len(devs), "devices": devs}


switch_monitor = SwitchMonitor()
