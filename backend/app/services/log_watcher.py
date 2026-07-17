"""LogWatcher — ingest PM2 / journalctl log lines, normalize, gate, publish.

v1.6.4 refactor (Opus #3):
- The on-disk PATTERNS list (~30 regexes) was removed.  All pattern → event
  type classification now lives in `app.services.event_normalizer`.  The
  watcher no longer creates incidents from regex hits; it publishes typed
  NormalizedEvent dicts onto `event_bus` under the `log_event` topic and
  `correlation_engine` (the single source of truth for rule firing →
  incident creation → response trigger) consumes them.

What this module still owns (kept):
  * File tailing for PM2 logs (rotation-aware) and journalctl fallback.
  * Internal-line filtering (`_is_internal_line` and friends).
  * Safe-IP gating (`AEGIS_SAFE_IPS`, RFC1918, CGNAT, KNOWN_SAFE_IPS).
  * Inline behavioural detectors that operate ACROSS multiple events and
    are therefore not expressible as a single Sigma rule:
        - brute_force_401 tracker (per-source-IP)
        - high request-rate tracker
        - port-scan tracker (unique ports per IP)
  * Honey-AI breadcrumb scan (`_scan_breadcrumbs`).
  * Tor-exit auto-block escalation in `_create_incident_from_log` (used
    only by the inline behavioural detectors above).
"""

import asyncio
import glob as _glob
import ipaddress as _ipaddress
import logging
import os
import re
import shutil
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional


def _resolve_extra_log_paths(raw: str = "") -> list[str]:
    """Glob-expand AEGIS_EXTRA_LOG_PATHS. Colon-separated, supports * and ?.

    Falls back to os.environ if no value passed in. Returns absolute file
    paths that exist. Empty -> empty list. Used by log_watcher to tail
    external log files (e.g. /web-logs/aegis-feed.jsonl) in addition to
    PM2 stdout/stderr.
    """
    if not raw:
        raw = os.environ.get("AEGIS_EXTRA_LOG_PATHS", "")
    result: list[str] = []
    for pattern in (p.strip() for p in raw.split(":") if p.strip()):
        for fpath in sorted(_glob.glob(os.path.expanduser(pattern))):
            if os.path.isfile(fpath):
                result.append(fpath)
    return result


logger = logging.getLogger("aegis.log_watcher")

# Private/internal IP ranges that should NEVER trigger alerts
# Includes RFC1918 + CGNAT/Tailscale (100.64.0.0/10)
_SAFE_NETWORKS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / Tailscale
]


# Well-known IPs that appear in logs but are NOT attackers
_KNOWN_SAFE_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "9.9.9.9",                       # Quad9 DNS
    "208.67.222.222", "208.67.220.220",  # OpenDNS
})


# Attacker allow-list loaded once at module load from AEGIS_ATTACKER_IPS.
from app.config import settings as _settings

# Import the canonical safe-IP checker that respects AEGIS_SAFE_IPS env var.
try:
    from app.core.attack_detector import _is_safe_ip as _attack_detector_is_safe_ip
except Exception:  # pragma: no cover - defensive
    def _attack_detector_is_safe_ip(ip: str) -> bool:
        return False

_ATTACKER_IPS: set[str] = {
    ip.strip()
    for ip in (_settings.AEGIS_ATTACKER_IPS or "").split(",")
    if ip.strip()
}
if _ATTACKER_IPS:
    logger.info(f"Attacker allow-list loaded: {sorted(_ATTACKER_IPS)}")


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is internal, private, Tailscale, or a known safe IP.

    An IP in `AEGIS_ATTACKER_IPS` always returns False — the explicit
    allow-list wins over the network-range classification.
    """
    if ip in _ATTACKER_IPS:
        return False
    if ip in _KNOWN_SAFE_IPS:
        return True
    try:
        addr = _ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private or any(addr in net for net in _SAFE_NETWORKS)
    except (ValueError, TypeError):
        return False


IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# IPs that belong to AEGIS itself - never create incidents for these
# Extend via AEGIS_INTERNAL_IPS env var (comma-separated)
_internal_default = {"127.0.0.1", "::1", "localhost"}
_internal_extra = os.environ.get("AEGIS_INTERNAL_IPS", "")
if _internal_extra:
    _internal_default.update(ip.strip() for ip in _internal_extra.split(",") if ip.strip())
INTERNAL_IPS = frozenset(_internal_default)

# Substrings that indicate a log line was emitted by AEGIS itself.
# Stops the self-referential feedback loop where the watcher tails its own
# stderr / correlation_engine output and matches its own emissions.
INTERNAL_SOURCE_MARKERS = (
    "aegis.scheduled_scanner",
    "aegis.scanner",
    "[aegis.",
    "[cayde6.",
    "[cayde6.log_watcher]",
    "[aegis.log_watcher]",
    "[aegis.correlation]",
    "[aegis.ai_engine]",
    # Python traceback artifacts from AEGIS crashes
    "sqlalchemy.exc.",
    "ExceptionGroup:",
    "greenlet_spawn",
)


def _extract_ip(line: str) -> Optional[str]:
    match = IP_PATTERN.search(line)
    return match.group(1) if match else None


def _is_internal_line(line: str) -> bool:
    """Return True if the log line is from AEGIS's own infrastructure."""
    for marker in INTERNAL_SOURCE_MARKERS:
        if marker in line:
            return True
    ip = _extract_ip(line)
    if ip and (ip in INTERNAL_IPS or _is_private_ip(ip)):
        return True
    stripped = re.sub(r'^\S+\s+\S+\s+', '', line).strip()
    if not stripped or stripped in ("-", "--", "---"):
        return True
    # v1.6.4: lines whose User-Agent matches a known-good crawler/monitor.
    try:
        from app.core.attack_detector import _check_benign_ua
        m = re.search(r'"([^"]+)"\s*$', line)
        if m and _check_benign_ua(m.group(1)):
            return True
    except Exception:  # pragma: no cover - defensive
        pass
    return False


# Paths that operator dashboards / Next.js assets hit at high frequency.
# Used to gate the inline behavioural detectors (brute_force_401, rate
# tracker, port-scan tracker) so legitimate browser polling cannot flip
# them into alert state.
_SAFE_PATHS = (
    "/dashboard/", "/api/v1/health", "/api/v1/dashboard/", "/ws",
    "/api/v1/nodes/heartbeat", "/api/v1/auth/logout",
    "/api/v1/auth/refresh", "/api/v1/auth/me", "/api/v1/auth/session",
    "/api/v1/me", "/api/v1/version",
    "/api/v1/threats/feed", "/favicon.ico", "/_next/",
)


def _is_safe_path(line: str, event_path: Optional[str] = None) -> bool:
    """True when the request targets an operator-dashboard / asset path.

    Prefers the normalized event's path when available; otherwise falls
    back to substring matching against the raw line.
    """
    if event_path:
        for p in _SAFE_PATHS:
            if p in event_path:
                return True
        return False
    return any(p in line for p in _SAFE_PATHS)


# Hard ceiling on distinct IP keys any per-IP tracker below will hold. Far
# above legitimate concurrent-scanner counts; caps worst-case heap growth if a
# scan storm outruns the periodic idle-key sweep.
_TRACKER_MAX_KEYS = 50_000


class PortScanTracker:
    """Track unique ports accessed per IP to detect port scanning."""

    def __init__(self, window_seconds: int = 60, threshold: int = 10):
        self.window = window_seconds
        self.threshold = threshold
        self._port_hits: dict = defaultdict(deque)  # ip -> deque of (timestamp, port)

    def record(self, ip: str, port: int) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)
        q = self._port_hits[ip]
        while q and q[0][0] < cutoff:
            q.popleft()
        q.append((now, port))
        unique_ports = len(set(p for _, p in q))
        return unique_ports >= self.threshold

    def prune(self, now: Optional[datetime] = None) -> int:
        """Evict IP keys whose deque is empty or whose newest hit is stale.
        Previously empty deques were never removed from the dict, leaking one
        entry per unique scanning IP. Only idle keys are dropped."""
        return _prune_dt_deque_map(
            self._port_hits, self.window, now, ts_getter=lambda item: item[0]
        )


class RateTracker:
    def __init__(self, window_seconds: int = 60, threshold: int = 100):
        self.window = window_seconds
        self.threshold = threshold
        self._requests: dict = defaultdict(deque)

    def record(self, ip: str) -> bool:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)
        q = self._requests[ip]
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        return len(q) >= self.threshold

    def prune(self, now: Optional[datetime] = None) -> int:
        """Evict IP keys whose deque is empty or whose newest request is stale."""
        return _prune_dt_deque_map(self._requests, self.window, now)


def _prune_dt_deque_map(mapping, window_s, now=None, ts_getter=lambda item: item):
    """Evict keys from an `ip -> deque` map keyed by `datetime` timestamps when
    the deque is empty OR its newest entry is older than `now - window_s`.
    Also LRU-caps the map at `_TRACKER_MAX_KEYS` as a burst backstop.
    Returns the number of keys evicted. Only removes IDLE keys."""
    if now is None:
        now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window_s)
    stale = []
    for key, dq in mapping.items():
        if not dq or ts_getter(dq[-1]) < cutoff:
            stale.append(key)
    for key in stale:
        mapping.pop(key, None)
    # Hard cap backstop: drop coldest keys by newest timestamp.
    over = len(mapping) - _TRACKER_MAX_KEYS
    if over > 0:
        _epoch = datetime.min
        victims = sorted(
            mapping.items(),
            key=lambda kv: (ts_getter(kv[1][-1]) if kv[1] else _epoch),
        )[:over]
        for key, _ in victims:
            mapping.pop(key, None)
    return len(stale)


# Fallback port extractor used only when the normalized event does not
# carry a target_port (e.g. raw scanner probe lines).
PORT_PATTERN = re.compile(r':(\d{2,5})\b')


def _normalized_event_to_dict(event) -> dict:
    """Best-effort serialization of a NormalizedEvent for the event bus.

    Tolerates both dataclass-style objects with `to_dict()` and plain
    dicts, so log_watcher doesn't have to import event_normalizer's
    types directly.
    """
    if event is None:
        return {}
    if isinstance(event, dict):
        return event
    if hasattr(event, "to_dict"):
        try:
            return event.to_dict()
        except Exception:
            pass
    # Last-resort attribute scrape.
    keys = (
        "event_type", "source_ip", "target_port", "status_code",
        "method", "path", "username", "raw_line", "severity",
        "threat_type", "pattern_name",
    )
    return {k: getattr(event, k, None) for k in keys}


def _event_attr(event, name, default=None):
    """Read an attribute from a NormalizedEvent or dict uniformly."""
    if event is None:
        return default
    if isinstance(event, dict):
        return event.get(name, default)
    return getattr(event, name, default)


class LogWatcher:
    """Watches PM2 logs, normalizes lines and publishes typed events.

    Responsibilities (single-purpose after the v1.6.4 refactor):
        1. Ingest raw lines from PM2 / journalctl / extra paths.
        2. Filter AEGIS-internal noise.
        3. Delegate pattern classification to `event_normalizer.normalize`.
        4. Gate ONCE on safe IPs (RFC1918, CGNAT, AEGIS_SAFE_IPS).
        5. Publish typed NormalizedEvent on the `log_event` topic so
           that correlation_engine.evaluate (the single source of
           truth for rule firing / incident creation) consumes it.
        6. Run inline behavioural detectors (brute-force / rate /
           port-scan / breadcrumb) — these still create their own
           incidents because they observe ACROSS events.

    Rule firing & incident creation for single-event patterns is owned
    exclusively by `correlation_engine.evaluate` downstream — this class
    no longer contains a PATTERNS list.
    """

    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._sweep_task: Optional[asyncio.Task] = None
        self._running = False
        self._rate_tracker = RateTracker(window_seconds=60, threshold=500)
        self._brute_force_tracker: dict = defaultdict(deque)
        self._brute_force_window = 60  # seconds (matches inline prune below)
        self._port_scan_tracker = PortScanTracker(window_seconds=60, threshold=10)
        self._recent_alerts: deque = deque(maxlen=500)
        # Incident deduplication: (ip, threat_type) -> last_created timestamp
        self._incident_cooldown: dict[str, datetime] = {}
        self._COOLDOWN_SECONDS = 300  # 5 min between incidents for same IP+type

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._watch_loop(), name="log_watcher")
        # Periodic memory-bounding sweep for the per-IP tracker dicts and the
        # incident-cooldown map. These prune deque contents by age on the hot
        # path but never removed the (empty) dict keys, so each leaked one entry
        # per unique attacker IP forever. This sweep evicts idle keys every 60s.
        self._sweep_task = asyncio.create_task(
            self._sweep_loop(), name="log_watcher_sweep"
        )
        logger.info("Log watcher started")

    async def stop(self):
        self._running = False
        for t in (self._task, self._sweep_task):
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        logger.info("Log watcher stopped")

    async def _sweep_loop(self, interval_s: int = 60):
        """Background idle-key eviction for all per-IP tracker dicts."""
        while self._running:
            try:
                await asyncio.sleep(interval_s)
                self._sweep_trackers()
            except asyncio.CancelledError:
                break
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug(f"log_watcher sweep error: {exc}")

    def _sweep_trackers(self, now: Optional[datetime] = None) -> None:
        """Evict idle keys from every per-IP tracker + prune incident cooldown.

        - _brute_force_tracker: `ip -> deque[datetime]`; empty deques (emptied by
          inline age-pruning or q.clear()) previously stayed as dict keys.
        - _rate_tracker / _port_scan_tracker: same empty-key retention pattern.
        - _incident_cooldown: previously only evicted when len > 1024, so entries
          accumulated below that threshold forever. Now proactively evicted.
        Only IDLE keys are removed; active-IP windows are preserved.
        """
        if now is None:
            now = datetime.utcnow()
        # brute-force tracker (60s window, datetime deque of bare timestamps)
        _prune_dt_deque_map(self._brute_force_tracker, self._brute_force_window, now)
        self._rate_tracker.prune(now)
        self._port_scan_tracker.prune(now)
        # incident cooldown: drop entries older than 2x the cooldown window.
        stale_cutoff = now - timedelta(seconds=self._COOLDOWN_SECONDS * 2)
        self._incident_cooldown = {
            k: v for k, v in self._incident_cooldown.items() if v >= stale_cutoff
        }

    async def _watch_loop(self):
        while self._running:
            try:
                await self._tail_pm2_logs()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Log watcher error: {e}. Restarting in 10s...")
                await asyncio.sleep(10)

    async def _tail_pm2_logs(self):
        extra_paths = ["/usr/local/bin"]
        env = os.environ.copy()
        env["PATH"] = ":".join(extra_paths) + ":" + env.get("PATH", "")

        pm2_path = shutil.which("pm2", path=env["PATH"])
        journalctl_path = shutil.which("journalctl")

        from app.config import settings

        if pm2_path:
            await self._tail_pm2_files(settings)
        elif journalctl_path:
            cmd = [
                journalctl_path, "-f", "--no-pager", "-o", "short",
                "-u", "sshd",
                "-u", "aegis-api",
                "-u", "aegis-firewall",
                "-u", "nginx",
                "-u", "apache2",
            ]
            logger.info(f"Starting journalctl log tail (no PM2 found): {' '.join(cmd)}")
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env=env,
                )
            except FileNotFoundError:
                logger.error("journalctl not found. Log watcher disabled.")
                self._running = False
                return

            try:
                while self._running:
                    try:
                        line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=30.0)
                    except asyncio.TimeoutError:
                        continue

                    if not line_bytes:
                        logger.warning("journalctl log stream ended")
                        break

                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if line:
                        await self._process_line(line)
            finally:
                try:
                    proc.terminate()
                    await proc.wait()
                except Exception:
                    pass
        else:
            logger.error("Neither PM2 nor journalctl found. Log watcher disabled.")
            self._running = False

    async def _resolve_pm2_log_paths(self, apps: list) -> dict:
        """Use 'pm2 jlist' to resolve actual log file paths for each app."""
        import json
        import subprocess
        result = {}
        try:
            proc = subprocess.run(
                ["pm2", "jlist"],
                capture_output=True, text=True, timeout=10,
            )
            pm2_info = json.loads(proc.stdout)
            for entry in pm2_info:
                name = entry.get("name", "")
                if name not in apps:
                    continue
                pm2env = entry.get("pm2_env", {})
                out_path = pm2env.get("pm_out_log_path", "")
                err_path = pm2env.get("pm_err_log_path", "")
                result[name] = {"out": out_path, "error": err_path}
        except Exception as exc:
            logger.warning(f"log_watcher: pm2 jlist failed, will fall back to default paths: {exc}")
        return result

    async def _tail_pm2_files(self, settings):
        """File-tail multiplexer for PM2 log files (rotation-aware)."""
        pm2_logs_dir = os.path.expanduser(
            os.environ.get("AEGIS_PM2_LOGS_DIR", "~/.pm2/logs")
        )
        apps = [
            a.strip()
            for a in (settings.AEGIS_MONITORED_APPS or "").split(",")
            if a.strip()
        ]

        pm2_paths = await self._resolve_pm2_log_paths(apps)

        # handle: [fp, inode, path, app_name, stream_kind]
        handles = []
        for app in apps:
            app_paths = pm2_paths.get(app, {})
            for stream in ("out", "error"):
                stream_key = stream
                if app_paths.get(stream_key):
                    fpath = app_paths[stream_key]
                else:
                    suffix = "out" if stream == "out" else "error"
                    fpath = os.path.join(pm2_logs_dir, f"{app}-{suffix}.log")
                if not os.path.exists(fpath):
                    logger.warning(f"log_watcher: PM2 log file not found, skipping: {fpath}")
                    continue
                try:
                    fp = open(fpath, "r", errors="replace")
                    fp.seek(0, 2)  # seek to EOF -> only tail new lines
                    inode = os.stat(fpath).st_ino
                    handles.append([fp, inode, fpath, app, stream])
                except Exception as exc:
                    logger.warning(f"log_watcher: cannot open {fpath}: {exc}")

        extra_paths_raw = getattr(settings, "AEGIS_EXTRA_LOG_PATHS", "") or ""
        for extra_path in _resolve_extra_log_paths(extra_paths_raw):
            try:
                fp = open(extra_path, "r", errors="replace")
                fp.seek(0, 2)
                inode = os.stat(extra_path).st_ino
                handles.append([fp, inode, extra_path, "extra", "out"])
                logger.info(f"log_watcher: tailing extra path: {extra_path}")
            except Exception as exc:
                logger.warning(f"log_watcher: cannot open extra path {extra_path}: {exc}")

        logger.info(
            f"log_watcher file-tail started: {len(handles)} files across {len(apps)} apps"
        )

        if not handles:
            logger.error("log_watcher: no PM2 log files opened — log watching disabled")
            self._running = False
            return

        rotation_check_interval = 30.0
        last_rotation_check = asyncio.get_event_loop().time()

        try:
            while self._running:
                for handle in handles:
                    fp, inode, path, app_name, stream_kind = handle
                    while True:
                        line = fp.readline()
                        if not line:
                            break
                        line = line.rstrip("\n").rstrip("\r")
                        if line:
                            await self._process_line(line, source=app_name)

                await asyncio.sleep(0.5)

                now = asyncio.get_event_loop().time()
                if now - last_rotation_check >= rotation_check_interval:
                    last_rotation_check = now
                    for handle in handles:
                        fp, inode, path, app_name, stream_kind = handle
                        try:
                            new_inode = os.stat(path).st_ino
                        except OSError:
                            continue
                        if new_inode != inode:
                            logger.info(f"log_watcher: rotation detected for {path}, reopening")
                            try:
                                fp.close()
                            except Exception:
                                pass
                            try:
                                new_fp = open(path, "r", errors="replace")
                                handle[0] = new_fp
                                handle[1] = new_inode
                            except Exception as exc:
                                logger.warning(f"log_watcher: reopen failed for {path}: {exc}")
        finally:
            for handle in handles:
                try:
                    handle[0].close()
                except Exception:
                    pass

    # ---------------------------------------------------------------
    # Per-line pipeline
    # ---------------------------------------------------------------
    async def _process_line(self, line: str, source: str = "cayde6-api"):
        """Ingest one raw log line.

        Pipeline order (single responsibility per stage):

            1. Publish the raw line to the `log_line` topic (UI stream).
            2. Drop AEGIS-internal lines.
            3. Normalize via `event_normalizer.normalize(line, source=...)`
               which now owns ALL pattern → event-type classification.
            4. Gate ONCE on safe IPs (RFC1918, CGNAT, AEGIS_SAFE_IPS).
            5. Publish typed NormalizedEvent on the `log_event` topic so
               that correlation_engine.evaluate (the single source of
               truth for rule firing / incident creation) consumes it.
            6. Run inline behavioural detectors (brute-force / rate /
               port-scan / breadcrumb) — these still create their own
               incidents because they observe ACROSS events.
        """
        # 1) Raw stream for the operator's "Live Log" widget.
        try:
            from app.core.events import event_bus
            await event_bus.publish("log_line", {
                "_event_type": "log_line",
                "line": line[:1000],
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception:
            pass  # Never let stream publishing break log processing.

        # 2) Drop internal/own infrastructure noise.
        if _is_internal_line(line):
            return

        # 3) Delegate classification.
        event = None
        try:
            from app.services import event_normalizer
            event = event_normalizer.normalize(line, source=source)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(f"event_normalizer.normalize failed: {exc}")
            event = None

        # If normalizer returned nothing the line is structural (banner,
        # divider, unparseable noise). Nothing else to do.
        if event is None:
            return

        # 4) Single top-of-pipeline IP gate.  Pulls source_ip from the
        #    typed event first, falls back to the raw-line scrape.
        source_ip = _event_attr(event, "source_ip") or _extract_ip(line)

        if source_ip and (source_ip in INTERNAL_IPS or _is_private_ip(source_ip)):
            return
        if source_ip and _attack_detector_is_safe_ip(source_ip):
            logger.debug(f"log_watcher: skipping safe IP {source_ip} (AEGIS_SAFE_IPS)")
            return

        # 5) Publish typed event for correlation_engine to consume.
        try:
            from app.core.events import event_bus
            payload = _normalized_event_to_dict(event)
            payload.setdefault("_event_type", "log_event")
            payload.setdefault("source", source)
            payload.setdefault("timestamp", datetime.utcnow().isoformat())
            if source_ip and "source_ip" not in payload:
                payload["source_ip"] = source_ip
            await event_bus.publish("log_event", payload)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(f"event_bus.publish(log_event) failed: {exc}")

        # 6) Inline behavioural detectors that operate over multiple
        #    events.  They use typed event fields so they can distinguish
        #    SSH vs HTTP (event.target_port) and apply path gating.
        await self._scan_breadcrumbs(line)
        await self._run_behavioural_detectors(line, event, source_ip)

    async def _run_behavioural_detectors(
        self,
        line: str,
        event,
        source_ip: Optional[str],
    ):
        """Brute-force, rate and port-scan trackers — typed-event aware."""
        if not source_ip:
            return

        event_path = _event_attr(event, "path")
        event_port = _event_attr(event, "target_port")
        status_code = _event_attr(event, "status_code")
        event_type = _event_attr(event, "event_type")
        event_method = _event_attr(event, "method")
        is_dashboard_request = _is_safe_path(line, event_path)

        # Defense-in-depth: a 401 that event_normalizer already classified as a
        # benign session-check (event_type http_request, not http_auth_failure)
        # must never advance the brute-force counter, even if the raw line slips
        # past _SAFE_PATHS substring matching. Login attempts are POSTs; a
        # non-POST 401 on an auth namespace is a session-check / token refresh.
        is_session_check_401 = False
        if isinstance(event_path, str):
            _bare_path = event_path.split("?", 1)[0]
            _is_auth_ns = _bare_path.startswith("/api/v1/auth/") or _bare_path.startswith("/auth/")
            _is_login = _bare_path.startswith("/api/v1/auth/login") or _bare_path.startswith("/api/v1/login")
            _method = (event_method or "").upper()
            if _is_auth_ns and not _is_login and _method and _method != "POST":
                is_session_check_401 = True
        if event_type in ("http_request", "session_check_401"):
            # Normalizer already ruled this benign.
            is_session_check_401 = is_session_check_401 or (
                isinstance(event_path, str)
                and (
                    event_path.startswith("/api/v1/auth/me")
                    or event_path.startswith("/api/v1/auth/refresh")
                    or event_path.startswith("/api/v1/auth/logout")
                    or event_path.startswith("/api/v1/auth/session")
                )
            )

        # ----- Port-scan tracker --------------------------------------
        # Prefer event.target_port (so we can tell port 22 / SSH from
        # port 80 / HTTP).  Fall back to extracting :PORT from raw line
        # when the event lacks one.
        port_for_scan: Optional[int] = None
        if isinstance(event_port, int):
            port_for_scan = event_port
        elif isinstance(event_port, str) and event_port.isdigit():
            port_for_scan = int(event_port)
        else:
            m = PORT_PATTERN.search(line)
            if m:
                try:
                    port_for_scan = int(m.group(1))
                except ValueError:
                    port_for_scan = None

        if port_for_scan is not None:
            if self._port_scan_tracker.record(source_ip, port_for_scan):
                alert_key = f"port_scan:{source_ip}"
                if alert_key not in self._recent_alerts:
                    self._recent_alerts.append(alert_key)
                    await self._create_incident_from_log(
                        line=line,
                        pattern_name="port_scan",
                        threat_type="port_scan",
                        severity="medium",
                        source_ip=source_ip,
                        description=f"Port scan detected: >10 unique ports probed by {source_ip} in 60s",
                    )

        # ----- Brute force (HTTP 401 or SSH auth fail) ----------------
        # v1.6.3.9: port-aware. Different thresholds + severities per surface:
        #   port 2222 (SSH honeypot) — every hit = CRITICAL, no threshold
        #   port 22   (real sshd)    — 5 in 60s   = CRITICAL
        #   port 8000 / 80 / 443     — 20 in 60s  = HIGH (HTTP API)
        #   dashboard paths          — skip entirely
        is_401 = (status_code == 401) or (" 401 " in line)
        if is_401 and not is_dashboard_request and not is_session_check_401:
            # Port-aware threshold + severity selection.
            if port_for_scan == 2222:
                threshold, severity_str, label = 1, "critical", "ssh_honeypot_brute"
            elif port_for_scan == 22:
                threshold, severity_str, label = 5, "critical", "ssh_real_brute"
            else:
                threshold, severity_str, label = 20, "high", "http_auth_brute"

            now = datetime.utcnow()
            cutoff = now - timedelta(seconds=60)
            q = self._brute_force_tracker[source_ip]
            while q and q[0] < cutoff:
                q.popleft()
            q.append(now)
            current_count = len(q)
            if current_count >= threshold:
                q.clear()
                # Emptied deque: drop the key so the tracker dict does not retain
                # one empty entry per unique brute-force source IP (leak fix).
                self._brute_force_tracker.pop(source_ip, None)
                alert_key = f"{label}:{source_ip}"
                if alert_key not in self._recent_alerts:
                    self._recent_alerts.append(alert_key)
                    await self._create_incident_from_log(
                        line=line,
                        pattern_name=label,
                        threat_type="brute_force",
                        severity=severity_str,
                        source_ip=source_ip,
                        description=(
                            f"Brute force detected: {current_count}+ failed auth "
                            f"attempts from {source_ip} in 60s on port {port_for_scan or 'unknown'}"
                        ),
                    )

        # ----- High request rate --------------------------------------
        if not is_dashboard_request and self._rate_tracker.record(source_ip):
            alert_key = f"rate:{source_ip}"
            if alert_key not in self._recent_alerts:
                self._recent_alerts.append(alert_key)
                await self._create_incident_from_log(
                    line=line,
                    pattern_name="high_request_rate",
                    threat_type="brute_force",
                    severity="high",
                    source_ip=source_ip,
                    description=(
                        f"High request rate detected from {source_ip} "
                        f"(>{self._rate_tracker.threshold} req/min)"
                    ),
                )

    async def _scan_breadcrumbs(self, line: str) -> None:
        """Scan a log line for Honey-AI breadcrumb UUIDs.

        A match proves an attacker consumed bait from a deception
        campaign and is now reusing the stolen value against a real
        service.  The tracker raises a CRITICAL incident via incident_cb.
        """
        if "hb" not in line and "-" not in line:
            return
        try:
            from app.services.honey_ai import breadcrumb_tracker
            from app.database import async_session
        except Exception:  # pragma: no cover
            return
        try:
            async with async_session() as db:
                await breadcrumb_tracker.scan_text(
                    db,
                    text=line,
                    source=f"log_watcher:{line[:200]}",
                    incident_cb=breadcrumb_tracker.raise_breadcrumb_incident,
                )
        except Exception:  # pragma: no cover - defensive
            pass

    async def _create_incident_from_log(
        self,
        line: str,
        pattern_name: str,
        threat_type: str,
        severity: str,
        source_ip: Optional[str],
        description: str,
    ):
        """Create an incident for the inline behavioural detectors only.

        Single-event pattern matches no longer come through here — they
        are produced by `correlation_engine.evaluate` from the typed
        NormalizedEvent we publish on the bus.
        """
        # Skip incidents without a real source IP.
        if not source_ip or source_ip in ('None', 'null', 'unknown', ''):
            logger.debug(f'Skipping incident without source IP: {pattern_name}')
            return

        # Skip private/Tailscale/internal IPs — NEVER attackers.
        if _is_private_ip(source_ip) or source_ip in INTERNAL_IPS:
            logger.debug(f'Skipping incident for internal IP {source_ip}: {pattern_name}')
            return

        # Honor AEGIS_SAFE_IPS CIDRs (Googlebot, Starlink, etc.).
        if _attack_detector_is_safe_ip(source_ip):
            logger.debug(
                f'Skipping incident for safe IP {source_ip} (AEGIS_SAFE_IPS): {pattern_name}'
            )
            return

        # Tor-exit recon/brute -> escalate + force-block.
        if threat_type in {"reconnaissance", "brute_force"}:
            try:
                from app.services.ip_intel import _load_tor_exits
                if source_ip in _load_tor_exits():
                    severity = "high"
                    description = f"[Tor exit] {description}"
                    try:
                        from app.core.ip_blocker import ip_blocker_service
                        ip_blocker_service.block_ip(source_ip)
                    except Exception as exc:
                        logger.debug(f"Tor exit auto-block failed for {source_ip}: {exc}")
            except Exception as exc:
                logger.debug(f"Tor exit lookup failed for {source_ip}: {exc}")

        # Incident dedup — same (IP, threat_type) within 5 min collapses.
        cooldown_key = f"{source_ip}:{threat_type}"
        now = datetime.utcnow()
        last_created = self._incident_cooldown.get(cooldown_key)
        if last_created and (now - last_created).total_seconds() < self._COOLDOWN_SECONDS:
            logger.debug(f'Incident cooldown active for {cooldown_key}, skipping')
            return
        self._incident_cooldown[cooldown_key] = now
        # TTL eviction so the cooldown dict can't grow unbounded under
        # sustained scan storms.  Drop entries older than 2x window.
        if len(self._incident_cooldown) > 1024:
            stale_cutoff = now - timedelta(seconds=self._COOLDOWN_SECONDS * 2)
            self._incident_cooldown = {
                k: v for k, v in self._incident_cooldown.items() if v >= stale_cutoff
            }

        try:
            from app.database import async_session
            from app.models.client import Client
            from app.services.ai_engine import ai_engine
            from sqlalchemy import select

            async with async_session() as db:
                # Deterministic client lookup: AEGIS_CLIENT_ID env
                # override, then oldest by created_at.
                aegis_client_id = os.environ.get("AEGIS_CLIENT_ID", "").strip()
                client = None
                if aegis_client_id:
                    client = await db.get(Client, aegis_client_id)
                if not client:
                    result = await db.execute(
                        select(Client).order_by(Client.created_at.asc()).limit(1)
                    )
                    client = result.scalar_one_or_none()
                if not client:
                    logger.warning("No client found - cannot create incident")
                    return

                alert_data = {
                    "source": "log_watcher",
                    "source_ip": source_ip,
                    "threat_type": threat_type,
                    "severity": severity,
                    "pattern": pattern_name,
                    "log_line": line[:500],
                    "description": description,
                    "title": f"{severity.upper()}: {pattern_name.replace('_', ' ').title()} detected",
                }

                logger.warning(
                    f"Security pattern detected [{pattern_name}] from {source_ip}: {description[:100]}"
                )
                await ai_engine.process_alert(alert_data, client, db)

                if severity in ("critical", "high"):
                    try:
                        from app.services.notifier import notifier
                        await notifier.notify_critical_event(
                            event_type=pattern_name,
                            details={
                                "severity": severity,
                                "source_ip": source_ip or "unknown",
                                "message": description[:300],
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Failed to send webhook for log event: {e}")

        except Exception as e:
            logger.error(f"Failed to create incident from log: {e}")


log_watcher = LogWatcher()
