"""
DoS Shield — core detection engine (TIER 1, app-layer, Mac Pro).

Stateless-singleton in-memory sliding-window DoS detector consulted by the thin
DoSShieldMiddleware (owner A, dos_middleware.py) as the OUTERMOST middleware so
floods are shed BEFORE the heavy AttackDetectorMiddleware and route handlers.

Detects:
  * per-IP HTTP flood            (dos.http_flood)
  * distributed flood            (dos.distributed)   — per-/24 subnet + global
  * expensive-endpoint hammering (dos.expensive_abuse)
  * slow-loris / concurrency     (dos.slowloris)
  * adaptive global under-attack (dos.under_attack)
  * active-mode escalation       (dos.ip_blocked)

Design properties honored from the interface_contract:
  * `record_request()` is the hot-path entrypoint, target < 0.2 ms, O(1) amortized.
  * `now` defaults to time.monotonic() so tests can inject a fake clock.
  * MONITOR mode (default) NEVER returns throttle/block — detection only.
  * ACTIVE mode returns throttle/block verdicts; escalation delegates to the
    EXISTING ip_blocker_service + firewall_client (no new blocklist/HTTP client).
  * Path is normalized (query stripped, numeric/id segments collapsed) BEFORE
    counting, so cache-bust query variation cannot dilute the per-IP counter.
  * NEVER calls _is_safe_ip in the hot path (middleware gates first) but escalate()
    re-checks the safelist as a hard interlock.
  * Reuses event_bus (app.core.events) with existing priority constants.

Blocking/firewall/attack_detector imports are LAZY (inside methods) to avoid
import cycles with the middleware/main wiring.
"""

from __future__ import annotations

import asyncio
import ipaddress as _ipaddress
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings
from app.core.events import (
    PRIORITY_CRITICAL,
    PRIORITY_HIGH,
    event_bus as _default_event_bus,
)
from app.core.mem_bounds import DEFAULT_MAX_KEYS, cap_lru, prune_stale_ts_map

logger = logging.getLogger("aegis.dos_shield")

# ---------------------------------------------------------------------------
# Module-level enums / constants (interface_contract, verbatim)
# ---------------------------------------------------------------------------
MODE_MONITOR = "monitor"
MODE_ACTIVE = "active"

ACTION_ALLOW = "allow"       # do nothing
ACTION_THROTTLE = "throttle"  # 429 (active mode only)
ACTION_BLOCK = "block"        # 429 + escalate (active mode only)

# reason codes
REASON_NONE = ""
REASON_PER_IP = "per_ip_flood"
REASON_SUBNET = "subnet_flood"
REASON_GLOBAL = "global_flood"
REASON_EXPENSIVE = "expensive_abuse"
REASON_SLOWLORIS = "slowloris"
REASON_UNDER_ATTACK = "under_attack"

# event names
EVT_HTTP_FLOOD = "dos.http_flood"
EVT_DISTRIBUTED = "dos.distributed"
EVT_EXPENSIVE = "dos.expensive_abuse"
EVT_SLOWLORIS = "dos.slowloris"
EVT_UNDER_ATTACK = "dos.under_attack"
EVT_IP_BLOCKED = "dos.ip_blocked"

# reason -> (event name, priority, severity)
_REASON_EVENT = {
    REASON_PER_IP: (EVT_HTTP_FLOOD, PRIORITY_HIGH, "high"),
    REASON_SUBNET: (EVT_DISTRIBUTED, PRIORITY_CRITICAL, "critical"),
    REASON_GLOBAL: (EVT_DISTRIBUTED, PRIORITY_CRITICAL, "critical"),
    REASON_EXPENSIVE: (EVT_EXPENSIVE, PRIORITY_HIGH, "high"),
    REASON_SLOWLORIS: (EVT_SLOWLORIS, PRIORITY_HIGH, "high"),
    REASON_UNDER_ATTACK: (EVT_UNDER_ATTACK, PRIORITY_CRITICAL, "critical"),
}


# ---------------------------------------------------------------------------
# Verdict dataclass (interface_contract)
# ---------------------------------------------------------------------------
@dataclass
class Verdict:
    action: str = ACTION_ALLOW
    reason: str = REASON_NONE
    ip: str = ""
    mode: str = MODE_MONITOR
    retry_after: int = 0
    event: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "reason": self.reason,
            "ip": self.ip,
            "mode": self.mode,
            "retry_after": self.retry_after,
            "event": self.event,
            "detail": dict(self.detail),
        }


# ---------------------------------------------------------------------------
# Per-IP tracking state (compact, per-request O(1))
# ---------------------------------------------------------------------------
@dataclass
class _IPState:
    hits: deque = field(default_factory=deque)          # timestamps (monotonic)
    expensive_hits: deque = field(default_factory=deque)  # timestamps for expensive paths
    concurrency: int = 0
    slow_ticks: int = 0
    last_reason: str = REASON_NONE
    last_seen: float = 0.0


class DoSShield:
    """In-memory sliding-window DoS detection brain. Pure, O(1) amortized."""

    def __init__(self):
        self._bus = _default_event_bus  # may be re-set via register_event_bus
        self._mode: str = MODE_MONITOR
        self._mode_override: Optional[str] = None  # set via set_mode()

        # sliding-window deques
        self._ip_state: dict[str, _IPState] = defaultdict(_IPState)
        self._subnet_hits: dict[str, deque] = defaultdict(deque)
        self._global_hits: deque = deque()

        # adaptive under-attack state (with hysteresis)
        self._under_attack: bool = False

        # event cooldown: (ip, reason) -> last publish monotonic ts
        self._event_cooldown: dict[tuple, float] = {}

        # counters (for snapshot)
        self._events_published: int = 0
        self._blocks: int = 0

        # escalation dedup: ip -> monotonic ts when blocked
        self._escalated: dict[str, float] = {}

        # background prune task
        self._task: Optional[asyncio.Task] = None
        self._running: bool = False

        # config fields (seeded by reload_config)
        self.per_ip_rps: float = 10.0
        self.per_ip_window: int = 10
        self.subnet_rps: float = 40.0
        self.subnet_window: int = 10
        self.global_rps: float = 50.0
        self.global_window: int = 10
        self.expensive_rpm: float = 6.0
        self.expensive_paths: tuple = ()
        self.concurrency_per_ip: int = 20
        self.slow_request_seconds: float = 25.0
        self.block_duration: int = 900
        self.under_attack_factor: float = 0.5
        self.event_cooldown: int = 30

        self.reload_config()

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #
    def register_event_bus(self, bus) -> None:
        """Store bus ref. Called once in lifespan (mirrors correlation_engine)."""
        self._bus = bus

    def reload_config(self) -> None:
        """(Re)read AEGIS_DOS_* from settings into live fields. Idempotent."""
        g = settings

        def _f(name, default):
            return float(getattr(g, name, default))

        def _i(name, default):
            return int(getattr(g, name, default))

        def _s(name, default):
            return str(getattr(g, name, default))

        self.per_ip_rps = _f("AEGIS_DOS_PER_IP_RPS", 10)
        self.per_ip_window = _i("AEGIS_DOS_PER_IP_WINDOW", 10)
        self.subnet_rps = _f("AEGIS_DOS_SUBNET_RPS", 40)
        self.subnet_window = _i("AEGIS_DOS_SUBNET_WINDOW", 10)
        self.global_rps = _f("AEGIS_DOS_GLOBAL_RPS", 50)
        self.global_window = _i("AEGIS_DOS_GLOBAL_WINDOW", 10)
        self.expensive_rpm = _f("AEGIS_DOS_EXPENSIVE_RPM", 6)
        raw_paths = _s(
            "AEGIS_DOS_EXPENSIVE_PATHS",
            "/api/v1/ask,/api/v1/surface/scan,/api/v1/surface/scan/now",
        )
        self.expensive_paths = tuple(
            p.strip() for p in raw_paths.split(",") if p.strip()
        )
        self.concurrency_per_ip = _i("AEGIS_DOS_CONCURRENCY_PER_IP", 20)
        self.slow_request_seconds = _f("AEGIS_DOS_SLOW_REQUEST_SECONDS", 25)
        self.block_duration = _i("AEGIS_DOS_BLOCK_DURATION", 900)
        self.under_attack_factor = _f("AEGIS_DOS_UNDER_ATTACK_FACTOR", 0.5)
        self.event_cooldown = _i("AEGIS_DOS_EVENT_COOLDOWN", 30)

        # mode source of truth = settings unless overridden via set_mode
        cfg_mode = _s("AEGIS_DOS_MODE", MODE_MONITOR).strip().lower()
        if cfg_mode not in (MODE_MONITOR, MODE_ACTIVE):
            cfg_mode = MODE_MONITOR
        self._mode = cfg_mode
        logger.info(
            "dos_shield config: mode=%s per_ip=%s/%ss subnet=%s/%ss global=%s/%ss "
            "expensive=%src/min concurrency=%s",
            self.mode, self.per_ip_rps, self.per_ip_window,
            self.subnet_rps, self.subnet_window,
            self.global_rps, self.global_window,
            self.expensive_rpm, self.concurrency_per_ip,
        )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        """Seed config, spawn background prune task. Idempotent."""
        self.reload_config()
        if self._running:
            return
        self._running = True
        try:
            self._task = asyncio.create_task(self._prune_loop())
        except RuntimeError:
            # no running loop (e.g. sync unit test) — skip background task
            self._task = None
        logger.info("dos_shield started (mode=%s)", self.mode)

    async def stop(self) -> None:
        """Cancel background task. Idempotent."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        logger.info("dos_shield stopped")

    async def _prune_loop(self) -> None:
        """Periodically drop cold IP/subnet state to bound memory."""
        while self._running:
            try:
                await asyncio.sleep(30)
                self._prune(time.monotonic())
            except asyncio.CancelledError:
                break
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("dos_shield prune error: %s", exc)

    def _prune(self, now: float) -> None:
        max_window = max(
            self.per_ip_window, self.subnet_window, self.global_window
        )
        cutoff = now - max_window
        # Absolute idle TTL: even a half-open / slow-loris connection stuck at
        # concurrency > 0 must be force-evicted once it has been idle far longer
        # than any active window, otherwise its _IPState leaks forever (rank 3).
        # 900s (or block_duration) is well beyond legitimate keep-alive.
        hard_ttl = max(max_window, self.block_duration, 900)
        hard_cutoff = now - hard_ttl
        # prune per-IP: drop entries with no recent hits and zero concurrency,
        # OR any entry idle past the absolute TTL regardless of concurrency.
        stale = []
        for ip, st in self._ip_state.items():
            self._prune_deque(st.hits, now - self.per_ip_window)
            self._prune_deque(st.expensive_hits, now - 60.0)
            idle = st.last_seen < cutoff
            if (
                (not st.hits and not st.expensive_hits and st.concurrency <= 0 and idle)
                or st.last_seen < hard_cutoff
            ):
                stale.append(ip)
        for ip in stale:
            self._ip_state.pop(ip, None)
        # Hard cap as a burst backstop: if a scan storm creates unique-IP state
        # faster than the 30s sweep can evict it, drop the coldest by last_seen.
        cap_lru(self._ip_state, DEFAULT_MAX_KEYS, lambda st: st.last_seen)
        # subnets
        stale_sub = []
        for sub, dq in self._subnet_hits.items():
            self._prune_deque(dq, now - self.subnet_window)
            if not dq:
                stale_sub.append(sub)
        for sub in stale_sub:
            self._subnet_hits.pop(sub, None)
        cap_lru(
            self._subnet_hits, DEFAULT_MAX_KEYS,
            lambda dq: dq[-1] if dq else 0.0,
        )
        self._prune_deque(self._global_hits, now - self.global_window)
        # escalation dedup expiry
        exp = [ip for ip, ts in self._escalated.items()
               if now - ts > self.block_duration]
        for ip in exp:
            self._escalated.pop(ip, None)
        # event cooldown: (ip, reason) -> last publish ts. Never evicted before;
        # accumulates one entry per unique (ip, reason) forever. Drop entries
        # older than 10x the cooldown window — safely past any suppression need.
        prune_stale_ts_map(
            self._event_cooldown, self.event_cooldown * 10, now
        )

    @staticmethod
    def _prune_deque(dq: deque, cutoff: float) -> None:
        while dq and dq[0] < cutoff:
            dq.popleft()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _normalize_path(self, path: str) -> str:
        """Collapse /api/v1/foo/123 -> /api/v1/foo/{id}; strip trailing slash;
        drop any query string. Numeric AND uuid/hex-ish id segments collapse."""
        if not path:
            return "/"
        # defensive: strip query/fragment if a caller passed a full URL path
        for sep in ("?", "#"):
            idx = path.find(sep)
            if idx != -1:
                path = path[:idx]
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        if not path:
            return "/"
        segments = path.split("/")
        out = []
        for seg in segments:
            if not seg:
                out.append(seg)
                continue
            if self._is_id_segment(seg):
                out.append("{id}")
            else:
                out.append(seg)
        return "/".join(out) or "/"

    @staticmethod
    def _is_id_segment(seg: str) -> bool:
        # pure numeric
        if seg.isdigit():
            return True
        # long hex / uuid-ish (>=16 hex chars or contains a dash + hex)
        s = seg.replace("-", "")
        if len(s) >= 16 and all(c in "0123456789abcdefABCDEF" for c in s):
            return True
        return False

    def _subnet_key(self, ip: str) -> str:
        """IPv4 -> 'a.b.c.0/24'; IPv6 -> '/64' prefix; malformed -> ip."""
        try:
            addr = _ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return ip
        if addr.version == 4:
            net = _ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        net = _ipaddress.ip_network(f"{ip}/64", strict=False)
        return str(net)

    # ------------------------------------------------------------------ #
    # Hot path
    # ------------------------------------------------------------------ #
    def record_request(
        self,
        ip: str,
        path: str,
        method: str,
        now: Optional[float] = None,
    ) -> Verdict:
        """THE hot-path entrypoint. Safe to call for every request.

        Returns a Verdict. In MONITOR mode action is ALWAYS ACTION_ALLOW but
        reason/event are still populated (detection only).
        """
        if now is None:
            now = time.monotonic()

        key_path = self._normalize_path(path)
        subnet = self._subnet_key(ip)

        st = self._ip_state[ip]
        st.last_seen = now

        # push + prune per-IP window
        st.hits.append(now)
        self._prune_deque(st.hits, now - self.per_ip_window)

        # subnet window
        sub_dq = self._subnet_hits[subnet]
        sub_dq.append(now)
        self._prune_deque(sub_dq, now - self.subnet_window)

        # global window
        self._global_hits.append(now)
        self._prune_deque(self._global_hits, now - self.global_window)

        # rates (requests-per-second averaged over the window)
        per_ip_rps = len(st.hits) / self.per_ip_window if self.per_ip_window else 0.0
        subnet_rps = len(sub_dq) / self.subnet_window if self.subnet_window else 0.0
        global_rps = (
            len(self._global_hits) / self.global_window if self.global_window else 0.0
        )

        is_expensive = self._is_expensive(key_path)
        if is_expensive:
            st.expensive_hits.append(now)
            self._prune_deque(st.expensive_hits, now - 60.0)

        # adaptive under-attack state (update BEFORE threshold eval so tightening applies)
        self._update_under_attack(global_rps)

        # effective thresholds (tighten under attack)
        factor = self.under_attack_factor if self._under_attack else 1.0
        eff_per_ip = self.per_ip_rps * factor
        eff_expensive_rpm = self.expensive_rpm * factor

        # ---- evaluate thresholds, highest severity first ----
        reason = REASON_NONE
        threshold = 0.0

        if is_expensive and len(st.expensive_hits) > eff_expensive_rpm:
            reason = REASON_EXPENSIVE
            threshold = eff_expensive_rpm
        elif global_rps > self.global_rps:
            reason = REASON_GLOBAL
            threshold = self.global_rps
        elif subnet_rps > self.subnet_rps:
            reason = REASON_SUBNET
            threshold = self.subnet_rps
        elif per_ip_rps > eff_per_ip:
            reason = REASON_PER_IP
            threshold = eff_per_ip
        elif st.concurrency > self.concurrency_per_ip:
            reason = REASON_SLOWLORIS
            threshold = float(self.concurrency_per_ip)

        detail = {
            "per_ip_rps": round(per_ip_rps, 3),
            "subnet_rps": round(subnet_rps, 3),
            "global_rps": round(global_rps, 3),
            "concurrency": st.concurrency,
            "window_s": self.per_ip_window,
            "threshold": round(threshold, 3),
            "path": key_path,
        }

        event_name = ""
        mode = self.mode

        if reason:
            st.last_reason = reason
            event_name = self._maybe_publish(
                reason, ip, subnet, key_path, method, detail, now
            )

        # decide action
        action = ACTION_ALLOW
        retry_after = 0
        if mode == MODE_ACTIVE and reason:
            # subnet/global/under_attack alone => throttle everyone non-safelisted;
            # per-IP / expensive / slowloris => block the offending IP.
            if reason in (REASON_PER_IP, REASON_EXPENSIVE, REASON_SLOWLORIS):
                action = ACTION_BLOCK
            else:
                action = ACTION_THROTTLE
            retry_after = self._retry_after(reason)

        return Verdict(
            action=action,
            reason=reason,
            ip=ip,
            mode=mode,
            retry_after=retry_after,
            event=event_name,
            detail=detail,
        )

    def _is_expensive(self, key_path: str) -> bool:
        return any(key_path.startswith(p) for p in self.expensive_paths)

    def _retry_after(self, reason: str) -> int:
        if reason in (REASON_GLOBAL, REASON_SUBNET, REASON_UNDER_ATTACK):
            return max(1, self.global_window)
        if reason == REASON_EXPENSIVE:
            return 60
        if reason in (REASON_PER_IP, REASON_SLOWLORIS):
            return max(1, self.per_ip_window)
        return 1

    def _update_under_attack(self, global_rps: float) -> None:
        """Set/clear under_attack with hysteresis.
        Enter when global_rps > global_rps threshold.
        Clear when global_rps falls below global_rps * 0.6.
        """
        prev = self._under_attack
        if not self._under_attack:
            if global_rps > self.global_rps:
                self._under_attack = True
        else:
            if global_rps < self.global_rps * 0.6:
                self._under_attack = False
        if self._under_attack != prev:
            # emit under_attack transition event (best-effort, respects cooldown)
            self._maybe_publish(
                REASON_UNDER_ATTACK,
                ip="global",
                subnet="",
                key_path="",
                method="",
                detail={
                    "per_ip_rps": 0.0,
                    "subnet_rps": 0.0,
                    "global_rps": round(global_rps, 3),
                    "concurrency": 0,
                    "window_s": self.global_window,
                    "threshold": round(self.global_rps, 3),
                    "path": "",
                    "under_attack": self._under_attack,
                },
                now=time.monotonic(),
            )

    # ------------------------------------------------------------------ #
    # Concurrency / slow-loris accounting
    # ------------------------------------------------------------------ #
    def begin_request(self, ip: str, now: Optional[float] = None) -> None:
        """Increment per-IP concurrency counter (slow-loris signal)."""
        if now is None:
            now = time.monotonic()
        st = self._ip_state[ip]
        st.concurrency += 1
        st.last_seen = now
        # store per-request start via a lightweight stack of start times
        starts = getattr(st, "_starts", None)
        if starts is None:
            starts = deque()
            setattr(st, "_starts", starts)
        starts.append(now)

    def end_request(self, ip: str, now: Optional[float] = None) -> None:
        """Decrement per-IP concurrency; record slow-request tick if long-lived."""
        if now is None:
            now = time.monotonic()
        st = self._ip_state.get(ip)
        if st is None:
            return
        if st.concurrency > 0:
            st.concurrency -= 1
        starts = getattr(st, "_starts", None)
        if starts:
            start = starts.popleft()
            if (now - start) > self.slow_request_seconds:
                st.slow_ticks += 1
                st.last_reason = REASON_SLOWLORIS

    # ------------------------------------------------------------------ #
    # Event publishing
    # ------------------------------------------------------------------ #
    def _maybe_publish(
        self,
        reason: str,
        ip: str,
        subnet: str,
        key_path: str,
        method: str,
        detail: dict,
        now: float,
    ) -> str:
        """Publish the dos.* event for `reason`, honoring per-(ip,reason) cooldown.
        Returns the event name (or "" if suppressed by cooldown)."""
        meta = _REASON_EVENT.get(reason)
        if not meta:
            return ""
        event_name, priority, severity = meta

        ck = (ip, reason)
        last = self._event_cooldown.get(ck, 0.0)
        if now - last < self.event_cooldown:
            return ""  # suppressed
        self._event_cooldown[ck] = now

        payload = {
            "event_type": event_name,
            "source_ip": ip,
            "subnet": subnet,
            "request_path": key_path,
            "request_method": method,
            "per_ip_rps": detail.get("per_ip_rps", 0.0),
            "subnet_rps": detail.get("subnet_rps", 0.0),
            "global_rps": detail.get("global_rps", 0.0),
            "concurrency": detail.get("concurrency", 0),
            "reason": reason,
            "mode": self.mode,
            "window_s": detail.get("window_s", 0),
            "threshold": detail.get("threshold", 0.0),
            "under_attack": self._under_attack,
            "severity": severity,
            "detector": "dos_shield",
        }

        self._publish_async(event_name, payload, priority)
        self._events_published += 1
        return event_name

    def _publish_async(self, event_name: str, payload: dict, priority: int) -> None:
        """Fire-and-forget publish that tolerates missing/absent event loop."""
        bus = self._bus
        if bus is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        try:
            if loop is not None:
                loop.create_task(bus.publish(event_name, payload, priority=priority))
            else:
                # no loop (sync unit test) — run synchronously, best effort
                asyncio.run(bus.publish(event_name, payload, priority=priority))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("dos_shield publish failed for %s: %s", event_name, exc)

    # ------------------------------------------------------------------ #
    # Escalation (ACTIVE mode block path)
    # ------------------------------------------------------------------ #
    async def escalate(self, ip: str, reason: str) -> dict:
        """ACTIVE-mode block path. Idempotent per ip within block-duration.
        Delegates to EXISTING ip_blocker_service + firewall_client. Network-tier
        hashlimit/connlimit is NOT invoked here (operator-gated elsewhere)."""
        # hard safelist interlock
        try:
            from app.core.attack_detector import _is_safe_ip
            if _is_safe_ip(ip):
                return {"blocked": False, "reason": "safelisted", "ip": ip}
        except Exception as exc:
            logger.debug("dos_shield _is_safe_ip check failed for %s: %s", ip, exc)

        now = time.monotonic()
        last = self._escalated.get(ip)
        if last is not None and (now - last) < self.block_duration:
            return {"blocked": True, "ip": ip, "reason": reason, "deduped": True}
        self._escalated[ip] = now

        # (2) local 403 + persistence + attack_detector mirror
        try:
            from app.core.ip_blocker import ip_blocker_service
            ip_blocker_service.block_ip(ip)
        except Exception as exc:
            logger.error("dos_shield local block failed for %s: %s", ip, exc)

        # (3) Pi per-IP DROP (existing path)
        try:
            from app.core.firewall_client import firewall_client
            await firewall_client.block_ip(ip)
        except Exception as exc:
            logger.error("dos_shield firewall block failed for %s: %s", ip, exc)

        self._blocks += 1

        # (4) publish dos.ip_blocked (critical)
        payload = {
            "event_type": EVT_IP_BLOCKED,
            "source_ip": ip,
            "subnet": self._subnet_key(ip),
            "reason": reason,
            "mode": self.mode,
            "under_attack": self._under_attack,
            "severity": "critical",
            "detector": "dos_shield",
        }
        self._publish_async(EVT_IP_BLOCKED, payload, PRIORITY_CRITICAL)

        return {"blocked": True, "ip": ip, "reason": reason}

    # ------------------------------------------------------------------ #
    # Snapshot / state
    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict:
        """Read-only state for /dos/status."""
        now = time.monotonic()
        global_rps = (
            len(self._global_hits) / self.global_window if self.global_window else 0.0
        )

        offenders = []
        for ip, st in self._ip_state.items():
            # count recent hits without mutating (copy-free scan)
            recent = sum(1 for t in st.hits if t >= now - self.per_ip_window)
            if recent <= 0 and st.concurrency <= 0:
                continue
            rps = recent / self.per_ip_window if self.per_ip_window else 0.0
            offenders.append({
                "ip": ip,
                "rps": round(rps, 3),
                "concurrency": st.concurrency,
                "last_reason": st.last_reason,
            })
        offenders.sort(key=lambda o: (o["rps"], o["concurrency"]), reverse=True)
        offenders = offenders[:20]

        netshield_env = bool(getattr(settings, "AEGIS_DOS_NETSHIELD", 0))
        try:
            netshield_env = str(getattr(settings, "AEGIS_DOS_NETSHIELD", "0")).strip() in (
                "1", "true", "True", "yes", "on",
            ) or netshield_env
        except Exception:
            pass

        return {
            "mode": self.mode,
            "under_attack": self._under_attack,
            "global_rps": round(global_rps, 3),
            "global_window_s": self.global_window,
            "netshield_enabled": False,  # runtime-enabled state owned by /dos router
            "netshield_env_gate": netshield_env,
            "thresholds": {
                "per_ip_rps": self.per_ip_rps,
                "subnet_rps": self.subnet_rps,
                "global_rps": self.global_rps,
                "expensive_rpm": self.expensive_rpm,
                "concurrency_per_ip": self.concurrency_per_ip,
                "block_duration_s": self.block_duration,
            },
            "counters": {
                "tracked_ips": len(self._ip_state),
                "tracked_subnets": len(self._subnet_hits),
                "events_published": self._events_published,
                "blocks": self._blocks,
            },
            "top_offenders": offenders,
        }

    # ------------------------------------------------------------------ #
    # Mode
    # ------------------------------------------------------------------ #
    @property
    def mode(self) -> str:
        if self._mode_override is not None:
            return self._mode_override
        return self._mode

    def set_mode(self, mode: str) -> None:
        mode = (mode or "").strip().lower()
        if mode not in (MODE_MONITOR, MODE_ACTIVE):
            raise ValueError(f"invalid dos mode: {mode!r}")
        self._mode_override = mode
        logger.warning("dos_shield mode set to %s (runtime override)", mode)

    @property
    def under_attack(self) -> bool:
        return self._under_attack


# ---------------------------------------------------------------------------
# Module-level singleton (interface_contract):
#   from app.services.dos_shield import dos_shield
# ---------------------------------------------------------------------------
dos_shield = DoSShield()
