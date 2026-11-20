"""Read-only REST client for a MikroTik (RouterOS 7) switch.

Same opt-in pattern as ``firewall_client``: nothing happens unless
``AEGIS_SWITCH_URL`` is set. Credentials (HTTP Basic) come from
``AEGIS_SWITCH_USER`` / ``AEGIS_SWITCH_PASSWORD``; no address or secret is
hardcoded here.

Design rules:
  * READ ONLY. The only verbs this module can emit are GET and a single POST to
    ``/interface/ethernet/monitor`` (which RouterOS uses as a read call). The
    guard lives in ``_request`` so a future helper cannot write by accident.
  * NEVER raises. Network/auth/parse failures are logged and the helper returns
    ``None`` (a failed poll), which is distinct from ``[]`` (a successful poll
    that returned nothing). The monitor relies on that distinction.
  * RouterOS returns every value as a string ("true", "61"). ``to_bool`` /
    ``to_int`` coerce defensively; a missing or odd field becomes ``None``.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

import httpx

from app.config import settings

logger = logging.getLogger("aegis.switch_client")

CONNECT_TIMEOUT = 3.0
TOTAL_TIMEOUT = 8.0
RETRY_BACKOFF = 0.5

# The complete write-capable surface of this client: one read-only POST.
_READ_POST_PATHS = frozenset({"/interface/ethernet/monitor"})


def switch_url() -> str:
    return (getattr(settings, "AEGIS_SWITCH_URL", "") or "").strip().rstrip("/")


def is_enabled() -> bool:
    return bool(switch_url())


# --- coercion -----------------------------------------------------------------

def to_bool(value: Any) -> Optional[bool]:
    """"true"/"false"/"yes"/"no"/bool/0/1 -> bool; anything else -> None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"):
            return True
        if v in ("false", "no", "0"):
            return False
    return None


def to_int(value: Any) -> Optional[int]:
    """"61" -> 61; missing/garbage -> None. Bools are not numbers here."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


_RATE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([GMK]?)bps\s*$", re.IGNORECASE)


def parse_rate_mbps(rate: Any) -> Optional[int]:
    """"100Mbps" -> 100, "1Gbps" -> 1000, "2.5Gbps" -> 2500; else None."""
    if not isinstance(rate, str):
        return None
    m = _RATE_RE.match(rate)
    if not m:
        return None
    mult = {"G": 1000.0, "M": 1.0, "K": 0.001, "": 0.000001}[m.group(2).upper()]
    return int(round(float(m.group(1)) * mult))


def _s(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value != "" else None


# --- normalisers (pure, unit-testable) ----------------------------------------

def normalize_interface(raw: dict) -> dict:
    return {
        "name": _s(raw.get("name")),
        "type": _s(raw.get("type")),
        "running": to_bool(raw.get("running")),
        "disabled": to_bool(raw.get("disabled")),
        "link_downs": to_int(raw.get("link-downs")),
        "last_link_up": _s(raw.get("last-link-up-time")),
        "mac": _s(raw.get("mac-address")),
        "rx_byte": to_int(raw.get("rx-byte")),
        "tx_byte": to_int(raw.get("tx-byte")),
        "rx_error": to_int(raw.get("rx-error")),
        "tx_error": to_int(raw.get("tx-error")),
        "rx_drop": to_int(raw.get("rx-drop")),
        "tx_drop": to_int(raw.get("tx-drop")),
        "tx_queue_drop": to_int(raw.get("tx-queue-drop")),
    }


def normalize_ethernet(raw: dict) -> dict:
    return {
        "name": _s(raw.get("name")),
        "auto_negotiation": to_bool(raw.get("auto-negotiation")),
        "rx_fcs_error": to_int(raw.get("rx-fcs-error")),
        "rx_align_error": to_int(raw.get("rx-align-error")),
        "rx_overflow": to_int(raw.get("rx-overflow")),
        "rx_fragment": to_int(raw.get("rx-fragment")),
        "rx_too_long": to_int(raw.get("rx-too-long")),
        "rx_too_short": to_int(raw.get("rx-too-short")),
        "rx_pause": to_int(raw.get("rx-pause")),
        "rx_broadcast": to_int(raw.get("rx-broadcast")),
        "rx_multicast": to_int(raw.get("rx-multicast")),
        "tx_broadcast": to_int(raw.get("tx-broadcast")),
    }


def normalize_monitor(raw: dict) -> dict:
    """A port with no link has neither ``rate`` nor ``full-duplex``: both None."""
    rate = _s(raw.get("rate"))
    return {
        "name": _s(raw.get("name")),
        "status": _s(raw.get("status")),
        "rate": rate,
        "rate_mbps": parse_rate_mbps(rate),
        "full_duplex": to_bool(raw.get("full-duplex")),
        "auto_negotiation": _s(raw.get("auto-negotiation")),
    }


def normalize_host(raw: dict) -> dict:
    mac = _s(raw.get("mac-address"))
    return {
        "mac": mac.upper() if mac else None,
        "port": _s(raw.get("on-interface")) or _s(raw.get("interface")),
        "local": to_bool(raw.get("local")),
        "dynamic": to_bool(raw.get("dynamic")),
        "disabled": to_bool(raw.get("disabled")),
        "invalid": to_bool(raw.get("invalid")),
    }


def normalize_resource(raw: dict) -> dict:
    return {
        "version": _s(raw.get("version")),
        "board": _s(raw.get("board-name")),
        "uptime": _s(raw.get("uptime")),
        "cpu_load": to_int(raw.get("cpu-load")),
        "free_memory": to_int(raw.get("free-memory")),
        "total_memory": to_int(raw.get("total-memory")),
    }


# --- client -------------------------------------------------------------------

class SwitchClient:
    """Async, read-only RouterOS REST client. Every public method is exception-safe."""

    def __init__(self, transport: Optional[httpx.AsyncBaseTransport] = None):
        # ``transport`` exists so tests can inject httpx.MockTransport.
        self._transport = transport

    def _auth(self) -> Optional[httpx.BasicAuth]:
        user = (getattr(settings, "AEGIS_SWITCH_USER", "") or "").strip()
        pw = getattr(settings, "AEGIS_SWITCH_PASSWORD", "") or ""
        return httpx.BasicAuth(user, pw) if user else None

    async def _request(self, method: str, path: str, json_body: Any = None) -> Any:
        """Return decoded JSON, or None on any failure. One retry with backoff
        on transport errors / 5xx; never on 401/403/404 (retrying cannot help)."""
        base = switch_url()
        if not base:
            return None
        if method == "GET":
            pass
        elif method == "POST" and path in _READ_POST_PATHS:
            pass
        else:  # defence in depth: this client must never be able to write
            logger.error("switch_client refused non-read request %s %s", method, path)
            return None

        timeout = httpx.Timeout(TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT)
        for attempt in (1, 2):
            try:
                async with httpx.AsyncClient(
                    base_url=f"{base}/rest", timeout=timeout,
                    auth=self._auth(), transport=self._transport,
                ) as http:
                    resp = await http.request(method, path, json=json_body)
                if resp.status_code in (401, 403, 404):
                    logger.warning("switch %s %s -> HTTP %s", method, path, resp.status_code)
                    return None
                if resp.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"HTTP {resp.status_code}", request=resp.request, response=resp)
                resp.raise_for_status()
                return resp.json()
            except Exception as e:  # network, timeout, 5xx, bad JSON: all swallowed
                if attempt == 1:
                    logger.debug("switch %s %s failed (%s: %s); retrying",
                                 method, path, type(e).__name__, e)
                    await asyncio.sleep(RETRY_BACKOFF)
                    continue
                logger.warning("switch %s %s failed: %s: %s", method, path, type(e).__name__, e)
                return None
        return None

    @staticmethod
    def _rows(data: Any, norm) -> Optional[list[dict]]:
        if not isinstance(data, list):
            return None
        return [norm(r) for r in data if isinstance(r, dict)]

    async def get_interfaces(self) -> Optional[list[dict]]:
        return self._rows(await self._request("GET", "/interface"), normalize_interface)

    async def get_ethernet(self) -> Optional[list[dict]]:
        return self._rows(await self._request("GET", "/interface/ethernet"), normalize_ethernet)

    async def monitor_port(self, name: str) -> Optional[dict]:
        data = await self._request(
            "POST", "/interface/ethernet/monitor", {"numbers": name, "once": ""})
        rows = self._rows(data, normalize_monitor)
        return rows[0] if rows else None

    async def get_bridge_hosts(self) -> Optional[list[dict]]:
        return self._rows(await self._request("GET", "/interface/bridge/host"), normalize_host)

    async def get_resource(self) -> Optional[dict]:
        data = await self._request("GET", "/system/resource")
        if isinstance(data, list):
            data = data[0] if data and isinstance(data[0], dict) else None
        return normalize_resource(data) if isinstance(data, dict) else None


switch_client = SwitchClient()
