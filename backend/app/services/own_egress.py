"""Never treat this install's own public address as an attacker.

The server usually sits behind the same NAT as the people who run it. Their
laptops, scripts and uptime checks reach the public hostnames from the site's
own public IP, and that IP is dynamic at most ISPs: a static safelist entry is
right until the lease changes, and then AEGIS blocks its own office (it did,
twice). So AEGIS looks up its current egress address on a timer and keeps it in
the runtime `internal` safelist, which every detection path already consults.

An address stays listed for OWN_EGRESS_KEEP_DAYS after it was last seen, then
it is dropped: an old lease gets handed to somebody else. Only entries this
module added are ever removed. Disable with AEGIS_OWN_EGRESS_SAFELIST=false,
for example on a host whose egress is a shared proxy.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

from app.config import settings
from app.core import safelist_store as store

logger = logging.getLogger("aegis.own_egress")

ADDED_BY = "auto:own-egress"
NOTE = "This install's own public address, detected automatically"
OWN_EGRESS_KEEP_DAYS = 7
CHECK_INTERVAL_MINUTES = 10
_DEFAULT_URLS = "https://api.ipify.org,https://icanhazip.com,https://ifconfig.me/ip"

_last_ip: Optional[str] = None


def _state_file() -> Path:
    return store.SAFELIST_FILE.with_name("own_egress.json")


def _urls() -> list[str]:
    raw = getattr(settings, "AEGIS_OWN_EGRESS_URLS", "") or _DEFAULT_URLS
    return [u.strip() for u in raw.split(",") if u.strip()]


def _public_ip(text: str) -> Optional[str]:
    """The response body as a canonical PUBLIC address, or None."""
    try:
        addr = ipaddress.ip_address((text or "").strip()[:64])
    except ValueError:
        return None
    if not addr.is_global:      # private, CGNAT, loopback, link-local, reserved...
        return None
    return str(addr)


async def discover() -> Optional[str]:
    """Ask the lookup services in turn; the first well-formed answer wins."""
    async with httpx.AsyncClient(timeout=6.0, follow_redirects=False) as client:
        for url in _urls():
            try:
                resp = await client.get(url, headers={"User-Agent": "aegis-own-egress"})
                if resp.status_code == 200:
                    ip = _public_ip(resp.text)
                    if ip:
                        return ip
            except Exception as exc:
                logger.debug(f"own-egress lookup via {url} failed: {exc}")
    return None


def _read_state() -> dict:
    try:
        data = json.loads(_state_file().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(state: dict) -> None:
    from app.core.ip_blocker import atomic_write_text
    atomic_write_text(_state_file(), json.dumps(state, indent=1, sort_keys=True) + "\n")


def record(ip: str, now: Optional[datetime] = None) -> dict:
    """Safelist `ip`, refresh its last-seen time and drop expired old leases."""
    now = now or datetime.now(timezone.utc)
    state = _read_state()
    state[ip] = now.isoformat(timespec="seconds")
    added = store.add(store.INTERNAL, ip, False, ADDED_BY, NOTE)

    ours = {e["value"] for e in store.list_entries(store.INTERNAL) if e.get("added_by") == ADDED_BY}
    cutoff = now - timedelta(days=OWN_EGRESS_KEEP_DAYS)
    dropped = []
    for old in sorted(ours - {ip}):
        seen = state.get(old)
        try:
            fresh = seen is not None and datetime.fromisoformat(seen) > cutoff
        except ValueError:
            fresh = False
        if not fresh:
            store.remove(store.INTERNAL, old)
            state.pop(old, None)
            dropped.append(old)
    for stale in [k for k in state if k not in ours and k != ip]:
        state.pop(stale, None)
    _write_state(state)
    return {"ip": ip, "added": added, "dropped": dropped}


async def refresh() -> Optional[dict]:
    """Scheduled job: keep the current egress address safelisted and unblocked."""
    global _last_ip
    if not getattr(settings, "AEGIS_OWN_EGRESS_SAFELIST", True):
        return None
    ip = await discover()
    if not ip:
        logger.debug("own-egress: no lookup service answered; keeping the last known address")
        return None
    result = record(ip)
    if result["added"] or ip != _last_ip:
        logger.warning(f"own-egress: this install's public address is {ip}; it is never blocked"
                       + (f" (dropped old lease(s): {', '.join(result['dropped'])})" if result["dropped"] else ""))
    _last_ip = ip
    # If it is blocked right now (the lease changed after the block), lift it.
    try:
        from app.core.ip_blocker import ip_blocker_service
        if ip in ip_blocker_service.list_blocked():
            from app.database import async_session
            from app.services import safelist as safelist_svc
            async with async_session() as db:
                out = await safelist_svc.unblock_everywhere(ip, db, ADDED_BY)
                await db.commit()
            logger.warning(f"own-egress: {ip} was blocked; lifted on every layer: {out}")
            result["unblocked"] = True
    except Exception as exc:
        logger.error(f"own-egress: could not lift the block on {ip}: {exc}")
    return result


async def start() -> None:
    if not getattr(settings, "AEGIS_OWN_EGRESS_SAFELIST", True):
        logger.info("own-egress safelist disabled (AEGIS_OWN_EGRESS_SAFELIST=false)")
        return
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        from app.services.scheduled_scanner import scheduled_scanner
        scheduled_scanner.scheduler.add_job(
            refresh, IntervalTrigger(minutes=CHECK_INTERVAL_MINUTES),
            id="own_egress_refresh", replace_existing=True, max_instances=1,
            next_run_time=datetime.now(),
        )
        logger.info("own-egress safelist started")
    except Exception as exc:
        logger.error(f"own-egress safelist failed to start: {exc}")
