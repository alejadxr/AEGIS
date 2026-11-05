"""Runtime safelist: operator-managed entries layered on top of the env vars.

AEGIS_SAFE_IPS / AEGIS_INTERNAL_IPS / AEGIS_SHARED_EGRESS_IPS are read once at
import in ``attack_detector`` and can only be changed by editing ``.env`` and
restarting the API. That is the wrong tool for "stop blocking this customer's
office *now*". This module holds a second, mutable layer:

* persisted to a JSON file (atomic write, same helper the blocklist uses), so it
  survives a restart without touching ``.env``;
* merged at READ time with the env layer: ``attack_detector._is_safe_ip`` and
  ``is_shared_egress`` ask this store as well as their own env-derived sets, so
  an addition takes effect on the very next call, with no restart and no
  reload hook for the detectors to forget;
* never able to remove an env entry. The env layer is owned by whoever edits
  ``.env``; the API reports such entries as env-pinned instead of pretending.

This module must not import ``attack_detector`` (it imports us). Anything that
needs the env view lives in ``app.services.safelist``.

Why the file is re-checked on a timer: the API may run more than one worker, and
a change made through worker A must reach worker B. ``_maybe_reload`` stats the
file at most every ``_RELOAD_CHECK_S`` seconds, which keeps the per-request cost
of ``_is_safe_ip`` to a monotonic-clock read.
"""
import ipaddress
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aegis.safelist_store")

# Same shape as BLOCKED_IPS_FILE: an env override, else a per-user default that
# the PM2 process can write. Read at call time (module attribute) so tests can
# point it at a tmp path.
SAFELIST_FILE = Path(os.environ.get(
    "AEGIS_SAFELIST_FILE",
    str(Path.home() / ".aegis" / "safelist.json"),
))

SAFE = "safe"
INTERNAL = "internal"
SHARED_EGRESS = "shared_egress"
CATEGORIES = (SAFE, INTERNAL, SHARED_EGRESS)

# A typo'd "10.0.0.0/8" or "0.0.0.0/0" must not be able to switch the platform's
# defences off for a whole continent. /16 is what the shipped env docs use for
# Googlebot (66.249.0.0/16); anything wider is refused, and an operator who
# really needs it can still put it in .env on purpose.
MAX_V4_SPAN = 16
MAX_V6_SPAN = 32

_RELOAD_CHECK_S = 5.0

_lock = threading.Lock()


class SafelistError(ValueError):
    """A value the store refuses to hold (malformed, too broad, wrong category)."""


def normalize(value: str) -> tuple[str, bool]:
    """Return (canonical_text, is_network). Raises SafelistError.

    A /32 (or /128) collapses to a plain address so the same host cannot be
    listed twice under two spellings, and so removal by either form works.
    Hostnames are refused: the env layer tolerates them for historical reasons
    ("localhost"), but a name cannot be matched against a peer address.
    """
    if not isinstance(value, str) or not value.strip():
        raise SafelistError("value is empty")
    text = value.strip()
    if len(text) > 64:
        raise SafelistError("value is too long")
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise SafelistError(f"{text!r} is not a valid CIDR range")
        if net.num_addresses == 1:
            return str(net.network_address), False
        floor = MAX_V4_SPAN if net.version == 4 else MAX_V6_SPAN
        if net.prefixlen < floor:
            raise SafelistError(
                f"{net} is wider than /{floor}; refusing a range that broad. "
                f"Put it in the environment on purpose if you really mean it."
            )
        return str(net), True
    try:
        return str(ipaddress.ip_address(text)), False
    except ValueError:
        raise SafelistError(f"{text!r} is not a valid IP address or CIDR range")


class _Snapshot:
    """Immutable match structures, swapped atomically on every change."""
    __slots__ = ("entries", "literals", "networks")

    def __init__(self, entries: dict):
        self.entries = entries  # {category: {canonical: meta}}
        self.literals = {c: frozenset(k for k, m in v.items() if not m["network"])
                         for c, v in entries.items()}
        self.networks = {c: tuple(ipaddress.ip_network(k) for k, m in v.items() if m["network"])
                         for c, v in entries.items()}


def _empty() -> dict:
    return {c: {} for c in CATEGORIES}


_snapshot: _Snapshot = _Snapshot(_empty())
_loaded_mtime: Optional[float] = None
_next_check: float = 0.0


def _read_file() -> dict:
    """Parse the file into {category: {canonical: meta}}. Bad entries are dropped
    and logged; a missing or unreadable file is an empty runtime layer, never a
    crash (the env layer still protects the operator)."""
    entries = _empty()
    path = SAFELIST_FILE
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        return entries
    except Exception as exc:
        logger.error(f"safelist_store: cannot read {path}: {exc}")
        return entries
    if not isinstance(raw, dict):
        logger.error(f"safelist_store: {path} is not a JSON object; ignoring it")
        return entries
    for cat in CATEGORIES:
        for item in raw.get(cat) or []:
            if not isinstance(item, dict):
                continue
            try:
                key, is_net = normalize(str(item.get("value", "")))
            except SafelistError as exc:
                logger.warning(f"safelist_store: dropping bad {cat} entry {item.get('value')!r}: {exc}")
                continue
            entries[cat][key] = {
                "network": is_net,
                "added_by": str(item.get("added_by") or "unknown")[:120],
                "added_at": str(item.get("added_at") or ""),
                "note": str(item.get("note") or "")[:300],
            }
    return entries


def load() -> None:
    """(Re)load from disk and swap the snapshot. Safe to call at any time."""
    global _snapshot, _loaded_mtime
    with _lock:
        try:
            mtime = SAFELIST_FILE.stat().st_mtime
        except OSError:
            mtime = None
        _snapshot = _Snapshot(_read_file())
        _loaded_mtime = mtime


def _maybe_reload() -> None:
    """Pick up a change made by another worker. Throttled; never raises."""
    global _next_check
    now = time.monotonic()
    if now < _next_check:
        return
    _next_check = now + _RELOAD_CHECK_S
    try:
        try:
            mtime = SAFELIST_FILE.stat().st_mtime
        except OSError:
            mtime = None
        if mtime != _loaded_mtime:
            load()
    except Exception as exc:  # the hot path must not fail because of a disk hiccup
        logger.debug(f"safelist_store reload check failed: {exc}")


def matches(category: str, ip: str, addr=None) -> bool:
    """True if `ip` is covered by a runtime entry in `category`.

    Called from ``_is_safe_ip`` on every request, so it is a frozenset lookup
    plus a scan of a handful of networks. Parse-safe: junk returns False.
    """
    _maybe_reload()
    snap = _snapshot
    if ip in snap.literals[category]:
        return True
    nets = snap.networks[category]
    if not nets:
        return False
    if addr is None:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
    return any(addr in n for n in nets)


def list_entries(category: str) -> list[dict]:
    _maybe_reload()
    return [{"value": k, "kind": "cidr" if m["network"] else "ip", "source": "runtime",
             "added_by": m["added_by"], "added_at": m["added_at"], "note": m["note"]}
            for k, m in sorted(_snapshot.entries[category].items())]


def has(category: str, canonical: str) -> bool:
    _maybe_reload()
    return canonical in _snapshot.entries[category]


def _persist(entries: dict) -> None:
    from app.core.ip_blocker import atomic_write_text
    doc = {"version": 1}
    for cat in CATEGORIES:
        doc[cat] = [{"value": k, "added_by": m["added_by"], "added_at": m["added_at"], "note": m["note"]}
                    for k, m in sorted(entries[cat].items())]
    atomic_write_text(SAFELIST_FILE, json.dumps(doc, indent=2) + "\n")


def _mutate(fn) -> None:
    """Re-read from disk, apply `fn`, write, swap. Re-reading first means two
    workers adding different entries do not overwrite each other's change."""
    global _snapshot, _loaded_mtime
    with _lock:
        entries = _read_file()
        fn(entries)
        _persist(entries)   # raises on a failed write: the caller must not report success
        _snapshot = _Snapshot(entries)
        try:
            _loaded_mtime = SAFELIST_FILE.stat().st_mtime
        except OSError:
            _loaded_mtime = None


def add(category: str, canonical: str, is_network: bool, added_by: str, note: str = "") -> bool:
    """Add a normalized entry. Returns False if it was already present."""
    if category not in CATEGORIES:
        raise SafelistError(f"unknown category {category!r}")
    created = {"v": False}

    def _do(entries):
        if canonical in entries[category]:
            return
        entries[category][canonical] = {
            "network": is_network,
            "added_by": str(added_by)[:120],
            "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": (note or "")[:300],
        }
        created["v"] = True

    _mutate(_do)
    return created["v"]


def remove(category: str, canonical: str) -> bool:
    """Remove a runtime entry. Returns False if it was not there."""
    if category not in CATEGORIES:
        raise SafelistError(f"unknown category {category!r}")
    removed = {"v": False}

    def _do(entries):
        if entries[category].pop(canonical, None) is not None:
            removed["v"] = True

    _mutate(_do)
    return removed["v"]


load()
