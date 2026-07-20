"""
Offline GeoIP / ASN lookup — db-ip.com Lite CSV.

The db-ip.com Lite CSV is sorted by start_ip range. We load it once into a
list of (start_int, end_int, asn, owner) tuples and binary-search at lookup
time. Memory cost: ~470K rows × ~80B = ~38 MB. Acceptable for AEGIS.

Refresh policy: the file is updated monthly. Re-downloaded by
`threat_feeds._refresh_offline_geoip()` (weekly cron). Manual override:
delete the CSV and restart.

CSV format (no header):
    start_ip,end_ip,asn,"owner"

ASN field is the bare number ("13335"); we return "AS13335" to match the
rest of AEGIS's ASN convention.

No external HTTP at lookup time. No PyPI dependency. Pure Python stdlib.
"""

from __future__ import annotations

import array
import csv
import functools
import ipaddress
import logging
import os
import time
from bisect import bisect_right
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("aegis.offline_geoip")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_ASN_CSV = _DATA_DIR / "dbip-asn-lite.csv"
_CITY_CSV = _DATA_DIR / "dbip-city-lite.csv"

# Default URL pattern — month is computed at refresh time.
_DBIP_ASN_URL_TMPL = "https://download.db-ip.com/free/dbip-asn-lite-{ym}.csv.gz"
_DBIP_CITY_URL_TMPL = "https://download.db-ip.com/free/dbip-city-lite-{ym}.csv.gz"

# ---------------------------------------------------------------------------
# MEMORY LAYOUT (v1.6.4.6 — memory-leak fix)
# ---------------------------------------------------------------------------
# The db-ip *city* Lite CSV is 8.07 MILLION rows. Previously it was parsed into
# Python `list[int]` (starts/ends) + `list[tuple[str,str,str]]` (country/region/
# city). A Python int is ~28 B and a 3-string tuple ~200 B, so the city table
# alone cost ~2 GB of RSS — the dominant term in the 3.2 GB worker footprint.
#
# Fix:
#   * starts/ends are stored in `array.array('Q')` — 8 bytes per entry, not ~36.
#   * region/city are DROPPED (nothing depends on them from the offline source;
#     ip_intel only uses offline country/asn as a fallback, region/city come
#     from the live HTTP providers). Only `country` is kept, as a compact
#     uint32 index into a small deduplicated country table (~250 entries).
#   * IPv6 rows are skipped: their 128-bit ints overflow `array('Q')` (uint64)
#     and IPv6 attacker geolocation is rarely needed. IPv6 lookups return None.
# Result: city footprint ~2 GB -> ~160 MB.
# ---------------------------------------------------------------------------

# ASN ranges: compact uint64 arrays for the range bounds, small tuple list for
# the (asn, owner) payload (only ~471K rows, ~40 MB — left as-is).
_asn_starts: "array.array[int]" = array.array("Q")
_asn_ends: "array.array[int]" = array.array("Q")
_asn_data: list[tuple[str, str]] = []  # (asn, owner)
_asn_loaded_at: float = 0.0

# City ranges: uint64 bounds + a uint32 index into `_city_country_table`.
_city_starts: "array.array[int]" = array.array("Q")
_city_ends: "array.array[int]" = array.array("Q")
_city_country_idx: "array.array[int]" = array.array("I")  # index -> _city_country_table
_city_country_table: list[str] = []
_city_loaded_at: float = 0.0

_LOAD_TTL = 24 * 3600.0 * 365  # effectively never re-read on the live process — reload happens on restart

# uint64 ceiling — IPv6 ints exceed this and are skipped (see layout note).
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def _ip_to_int(ip: str) -> Optional[int]:
    try:
        addr = ipaddress.ip_address(ip)
        return int(addr)
    except ValueError:
        return None


def _load_asn_csv() -> None:
    global _asn_starts, _asn_ends, _asn_data, _asn_loaded_at
    now = time.monotonic()
    if _asn_starts and (now - _asn_loaded_at) < _LOAD_TTL:
        return
    if not _ASN_CSV.exists():
        logger.debug("dbip ASN csv not present at %s", _ASN_CSV)
        return
    starts = array.array("Q")
    ends = array.array("Q")
    data: list[tuple[str, str]] = []
    try:
        with _ASN_CSV.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 4:
                    continue
                # Skip IPv6 (colon in the address) — overflows uint64 arrays.
                if ":" in row[0]:
                    continue
                s = _ip_to_int(row[0])
                e = _ip_to_int(row[1])
                if s is None or e is None or e > _UINT64_MAX:
                    continue
                asn_raw = row[2].strip()
                owner = row[3].strip().strip('"')
                asn = f"AS{asn_raw}" if asn_raw.isdigit() else asn_raw
                starts.append(s)
                ends.append(e)
                data.append((asn, owner))
    except Exception as exc:
        logger.warning("dbip ASN csv load failed: %s", exc)
        return
    _asn_starts = starts
    _asn_ends = ends
    _asn_data = data
    _asn_loaded_at = now
    # v1.6.4.9: drop memoized negatives. `lookup` is lru_cached and returns None
    # while the CSVs are still parsing; anything queried during that window (the
    # dashboard warmup pre-runs the /threat-map aggregates ~80s before the city
    # CSV finishes) would otherwise stay None for the life of the process —
    # which is exactly how the threat map ended up reporting every attacker as
    # "Unknown / ??" after a restart.
    lookup.cache_clear()
    logger.info("offline_geoip: loaded %d ASN ranges from %s", len(starts), _ASN_CSV.name)


def _load_city_csv() -> None:
    global _city_starts, _city_ends, _city_country_idx, _city_country_table, _city_loaded_at
    now = time.monotonic()
    if _city_starts and (now - _city_loaded_at) < _LOAD_TTL:
        return
    if not _CITY_CSV.exists():
        logger.debug("dbip city csv not present at %s", _CITY_CSV)
        return
    starts = array.array("Q")
    ends = array.array("Q")
    country_idx = array.array("I")
    table: list[str] = []
    table_map: dict[str, int] = {}
    try:
        with _CITY_CSV.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 8:
                    continue
                # Skip IPv6 (overflows uint64 arrays); IPv6 geo rarely needed.
                if ":" in row[0]:
                    continue
                s = _ip_to_int(row[0])
                e = _ip_to_int(row[1])
                if s is None or e is None or e > _UINT64_MAX:
                    continue
                # db-ip city CSV columns:
                # start, end, continent, country, state1, state2, city, ...
                # Only `country` is retained (region/city dropped — see layout note).
                country = (row[3] if len(row) > 3 else "").strip()
                ci = table_map.get(country)
                if ci is None:
                    ci = len(table)
                    table.append(country)
                    table_map[country] = ci
                starts.append(s)
                ends.append(e)
                country_idx.append(ci)
    except Exception as exc:
        logger.warning("dbip city csv load failed: %s", exc)
        return
    _city_starts = starts
    _city_ends = ends
    _city_country_idx = country_idx
    _city_country_table = table
    _city_loaded_at = now
    # v1.6.4.9: see _load_asn_csv — country resolution only becomes possible
    # here, so every entry memoized before this point is a false negative.
    lookup.cache_clear()
    logger.info(
        "offline_geoip: loaded %d city ranges (%d distinct countries) from %s",
        len(starts), len(table), _CITY_CSV.name,
    )


def _lookup_range(starts, ends, ip_int: int) -> int | None:
    """Binary search: return index where starts[i] <= ip_int <= ends[i], else None.

    `starts`/`ends` are array.array('Q') (or any sorted indexable of ints).
    """
    if not starts:
        return None
    # bisect_right returns the index where ip_int would be inserted to keep
    # `starts` sorted. The candidate range is at index (bisect_right - 1).
    idx = bisect_right(starts, ip_int) - 1
    if idx < 0:
        return None
    if ends[idx] >= ip_int:
        return idx
    return None


@functools.lru_cache(maxsize=8192)
def lookup(ip: str) -> dict | None:
    """Return {asn, asn_owner, country, region, city, source} or None.

    Cache is cleared by the refresh job (see refresh_async) so stale ASN
    owners don't survive a monthly db-ip refresh.
    """
    ip_int = _ip_to_int(ip)
    if ip_int is None:
        return None
    # v1.6.3.3: only trigger CSV load if cache is already populated; never
    # block the event loop synchronously to parse 8M rows. If unloaded,
    # return None and let the warmup task fill the cache off-loop.
    if not _asn_starts:
        return None

    out: dict = {"source": "dbip_offline"}
    a_idx = _lookup_range(_asn_starts, _asn_ends, ip_int)
    if a_idx is not None:
        asn, owner = _asn_data[a_idx]
        out["asn"] = asn
        out["asn_owner"] = owner

    # City lookup is opportunistic — skip silently when the CSV hasn't been
    # parsed yet. v1.6.4.6: only `country` is stored (region/city dropped to
    # save ~2 GB RSS); region/city now come only from live HTTP providers.
    if _city_starts:
        c_idx = _lookup_range(_city_starts, _city_ends, ip_int)
        if c_idx is not None:
            country = _city_country_table[_city_country_idx[c_idx]]
            if country:
                out["country"] = country

    # No useful data? Return None so caller doesn't add an empty feed.
    if "asn" not in out and "country" not in out:
        return None
    return out


# ---------------------------------------------------------------------------
# Refresh — called from threat_feeds.py weekly cron
# ---------------------------------------------------------------------------

async def refresh_async(force: bool = False) -> dict:
    """Download the current month's db-ip Lite CSVs and persist locally.

    Returns a small status dict. Safe to call repeatedly; only downloads when
    the local file is missing OR older than 25 days OR force=True.
    """
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    out: dict = {"asn": "skipped", "city": "skipped"}
    import datetime as _dt
    now = _dt.datetime.utcnow()
    ym = f"{now.year}-{now.month:02d}"

    for kind, dest, url_tmpl in (
        ("asn", _ASN_CSV, _DBIP_ASN_URL_TMPL),
        ("city", _CITY_CSV, _DBIP_CITY_URL_TMPL),
    ):
        try:
            need = force or (not dest.exists()) or (
                (time.time() - dest.stat().st_mtime) > 25 * 86400
            )
            if not need:
                out[kind] = "fresh"
                continue
            # Try this month first, then previous month if 404.
            candidates = [ym]
            prev_month = (now.replace(day=1) - _dt.timedelta(days=1))
            candidates.append(f"{prev_month.year}-{prev_month.month:02d}")
            async with httpx.AsyncClient(timeout=60.0) as client:
                for cand in candidates:
                    url = url_tmpl.format(ym=cand)
                    try:
                        r = await client.get(url)
                        if r.status_code != 200:
                            continue
                        # Decompress gzip
                        import gzip
                        raw = gzip.decompress(r.content)
                        dest.write_bytes(raw)
                        out[kind] = f"downloaded {cand} ({len(raw)} bytes)"
                        logger.info("offline_geoip: %s downloaded %s -> %s", kind, cand, dest)
                        break
                    except Exception as exc:
                        logger.debug("dbip %s candidate %s failed: %s", kind, cand, exc)
                else:
                    out[kind] = "error: no candidate worked"
        except Exception as exc:
            out[kind] = f"error: {exc}"
    # v1.6.3.3: do NOT invalidate in-memory cache here. Doing so causes the
    # next lookup() to trigger a full 8M-row CSV reparse SYNCHRONOUSLY on the
    # event loop (3-4 minutes of blocked I/O for the entire process). New CSV
    # data on disk will be picked up on next process restart. The lru_cache is
    # also kept warm — values it returned reflect the old CSV but the dataset
    # changes at most monthly, and stale ASN/country tags are non-blocking.
    return out


def status() -> dict:
    """Report what's cached locally."""
    return {
        "asn_csv": {
            "path": str(_ASN_CSV),
            "exists": _ASN_CSV.exists(),
            "size": _ASN_CSV.stat().st_size if _ASN_CSV.exists() else 0,
            "ranges_loaded": len(_asn_starts),
        },
        "city_csv": {
            "path": str(_CITY_CSV),
            "exists": _CITY_CSV.exists(),
            "size": _CITY_CSV.stat().st_size if _CITY_CSV.exists() else 0,
            "ranges_loaded": len(_city_starts),
        },
    }
