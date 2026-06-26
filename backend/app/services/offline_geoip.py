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

# In-memory parallel arrays — keep the cold-path sorted-start-ip list separate
# from the payload so bisect over a flat list is cache-friendly.
_asn_starts: list[int] = []
_asn_ends: list[int] = []
_asn_data: list[tuple[str, str]] = []  # (asn, owner)
_asn_loaded_at: float = 0.0

_city_starts: list[int] = []
_city_ends: list[int] = []
_city_data: list[tuple[str, str, str]] = []  # (country, region, city)
_city_loaded_at: float = 0.0

_LOAD_TTL = 6 * 3600.0  # re-read CSV every 6h in case it was refreshed


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
    starts: list[int] = []
    ends: list[int] = []
    data: list[tuple[str, str]] = []
    try:
        with _ASN_CSV.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 4:
                    continue
                s = _ip_to_int(row[0])
                e = _ip_to_int(row[1])
                if s is None or e is None:
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
    logger.info("offline_geoip: loaded %d ASN ranges from %s", len(starts), _ASN_CSV.name)


def _load_city_csv() -> None:
    global _city_starts, _city_ends, _city_data, _city_loaded_at
    now = time.monotonic()
    if _city_starts and (now - _city_loaded_at) < _LOAD_TTL:
        return
    if not _CITY_CSV.exists():
        logger.debug("dbip city csv not present at %s", _CITY_CSV)
        return
    starts: list[int] = []
    ends: list[int] = []
    data: list[tuple[str, str, str]] = []
    try:
        with _CITY_CSV.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if len(row) < 8:
                    continue
                s = _ip_to_int(row[0])
                e = _ip_to_int(row[1])
                if s is None or e is None:
                    continue
                # db-ip city CSV columns:
                # start, end, continent, country, state1, state2, city, postcode, lat, lon, tz
                country = (row[3] if len(row) > 3 else "").strip()
                region = (row[4] if len(row) > 4 else "").strip()
                city = (row[6] if len(row) > 6 else "").strip()
                starts.append(s)
                ends.append(e)
                data.append((country, region, city))
    except Exception as exc:
        logger.warning("dbip city csv load failed: %s", exc)
        return
    _city_starts = starts
    _city_ends = ends
    _city_data = data
    _city_loaded_at = now
    logger.info("offline_geoip: loaded %d city ranges from %s", len(starts), _CITY_CSV.name)


def _lookup_range(starts: list[int], ends: list[int], ip_int: int) -> int | None:
    """Binary search: return index where starts[i] <= ip_int <= ends[i], else None."""
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
    _load_asn_csv()
    _load_city_csv()

    out: dict = {"source": "dbip_offline"}
    a_idx = _lookup_range(_asn_starts, _asn_ends, ip_int)
    if a_idx is not None:
        asn, owner = _asn_data[a_idx]
        out["asn"] = asn
        out["asn_owner"] = owner

    c_idx = _lookup_range(_city_starts, _city_ends, ip_int)
    if c_idx is not None:
        country, region, city = _city_data[c_idx]
        if country:
            out["country"] = country
        if region:
            out["region"] = region
        if city:
            out["city"] = city

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
    # Force-invalidate caches so next lookup picks up new data
    global _asn_loaded_at, _city_loaded_at
    _asn_loaded_at = 0.0
    _city_loaded_at = 0.0
    try:
        lookup.cache_clear()
    except Exception:
        pass
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
