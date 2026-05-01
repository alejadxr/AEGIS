"""RaaS group threat intel — refreshes from public feeds, exposes IOCs to AEGIS."""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("aegis.raas_intel")

DATA_DIR = Path(__file__).parent.parent / "data" / "raas"
REFRESH_INTERVAL = timedelta(hours=6)

RAAS_FEEDS = {
    "ransomlook": "https://www.ransomlook.io/api/groups",
    "cisa_lockbit": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a/iocs.json",
}


@dataclass
class RaaSGroup:
    id: str
    name: str
    aliases: list[str]
    active_since: str
    last_seen: str
    targets_industry: list[str]
    c2_ips: list[str] = field(default_factory=list)
    c2_domains: list[str] = field(default_factory=list)
    onion_addresses: list[str] = field(default_factory=list)
    file_extensions: list[str] = field(default_factory=list)
    ransom_note_artifacts: list[str] = field(default_factory=list)


@dataclass
class RaaSPack:
    groups: dict[str, RaaSGroup] = field(default_factory=dict)
    last_refresh: Optional[datetime] = None

    @classmethod
    def load_from_disk(cls) -> "RaaSPack":
        pack = cls()
        if not DATA_DIR.exists():
            return pack
        for f in DATA_DIR.glob("*.json"):
            try:
                d = json.loads(f.read_text())
                pack.groups[d["id"]] = RaaSGroup(**d)
            except Exception as exc:
                logger.warning("RaaS feed %s failed to parse: %s", f.name, exc)
        return pack

    def all_iocs(self) -> dict[str, list[str]]:
        ips, domains, onions, exts = [], [], [], []
        for g in self.groups.values():
            ips.extend(g.c2_ips)
            domains.extend(g.c2_domains)
            onions.extend(g.onion_addresses)
            exts.extend(g.file_extensions)
        return {"ip": ips, "domain": domains, "onion": onions, "file_ext": exts}


class RaaSIntel:
    def __init__(self, http: Optional[httpx.AsyncClient] = None):
        self._http = http or httpx.AsyncClient(timeout=30)
        self._pack = RaaSPack.load_from_disk()

    @property
    def pack(self) -> RaaSPack:
        return self._pack

    async def refresh(self) -> int:
        """Pull latest feeds and persist to DATA_DIR. Returns number of groups updated."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        updated = 0
        for source_id, url in RAAS_FEEDS.items():
            try:
                r = await self._http.get(url)
                r.raise_for_status()
                data = r.json()
                for group_data in self._normalize(source_id, data):
                    gid = group_data["id"]
                    (DATA_DIR / f"{gid}.json").write_text(json.dumps(group_data, indent=2))
                    self._pack.groups[gid] = RaaSGroup(**group_data)
                    updated += 1
            except httpx.HTTPError as exc:
                logger.warning("Source %s unavailable: %s", source_id, exc)
            except Exception as exc:
                logger.error("Source %s parse failed: %s", source_id, exc)
        self._pack.last_refresh = datetime.utcnow()
        return updated

    def _normalize(self, source_id: str, raw) -> list[dict]:
        """Adapt source-specific shape to RaaSGroup kwargs."""
        if source_id == "ransomlook":
            if not isinstance(raw, dict):
                return []
            return [
                {
                    "id": g["name"].lower().replace(" ", "_"),
                    "name": g["name"],
                    "aliases": g.get("aliases", []),
                    "active_since": g.get("first_seen", "unknown"),
                    "last_seen": g.get("last_seen", "unknown"),
                    "targets_industry": g.get("sectors", []),
                    "c2_ips": g.get("ips", []),
                    "c2_domains": g.get("domains", []),
                    "onion_addresses": g.get("onions", []),
                    "file_extensions": g.get("extensions", []),
                    "ransom_note_artifacts": g.get("notes", []),
                }
                for g in raw.get("groups", [])
                if isinstance(g, dict) and g.get("name")
            ]
        if source_id == "cisa_lockbit":
            if not isinstance(raw, dict):
                return []
            return [
                {
                    "id": "lockbit_cisa",
                    "name": "LockBit (CISA AA-23-061a)",
                    "aliases": ["LockBit 3.0", "LockBit Black"],
                    "active_since": "2019-09-01",
                    "last_seen": raw.get("last_updated", "2024-01-01"),
                    "targets_industry": raw.get("sectors_targeted", []),
                    "c2_ips": raw.get("ips", []),
                    "c2_domains": raw.get("domains", []),
                    "onion_addresses": raw.get("onions", []),
                    "file_extensions": [".lockbit", ".lockbit3"],
                    "ransom_note_artifacts": ["Restore-My-Files.txt"],
                }
            ]
        return []

    async def start(self):
        """Background loop — refresh every REFRESH_INTERVAL."""
        while True:
            try:
                count = await self.refresh()
                logger.info("RaaS intel refresh: %d groups", count)
            except Exception as exc:
                logger.error("RaaS refresh failed: %s", exc)
            await asyncio.sleep(REFRESH_INTERVAL.total_seconds())
