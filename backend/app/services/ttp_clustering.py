"""
TTP Sequence Clustering for AEGIS.

Detects repeated attack patterns even when source IPs rotate (Tor exits, VPN
hopping, botnets). Groups incidents by their MITRE TTP fingerprint —
(technique, tactic) tuple — and surfaces clusters with 3+ distinct source IPs
in the last 24h as "campaigns" for human triage.

Does NOT auto-block based on clustering. Surfaces data only.
"""
from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident

logger = logging.getLogger("aegis.ttp_clustering")

# Minimum distinct source IPs needed to consider a TTP cluster a "campaign".
CAMPAIGN_MIN_DISTINCT_IPS = 3
# Default lookback window for campaign detection.
DEFAULT_WINDOW_HOURS = 24


def compute_ttp_fingerprint(incident: Incident) -> Optional[str]:
    """Return a stable fingerprint string for an incident's MITRE TTP, or None."""
    technique = (incident.mitre_technique or "").strip()
    tactic = (incident.mitre_tactic or "").strip()
    if not technique and not tactic:
        return None
    # Tuple-style fingerprint (sortable, human-readable)
    return f"{tactic}::{technique}"


def cluster_id_for(fingerprint: str) -> str:
    """8-char stable hash used as the public cluster identifier."""
    return hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:8]


async def detect_campaigns(
    db: AsyncSession,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    min_distinct_ips: int = CAMPAIGN_MIN_DISTINCT_IPS,
    client_id: Optional[str] = None,
    limit: int = 20,
) -> list[dict]:
    """
    Group recent incidents by TTP fingerprint and return active campaigns.

    Returns a list of cluster dicts sorted by total_incidents desc, capped at `limit`:
      {
        cluster_id, ttp_fingerprint, mitre_technique, mitre_tactic,
        distinct_ips, total_incidents, first_seen, last_seen, sample_ips
      }
    """
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    q = select(Incident).where(Incident.detected_at >= cutoff)
    if client_id:
        q = q.where(Incident.client_id == client_id)

    result = await db.execute(q)
    incidents = result.scalars().all()

    # Group by fingerprint
    by_fp: dict[str, list[Incident]] = defaultdict(list)
    for inc in incidents:
        fp = compute_ttp_fingerprint(inc)
        if fp is None:
            continue
        by_fp[fp].append(inc)

    campaigns: list[dict] = []
    for fp, group in by_fp.items():
        distinct_ips = {i.source_ip for i in group if i.source_ip}
        if len(distinct_ips) < min_distinct_ips:
            continue
        first_seen = min(i.detected_at for i in group)
        last_seen = max(i.detected_at for i in group)
        sample = sorted(distinct_ips)[:5]
        # Pick representative technique/tactic from first incident
        rep = group[0]
        campaigns.append({
            "cluster_id": cluster_id_for(fp),
            "ttp_fingerprint": fp,
            "mitre_technique": rep.mitre_technique,
            "mitre_tactic": rep.mitre_tactic,
            "distinct_ips": len(distinct_ips),
            "total_incidents": len(group),
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "sample_ips": sample,
            "window_hours": window_hours,
        })

    campaigns.sort(key=lambda c: (c["total_incidents"], c["distinct_ips"]), reverse=True)
    return campaigns[:limit]
