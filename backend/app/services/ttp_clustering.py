"""
TTP Sequence Clustering for AEGIS.

Detects repeated attack patterns even when source IPs rotate (Tor exits, VPN
hopping, botnets). Groups incidents by their MITRE TTP fingerprint —
(technique, tactic) tuple — and surfaces clusters with 3+ distinct source IPs
in the last 24h as "campaigns" for human triage.

Does NOT auto-block based on clustering. Surfaces data only.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from collections import Counter, defaultdict
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


# ---------------------------------------------------------------------------
# Drill-down detail (v1.7+) — used by GET /threats/campaigns/{cluster_id}
# ---------------------------------------------------------------------------

# MITRE technique → human-readable name + tactic hint. Lightweight (keeps the
# file self-contained); add to it as new techniques appear in incident sources.
_MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1110.004": {"name": "Credential Stuffing", "tactic": "Credential Access"},
    "T1595.001": {"name": "Scanning IP Blocks", "tactic": "Reconnaissance"},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
    "T1595.003": {"name": "Wordlist Scanning", "tactic": "Reconnaissance"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
    "T1071.001": {"name": "Web Protocols (C2)", "tactic": "Command and Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}


def _expand_technique(tcode: Optional[str], tactic_hint: Optional[str]) -> dict:
    """Return {id, name, tactic, url} for a MITRE technique code."""
    if not tcode:
        return {
            "id": None,
            "name": "Unspecified technique",
            "tactic": tactic_hint or "Unknown",
            "url": None,
            "description": "No MITRE technique was attached to these incidents.",
        }
    meta = _MITRE_TECHNIQUES.get(tcode, {})
    base = tcode.split(".")[0]
    sub = tcode.split(".")[1] if "." in tcode else None
    url = f"https://attack.mitre.org/techniques/{base}/{sub}/" if sub else f"https://attack.mitre.org/techniques/{base}/"
    return {
        "id": tcode,
        "name": meta.get("name", tcode),
        "tactic": meta.get("tactic", tactic_hint or "Unknown"),
        "url": url,
        "description": meta.get("name", tcode),
    }


def _recommended_action(technique: Optional[str], distinct_ips: int, is_active: bool) -> str:
    if not is_active:
        return "Campaign is dormant (no incidents in the last 24h). Monitor; no action required."
    if technique and technique.startswith("T1110"):
        return f"Brute-force pattern across {distinct_ips} IPs — rate-limit auth endpoints, force MFA, and block recurring offenders."
    if technique and technique.startswith("T1595"):
        return f"Recon pattern across {distinct_ips} IPs — exposing nothing new is the best defence. Confirm honeypot is catching them and review surface assets."
    if technique == "T1190":
        return "Exploit attempts on public app — patch the targeted endpoint, enable WAF rules for the technique, and block source IPs."
    return f"Investigate the {distinct_ips} attacker IPs in IP Intel; block confirmed-malicious."


async def get_campaign_detail(
    db: AsyncSession,
    cluster_id: str,
    window_hours: int = 168,
    client_id: Optional[str] = None,
    max_ip_enrichments: int = 50,
) -> Optional[dict]:
    """
    Return rich detail for a single cluster, or None if not found in the window.

    Includes incidents list, distinct IPs with brief IP intel, MITRE
    technique expansion, severity distribution, active flag, recommended action.
    """
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    q = select(Incident).where(Incident.detected_at >= cutoff)
    if client_id:
        q = q.where(Incident.client_id == client_id)
    result = await db.execute(q)
    all_incidents = result.scalars().all()

    # Find incidents whose fingerprint hashes to cluster_id
    members: list[Incident] = []
    fingerprint: Optional[str] = None
    for inc in all_incidents:
        fp = compute_ttp_fingerprint(inc)
        if fp is None:
            continue
        if cluster_id_for(fp) == cluster_id:
            members.append(inc)
            fingerprint = fp

    if not members or fingerprint is None:
        return None

    rep = members[0]
    technique = _expand_technique(rep.mitre_technique, rep.mitre_tactic)
    distinct_ip_list = sorted({i.source_ip for i in members if i.source_ip})
    first_seen = min(i.detected_at for i in members)
    last_seen = max(i.detected_at for i in members)
    now = datetime.utcnow()
    is_active = (now - last_seen) <= timedelta(hours=24)

    severity_dist = dict(Counter((i.severity or "unknown").lower() for i in members))

    # Enrich each IP via ip_intel.lookup with a hard per-IP timeout. Bounded.
    enriched_ips: list[dict] = []
    try:
        from app.services import ip_intel
        ips_to_enrich = distinct_ip_list[:max_ip_enrichments]

        async def _enrich(ip: str) -> dict:
            try:
                data = await asyncio.wait_for(ip_intel.lookup(ip, deep=False), timeout=3.0)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                data = {"ip": ip, "error": "lookup_failed"}
            return {
                "ip": ip,
                "country": data.get("country") or data.get("country_code"),
                "asn": data.get("asn"),
                "org": (data.get("org") or "")[:80] if data.get("org") else None,
                "classification": data.get("classification") or ("internal" if data.get("internal") else None),
                "is_tor": bool(data.get("is_tor")) if "is_tor" in data else None,
                "is_vpn": bool(data.get("is_vpn")) if "is_vpn" in data else None,
                "risk_score": data.get("risk_score"),
                "blocked": False,  # filled below
            }

        enriched_ips = await asyncio.gather(*[_enrich(ip) for ip in ips_to_enrich], return_exceptions=False)
    except Exception as exc:  # noqa: BLE001
        logger.warning("ip enrichment failed for cluster %s: %s", cluster_id, exc)
        enriched_ips = [{"ip": ip, "error": "enrichment_failed"} for ip in distinct_ip_list[:max_ip_enrichments]]

    # Cross-reference blocked IPs (best-effort, file-backed).
    try:
        import os
        blocked_path = os.path.expanduser(os.environ.get("BLOCKED_IPS_FILE", "~/.aegis/blocked_ips.txt"))
        if os.path.exists(blocked_path):
            with open(blocked_path, "r", encoding="utf-8") as fh:
                blocked_set = {line.strip() for line in fh if line.strip() and not line.startswith("#")}
            for entry in enriched_ips:
                entry["blocked"] = entry["ip"] in blocked_set
    except Exception:  # noqa: BLE001
        pass

    incident_dicts = sorted(
        [
            {
                "id": inc.id,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "source_ip": inc.source_ip,
                "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
            }
            for inc in members
        ],
        key=lambda d: d["detected_at"] or "",
    )

    # Investigated flag from client.settings
    investigated = None
    if client_id:
        try:
            from app.models.client import Client as ClientModel
            cli = await db.get(ClientModel, client_id)
            if cli and isinstance(cli.settings, dict):
                inv_map = (cli.settings.get("investigated_clusters") or {})
                if cluster_id in inv_map:
                    investigated = inv_map[cluster_id]
        except Exception:  # noqa: BLE001
            pass

    return {
        "cluster_id": cluster_id,
        "ttp_fingerprint": fingerprint,
        "mitre_technique": rep.mitre_technique,
        "mitre_tactic": rep.mitre_tactic,
        "technique_detail": technique,
        "distinct_ips_count": len(distinct_ip_list),
        "total_incidents": len(members),
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "duration_hours": round((last_seen - first_seen).total_seconds() / 3600, 1),
        "is_active": is_active,
        "severity_distribution": severity_dist,
        "recommended_action": _recommended_action(rep.mitre_technique, len(distinct_ip_list), is_active),
        "ips": enriched_ips,
        "incidents": incident_dicts,
        "window_hours": window_hours,
        "investigated": investigated,
    }


async def mark_campaign_investigated(
    db: AsyncSession,
    cluster_id: str,
    client_id: str,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
) -> dict:
    """Persist an 'investigated' flag for a cluster on the client's settings JSON.

    Stored at client.settings["investigated_clusters"][cluster_id] = {at, by_email}.
    """
    from app.models.client import Client as ClientModel

    cli = await db.get(ClientModel, client_id)
    if not cli:
        return {"ok": False, "error": "client_not_found"}

    settings = dict(cli.settings) if isinstance(cli.settings, dict) else {}
    inv_map = dict(settings.get("investigated_clusters") or {})
    entry = {
        "at": datetime.utcnow().isoformat(),
        "by_user_id": user_id,
        "by_email": user_email,
    }
    inv_map[cluster_id] = entry
    settings["investigated_clusters"] = inv_map
    cli.settings = settings
    await db.commit()
    return {"ok": True, "cluster_id": cluster_id, "entry": entry}
