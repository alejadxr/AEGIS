import asyncio
import json
import subprocess
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.config import settings
from app.database import get_db
from app.core.auth import AuthContext, require_viewer
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.action import Action
from app.models.honeypot import HoneypotInteraction
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class OverviewStats(BaseModel):
    total_assets: int
    open_vulnerabilities: int
    critical_vulnerabilities: int
    active_incidents: int
    honeypot_interactions: int
    actions_taken: int
    risk_level: str


class TimelineEvent(BaseModel):
    id: str
    type: str
    title: str
    severity: str | None = None
    timestamp: str


# ISO 3166-1 alpha-2 → country name map for common countries.
# Fallback: use country_code as name for anything not listed.
_COUNTRY_NAMES: dict[str, str] = {
    "US": "United States", "CN": "China", "RU": "Russia", "DE": "Germany",
    "GB": "United Kingdom", "FR": "France", "NL": "Netherlands", "BR": "Brazil",
    "IN": "India", "UA": "Ukraine", "KR": "South Korea", "JP": "Japan",
    "CA": "Canada", "AU": "Australia", "SG": "Singapore", "HK": "Hong Kong",
    "TR": "Turkey", "VN": "Vietnam", "IT": "Italy", "ES": "Spain",
    "PL": "Poland", "IR": "Iran", "RO": "Romania", "SE": "Sweden",
    "NO": "Norway", "FI": "Finland", "DK": "Denmark", "CH": "Switzerland",
    "AT": "Austria", "BE": "Belgium", "PH": "Philippines", "ID": "Indonesia",
    "TH": "Thailand", "MY": "Malaysia", "MX": "Mexico", "AR": "Argentina",
    "ZA": "South Africa", "EG": "Egypt", "NG": "Nigeria", "IL": "Israel",
    "SA": "Saudi Arabia", "AE": "UAE", "PK": "Pakistan", "BD": "Bangladesh",
    "CZ": "Czech Republic", "HU": "Hungary", "PT": "Portugal", "GR": "Greece",
    "BG": "Bulgaria", "SK": "Slovakia", "HR": "Croatia", "RS": "Serbia",
    "BY": "Belarus", "KZ": "Kazakhstan", "TW": "Taiwan", "HN": "Honduras",
    "PA": "Panama", "BO": "Bolivia", "CL": "Chile", "CO": "Colombia",
    "PE": "Peru", "VE": "Venezuela", "CU": "Cuba", "EC": "Ecuador",
    "TZ": "Tanzania", "KE": "Kenya", "GH": "Ghana", "ET": "Ethiopia",
    "MA": "Morocco", "TN": "Tunisia", "DZ": "Algeria", "LY": "Libya",
    "SY": "Syria", "IQ": "Iraq", "AF": "Afghanistan", "MM": "Myanmar",
    "KH": "Cambodia", "LK": "Sri Lanka", "NP": "Nepal", "NZ": "New Zealand",
}


class ThreatMapEntry(BaseModel):
    country: str
    country_code: str
    count: int


@router.get("/overview", response_model=OverviewStats)
async def get_overview(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard overview statistics."""
    client = auth.client
    (
        total_assets, open_vulns, critical_vulns,
        active_incidents, hp_interactions, actions_taken,
    ) = await asyncio.gather(
        db.scalar(select(func.count(Asset.id)).where(Asset.client_id == client.id)),
        db.scalar(select(func.count(Vulnerability.id)).where(
            Vulnerability.client_id == client.id,
            Vulnerability.status == "open",
        )),
        db.scalar(select(func.count(Vulnerability.id)).where(
            Vulnerability.client_id == client.id,
            Vulnerability.severity == "critical",
            Vulnerability.status == "open",
        )),
        db.scalar(select(func.count(Incident.id)).where(
            Incident.client_id == client.id,
            Incident.status.in_(["open", "investigating"]),
        )),
        db.scalar(select(func.count(HoneypotInteraction.id)).where(
            HoneypotInteraction.client_id == client.id,
        )),
        db.scalar(select(func.count(Action.id)).where(
            Action.client_id == client.id,
            Action.status == "executed",
        )),
    )
    total_assets = total_assets or 0
    open_vulns = open_vulns or 0
    critical_vulns = critical_vulns or 0
    active_incidents = active_incidents or 0
    hp_interactions = hp_interactions or 0
    actions_taken = actions_taken or 0

    score = critical_vulns * 10 + active_incidents * 5
    if score >= 50:
        risk_level = "critical"
    elif score >= 20:
        risk_level = "high"
    elif score >= 5:
        risk_level = "medium"
    else:
        risk_level = "low"

    return OverviewStats(
        total_assets=total_assets,
        open_vulnerabilities=open_vulns,
        critical_vulnerabilities=critical_vulns,
        active_incidents=active_incidents,
        honeypot_interactions=hp_interactions,
        actions_taken=actions_taken,
        risk_level=risk_level,
    )


@router.get("/timeline", response_model=list[TimelineEvent])
async def get_timeline(
    limit: int = 50,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get recent activity timeline."""
    client = auth.client
    events = []

    result = await db.execute(
        select(Incident)
        .where(Incident.client_id == client.id)
        .order_by(Incident.detected_at.desc())
        .limit(limit // 2)
    )
    for inc in result.scalars().all():
        events.append(TimelineEvent(
            id=inc.id,
            type="incident",
            title=inc.title,
            severity=inc.severity,
            timestamp=inc.detected_at.isoformat(),
        ))

    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.client_id == client.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit // 2)
    )
    for log in result.scalars().all():
        events.append(TimelineEvent(
            id=log.id,
            type="audit",
            title=f"AI: {log.action}",
            severity=None,
            timestamp=log.timestamp.isoformat(),
        ))

    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]


class Top10Row(BaseModel):
    label: str
    count: int
    meta: str | None = None


class LiveMetrics(BaseModel):
    top_attackers: list[Top10Row]
    top_targets: list[Top10Row]
    top_attack_types: list[Top10Row]
    incidents_open: int
    honeypot_hits_24h: int
    blocked_actions_24h: int
    ai_decisions_24h: int
    generated_at: str


@router.get("/live-metrics", response_model=LiveMetrics)
async def get_live_metrics(
    window: str = "24h",
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Cached aggregates for the Live SOC dashboard.

    v1.6.2: configurable ?window=24h|7d|30d|all so operators can see slow-burn
    campaigns that the previous hard-coded 24h cutoff hid.

    Returns:
      - Top 10 attacker IPs (by incident count)
      - Top 10 targets (assets by incident count)
      - Top 10 attack types (by mitre_technique count)
      - Rolling counters (open incidents, hits, blocks, decisions)
    """
    client = auth.client
    # v1.6.2: configurable window. "all" disables the time filter.
    _WINDOW_MAP = {
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "all": None,
    }
    delta = _WINDOW_MAP.get(window, timedelta(hours=24))
    cutoff = datetime.utcnow() - delta if delta else datetime(1970, 1, 1)

    # v1.6.3.2: run all 7 queries in parallel via asyncio.gather instead of
    # sequentially. Previously this endpoint took ~1.1s on a busy DB because
    # each await blocked the next. Now total time ≈ slowest single query.
    attackers_q = db.execute(
        select(Incident.source_ip, func.count(Incident.id).label("c"))
        .where(
            Incident.client_id == client.id,
            Incident.source_ip.is_not(None),
            Incident.detected_at >= cutoff,
        )
        .group_by(Incident.source_ip)
        .order_by(func.count(Incident.id).desc())
        .limit(10)
    )
    targets_q = db.execute(
        select(Asset.hostname, Asset.ip_address, func.count(Incident.id).label("c"))
        .join(Incident, Incident.target_asset_id == Asset.id, isouter=False)
        .where(Asset.client_id == client.id, Incident.detected_at >= cutoff)
        .group_by(Asset.hostname, Asset.ip_address)
        .order_by(func.count(Incident.id).desc())
        .limit(10)
    )
    types_q = db.execute(
        select(Incident.mitre_technique, func.count(Incident.id).label("c"))
        .where(
            Incident.client_id == client.id,
            Incident.mitre_technique.is_not(None),
            Incident.detected_at >= cutoff,
        )
        .group_by(Incident.mitre_technique)
        .order_by(func.count(Incident.id).desc())
        .limit(10)
    )
    open_q = db.scalar(
        select(func.count(Incident.id)).where(
            Incident.client_id == client.id,
            Incident.status.in_(["open", "investigating"]),
        )
    )
    honey_q = db.scalar(
        select(func.count(HoneypotInteraction.id)).where(
            HoneypotInteraction.client_id == client.id,
            HoneypotInteraction.timestamp >= cutoff,
        )
    )
    blocked_q = db.scalar(
        select(func.count(Action.id)).where(
            Action.client_id == client.id,
            Action.status == "executed",
            Action.created_at >= cutoff,
        )
    )
    decisions_q = db.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.client_id == client.id,
            AuditLog.timestamp >= cutoff,
        )
    )

    (
        attackers_result, targets_result, types_result,
        incidents_open, honeypot_hits_24h, blocked_actions_24h, ai_decisions_24h,
    ) = await asyncio.gather(
        attackers_q, targets_q, types_q, open_q, honey_q, blocked_q, decisions_q,
    )

    top_attackers = [
        Top10Row(label=row[0] or "unknown", count=int(row[1] or 0))
        for row in attackers_result.all()
    ]
    top_targets = [
        Top10Row(
            label=row[0] or row[1] or "unknown",
            count=int(row[2] or 0),
            meta=row[1] if row[0] and row[1] else None,
        )
        for row in targets_result.all()
    ]
    top_attack_types = [
        Top10Row(label=row[0] or "unknown", count=int(row[1] or 0))
        for row in types_result.all()
    ]
    incidents_open = incidents_open or 0
    honeypot_hits_24h = honeypot_hits_24h or 0
    blocked_actions_24h = blocked_actions_24h or 0
    ai_decisions_24h = ai_decisions_24h or 0

    return LiveMetrics(
        top_attackers=top_attackers,
        top_targets=top_targets,
        top_attack_types=top_attack_types,
        incidents_open=int(incidents_open),
        honeypot_hits_24h=int(honeypot_hits_24h),
        blocked_actions_24h=int(blocked_actions_24h),
        ai_decisions_24h=int(ai_decisions_24h),
        generated_at=datetime.utcnow().isoformat(),
    )


@router.get("/threat-map", response_model=list[ThreatMapEntry])
async def get_threat_map(
    window: str = "all",
    limit_per_source: int = 2000,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get threat geography data grouped by country.

    v1.6.2: adds ?window=24h|7d|30d|all (default: all — full history) and
    ?limit_per_source=N (default 2000, was 200 hard-coded). The previous
    LIMIT 200 per leg caused a single high-volume attacker to crowd out the
    long-tail of historical attackers. The [:50] country cap is also removed
    so every ISO-3166 code with any activity is returned.

    Resolves attacker IPs to countries via offline GeoIP and returns
    {country, country_code, count} for the GlobalThreatMap component.
    """
    from app.services import offline_geoip

    client = auth.client

    # v1.6.2: configurable window
    _WINDOW_MAP = {
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "all": None,
    }
    delta = _WINDOW_MAP.get(window, None)
    cutoff = datetime.utcnow() - delta if delta else None

    # Collect attacker IPs from honeypot interactions
    hp_q = select(
        HoneypotInteraction.source_ip,
        func.count(HoneypotInteraction.id).label("count"),
    ).where(HoneypotInteraction.client_id == client.id)
    if cutoff:
        hp_q = hp_q.where(HoneypotInteraction.timestamp >= cutoff)
    hp_q = (
        hp_q.group_by(HoneypotInteraction.source_ip)
        .order_by(func.count(HoneypotInteraction.id).desc())
        .limit(limit_per_source)
    )
    # Collect attacker IPs from incidents
    inc_q = select(
        Incident.source_ip,
        func.count(Incident.id).label("count"),
    ).where(
        Incident.client_id == client.id,
        Incident.source_ip.is_not(None),
    )
    if cutoff:
        inc_q = inc_q.where(Incident.detected_at >= cutoff)
    inc_q = (
        inc_q.group_by(Incident.source_ip)
        .order_by(func.count(Incident.id).desc())
        .limit(limit_per_source)
    )
    hp_result, inc_result = await asyncio.gather(db.execute(hp_q), db.execute(inc_q))

    # Aggregate count per IP (combine both sources)
    ip_counts: dict[str, int] = {}
    for row in hp_result.all():
        ip = row[0]
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + int(row[1] or 0)
    for row in inc_result.all():
        ip = row[0]
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + int(row[1] or 0)

    # Resolve IPs to countries and aggregate count per country
    country_counts: dict[str, int] = {}
    for ip, count in ip_counts.items():
        geo = offline_geoip.lookup(ip)
        country_code = (geo or {}).get("country", "??")
        if not country_code:
            country_code = "??"
        country_counts[country_code] = country_counts.get(country_code, 0) + count

    # Build response sorted by count descending — v1.6.2: removed [:50] cap so
    # every ISO-3166 code with activity is returned to the frontend.
    entries = []
    for cc, count in sorted(country_counts.items(), key=lambda x: -x[1]):
        country_name = _COUNTRY_NAMES.get(cc, cc if cc != "??" else "Unknown")
        entries.append(ThreatMapEntry(
            country=country_name,
            country_code=cc,
            count=count,
        ))
    return entries


# ---------------------------------------------------------------------------
# Monitored Apps
# ---------------------------------------------------------------------------

class MonitoredAppOut(BaseModel):
    name: str
    status: str
    open_incidents: int
    last_activity: Optional[str] = None
    resolved_count: int


class MonitoredAppsOut(BaseModel):
    apps: list[MonitoredAppOut]
    count: int


def _get_pm2_statuses() -> dict[str, str]:
    """
    Try to read PM2 process list. Returns {name: status} dict.
    Falls back to empty dict on any error (pm2 not installed, not in PATH, etc).
    Never uses lsof.
    """
    try:
        result = subprocess.run(
            ["pm2", "jlist"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        procs = json.loads(result.stdout)
        return {
            p.get("name", ""): (p.get("pm2_env", {}) or {}).get("status", "unknown")
            for p in procs
            if p.get("name")
        }
    except Exception:
        return {}


@router.get("/monitored-apps", response_model=MonitoredAppsOut)
async def get_monitored_apps(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the list of apps monitored by AEGIS log_watcher.

    Source: AEGIS_MONITORED_APPS env var (comma-separated app names).
    If the env var is unset, returns an empty list rather than guessing.

    Each entry is enriched with:
    - status: PM2 process status (online/stopped/errored/unknown) — best-effort
    - open_incidents: count of open/investigating incidents whose source matches the app
    - last_activity: ISO timestamp of the most recent related incident
    - resolved_count: count of resolved incidents for the app
    """
    client = auth.client

    # Parse from pydantic settings (loaded from .env at startup)
    raw_env = (settings.AEGIS_MONITORED_APPS or "").strip()
    app_names: list[str] = [a.strip() for a in raw_env.split(",") if a.strip()] if raw_env else []

    # Best-effort PM2 status (runs in thread pool so it doesn't block the loop)
    loop = asyncio.get_event_loop()
    pm2_statuses: dict[str, str] = await loop.run_in_executor(None, _get_pm2_statuses)

    apps: list[MonitoredAppOut] = []

    # v1.6.3.2: single GROUP BY query instead of 3×N sequential queries.
    # Previous loop did open_count + resolved_count + max(detected_at) per app —
    # 27 queries for 9 monitored apps. Now 1 query returns all rows aggregated.
    agg_rows = await db.execute(
        select(
            Incident.source,
            Incident.status,
            func.count(Incident.id).label('c'),
            func.max(Incident.detected_at).label('last'),
        )
        .where(
            Incident.client_id == client.id,
            Incident.source.in_(app_names) if app_names else func.false(),
        )
        .group_by(Incident.source, Incident.status)
    )
    # name -> {open_count, resolved_count, last_activity}
    stats: dict[str, dict] = {name: {"open": 0, "resolved": 0, "last": None} for name in app_names}
    for row in agg_rows.all():
        src, status, cnt, last = row[0], row[1], int(row[2] or 0), row[3]
        if src not in stats:
            continue
        if status in ("open", "investigating"):
            stats[src]["open"] += cnt
        elif status == "resolved":
            stats[src]["resolved"] += cnt
        if last is not None and (stats[src]["last"] is None or last > stats[src]["last"]):
            stats[src]["last"] = last

    for name in app_names:
        s = stats[name]
        status = pm2_statuses.get(name, "unknown")
        apps.append(MonitoredAppOut(
            name=name,
            status=status,
            open_incidents=int(s["open"]),
            last_activity=s["last"].isoformat() if s["last"] else None,
            resolved_count=int(s["resolved"]),
        ))

    return MonitoredAppsOut(apps=apps, count=len(apps))
