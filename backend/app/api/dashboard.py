import asyncio
import json
import logging
import subprocess
from datetime import datetime, timedelta

logger = logging.getLogger("aegis.dashboard")
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


_OVERVIEW_CACHE: dict = {"ts": 0.0, "client": None, "data": None}
_OVERVIEW_CACHE_TTL = 30.0  # seconds


@router.get("/overview", response_model=OverviewStats)
async def get_overview(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard overview statistics.

    v1.6.3.10: results cached 30s per client + COUNT queries bounded to a
    30-day window on growing tables (honeypot_interactions, actions). The
    operator's KPI tile is interested in "recent" not "all-time", and the
    unbounded COUNT was scanning > 1 M rows on every dashboard load.
    """
    import time as _time
    client = auth.client
    now = _time.monotonic()
    cached = _OVERVIEW_CACHE
    if cached["data"] and cached["client"] == client.id and (now - cached["ts"]) < _OVERVIEW_CACHE_TTL:
        return cached["data"]

    cutoff_30d = datetime.utcnow() - timedelta(days=30)

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
        # v1.6.3.10: bound to 30d. Unbounded scan was the slowest leg of the gather.
        db.scalar(select(func.count(HoneypotInteraction.id)).where(
            HoneypotInteraction.client_id == client.id,
            HoneypotInteraction.timestamp >= cutoff_30d,
        )),
        db.scalar(select(func.count(Action.id)).where(
            Action.client_id == client.id,
            Action.status == "executed",
            Action.created_at >= cutoff_30d,
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

    out = OverviewStats(
        total_assets=total_assets,
        open_vulnerabilities=open_vulns,
        critical_vulnerabilities=critical_vulns,
        active_incidents=active_incidents,
        honeypot_interactions=hp_interactions,
        actions_taken=actions_taken,
        risk_level=risk_level,
    )
    _OVERVIEW_CACHE["ts"] = now
    _OVERVIEW_CACHE["client"] = client.id
    _OVERVIEW_CACHE["data"] = out
    return out


# ---------------------------------------------------------------------------
# Featured Incident
# ---------------------------------------------------------------------------

class FeaturedIncidentOut(BaseModel):
    incident_number: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    detected_at: Optional[str] = None
    affected_asset: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    source_ip: Optional[str] = None
    confidence: Optional[int] = None
    description: Optional[str] = None


def _derive_confidence(ai_analysis, severity: Optional[str]) -> int:
    """Derive a 0-100 confidence integer from ai_analysis or severity.

    Looks for keys 'confidence' or 'ai_confidence' in the ai_analysis JSON.
    Handles both fractional (0.0-1.0) and percentage (0-100) formats.
    Falls back to a severity-based heuristic, then to 75 as a safe default.
    """
    if ai_analysis:
        blob = ai_analysis
        if isinstance(blob, str):
            try:
                blob = json.loads(blob)
            except Exception:
                blob = {}
        if isinstance(blob, dict):
            for key in ("confidence", "ai_confidence"):
                val = blob.get(key)
                if val is not None:
                    try:
                        fval = float(val)
                        # Fractional probability → percentage
                        if fval <= 1.0:
                            fval = fval * 100
                        return max(0, min(100, int(fval)))
                    except (ValueError, TypeError):
                        pass
    _SEVERITY_MAP: dict[str, int] = {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "low": 40,
    }
    return _SEVERITY_MAP.get(severity or "", 75)


@router.get("/featured-incident", response_model=FeaturedIncidentOut)
async def get_featured_incident(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Return the most prominent open incident for the dashboard hero widget.

    Priority: most-recent OPEN/INVESTIGATING with severity in [critical, high].
    Fallback: most-recent OPEN/INVESTIGATING of any severity.
    Returns HTTP 200 with all-null payload when no open incidents exist — never 404.
    """
    client = auth.client

    # 1. Primary: critical or high severity, open/investigating
    result = await db.execute(
        select(Incident)
        .where(
            Incident.client_id == client.id,
            Incident.status.in_(["open", "investigating"]),
            Incident.severity.in_(["critical", "high"]),
            ~Incident.title.like("[FP-%"),  # never feature a false-positive
        )
        .order_by(Incident.detected_at.desc())
        .limit(1)
    )
    incident = result.scalars().first()

    # 2. Fallback: any open/investigating regardless of severity
    if incident is None:
        result = await db.execute(
            select(Incident)
            .where(
                Incident.client_id == client.id,
                Incident.status.in_(["open", "investigating"]),
                ~Incident.title.like("[FP-%"),
            )
            .order_by(Incident.detected_at.desc())
            .limit(1)
        )
        incident = result.scalars().first()

    # 3. Nothing open at all — return empty payload (200, not 404)
    if incident is None:
        return FeaturedIncidentOut()

    # Resolve affected asset from target_asset_id
    affected_asset = "N/A"
    if incident.target_asset_id:
        asset_result = await db.execute(
            select(Asset).where(Asset.id == incident.target_asset_id)
        )
        asset = asset_result.scalars().first()
        if asset:
            affected_asset = asset.hostname or asset.ip_address or "N/A"

    # incident_number: first 4 hex chars of id (strip dashes), uppercased, prefixed "INC-"
    raw_id = str(incident.id).replace("-", "")
    incident_number = f"INC-{raw_id[:4].upper()}"

    confidence = _derive_confidence(
        getattr(incident, "ai_analysis", None),
        incident.severity,
    )

    description: Optional[str] = None
    if incident.description:
        description = incident.description[:280]

    return FeaturedIncidentOut(
        incident_number=incident_number,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        detected_at=incident.detected_at.isoformat() if incident.detected_at else None,
        affected_asset=affected_asset,
        mitre_technique=incident.mitre_technique or "N/A",
        mitre_tactic=incident.mitre_tactic or None,
        source_ip=incident.source_ip or "N/A",
        confidence=confidence,
        description=description,
    )


class MonthCount(BaseModel):
    month: str  # "YYYY-MM"
    count: int


class AuthAttemptsMonthlyOut(BaseModel):
    months: list[MonthCount]
    total: int
    peak_month: Optional[str] = None


@router.get("/auth-attempts/monthly", response_model=AuthAttemptsMonthlyOut)
async def get_auth_attempts_monthly(
    months: int = 6,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Monthly counts of authentication-failure-like incidents for the last N months.

    Matches incidents by:
      - mitre_technique starting with T1110 (Brute Force technique group)
      - title containing 'auth', 'login', or 'brute' (case-insensitive)

    Gap-fills months with zero counts so the caller always receives exactly
    `months` entries ordered oldest-to-newest.

    Note: Incident model has no dedicated threat_type column; the T1110 MITRE
    technique and title-keyword filters cover all brute-force/auth-failure
    incidents created by the correlation engine.
    """
    from sqlalchemy import or_

    client = auth.client
    now = datetime.utcnow()

    # Compute the first day of the oldest month in the window.
    # e.g. months=6, current=2026-06 → cutoff=2026-01-01
    cutoff_year = now.year
    cutoff_month = now.month - (months - 1)
    while cutoff_month <= 0:
        cutoff_month += 12
        cutoff_year -= 1
    cutoff = datetime(cutoff_year, cutoff_month, 1)

    auth_filter = or_(
        Incident.mitre_technique.like("T1110%"),
        func.lower(Incident.title).like("%auth%"),
        func.lower(Incident.title).like("%login%"),
        func.lower(Incident.title).like("%brute%"),
    )

    month_bucket = func.date_trunc("month", Incident.detected_at).label("month_bucket")
    result = await db.execute(
        select(
            month_bucket,
            func.count(Incident.id).label("cnt"),
        )
        .where(
            Incident.client_id == client.id,
            Incident.detected_at >= cutoff,
            auth_filter,
            ~Incident.title.like("[FP-%"),  # exclude false-positive-tagged incidents
        )
        .group_by(month_bucket)
        .order_by(month_bucket)
    )

    # Build a "YYYY-MM" → count lookup from DB rows.
    db_counts: dict[str, int] = {}
    for row in result.all():
        bucket: datetime = row[0]
        db_counts[bucket.strftime("%Y-%m")] = int(row[1] or 0)

    # Walk from cutoff month to current month, filling zeros for missing months.
    month_list: list[MonthCount] = []
    y, m = cutoff_year, cutoff_month
    cur_y, cur_m = now.year, now.month
    while (y, m) <= (cur_y, cur_m):
        key = f"{y:04d}-{m:02d}"
        month_list.append(MonthCount(month=key, count=db_counts.get(key, 0)))
        m += 1
        if m > 12:
            m = 1
            y += 1

    total = sum(e.count for e in month_list)
    peak_month: Optional[str] = (
        max(month_list, key=lambda e: e.count).month
        if month_list and total > 0
        else None
    )

    return AuthAttemptsMonthlyOut(months=month_list, total=total, peak_month=peak_month)


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
    window: str = "30d",
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Cached aggregates for the Live SOC dashboard.

    v1.6.2: configurable ?window=24h|7d|30d|all so operators can see slow-burn
    campaigns that the previous hard-coded 24h cutoff hid.

    v1.7.1: default window widened 24h -> 30d. Real attacker/target data is
    weeks old (the June AWS SQLi wave); the old 24h default rendered the Live
    SOC top-lists empty even though 8+ attackers exist in the 30-day view.
    Operators can still narrow via ?window=24h|7d or broaden via ?window=all.

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
            ~Incident.title.like("[FP-%"),  # exclude crawlers/operator FPs from top attackers
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
            ~Incident.title.like("[FP-%"),  # exclude FP-tagged from attack-type mix
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
        ~Incident.title.like("[FP-%"),  # keep crawlers/operator off the threat map
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


import time as _time
_PM2_CACHE: dict = {"ts": 0.0, "data": {}}
_PM2_CACHE_TTL = 60.0  # v1.6.3.10: 15s -> 60s — PM2 statuses change rarely


def _get_pm2_statuses() -> dict[str, str]:
    """Cached PM2 process list. TTL 60s — PM2 jlist subprocess can take 5+s
    on a busy box and was the dominant bottleneck on /monitored-apps.
    Cache is warmed at app startup via warmup_pm2_cache so first request
    after restart is fast."""
    now = _time.monotonic()
    cached = _PM2_CACHE
    if cached["data"] and (now - cached["ts"]) < _PM2_CACHE_TTL:
        return cached["data"]
    try:
        result = subprocess.run(
            ["pm2", "jlist"],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return cached["data"] or {}
        procs = json.loads(result.stdout)
        data = {
            p.get("name", ""): (p.get("pm2_env", {}) or {}).get("status", "unknown")
            for p in procs
            if p.get("name")
        }
        _PM2_CACHE["ts"] = now
        _PM2_CACHE["data"] = data
        return data
    except Exception:
        return cached["data"] or {}


async def warmup_pm2_cache() -> None:
    """Run PM2 jlist off the event loop at startup so first /monitored-apps
    request after restart doesn't pay the 1-5s cold-cache penalty."""
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _get_pm2_statuses)
    except Exception:
        pass


async def warmup_dashboard_cache() -> None:
    """v1.6.3.11 — pre-warm DB pool + SQLAlchemy compile cache + dashboard
    result caches at startup so the FIRST request after restart pays the
    same warm-cache latency as steady-state.

    Pre-warmups:
      * 5 parallel connection-pool opens (warms pool_pre_ping checks)
      * /overview gather() — caches per-client + warms compile cache
      * /monitored-apps GROUP BY — warms compile cache
      * /featured-incident lookup — warms compile cache
      * /threat-map aggregates — warms compile cache
      * /live-metrics 24h window — warms compile cache

    All run sequentially after PM2 warmup. The bootstrap demo client is
    looked up from the DB so we don't have to know the client_id upfront.
    Total expected cold cost: ~2 s amortized across startup; eliminates
    the ~1.25 s cold tax that operators see on first dashboard load.
    """
    try:
        from sqlalchemy import select, func as _f
        from datetime import datetime as _dt, timedelta as _td
        from app.database import async_session, engine
        from app.models.client import Client as _Client
        from app.models.asset import Asset as _Asset
        from app.models.incident import Incident as _Inc
        from app.models.honeypot import HoneypotInteraction as _HP
        from app.models.action import Action as _Act
        from app.models.vulnerability import Vulnerability as _Vuln
    except Exception as exc:
        logger.warning(f'dashboard warmup: imports failed: {exc}')
        return

    # 1) Warm DB pool — 5 parallel connection opens (each does pool_pre_ping)
    try:
        async def _ping():
            async with async_session() as s:
                await s.scalar(select(_f.now()))
        await asyncio.gather(*[_ping() for _ in range(5)])
    except Exception as exc:
        logger.debug(f'dashboard warmup: pool ping failed: {exc}')

    # 2) Resolve a real client_id (first row — bootstrap demo client)
    try:
        async with async_session() as db:
            client = await db.scalar(select(_Client).limit(1))
            if client is None:
                logger.info('dashboard warmup: no clients yet — skipping query pre-warm')
                return
    except Exception as exc:
        logger.warning(f'dashboard warmup: client lookup failed: {exc}')
        return

    cutoff_30d = _dt.utcnow() - _td(days=30)
    cutoff_90d = _dt.utcnow() - _td(days=90)
    cutoff_24h = _dt.utcnow() - _td(hours=24)

    # 3) Pre-run /overview queries SERIALLY (single session can't do
    # concurrent queries — that's why this differs from the live endpoint
    # which uses a fresh session per request). Populates _OVERVIEW_CACHE.
    try:
        async with async_session() as db:
            total_assets = await db.scalar(select(_f.count(_Asset.id)).where(_Asset.client_id == client.id))
            open_vulns = await db.scalar(select(_f.count(_Vuln.id)).where(
                _Vuln.client_id == client.id, _Vuln.status == 'open',
            ))
            critical_vulns = await db.scalar(select(_f.count(_Vuln.id)).where(
                _Vuln.client_id == client.id, _Vuln.severity == 'critical', _Vuln.status == 'open',
            ))
            active_incidents = await db.scalar(select(_f.count(_Inc.id)).where(
                _Inc.client_id == client.id, _Inc.status.in_(['open', 'investigating']),
            ))
            hp_interactions = await db.scalar(select(_f.count(_HP.id)).where(
                _HP.client_id == client.id, _HP.timestamp >= cutoff_30d,
            ))
            actions_taken = await db.scalar(select(_f.count(_Act.id)).where(
                _Act.client_id == client.id, _Act.status == 'executed',
                _Act.created_at >= cutoff_30d,
            ))
            # Populate the response cache so first /overview request is instant
            total_assets = total_assets or 0
            open_vulns = open_vulns or 0
            critical_vulns = critical_vulns or 0
            active_incidents = active_incidents or 0
            hp_interactions = hp_interactions or 0
            actions_taken = actions_taken or 0
            score = critical_vulns * 10 + active_incidents * 5
            risk_level = (
                'critical' if score >= 50 else
                'high' if score >= 20 else
                'medium' if score >= 5 else 'low'
            )
            import time as _t
            _OVERVIEW_CACHE['ts'] = _t.monotonic()
            _OVERVIEW_CACHE['client'] = client.id
            _OVERVIEW_CACHE['data'] = OverviewStats(
                total_assets=total_assets,
                open_vulnerabilities=open_vulns,
                critical_vulnerabilities=critical_vulns,
                active_incidents=active_incidents,
                honeypot_interactions=hp_interactions,
                actions_taken=actions_taken,
                risk_level=risk_level,
            )
    except Exception as exc:
        logger.warning(f'dashboard warmup: /overview pre-run failed: {exc}')

    # 4) Pre-run /monitored-apps GROUP BY (warms compile cache)
    try:
        async with async_session() as db:
            await db.execute(
                select(_Inc.source, _Inc.status, _f.count(_Inc.id), _f.max(_Inc.detected_at))
                .where(_Inc.client_id == client.id, _Inc.detected_at >= cutoff_90d)
                .group_by(_Inc.source, _Inc.status)
            )
    except Exception as exc:
        logger.debug(f'dashboard warmup: /monitored-apps pre-run failed: {exc}')

    # 5) Pre-run /featured-incident lookup
    try:
        async with async_session() as db:
            await db.scalar(
                select(_Inc).where(_Inc.client_id == client.id)
                .order_by(_Inc.detected_at.desc()).limit(1)
            )
    except Exception as exc:
        logger.debug(f'dashboard warmup: /featured-incident pre-run failed: {exc}')

    # 6) Pre-run /threat-map aggregates (incidents + honeypot, both bounded)
    try:
        async with async_session() as db:
            await db.execute(
                select(_Inc.source_ip, _f.count(_Inc.id))
                .where(_Inc.client_id == client.id, _Inc.source_ip.isnot(None))
                .group_by(_Inc.source_ip).limit(500)
            )
            await db.execute(
                select(_HP.source_ip, _f.count(_HP.id))
                .where(_HP.client_id == client.id, _HP.source_ip.isnot(None))
                .group_by(_HP.source_ip).limit(500)
            )
    except Exception as exc:
        logger.debug(f'dashboard warmup: /threat-map pre-run failed: {exc}')

    # 7) Pre-run /live-metrics 24h window (the default window)
    try:
        async with async_session() as db:
            await db.execute(
                select(_f.count(_Inc.id))
                .where(_Inc.client_id == client.id, _Inc.detected_at >= cutoff_24h)
            )
    except Exception as exc:
        logger.debug(f'dashboard warmup: /live-metrics pre-run failed: {exc}')

    logger.info('dashboard warmup: pool + compile cache + result cache primed')


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

    # v1.6.3.2: single GROUP BY query instead of 3Ã—N sequential queries.
    # Previous loop did open_count + resolved_count + max(detected_at) per app —
    # 27 queries for 9 monitored apps. Now 1 query returns all rows aggregated.
    # v1.6.3.10: bound to 90d window. Older incidents are operationally noise
    # and the unbounded scan over a growing table was the second slowest
    # contributor after PM2 jlist.
    cutoff_90d = datetime.utcnow() - timedelta(days=90)
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
            Incident.detected_at >= cutoff_90d,
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
