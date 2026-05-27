"""
IP Intelligence — internal history helpers (AEGIS v1.8).

Pure DB / local-file lookups against AEGIS's own observations:
  - incidents table          → past detections involving this IP
  - honeypot_interactions    → deception engagement history
  - attacker_profiles        → phantom profiler output
  - actions                  → response actions taken for this IP
  - threat_intel             → cross-ref against cached threat feeds
  - related IPs              → same /24 and same ASN (capped)

NO external HTTP. The optional AI threat brief lives in `_ai_threat_brief`
and is the ONE place ai_manager may be called from the intel pipeline;
it's gated behind deep=True AND AEGIS_AI_MODE != offline.

Global view (no client_id filter): AEGIS prod runs single-tenant on Mac Pro
and the public ip_intel API is already global by design (the behavioral
feed in the parent module is a global file). Operators see all clients.

Every helper enforces a strict 500 ms timeout; on miss/timeout it returns
None / empty so the response stays inside the 4 s budget.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections import Counter
from typing import Any

from sqlalchemy import desc, func, select, text

logger = logging.getLogger("aegis.ip_intel.history")

_QUERY_TIMEOUT = 0.5  # seconds per sub-query
_ROW_CAP = 200


async def _run_with_timeout(coro, label: str):
    try:
        return await asyncio.wait_for(coro, timeout=_QUERY_TIMEOUT)
    except asyncio.TimeoutError:
        logger.debug("ip_intel.history: %s timed out", label)
        return None
    except Exception as exc:
        logger.debug("ip_intel.history: %s error: %s", label, exc)
        return None


def _slash24_prefix(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".%"
    # /64 for v6
    if isinstance(addr, ipaddress.IPv6Address):
        # not currently supported in related lookup — return None
        return None
    return None


async def _history_incidents(ip: str) -> dict[str, Any] | None:
    """Counts + severity mix + top MITRE techniques for this IP."""
    from app.database import async_session
    from app.models.incident import Incident

    async def _q():
        async with async_session() as s:
            stmt = (
                select(Incident.severity, Incident.status, Incident.mitre_technique,
                       Incident.detected_at)
                .where(Incident.source_ip == ip)
                .order_by(desc(Incident.detected_at))
                .limit(_ROW_CAP)
            )
            rows = (await s.execute(stmt)).all()
        if not rows:
            return {"count": 0}
        severities = Counter(r[0] for r in rows if r[0])
        statuses = Counter(r[1] for r in rows if r[1])
        mitre = Counter(r[2] for r in rows if r[2])
        ts = [r[3] for r in rows if r[3]]
        return {
            "count": len(rows),
            "first": ts[-1].isoformat() if ts else None,
            "last": ts[0].isoformat() if ts else None,
            "severities": dict(severities),
            "statuses": dict(statuses),
            "mitre_top": [t for t, _ in mitre.most_common(3)],
        }

    return await _run_with_timeout(_q(), "incidents")


async def _history_honeypot(ip: str) -> dict[str, Any] | None:
    from app.database import async_session
    from app.models.honeypot import HoneypotInteraction

    async def _q():
        async with async_session() as s:
            stmt = (
                select(HoneypotInteraction.commands,
                       HoneypotInteraction.credentials_tried,
                       HoneypotInteraction.protocol,
                       HoneypotInteraction.timestamp)
                .where(HoneypotInteraction.source_ip == ip)
                .order_by(desc(HoneypotInteraction.timestamp))
                .limit(_ROW_CAP)
            )
            rows = (await s.execute(stmt)).all()
        if not rows:
            return {"total": 0}
        commands_c: Counter = Counter()
        creds_c: Counter = Counter()
        protos: Counter = Counter()
        ts = []
        for cmds, creds, proto, t in rows:
            if isinstance(cmds, list):
                for c in cmds[:50]:
                    commands_c[str(c)[:80]] += 1
            if isinstance(creds, list):
                for c in creds[:50]:
                    creds_c[str(c)[:80]] += 1
            if proto:
                protos[proto] += 1
            if t:
                ts.append(t)
        return {
            "total": len(rows),
            "protocols": dict(protos),
            "last": ts[0].isoformat() if ts else None,
            "first": ts[-1].isoformat() if ts else None,
            "commands": [c for c, _ in commands_c.most_common(8)],
            "creds": [c for c, _ in creds_c.most_common(8)],
        }

    return await _run_with_timeout(_q(), "honeypot")


async def _history_profile(ip: str) -> dict[str, Any] | None:
    from app.database import async_session
    from app.models.attacker_profile import AttackerProfile

    async def _q():
        async with async_session() as s:
            stmt = (
                select(AttackerProfile.sophistication,
                       AttackerProfile.tools_used,
                       AttackerProfile.techniques,
                       AttackerProfile.ai_assessment,
                       AttackerProfile.total_interactions,
                       AttackerProfile.first_seen,
                       AttackerProfile.last_seen)
                .where(AttackerProfile.source_ip == ip)
                .limit(1)
            )
            row = (await s.execute(stmt)).first()
        if not row:
            return None
        return {
            "sophistication": row[0],
            "tools_used": row[1] if isinstance(row[1], list) else [],
            "techniques": row[2] if isinstance(row[2], list) else [],
            "ai_assessment": row[3],
            "total_interactions": row[4] or 0,
            "first_seen": row[5].isoformat() if row[5] else None,
            "last_seen": row[6].isoformat() if row[6] else None,
        }

    return await _run_with_timeout(_q(), "profile")


async def _history_actions(ip: str) -> list[dict[str, Any]] | None:
    """Every block/unblock/notify ever taken against this IP, newest first."""
    from app.database import async_session
    from app.models.action import Action
    from app.models.incident import Incident

    async def _q():
        async with async_session() as s:
            stmt = (
                select(Action.action_type, Action.target, Action.status,
                       Action.ai_reasoning, Action.created_at, Action.executed_at)
                .join(Incident, Action.incident_id == Incident.id)
                .where(Incident.source_ip == ip)
                .order_by(desc(Action.created_at))
                .limit(50)
            )
            rows = (await s.execute(stmt)).all()
        out = []
        for at, tgt, st, reason, c_at, x_at in rows:
            out.append({
                "type": at,
                "target": tgt,
                "status": st,
                "reasoning": (reason[:240] + "…") if reason and len(reason) > 240 else reason,
                "created_at": c_at.isoformat() if c_at else None,
                "executed_at": x_at.isoformat() if x_at else None,
            })
        return out

    return await _run_with_timeout(_q(), "actions")


async def _related_ips(ip: str, asn: str | None) -> dict[str, list[str]] | None:
    """IPs sharing the same /24 (incidents) or same ASN (we can't query
    ip_intel cache cross-IP cheaply, so we do /24 only here — same-ASN is
    surfaced if the caller has cached intel)."""
    from app.database import async_session
    from app.models.incident import Incident

    prefix = _slash24_prefix(ip)

    async def _q():
        out: dict[str, list[str]] = {"same_subnet": [], "same_asn": []}
        if not prefix:
            return out
        async with async_session() as s:
            stmt = (
                select(Incident.source_ip, func.count(Incident.id))
                .where(Incident.source_ip.like(prefix))
                .where(Incident.source_ip != ip)
                .group_by(Incident.source_ip)
                .order_by(desc(func.count(Incident.id)))
                .limit(10)
            )
            rows = (await s.execute(stmt)).all()
        out["same_subnet"] = [r[0] for r in rows if r[0]]
        return out

    return await _run_with_timeout(_q(), "related")


async def _external_feeds_match(ip: str) -> list[dict[str, Any]] | None:
    """Cross-reference IP against cached threat_intel rows (emerging_threats,
    feodo_tracker, tor_exit_nodes, etc.)."""
    from app.database import async_session
    from app.models.threat_intel import ThreatIntel

    async def _q():
        async with async_session() as s:
            stmt = (
                select(ThreatIntel.source, ThreatIntel.threat_type,
                       ThreatIntel.confidence, ThreatIntel.last_seen,
                       ThreatIntel.tags)
                .where(ThreatIntel.ioc_type == "ip")
                .where(ThreatIntel.ioc_value == ip)
                .limit(20)
            )
            rows = (await s.execute(stmt)).all()
        return [
            {
                "feed": src,
                "threat_type": tt,
                "confidence": conf,
                "last_seen": ls.isoformat() if ls else None,
                "tags": tags if isinstance(tags, list) else [],
            }
            for src, tt, conf, ls, tags in rows
        ]

    return await _run_with_timeout(_q(), "feeds")


# ---------------------------------------------------------------------------
# Optional AI threat brief (the ONE LLM hook in the intel pipeline)
# ---------------------------------------------------------------------------

async def _ai_threat_brief(ip: str, intel: dict[str, Any]) -> dict[str, Any] | None:
    """
    Produce a 100-200 word natural-language threat assessment.

    Returns None when AEGIS_AI_MODE is offline OR when ai_manager returns
    empty content. Provenance is always tagged.

    Reuses ai_manager.chat() — which already short-circuits to empty content
    when AEGIS_AI_MODE in {disabled, offline, off, none}.
    """
    import os as _os
    mode = _os.environ.get("AEGIS_AI_MODE", "optional").strip().lower()
    if mode in {"disabled", "offline", "off", "none"}:
        return None

    # Build a compact deterministic prompt — no PII other than the IP itself.
    facts: list[str] = [
        f"IP: {ip}",
        f"Classification: {intel.get('classification')}",
        f"ASN: {intel.get('asn')} ({intel.get('asn_reputation_owner') or intel.get('org')})",
        f"Country: {intel.get('country')}",
        f"Flags: tor={intel.get('is_tor')} vpn={intel.get('is_vpn')} "
        f"proxy={intel.get('is_proxy')} dc={intel.get('is_datacenter')} "
        f"malicious={intel.get('is_malicious')} scanner={intel.get('is_scanner')}",
    ]
    conf = intel.get("confidence") or {}
    if conf:
        facts.append(
            f"Confidence: tor={conf.get('tor')} vpn={conf.get('vpn')} "
            f"attacker={conf.get('attacker')} dc={conf.get('datacenter')}"
        )
    if intel.get("spamhaus_match"):
        facts.append("On Spamhaus DROP list.")
    if intel.get("tor_list_match"):
        facts.append("Verified Tor exit (live list).")
    if intel.get("shodan_vulns"):
        facts.append(f"Shodan vulns: {','.join(intel['shodan_vulns'][:6])}")
    if intel.get("shodan_ports"):
        facts.append(f"Open ports: {','.join(str(p) for p in intel['shodan_ports'][:10])}")
    if intel.get("abuseipdb_score") is not None:
        facts.append(f"AbuseIPDB score: {intel['abuseipdb_score']}/100")
    hist = intel.get("history") or {}
    inc = hist.get("incidents") or {}
    if inc.get("count"):
        facts.append(
            f"AEGIS history: {inc.get('count')} incidents, severities={inc.get('severities')}, "
            f"top MITRE={inc.get('mitre_top')}"
        )
    hp = hist.get("honeypot") or {}
    if hp.get("total"):
        facts.append(f"Honeypot: {hp.get('total')} interactions, last={hp.get('last')}")
    feeds = intel.get("external_feeds") or []
    if feeds:
        facts.append(
            "External feeds: " + ", ".join(f"{f.get('feed')} ({f.get('threat_type')})" for f in feeds[:5])
        )
    behavioral = intel.get("behavioral") or {}
    if behavioral.get("hits"):
        facts.append(
            f"Observed: {behavioral.get('hits')} hits across {behavioral.get('distinct_apps')} apps, "
            f"paths={','.join((behavioral.get('paths') or [])[:5])}"
        )

    system_msg = (
        "You are AEGIS, an autonomous cybersecurity defense system. "
        "Write a concise 100-180 word threat assessment for an IP based ONLY on "
        "the facts provided. Be specific. Cite the strongest signals. State the "
        "recommended action (block / monitor / allow) and confidence (low/med/high). "
        "No hedging. No filler. No markdown."
    )
    user_msg = "FACTS:\n" + "\n".join(facts) + "\n\nWrite the assessment."

    try:
        from app.core.ai_manager import ai_manager
        t0 = time.time()
        res = await asyncio.wait_for(
            ai_manager.chat(
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                task_type="ip_threat_brief",
                temperature=0.2,
                max_tokens=350,
            ),
            timeout=12.0,
        )
    except asyncio.TimeoutError:
        logger.warning("ai_threat_brief timed out for %s", ip)
        return None
    except Exception as exc:
        logger.warning("ai_threat_brief error for %s: %s", ip, exc)
        return None

    content = (res or {}).get("content", "").strip()
    if not content:
        return None

    return {
        "text": content,
        "_provenance": {
            "kind": "agent",
            "source": f"{res.get('provider', 'unknown')}:{res.get('model', 'unknown')}",
            "tokens_used": res.get("tokens_used"),
            "cost_usd": res.get("cost_usd"),
            "latency_ms": int((time.time() - t0) * 1000),
        },
    }


# ---------------------------------------------------------------------------
# Public assembly
# ---------------------------------------------------------------------------

async def assemble_history(ip: str, asn: str | None = None) -> dict[str, Any]:
    """
    Gather ALL internal-history blocks in parallel within a 4 s total budget.

    Returns a dict with keys: incidents, honeypot, profile, actions.
    Missing/timed-out fields are returned as empty placeholders so the shape
    stays stable for consumers.
    """
    incidents_t = asyncio.create_task(_history_incidents(ip))
    honeypot_t = asyncio.create_task(_history_honeypot(ip))
    profile_t = asyncio.create_task(_history_profile(ip))
    actions_t = asyncio.create_task(_history_actions(ip))

    try:
        await asyncio.wait_for(
            asyncio.gather(incidents_t, honeypot_t, profile_t, actions_t,
                           return_exceptions=True),
            timeout=4.0,
        )
    except asyncio.TimeoutError:
        logger.warning("assemble_history total budget exceeded for %s", ip)

    def _safe(t: asyncio.Task) -> Any:
        if not t.done():
            t.cancel()
            return None
        try:
            return t.result()
        except Exception:
            return None

    return {
        "incidents": _safe(incidents_t) or {"count": 0},
        "honeypot": _safe(honeypot_t) or {"total": 0},
        "profile": _safe(profile_t),
        "actions": _safe(actions_t) or [],
    }
