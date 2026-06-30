"""Tests for retention purge + stuck-incident closer (v1.6.2)."""
import json
from datetime import datetime, timedelta

import pytest


@pytest.mark.asyncio
async def test_old_resolved_incidents_purged(db_session, demo_client, monkeypatch):
    """Incidents older than RETENTION_DAYS with status=resolved should be deleted."""
    monkeypatch.setenv("AEGIS_RETENTION_DAYS", "30")
    monkeypatch.delenv("AEGIS_RETENTION_DRY_RUN", raising=False)
    from app.models.incident import Incident
    old = Incident(
        client_id=demo_client.id,
        title="old resolved",
        severity="low",
        status="resolved",
        detected_at=datetime.utcnow() - timedelta(days=45),
        resolved_at=datetime.utcnow() - timedelta(days=44),
    )
    db_session.add(old)
    await db_session.commit()

    import importlib
    import app.services.retention as ret
    importlib.reload(ret)
    summary = await ret.nightly_retention_purge()
    assert summary["incidents"] >= 1


@pytest.mark.asyncio
async def test_recent_resolved_incidents_kept(db_session, demo_client, monkeypatch):
    """Incidents younger than RETENTION_DAYS should NOT be deleted."""
    monkeypatch.setenv("AEGIS_RETENTION_DAYS", "30")
    monkeypatch.delenv("AEGIS_RETENTION_DRY_RUN", raising=False)
    from app.models.incident import Incident
    recent = Incident(
        client_id=demo_client.id,
        title="recent resolved",
        severity="low",
        status="resolved",
        detected_at=datetime.utcnow() - timedelta(days=10),
        resolved_at=datetime.utcnow() - timedelta(days=9),
    )
    db_session.add(recent)
    await db_session.commit()

    import importlib
    import app.services.retention as ret
    importlib.reload(ret)
    await ret.nightly_retention_purge()

    from sqlalchemy import select
    result = await db_session.execute(select(Incident).where(Incident.title == "recent resolved"))
    assert result.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_dry_run_does_not_delete(db_session, demo_client, monkeypatch):
    """AEGIS_RETENTION_DRY_RUN=1 should report counts but not mutate DB."""
    monkeypatch.setenv("AEGIS_RETENTION_DAYS", "30")
    monkeypatch.setenv("AEGIS_RETENTION_DRY_RUN", "1")
    from app.models.incident import Incident
    old = Incident(
        client_id=demo_client.id,
        title="dry-run candidate",
        severity="low",
        status="resolved",
        detected_at=datetime.utcnow() - timedelta(days=45),
    )
    db_session.add(old)
    await db_session.commit()

    import importlib
    import app.services.retention as ret
    importlib.reload(ret)
    summary = await ret.nightly_retention_purge()
    assert summary["dry_run"] is True

    from sqlalchemy import select
    result = await db_session.execute(select(Incident).where(Incident.title == "dry-run candidate"))
    assert result.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_stuck_incidents_closed_when_ip_already_blocked(db_session, demo_client, monkeypatch):
    """Stuck investigating-status incidents older than 24h with blocked source_ip → resolved."""
    monkeypatch.delenv("AEGIS_RETENTION_DRY_RUN", raising=False)
    from app.models.incident import Incident
    from app.models.threat_intel import ThreatIntel

    stuck = Incident(
        client_id=demo_client.id,
        title="stuck",
        severity="medium",
        status="investigating",
        source_ip="1.2.3.4",
        detected_at=datetime.utcnow() - timedelta(hours=48),
    )
    db_session.add(stuck)
    db_session.add(ThreatIntel(
        ioc_type="ip",
        ioc_value="1.2.3.4",
        source="firewall",
        confidence=0.9,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    ))
    await db_session.commit()

    import importlib
    import app.services.retention as ret
    importlib.reload(ret)
    summary = await ret.hourly_stuck_incident_closer()
    assert summary["closed"] >= 1


@pytest.mark.asyncio
async def test_jsonl_audit_log_written(tmp_path, db_session, demo_client, monkeypatch):
    """Each retention run appends a JSONL record to AEGIS_RETENTION_AUDIT_LOG."""
    log_path = tmp_path / "retention-audit.jsonl"
    monkeypatch.setenv("AEGIS_RETENTION_AUDIT_LOG", str(log_path))
    monkeypatch.setenv("AEGIS_RETENTION_DAYS", "30")

    import importlib
    import app.services.retention as ret
    importlib.reload(ret)
    await ret.nightly_retention_purge()

    assert log_path.exists()
    content = log_path.read_text().strip()
    assert content
    rec = json.loads(content.splitlines()[0])
    assert rec["job"] == "nightly_retention_purge"
