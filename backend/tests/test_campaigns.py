"""Tests for TTP campaign endpoints (list + drill-down)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.services.ttp_clustering import cluster_id_for, compute_ttp_fingerprint

from tests.conftest import api_key_headers


pytestmark = pytest.mark.asyncio


async def _seed_campaign(db: AsyncSession, client_id: str, ips: list[str], technique: str = "T1595.001", tactic: str = "Reconnaissance") -> str:
    """Seed N incidents sharing a TTP across `ips`. Returns the cluster_id."""
    now = datetime.utcnow()
    for idx, ip in enumerate(ips):
        inc = Incident(
            id=str(uuid.uuid4()),
            client_id=client_id,
            title=f"Recon probe from {ip}",
            severity="medium" if idx % 2 == 0 else "high",
            status="open",
            source="log_watcher",
            source_ip=ip,
            mitre_technique=technique,
            mitre_tactic=tactic,
            detected_at=now - timedelta(minutes=10 * idx),
        )
        db.add(inc)
    await db.commit()
    fp = f"{tactic}::{technique}"
    return cluster_id_for(fp)


async def test_list_campaigns_returns_seeded_cluster(client, test_client_a, db_session: AsyncSession):
    """List endpoint returns a campaign when ≥ min_distinct_ips IPs share a TTP."""
    await _seed_campaign(
        db_session,
        test_client_a.id,
        ["185.220.101.42", "185.220.101.230", "185.220.101.250"],
    )
    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/threats/campaigns?window_hours=24&min_distinct_ips=2", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    camp = body["campaigns"][0]
    assert camp["distinct_ips"] == 3
    assert camp["mitre_technique"] == "T1595.001"
    assert "cluster_id" in camp
    assert len(camp["cluster_id"]) == 8


async def test_campaign_detail_404_for_unknown(client, test_client_a):
    """Drill-down returns 404 for a cluster_id with no incidents in window."""
    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/threats/campaigns/deadbeef?window_hours=24", headers=headers)
    assert resp.status_code == 404
    assert "deadbeef" in resp.json()["detail"]


async def test_campaign_detail_shape(client, test_client_a, db_session: AsyncSession):
    """Drill-down returns expected shape with seeded incidents."""
    cluster = await _seed_campaign(
        db_session,
        test_client_a.id,
        ["192.0.2.10", "192.0.2.11"],
        technique="T1110.001",
        tactic="Credential Access",
    )
    headers = api_key_headers(test_client_a)
    resp = await client.get(
        f"/api/v1/threats/campaigns/{cluster}?window_hours=24",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["cluster_id"] == cluster
    assert body["mitre_technique"] == "T1110.001"
    assert body["distinct_ips_count"] == 2
    assert body["total_incidents"] == 2
    assert body["is_active"] in (True, False)
    assert "technique_detail" in body and body["technique_detail"]["id"] == "T1110.001"
    assert body["technique_detail"]["name"] == "Password Guessing"
    assert "url" in body["technique_detail"]
    assert "ips" in body and len(body["ips"]) == 2
    assert "incidents" in body and len(body["incidents"]) == 2
    assert "severity_distribution" in body
    assert "recommended_action" in body and len(body["recommended_action"]) > 10
