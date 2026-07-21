"""Fix 3 (P0 asset-scorer sweep): report_generator's asset risk numbers must
match the live dashboard (app.api.surface.list_assets), not the stale/legacy
``Asset.risk_score`` DB column.

No DB, no app startup — AsyncSession.execute() is mocked directly, matching
this suite's "no DB required" convention (see tests/unit/conftest.py).
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.asset import Asset
from app.services import asset_risk
from app.services import report_generator as rg


class _FakeResult:
    """Minimal stand-in for a SQLAlchemy Result — only `.all()` is used by
    the code under test."""

    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


@pytest.mark.asyncio
async def test_report_asset_risk_matches_live_surface_scoring():
    """report_generator._score_assets_live() must return byte-identical
    numbers to calling asset_risk.score_asset() directly with the same
    inputs — the exact function app.api.surface.list_assets uses — and must
    NOT echo the stored (possibly stale/legacy-AI-scored) risk_score column.
    """
    client_id = "client-1"
    ports = [{"port": 5432, "protocol": "tcp", "service": "postgresql", "state": "open"}]
    asset = Asset(
        id="asset-1",
        client_id=client_id,
        hostname="host-a",
        ip_address="10.0.0.5",
        asset_type="server",
        ports=ports,
        technologies=[],
        status="active",
        risk_score=1.0,  # deliberately stale/wrong — must be ignored by the fix
    )

    # 1st db.execute(): open-vulnerability GROUP BY aggregation -> 2 open highs
    vuln_rows = [("asset-1", "high", 2)]
    # 2nd db.execute(): fleet-wide (id, ip_address, hostname, ports) rows,
    # used to build the same host_index surface.py builds.
    fleet_rows = [
        SimpleNamespace(id="asset-1", ip_address="10.0.0.5", hostname="host-a", ports=ports)
    ]

    db = AsyncMock()
    db.execute.side_effect = [_FakeResult(vuln_rows), _FakeResult(fleet_rows)]

    scores = await rg._score_assets_live(client_id, db, [asset])

    # Independently recompute exactly what app.api.surface.list_assets would
    # compute for this same asset (critical=0, high=2, total=2).
    host_index = asset_risk.build_host_index(fleet_rows)
    expected = asset_risk.score_asset(
        ports=ports,
        ip_address="10.0.0.5",
        hostname="host-a",
        critical_vulns=0,
        high_vulns=2,
        total_vulns=2,
        host_index=host_index,
    )

    assert scores["asset-1"]["risk_score"] == expected["risk_score"]
    assert scores["asset-1"]["risk_method"] == asset_risk.MODEL_VERSION
    # And, critically, the live score must differ from the stale stored
    # column used before the fix — proving this isn't an accidental match.
    assert scores["asset-1"]["risk_score"] != asset.risk_score
