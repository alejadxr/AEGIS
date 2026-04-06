"""
Behavioral ML baseline API routes.

Endpoints
---------
GET  /api/v1/behavioral/status                 - ML engine status
GET  /api/v1/behavioral/baselines              - all asset baselines
GET  /api/v1/behavioral/baselines/{asset_id}   - specific asset baseline
GET  /api/v1/behavioral/anomalies              - recent anomalies detected
POST /api/v1/behavioral/retrain                - force retrain all models
POST /api/v1/behavioral/retrain/{asset_id}     - retrain specific asset
"""

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.params import Depends
from pydantic import BaseModel

from app.core.auth import AuthContext, require_admin, require_analyst, require_viewer
from app.services.behavioral_ml import behavioral_engine

router = APIRouter(prefix="/behavioral", tags=["behavioral-ml"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FeatureStats(BaseModel):
    connection_count: Optional[float] = None
    unique_ips: Optional[float] = None
    request_rate: Optional[float] = None
    error_rate: Optional[float] = None
    new_ports: Optional[float] = None
    data_volume: Optional[float] = None
    auth_failures: Optional[float] = None
    unique_user_agents: Optional[float] = None


class BaselineOut(BaseModel):
    asset_id: str
    data_points: int
    history_size: int
    model_trained: bool
    last_train: Optional[str] = None
    feature_means: dict[str, float]
    feature_stds: dict[str, float]
    recent_anomalies: int


class AnomalyOut(BaseModel):
    asset_id: str
    timestamp: str
    anomaly_score: float
    contributors: list[list[str]]
    description: str
    metrics: dict[str, float]


class StatusOut(BaseModel):
    running: bool
    started_at: Optional[str] = None
    assets_tracked: int
    models_trained: int
    total_data_points: int
    total_anomalies_detected: int
    eval_interval_seconds: int
    retrain_interval_seconds: int
    model_dir: str


class RetrainResultOut(BaseModel):
    success: bool
    asset_id: Optional[str] = None
    error: Optional[str] = None
    data_points: Optional[int] = None
    history_size: Optional[int] = None


class RetrainAllOut(BaseModel):
    results: dict[str, Any]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/status", response_model=StatusOut)
async def get_status(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return ML engine status: models trained, last retrain, data points, etc.
    """
    return StatusOut(**behavioral_engine.stats())


@router.get("/baselines", response_model=list[BaselineOut])
async def list_baselines(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return learned baseline statistics for all tracked assets.
    """
    baselines = behavioral_engine.get_all_baselines()
    return [BaselineOut(**b) for b in baselines]


@router.get("/baselines/{asset_id}", response_model=BaselineOut)
async def get_baseline(
    asset_id: str,
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return learned baseline statistics for a specific asset.
    """
    baseline = behavioral_engine.get_baseline(asset_id)
    if baseline is None:
        raise HTTPException(status_code=404, detail=f"No baseline for asset '{asset_id}'")
    return BaselineOut(**baseline)


@router.get("/anomalies", response_model=list[AnomalyOut])
async def list_anomalies(
    limit: int = Query(default=100, ge=1, le=1000),
    asset_id: Optional[str] = Query(default=None),
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return recent anomalies detected by the behavioral ML engine.

    Optional query params:
    - limit: max number of results (default 100)
    - asset_id: filter by specific asset
    """
    anomalies = behavioral_engine.get_recent_anomalies(limit=limit)
    if asset_id:
        anomalies = [a for a in anomalies if a["asset_id"] == asset_id]
    return [AnomalyOut(**a) for a in anomalies]


@router.post("/retrain", response_model=RetrainAllOut)
async def retrain_all(
    auth: AuthContext = Depends(require_admin),
):
    """
    Force retrain Isolation Forest models for all tracked assets.
    Admin only.
    """
    results = behavioral_engine.retrain_all()
    return RetrainAllOut(results=results)


@router.post("/retrain/{asset_id}", response_model=RetrainResultOut)
async def retrain_asset(
    asset_id: str,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Force retrain the Isolation Forest model for a specific asset.
    Analyst or admin only.
    """
    result = behavioral_engine.retrain(asset_id)
    return RetrainResultOut(**result)
