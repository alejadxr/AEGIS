"""
Behavioral baseline ML anomaly detection for AEGIS.

Uses Isolation Forest to learn what "normal" looks like for each asset,
then alerts when behaviour deviates.  Catches slow / stealthy attacks that
don't trigger any Sigma rule.

Data sources (read-only references, not modified here):
  - incidents table       -> auth_failures
  - honeypot_interactions -> connection patterns
  - audit_log             -> request counts
  - agent_events          -> process / network data

Trained models are persisted to MODEL_DIR so they survive restarts.
"""

import asyncio
import logging
import os
import pickle
import time
from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("aegis.behavioral_ml")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL_DIR = os.environ.get("AEGIS_MODEL_DIR", "/tmp/aegis_models")

FEATURE_NAMES: list[str] = [
    "connection_count",
    "unique_ips",
    "request_rate",
    "error_rate",
    "new_ports",
    "data_volume",
    "auth_failures",
    "unique_user_agents",
]

# Minimum hours of data before we train a model
MIN_TRAINING_HOURS = 24

# Retrain interval in seconds (24 h)
RETRAIN_INTERVAL_S = 86_400

# Rolling window for training data (7 days)
ROLLING_WINDOW_S = 7 * 86_400

# Evaluation interval in seconds (5 min)
EVAL_INTERVAL_S = 300

# Anomaly score threshold (sklearn returns negative for anomalies)
ANOMALY_THRESHOLD = -0.5

# Isolation Forest contamination parameter
CONTAMINATION = 0.05


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_metrics() -> dict[str, float]:
    """Return a zeroed-out metric dict."""
    return {f: 0.0 for f in FEATURE_NAMES}


def _metrics_to_array(metrics: dict[str, float]) -> np.ndarray:
    """Convert a metrics dict to a 1-D numpy array in canonical order."""
    return np.array([metrics.get(f, 0.0) for f in FEATURE_NAMES], dtype=np.float64)


# ---------------------------------------------------------------------------
# Per-asset state
# ---------------------------------------------------------------------------

class AssetBaseline:
    """Holds training data, trained model and stats for a single asset."""

    __slots__ = (
        "asset_id",
        "history",          # deque of (timestamp, metrics_dict)
        "model",            # trained IsolationForest or None
        "last_train_ts",    # epoch when model was last trained
        "data_points",      # total data points ever recorded
        "feature_means",    # dict of feature name -> mean (from training set)
        "feature_stds",     # dict of feature name -> std  (from training set)
        "anomalies",        # deque of recent anomaly dicts (capped)
    )

    def __init__(self, asset_id: str) -> None:
        self.asset_id = asset_id
        self.history: deque[tuple[float, dict[str, float]]] = deque()
        self.model: Optional[IsolationForest] = None
        self.last_train_ts: float = 0.0
        self.data_points: int = 0
        self.feature_means: dict[str, float] = {}
        self.feature_stds: dict[str, float] = {}
        self.anomalies: deque[dict[str, Any]] = deque(maxlen=200)

    # -- training ---------------------------------------------------------

    def _prune_history(self) -> None:
        """Drop entries older than the rolling window."""
        cutoff = time.time() - ROLLING_WINDOW_S
        while self.history and self.history[0][0] < cutoff:
            self.history.popleft()

    def has_enough_data(self) -> bool:
        if not self.history:
            return False
        span = self.history[-1][0] - self.history[0][0]
        return span >= MIN_TRAINING_HOURS * 3600

    def train(self) -> bool:
        """Train (or retrain) the Isolation Forest. Returns True on success."""
        self._prune_history()

        if not self.has_enough_data():
            logger.debug(
                "Asset %s: not enough data to train (%d points)",
                self.asset_id,
                len(self.history),
            )
            return False

        X = np.array([_metrics_to_array(m) for _, m in self.history])

        # Compute and store feature statistics for explainability
        self.feature_means = {
            f: float(np.mean(X[:, i])) for i, f in enumerate(FEATURE_NAMES)
        }
        self.feature_stds = {
            f: float(np.std(X[:, i])) if np.std(X[:, i]) > 0 else 1.0
            for i, f in enumerate(FEATURE_NAMES)
        }

        model = IsolationForest(
            contamination=CONTAMINATION,
            n_estimators=100,
            random_state=42,
            n_jobs=1,
        )
        model.fit(X)

        self.model = model
        self.last_train_ts = time.time()
        logger.info(
            "Asset %s: Isolation Forest trained on %d samples",
            self.asset_id,
            len(X),
        )
        return True

    # -- evaluation -------------------------------------------------------

    def evaluate(self, metrics: dict[str, float]) -> dict[str, Any]:
        """
        Score a single observation. Returns dict with:
            anomaly_score  : float (negative = more anomalous)
            is_anomaly     : bool
            contributors   : list of (feature, deviation_str)
        """
        if self.model is None:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "contributors": [],
                "detail": "no model trained yet",
            }

        x = _metrics_to_array(metrics).reshape(1, -1)
        score = float(self.model.decision_function(x)[0])
        prediction = int(self.model.predict(x)[0])  # -1 = anomaly, 1 = normal
        is_anomaly = prediction == -1

        # Determine which features contributed most to the anomaly
        contributors: list[tuple[str, str]] = []
        if is_anomaly and self.feature_means:
            deviations: list[tuple[str, float, str]] = []
            for i, f in enumerate(FEATURE_NAMES):
                mean = self.feature_means.get(f, 0.0)
                std = self.feature_stds.get(f, 1.0)
                val = metrics.get(f, 0.0)
                if std > 0 and mean > 0:
                    ratio = val / mean
                    z = abs(val - mean) / std
                    if z > 2.0:
                        deviations.append((f, z, f"{ratio:.1f}x baseline"))
                elif mean == 0 and val > 0:
                    deviations.append((f, float("inf"), f"new activity ({val:.0f})"))

            deviations.sort(key=lambda t: t[1], reverse=True)
            contributors = [(d[0], d[2]) for d in deviations[:5]]

        return {
            "anomaly_score": round(score, 4),
            "is_anomaly": is_anomaly,
            "contributors": contributors,
        }

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialisable summary for API responses."""
        return {
            "asset_id": self.asset_id,
            "data_points": self.data_points,
            "history_size": len(self.history),
            "model_trained": self.model is not None,
            "last_train": (
                datetime.fromtimestamp(self.last_train_ts, tz=timezone.utc).isoformat()
                if self.last_train_ts
                else None
            ),
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "recent_anomalies": len(self.anomalies),
        }


# ---------------------------------------------------------------------------
# Behavioral Engine (singleton)
# ---------------------------------------------------------------------------

class BehavioralEngine:
    """
    Central manager for per-asset behavioural baselines.

    Lifecycle: call start() during app startup, stop() during shutdown.
    Feed data via record_metric().  The engine trains models automatically
    and runs periodic anomaly evaluation.
    """

    def __init__(self) -> None:
        self._assets: dict[str, AssetBaseline] = {}
        self._running = False
        self._eval_task: Optional[asyncio.Task] = None
        self._retrain_task: Optional[asyncio.Task] = None
        self._started_at: Optional[str] = None
        self._total_anomalies: int = 0
        self._all_anomalies: deque[dict[str, Any]] = deque(maxlen=1000)

    # -- public API -------------------------------------------------------

    def record_metric(self, asset_id: str, metrics: dict[str, float]) -> None:
        """
        Ingest a data point for the given asset.

        *metrics* should contain some or all of the 8 feature keys.
        Missing keys default to 0.
        """
        baseline = self._get_or_create(asset_id)
        ts = time.time()
        full = _empty_metrics()
        for k in FEATURE_NAMES:
            if k in metrics:
                full[k] = float(metrics[k])
        baseline.history.append((ts, full))
        baseline.data_points += 1

    def evaluate_current(self, asset_id: str) -> dict[str, Any]:
        """Evaluate the most recent metrics for an asset."""
        baseline = self._assets.get(asset_id)
        if baseline is None:
            return {"error": f"No data for asset '{asset_id}'"}

        if not baseline.history:
            return {"error": f"No metrics recorded for asset '{asset_id}'"}

        _, latest = baseline.history[-1]
        result = baseline.evaluate(latest)
        result["asset_id"] = asset_id
        result["evaluated_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def get_baseline(self, asset_id: str) -> Optional[dict[str, Any]]:
        """Return the learned baseline stats for an asset, or None."""
        baseline = self._assets.get(asset_id)
        if baseline is None:
            return None
        return baseline.to_dict()

    def get_all_baselines(self) -> list[dict[str, Any]]:
        """Return baselines for all known assets."""
        return [b.to_dict() for b in self._assets.values()]

    def get_recent_anomalies(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent anomaly alerts across all assets."""
        items = list(self._all_anomalies)
        items.reverse()
        return items[:limit]

    def retrain(self, asset_id: str) -> dict[str, Any]:
        """Force retrain a specific asset model."""
        baseline = self._assets.get(asset_id)
        if baseline is None:
            return {"success": False, "error": f"No data for asset '{asset_id}'"}

        ok = baseline.train()
        if ok:
            self._save_model(asset_id)
        return {
            "success": ok,
            "asset_id": asset_id,
            "data_points": baseline.data_points,
            "history_size": len(baseline.history),
        }

    def retrain_all(self) -> dict[str, Any]:
        """Force retrain models for all known assets."""
        results: dict[str, Any] = {}
        for asset_id in list(self._assets):
            results[asset_id] = self.retrain(asset_id)
        return results

    def stats(self) -> dict[str, Any]:
        """Return engine status summary."""
        trained = sum(1 for b in self._assets.values() if b.model is not None)
        return {
            "running": self._running,
            "started_at": self._started_at,
            "assets_tracked": len(self._assets),
            "models_trained": trained,
            "total_data_points": sum(b.data_points for b in self._assets.values()),
            "total_anomalies_detected": self._total_anomalies,
            "eval_interval_seconds": EVAL_INTERVAL_S,
            "retrain_interval_seconds": RETRAIN_INTERVAL_S,
            "model_dir": MODEL_DIR,
        }

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> None:
        """Start background evaluation and retrain loops."""
        if self._running:
            return

        self._running = True
        self._started_at = datetime.now(timezone.utc).isoformat()

        # Ensure model directory exists
        Path(MODEL_DIR).mkdir(parents=True, exist_ok=True)

        # Load any persisted models
        self._load_all_models()

        self._eval_task = asyncio.create_task(self._eval_loop())
        self._retrain_task = asyncio.create_task(self._retrain_loop())
        logger.info("BehavioralEngine started (eval=%ds, retrain=%ds)", EVAL_INTERVAL_S, RETRAIN_INTERVAL_S)

    async def stop(self) -> None:
        """Stop background loops."""
        self._running = False
        for task in (self._eval_task, self._retrain_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._eval_task = None
        self._retrain_task = None

        # Persist all models on shutdown
        self._save_all_models()
        logger.info("BehavioralEngine stopped")

    # -- background loops -------------------------------------------------

    async def _eval_loop(self) -> None:
        """Periodically evaluate all assets for anomalies."""
        while self._running:
            try:
                await asyncio.sleep(EVAL_INTERVAL_S)
                self._run_evaluation()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in eval loop")

    async def _retrain_loop(self) -> None:
        """Periodically retrain all models."""
        while self._running:
            try:
                await asyncio.sleep(RETRAIN_INTERVAL_S)
                self._run_retrain()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in retrain loop")

    def _run_evaluation(self) -> None:
        """Evaluate latest metrics for every asset with a trained model."""
        for asset_id, baseline in self._assets.items():
            if baseline.model is None or not baseline.history:
                continue

            _, latest = baseline.history[-1]
            result = baseline.evaluate(latest)

            if result["is_anomaly"]:
                contributors = result["contributors"]
                detail_parts = [f"{f} {desc}" for f, desc in contributors]
                detail = ", ".join(detail_parts) if detail_parts else "general deviation"

                anomaly_record = {
                    "asset_id": asset_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "anomaly_score": result["anomaly_score"],
                    "contributors": contributors,
                    "description": f"Asset {asset_id} showing unusual behavior: {detail}",
                    "metrics": deepcopy(latest),
                }

                baseline.anomalies.append(anomaly_record)
                self._all_anomalies.append(anomaly_record)
                self._total_anomalies += 1

                logger.warning(
                    "ANOMALY detected for asset %s (score=%.3f): %s",
                    asset_id,
                    result["anomaly_score"],
                    detail,
                )

    def _run_retrain(self) -> None:
        """Retrain all models that have enough data."""
        for asset_id, baseline in self._assets.items():
            if baseline.has_enough_data():
                ok = baseline.train()
                if ok:
                    self._save_model(asset_id)

    # -- persistence ------------------------------------------------------

    def _model_path(self, asset_id: str) -> str:
        safe_id = asset_id.replace("/", "_").replace("\\", "_").replace(" ", "_")
        return os.path.join(MODEL_DIR, f"iforest_{safe_id}.pkl")

    def _save_model(self, asset_id: str) -> None:
        baseline = self._assets.get(asset_id)
        if baseline is None or baseline.model is None:
            return
        path = self._model_path(asset_id)
        try:
            Path(MODEL_DIR).mkdir(parents=True, exist_ok=True)
            payload = {
                "model": baseline.model,
                "feature_means": baseline.feature_means,
                "feature_stds": baseline.feature_stds,
                "last_train_ts": baseline.last_train_ts,
                "data_points": baseline.data_points,
            }
            with open(path, "wb") as f:
                pickle.dump(payload, f)
            logger.debug("Model saved: %s", path)
        except Exception:
            logger.exception("Failed to save model for %s", asset_id)

    def _load_model(self, asset_id: str) -> bool:
        path = self._model_path(asset_id)
        if not os.path.exists(path):
            return False
        try:
            with open(path, "rb") as f:
                payload = pickle.load(f)
            baseline = self._get_or_create(asset_id)
            baseline.model = payload["model"]
            baseline.feature_means = payload.get("feature_means", {})
            baseline.feature_stds = payload.get("feature_stds", {})
            baseline.last_train_ts = payload.get("last_train_ts", 0.0)
            baseline.data_points = payload.get("data_points", 0)
            logger.info("Model loaded for asset %s from %s", asset_id, path)
            return True
        except Exception:
            logger.exception("Failed to load model for %s", asset_id)
            return False

    def _save_all_models(self) -> None:
        for asset_id, baseline in self._assets.items():
            if baseline.model is not None:
                self._save_model(asset_id)

    def _load_all_models(self) -> None:
        """Load all persisted models from MODEL_DIR."""
        model_dir = Path(MODEL_DIR)
        if not model_dir.exists():
            return
        for path in model_dir.glob("iforest_*.pkl"):
            asset_id = path.stem.replace("iforest_", "")
            self._load_model(asset_id)

    # -- internal ---------------------------------------------------------

    def _get_or_create(self, asset_id: str) -> AssetBaseline:
        if asset_id not in self._assets:
            self._assets[asset_id] = AssetBaseline(asset_id)
        return self._assets[asset_id]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

behavioral_engine = BehavioralEngine()
