"""
Quantum Security API routes for Cayde-6.

Endpoints
---------
POST /api/v1/quantum/entropy               - Analyze Renyi entropy of data
POST /api/v1/quantum/entropy/network        - Analyze network flow entropy
GET  /api/v1/quantum/crypto/assess          - Assess all assets' crypto
POST /api/v1/quantum/crypto/assess          - Assess specific algorithm
GET  /api/v1/quantum/crypto/timeline        - Quantum vulnerability timeline
GET  /api/v1/quantum/adversarial/status     - Model drift monitoring status
POST /api/v1/quantum/adversarial/check      - Check model for poisoning
GET  /api/v1/quantum/readiness              - Overall quantum readiness score
"""

import base64
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.auth import AuthContext, require_analyst, require_viewer
from app.services.subscription import check_feature, require_feature
from app.modules.quantum.entropy_analyzer import RenyiEntropyAnalyzer
from app.modules.quantum.grover_calculator import GroverCalculator
from app.modules.quantum.adversarial_detector import AdversarialDetector

router = APIRouter(prefix="/quantum", tags=["quantum-security"])

# --- Singletons ---
entropy_analyzer = RenyiEntropyAnalyzer()
grover_calculator = GroverCalculator()
adversarial_detector = AdversarialDetector()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class EntropyRequest(BaseModel):
    data_base64: str = Field(
        default="",
        description="Base64-encoded data to analyze. If empty, returns a general entropy overview.",
    )
    alpha_orders: Optional[list[float]] = Field(
        None,
        description="Renyi alpha orders to compute (default: [0.5, 1.0, 2.0, inf])",
    )


class C2DetectionRequest(BaseModel):
    payload_base64: str = Field(..., description="Base64-encoded payload")
    timing_intervals_ms: Optional[list[float]] = Field(
        None,
        description="Timing intervals between packets in milliseconds",
    )


class NetworkFlowRequest(BaseModel):
    packets_base64: list[str] = Field(
        ...,
        description="List of base64-encoded packet payloads",
    )


class CryptoAssessRequest(BaseModel):
    algorithm: str = Field(..., description="Algorithm name (e.g. AES-128, RSA-2048)")
    key_bits: Optional[int] = Field(None, description="Key size in bits")


class AssetCryptoRequest(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    certificate_algorithm: Optional[str] = None
    encryption: Optional[str] = None
    signature: Optional[str] = None
    hash: Optional[str] = None


class DriftCheckRequest(BaseModel):
    current_distribution: dict[str, list[float]] = Field(
        ...,
        description="Current feature distributions to check against baseline",
    )
    baseline_distribution: Optional[dict[str, list[float]]] = Field(
        None,
        description="Baseline distributions (optional if baseline already set)",
    )


class EvasionCheckRequest(BaseModel):
    event_scores: list[float] = Field(
        ...,
        description="Detection scores for recent events",
    )
    detection_threshold: float = Field(0.5, description="Detection threshold")
    margin: float = Field(0.05, description="Suspicious band width below threshold")


class BaselineSetRequest(BaseModel):
    feature_distributions: dict[str, list[float]] = Field(
        ...,
        description="Feature distributions to set as baseline",
    )


class BaselineVerifyRequest(BaseModel):
    baseline_data: dict[str, list[float]] = Field(
        ...,
        description="Baseline data to verify integrity of",
    )


# ---------------------------------------------------------------------------
# Entropy Endpoints
# ---------------------------------------------------------------------------

@router.post("/entropy", summary="Analyze Renyi entropy of data")
async def analyze_entropy(
    req: EntropyRequest,
    auth: AuthContext = Depends(require_viewer),
):
    """Compute multi-order Renyi entropy for the provided data."""
    require_feature(auth.client, "quantum_entropy", "pro")

    # If no data provided, return a general entropy overview
    if not req.data_base64:
        return {
            "overview": True,
            "description": "Renyi entropy analysis module",
            "supported_orders": [0.5, 1.0, 2.0, float("inf")],
            "max_data_size_mb": 10,
            "capabilities": [
                "entropy_analysis",
                "c2_beacon_detection",
                "steganography_detection",
                "network_flow_analysis",
            ],
        }

    try:
        data = base64.b64decode(req.data_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty data after decoding")

    if len(data) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="Data exceeds 10MB limit")

    result = entropy_analyzer.analyze(data, alpha_orders=req.alpha_orders)
    return result


@router.post("/entropy/c2", summary="Detect C2 beacon traffic")
async def detect_c2(
    req: C2DetectionRequest,
    auth: AuthContext = Depends(require_viewer),
):
    """Analyze payload entropy to detect C2 beacon traffic patterns."""
    require_feature(auth.client, "quantum_entropy", "pro")
    try:
        payload = base64.b64decode(req.payload_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    result = entropy_analyzer.detect_c2_traffic(
        payload,
        timing_intervals_ms=req.timing_intervals_ms,
    )
    return result


@router.post("/entropy/stego", summary="Detect steganography")
async def detect_stego(
    req: EntropyRequest,
    file_type: str = "application/octet-stream",
    auth: AuthContext = Depends(require_viewer),
):
    """Detect steganographic content using Renyi entropy deviation analysis."""
    require_feature(auth.client, "quantum_entropy", "pro")
    try:
        data = base64.b64decode(req.data_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    result = entropy_analyzer.detect_steganography(data, file_type=file_type)
    return result


@router.post("/entropy/network", summary="Analyze network flow entropy")
async def analyze_network_flow(
    req: NetworkFlowRequest,
    auth: AuthContext = Depends(require_viewer),
):
    """Analyze entropy trend over a sequence of network packets."""
    require_feature(auth.client, "quantum_entropy", "pro")
    try:
        packets = [base64.b64decode(p) for p in req.packets_base64]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding in packets")

    if not packets:
        raise HTTPException(status_code=400, detail="No packets provided")

    result = entropy_analyzer.analyze_network_flow(packets)
    return result


# ---------------------------------------------------------------------------
# Crypto Assessment Endpoints
# ---------------------------------------------------------------------------

@router.get("/crypto/assess", summary="Assess all assets' crypto strength")
async def assess_all_crypto(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Assess quantum vulnerability of common cryptographic algorithms.
    Returns assessments for all known algorithms in the database.
    """
    require_feature(auth.client, "grover_calculator", "pro")
    from app.modules.quantum.grover_calculator import CRYPTO_ASSESSMENTS

    results = []
    for algo_name in sorted(CRYPTO_ASSESSMENTS.keys()):
        results.append(grover_calculator.assess_key_strength(algo_name))

    # Compute summary
    critical = sum(1 for r in results if r.get("status") == "critical")
    migrate = sum(1 for r in results if r.get("status") == "migrate")
    safe = sum(1 for r in results if r.get("status") == "safe")

    return {
        "total_algorithms": len(results),
        "summary": {"critical": critical, "migrate": migrate, "safe": safe},
        "assessments": results,
    }


@router.post("/crypto/assess", summary="Assess specific algorithm")
async def assess_algorithm(
    req: CryptoAssessRequest,
    auth: AuthContext = Depends(require_viewer),
):
    """Assess a specific cryptographic algorithm against quantum attacks."""
    require_feature(auth.client, "grover_calculator", "pro")
    result = grover_calculator.assess_key_strength(req.algorithm, req.key_bits)
    return result


@router.post("/crypto/assess/asset", summary="Assess asset crypto posture")
async def assess_asset_crypto(
    req: AssetCryptoRequest,
    auth: AuthContext = Depends(require_analyst),
):
    """Assess an asset's complete cryptographic posture against quantum threats."""
    require_feature(auth.client, "grover_calculator", "pro")
    result = grover_calculator.assess_asset(req.model_dump())
    return result


@router.get("/crypto/timeline", summary="Quantum vulnerability timeline")
async def crypto_timeline(
    auth: AuthContext = Depends(require_viewer),
):
    """Get timeline of when each cryptographic algorithm becomes quantum-vulnerable."""
    require_feature(auth.client, "grover_calculator", "pro")
    return grover_calculator.get_vulnerability_timeline()


# ---------------------------------------------------------------------------
# Adversarial Detection Endpoints
# ---------------------------------------------------------------------------

@router.get("/adversarial/status", summary="Model drift monitoring status")
async def adversarial_status(
    auth: AuthContext = Depends(require_viewer),
):
    """Get current adversarial monitoring state and recent history."""
    require_feature(auth.client, "adversarial_ml", "enterprise")
    return adversarial_detector.get_monitoring_status()


@router.post("/adversarial/baseline", summary="Set monitoring baseline")
async def set_adversarial_baseline(
    req: BaselineSetRequest,
    auth: AuthContext = Depends(require_analyst),
):
    """Establish baseline distributions for model drift monitoring."""
    require_feature(auth.client, "adversarial_ml", "enterprise")
    if not req.feature_distributions:
        raise HTTPException(status_code=400, detail="No feature distributions provided")

    return adversarial_detector.set_baseline(req.feature_distributions)


@router.post("/adversarial/check", summary="Check model for poisoning")
async def check_model_poisoning(
    req: DriftCheckRequest,
    auth: AuthContext = Depends(require_analyst),
):
    """Check current model distributions against baseline for poisoning detection."""
    require_feature(auth.client, "adversarial_ml", "enterprise")
    if not req.current_distribution:
        raise HTTPException(status_code=400, detail="No current distribution provided")

    result = adversarial_detector.monitor_model_drift(
        current_distribution=req.current_distribution,
        baseline_distribution=req.baseline_distribution,
    )
    return result


@router.post("/adversarial/evasion", summary="Detect evasion attacks")
async def detect_evasion(
    req: EvasionCheckRequest,
    auth: AuthContext = Depends(require_analyst),
):
    """Detect adversarial evasion by analyzing score clustering near detection threshold."""
    require_feature(auth.client, "adversarial_ml", "enterprise")
    if len(req.event_scores) < 5:
        raise HTTPException(status_code=400, detail="Need at least 5 event scores")

    return adversarial_detector.detect_evasion_attempt(
        event_scores=req.event_scores,
        detection_threshold=req.detection_threshold,
        margin=req.margin,
    )


@router.post("/adversarial/verify-baseline", summary="Verify baseline integrity")
async def verify_baseline(
    req: BaselineVerifyRequest,
    auth: AuthContext = Depends(require_analyst),
):
    """Check if a baseline distribution has been corrupted or gradually shifted."""
    require_feature(auth.client, "adversarial_ml", "enterprise")
    return adversarial_detector.verify_baseline_integrity(req.baseline_data)


# ---------------------------------------------------------------------------
# Quantum Readiness Score
# ---------------------------------------------------------------------------

@router.get("/readiness", summary="Overall quantum readiness score")
async def quantum_readiness(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Compute an overall quantum readiness score (0-100) based on:
    - Cryptographic algorithm assessment
    - Adversarial monitoring status
    - Post-quantum algorithm adoption

    Available to ALL tiers.  Free tier receives a simplified summary;
    Pro/Enterprise tiers get the full breakdown.
    """
    from app.modules.quantum.grover_calculator import CRYPTO_ASSESSMENTS

    timeline = grover_calculator.get_vulnerability_timeline()
    adversarial = adversarial_detector.get_monitoring_status()

    # Crypto score (0-50 points)
    total_algos = timeline["summary"]["total_algorithms"]
    safe_algos = timeline["summary"]["quantum_safe"]
    crypto_ratio = safe_algos / total_algos if total_algos > 0 else 0
    crypto_score = crypto_ratio * 50

    # Urgency penalty: algorithms vulnerable within 5 years
    urgent = sum(
        1 for v in timeline.get("upcoming_vulnerabilities", [])
        if v.get("years_remaining", 99) <= 5
    )
    urgency_penalty = min(urgent * 5, 20)

    # Adversarial monitoring score (0-30 points)
    monitoring_score = 0.0
    if adversarial["has_baseline"]:
        monitoring_score += 15.0
        recent = adversarial.get("recent_checks", [])
        if recent:
            healthy = sum(1 for c in recent if c.get("status") == "healthy")
            monitoring_score += 15.0 * (healthy / len(recent))

    # Post-quantum adoption bonus (0-20 points)
    pq_algos = [a for a in CRYPTO_ASSESSMENTS if CRYPTO_ASSESSMENTS[a]["type"].startswith("post_quantum")]
    pq_score = min(len(pq_algos) * 3, 20)

    total_score = max(0, crypto_score - urgency_penalty + monitoring_score + pq_score)
    total_score = min(total_score, 100)

    grade = (
        "A" if total_score >= 80 else
        "B" if total_score >= 60 else
        "C" if total_score >= 40 else
        "D" if total_score >= 20 else
        "F"
    )

    # Free tier: simplified overview (score + grade + summary only)
    is_pro = check_feature(auth.client, "grover_calculator")

    result = {
        "quantum_readiness_score": round(total_score, 1),
        "grade": grade,
        "summary": {
            "total_algorithms_tracked": total_algos,
            "quantum_safe": safe_algos,
            "already_vulnerable": timeline["summary"]["already_vulnerable"],
            "upcoming_vulnerabilities": timeline["summary"]["upcoming"],
            "monitoring_active": adversarial["has_baseline"],
            "urgent_migrations": urgent,
        },
        "assessed_at": datetime.utcnow().isoformat(),
    }

    if is_pro:
        # Full breakdown for Pro/Enterprise
        result["breakdown"] = {
            "crypto_safety": round(crypto_score, 1),
            "urgency_penalty": round(-urgency_penalty, 1),
            "adversarial_monitoring": round(monitoring_score, 1),
            "post_quantum_adoption": round(pq_score, 1),
        }
    else:
        result["upgrade_hint"] = "Upgrade to Pro for detailed quantum readiness breakdown and crypto assessment tools."

    return result
