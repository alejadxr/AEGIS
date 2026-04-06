"""
Adversarial ML Detection for AEGIS Quantum Security Module.

Detects model poisoning, evasion attacks, and baseline corruption using
KL-divergence and statistical testing. Protects AEGIS's own AI engine
from adversarial manipulation.

KL-divergence: D_KL(P || Q) = sum( P(x) * log(P(x) / Q(x)) )
Measures how much distribution P diverges from reference Q.
"""

import math
from datetime import datetime
from typing import Optional

import numpy as np
from scipy import stats as scipy_stats


class AdversarialDetector:
    """
    Detects adversarial attacks against ML models using information-theoretic
    measures. Monitors for:
    1. Model poisoning via distribution drift (KL-divergence)
    2. Evasion attacks via threshold clustering analysis
    3. Baseline corruption via statistical integrity tests
    """

    def __init__(
        self,
        kl_threshold: float = 0.5,
        evasion_cluster_threshold: float = 0.05,
        baseline_check_alpha: float = 0.01,
    ):
        """
        Args:
            kl_threshold: KL-divergence above this triggers poisoning alert.
            evasion_cluster_threshold: Fraction of events clustering near
                detection boundary that triggers evasion alert.
            baseline_check_alpha: Significance level for baseline integrity tests.
        """
        self.kl_threshold = kl_threshold
        self.evasion_cluster_threshold = evasion_cluster_threshold
        self.baseline_check_alpha = baseline_check_alpha

        # In-memory baseline storage (populated via set_baseline)
        self._baseline: Optional[dict] = None
        self._monitoring_history: list[dict] = []

    def set_baseline(self, feature_distributions: dict[str, list[float]]) -> dict:
        """
        Establish baseline distributions for monitoring.

        Args:
            feature_distributions: dict mapping feature names to lists of
                observed values forming the baseline distribution.
        """
        baseline = {}
        for name, values in feature_distributions.items():
            arr = np.array(values, dtype=np.float64)
            if len(arr) < 10:
                continue
            n_bins = min(max(int(np.sqrt(len(arr))), 10), 100)
            histogram, bin_edges = np.histogram(arr, bins=n_bins)
            # Normalize counts to probability distribution
            probs = histogram.astype(np.float64)
            total = probs.sum()
            if total > 0:
                probs = probs / total
            baseline[name] = {
                "probabilities": probs,
                "bin_edges": bin_edges,
                "mean": float(arr.mean()),
                "std": float(arr.std()),
                "n_samples": len(arr),
                "skewness": float(scipy_stats.skew(arr)),
                "kurtosis": float(scipy_stats.kurtosis(arr)),
            }

        self._baseline = baseline
        return {
            "status": "baseline_set",
            "features": list(baseline.keys()),
            "timestamp": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _kl_divergence(p: np.ndarray, q: np.ndarray, epsilon: float = 1e-10) -> float:
        """
        Compute KL-divergence D_KL(P || Q) = sum(P(x) * log(P(x) / Q(x))).

        Adds epsilon smoothing to avoid log(0) and division by zero.
        """
        p = np.asarray(p, dtype=np.float64) + epsilon
        q = np.asarray(q, dtype=np.float64) + epsilon
        # Renormalize after smoothing
        p = p / p.sum()
        q = q / q.sum()
        return float(np.sum(p * np.log(p / q)))

    @staticmethod
    def _js_divergence(p: np.ndarray, q: np.ndarray, epsilon: float = 1e-10) -> float:
        """
        Jensen-Shannon divergence (symmetric, bounded version of KL).
        JS(P || Q) = 0.5 * KL(P || M) + 0.5 * KL(Q || M), where M = (P+Q)/2
        """
        p = np.asarray(p, dtype=np.float64) + epsilon
        q = np.asarray(q, dtype=np.float64) + epsilon
        p = p / p.sum()
        q = q / q.sum()
        m = 0.5 * (p + q)
        kl_pm = float(np.sum(p * np.log(p / m)))
        kl_qm = float(np.sum(q * np.log(q / m)))
        return 0.5 * kl_pm + 0.5 * kl_qm

    def monitor_model_drift(
        self,
        current_distribution: dict[str, list[float]],
        baseline_distribution: Optional[dict[str, list[float]]] = None,
    ) -> dict:
        """
        Detect model poisoning by measuring KL-divergence between current
        feature distributions and the baseline.

        If KL > threshold for any feature, raises a poisoning alert.
        """
        # Use provided baseline or stored one
        if baseline_distribution:
            baseline_result = self.set_baseline(baseline_distribution)
        elif self._baseline is None:
            return {
                "status": "error",
                "message": "No baseline set. Call set_baseline() first or provide baseline_distribution.",
            }

        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "features_analyzed": 0,
            "alerts": [],
            "feature_drift": {},
            "overall_status": "healthy",
            "poisoning_detected": False,
        }

        alert_count = 0

        for feature_name, current_values in current_distribution.items():
            if feature_name not in self._baseline:
                continue

            baseline_info = self._baseline[feature_name]
            current_arr = np.array(current_values, dtype=np.float64)

            if len(current_arr) < 5:
                continue

            # Build histogram using same bins as baseline
            current_hist, _ = np.histogram(
                current_arr,
                bins=baseline_info["bin_edges"],
            )
            current_probs = current_hist.astype(np.float64)
            total = current_probs.sum()
            if total > 0:
                current_probs = current_probs / total

            baseline_probs = baseline_info["probabilities"]

            # Ensure same length (may differ by 1 due to bin edges)
            min_len = min(len(current_probs), len(baseline_probs))
            current_probs = current_probs[:min_len]
            baseline_probs = baseline_probs[:min_len]

            kl_div = self._kl_divergence(current_probs, baseline_probs)
            js_div = self._js_divergence(current_probs, baseline_probs)

            # Mean shift detection
            mean_shift = abs(float(current_arr.mean()) - baseline_info["mean"])
            std_ratio = float(current_arr.std()) / baseline_info["std"] if baseline_info["std"] > 0 else 1.0

            is_drifted = kl_div > self.kl_threshold

            drift_info = {
                "kl_divergence": round(kl_div, 6),
                "js_divergence": round(js_div, 6),
                "threshold": self.kl_threshold,
                "is_drifted": is_drifted,
                "mean_shift": round(mean_shift, 4),
                "std_ratio": round(std_ratio, 4),
                "current_mean": round(float(current_arr.mean()), 4),
                "baseline_mean": round(baseline_info["mean"], 4),
            }

            results["feature_drift"][feature_name] = drift_info
            results["features_analyzed"] += 1

            if is_drifted:
                alert_count += 1
                severity = "critical" if kl_div > self.kl_threshold * 5 else "high" if kl_div > self.kl_threshold * 2 else "medium"
                results["alerts"].append({
                    "feature": feature_name,
                    "type": "distribution_drift",
                    "severity": severity,
                    "kl_divergence": round(kl_div, 6),
                    "message": f"Feature '{feature_name}' distribution has shifted significantly "
                               f"(KL={kl_div:.4f} > threshold={self.kl_threshold}). "
                               f"Possible model poisoning.",
                })

        if alert_count > 0:
            results["poisoning_detected"] = True
            results["overall_status"] = "poisoning_suspected"
            if alert_count >= results["features_analyzed"] * 0.5:
                results["overall_status"] = "poisoning_likely"

        # Store in history
        self._monitoring_history.append({
            "timestamp": results["timestamp"],
            "status": results["overall_status"],
            "alerts": len(results["alerts"]),
            "features": results["features_analyzed"],
        })
        # Keep last 1000 entries
        if len(self._monitoring_history) > 1000:
            self._monitoring_history = self._monitoring_history[-1000:]

        return results

    def detect_evasion_attempt(
        self,
        event_scores: list[float],
        detection_threshold: float = 0.5,
        margin: float = 0.05,
    ) -> dict:
        """
        Detect evasion attacks by analyzing score clustering near the
        detection threshold.

        Adversarial evasion: attacker crafts inputs that score just below
        the detection threshold. This manifests as an abnormal concentration
        of scores in [threshold - margin, threshold].
        """
        if not event_scores:
            return {"evasion_detected": False, "reason": "no_scores"}

        scores = np.array(event_scores, dtype=np.float64)
        total = len(scores)

        # Count scores in the suspicious band just below threshold
        lower_bound = detection_threshold - margin
        in_band = np.sum((scores >= lower_bound) & (scores < detection_threshold))
        band_fraction = float(in_band) / total

        # Expected fraction under uniform distribution over the score range
        score_range = scores.max() - scores.min()
        expected_fraction = margin / score_range if score_range > 0 else 0.0

        # Statistical test: is the band over-represented?
        # Use binomial test: is the observed count significantly higher than expected?
        if total >= 10 and expected_fraction > 0:
            binom_p = scipy_stats.binom_test(
                int(in_band), total, expected_fraction, alternative="greater"
            ) if hasattr(scipy_stats, 'binom_test') else scipy_stats.binomtest(
                int(in_band), total, expected_fraction, alternative="greater"
            ).pvalue
        else:
            binom_p = 1.0

        evasion_detected = (
            band_fraction > self.evasion_cluster_threshold
            and binom_p < 0.01
        )

        # Analyze score distribution shape
        below_threshold = scores[scores < detection_threshold]
        above_threshold = scores[scores >= detection_threshold]

        return {
            "evasion_detected": evasion_detected,
            "confidence": round(1.0 - binom_p, 4) if evasion_detected else 0.0,
            "analysis": {
                "total_events": total,
                "below_threshold": int(len(below_threshold)),
                "above_threshold": int(len(above_threshold)),
                "in_suspicious_band": int(in_band),
                "band_range": [round(lower_bound, 4), round(detection_threshold, 4)],
                "band_fraction": round(band_fraction, 4),
                "expected_fraction": round(expected_fraction, 4),
                "enrichment_ratio": round(band_fraction / expected_fraction, 2) if expected_fraction > 0 else 0.0,
                "binomial_p_value": round(binom_p, 6),
            },
            "detection_threshold": detection_threshold,
            "margin": margin,
        }

    def verify_baseline_integrity(
        self,
        baseline_data: dict[str, list[float]],
    ) -> dict:
        """
        Verify the integrity of a baseline distribution itself.

        Detects if the baseline was gradually corrupted by checking:
        1. Normality (Shapiro-Wilk) or expected distribution shape
        2. Outlier contamination (modified Z-score)
        3. Temporal stationarity (split-half consistency)
        """
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "features_checked": 0,
            "integrity_status": "intact",
            "issues": [],
            "feature_results": {},
        }

        for name, values in baseline_data.items():
            arr = np.array(values, dtype=np.float64)
            if len(arr) < 20:
                continue

            results["features_checked"] += 1
            feature_result = {}

            # 1. Outlier contamination using modified Z-score (MAD-based)
            median = np.median(arr)
            mad = np.median(np.abs(arr - median))
            if mad > 0:
                modified_z = 0.6745 * (arr - median) / mad
                outlier_count = int(np.sum(np.abs(modified_z) > 3.5))
                outlier_fraction = outlier_count / len(arr)
            else:
                outlier_count = 0
                outlier_fraction = 0.0

            feature_result["outlier_analysis"] = {
                "outlier_count": outlier_count,
                "outlier_fraction": round(outlier_fraction, 4),
                "contaminated": outlier_fraction > 0.05,
            }

            # 2. Split-half stationarity test
            # If baseline was gradually shifted, first and second halves differ
            half = len(arr) // 2
            first_half = arr[:half]
            second_half = arr[half:]

            ks_stat, ks_p = scipy_stats.ks_2samp(first_half, second_half)
            feature_result["stationarity"] = {
                "ks_statistic": round(float(ks_stat), 4),
                "ks_p_value": round(float(ks_p), 6),
                "is_stationary": ks_p > self.baseline_check_alpha,
            }

            # 3. Distribution shape check (Shapiro-Wilk on subsample)
            subsample = arr[np.random.choice(len(arr), min(500, len(arr)), replace=False)]
            try:
                shapiro_stat, shapiro_p = scipy_stats.shapiro(subsample)
                feature_result["normality"] = {
                    "shapiro_statistic": round(float(shapiro_stat), 4),
                    "shapiro_p_value": round(float(shapiro_p), 6),
                    "is_normal": shapiro_p > self.baseline_check_alpha,
                }
            except Exception:
                feature_result["normality"] = {"error": "shapiro_test_failed"}

            # Aggregate issues for this feature
            issues = []
            if feature_result["outlier_analysis"]["contaminated"]:
                issues.append(f"High outlier contamination ({outlier_fraction:.1%}) in '{name}'")
            if not feature_result["stationarity"]["is_stationary"]:
                issues.append(f"Non-stationary baseline for '{name}' (KS p={ks_p:.4f}) — possible gradual drift")

            feature_result["issues"] = issues
            results["feature_results"][name] = feature_result
            results["issues"].extend(issues)

        if results["issues"]:
            results["integrity_status"] = "compromised"

        return results

    def get_monitoring_status(self) -> dict:
        """Return current monitoring state and recent history."""
        return {
            "has_baseline": self._baseline is not None,
            "baseline_features": list(self._baseline.keys()) if self._baseline else [],
            "monitoring_history_count": len(self._monitoring_history),
            "recent_checks": self._monitoring_history[-10:] if self._monitoring_history else [],
            "kl_threshold": self.kl_threshold,
            "evasion_cluster_threshold": self.evasion_cluster_threshold,
        }
