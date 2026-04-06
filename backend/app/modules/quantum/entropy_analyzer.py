"""
Renyi Entropy Analyzer for AEGIS Quantum Security Module.

Implements generalized Renyi entropy H_alpha(X) = 1/(1-alpha) * log2(sum(p_i^alpha))
for detecting C2 beacons, steganography, and anomalous network flows using
information-theoretic measures across multiple alpha orders.
"""

import math
from collections import Counter
from typing import Optional

import numpy as np


# Known C2 framework entropy profiles (collision entropy alpha=2 ranges)
# Real C2 traffic has characteristic entropy bands due to structured payloads
C2_PROFILES = {
    "cobalt_strike": {"h2_min": 5.8, "h2_max": 6.8, "regularity_min": 0.7},
    "metasploit": {"h2_min": 5.5, "h2_max": 6.5, "regularity_min": 0.6},
    "covenant": {"h2_min": 6.0, "h2_max": 7.0, "regularity_min": 0.65},
    "sliver": {"h2_min": 5.9, "h2_max": 6.9, "regularity_min": 0.72},
    "generic_encrypted_c2": {"h2_min": 7.0, "h2_max": 7.95, "regularity_min": 0.8},
}

# Expected entropy ranges by file type (Shannon entropy, alpha=1)
FILE_TYPE_ENTROPY = {
    "image/png": {"mean": 7.7, "std": 0.3},
    "image/jpeg": {"mean": 7.5, "std": 0.4},
    "image/bmp": {"mean": 4.5, "std": 1.5},
    "image/gif": {"mean": 6.5, "std": 1.0},
    "text/plain": {"mean": 4.5, "std": 0.8},
    "text/html": {"mean": 5.0, "std": 0.6},
    "application/pdf": {"mean": 7.2, "std": 0.5},
    "application/zip": {"mean": 7.99, "std": 0.01},
    "application/octet-stream": {"mean": 5.0, "std": 2.0},
}


class RenyiEntropyAnalyzer:
    """
    Multi-order Renyi entropy analyzer for security applications.

    Renyi entropy generalizes Shannon entropy with a parameter alpha that
    controls sensitivity to different parts of the probability distribution:
      - alpha=0.5: emphasizes rare symbols (steganography detection)
      - alpha=1.0: Shannon entropy (general randomness measure)
      - alpha=2.0: collision entropy (C2 beacon detection)
      - alpha=inf: min-entropy (worst-case predictability)
    """

    def __init__(self, stego_z_threshold: float = 3.0, c2_confidence_min: float = 0.6):
        self.stego_z_threshold = stego_z_threshold
        self.c2_confidence_min = c2_confidence_min

    @staticmethod
    def _byte_distribution(data: bytes) -> np.ndarray:
        """Compute probability distribution over byte values 0-255."""
        counts = np.zeros(256, dtype=np.float64)
        for b in data:
            counts[b] += 1.0
        total = counts.sum()
        if total == 0:
            return counts
        return counts / total

    @staticmethod
    def _renyi_entropy(probs: np.ndarray, alpha: float) -> float:
        """
        Compute Renyi entropy of order alpha.

        H_alpha(X) = 1/(1-alpha) * log2(sum(p_i^alpha))

        Special cases:
          alpha=1.0 -> Shannon entropy (limit): H = -sum(p_i * log2(p_i))
          alpha=inf -> min-entropy: H_inf = -log2(max(p_i))
        """
        nonzero = probs[probs > 0]
        if len(nonzero) == 0:
            return 0.0

        if alpha == float("inf"):
            return -math.log2(nonzero.max())

        if abs(alpha - 1.0) < 1e-10:
            # Shannon entropy as limit of Renyi when alpha -> 1
            return float(-np.sum(nonzero * np.log2(nonzero)))

        # General Renyi entropy
        power_sum = np.sum(nonzero ** alpha)
        if power_sum <= 0:
            return 0.0
        return float((1.0 / (1.0 - alpha)) * math.log2(power_sum))

    def analyze(
        self,
        data: bytes,
        alpha_orders: Optional[list[float]] = None,
    ) -> dict:
        """
        Compute Renyi entropy at multiple alpha orders for the given data.

        Returns dict with entropy values, byte distribution stats, and
        interpretation for each alpha order.
        """
        if alpha_orders is None:
            alpha_orders = [0.5, 1.0, 2.0, float("inf")]

        if not data:
            return {
                "error": "empty_data",
                "entropies": {},
                "data_size_bytes": 0,
            }

        probs = self._byte_distribution(data)
        unique_symbols = int(np.count_nonzero(probs))

        entropies = {}
        for alpha in alpha_orders:
            h = self._renyi_entropy(probs, alpha)
            label = self._alpha_label(alpha)
            entropies[str(alpha)] = {
                "value": round(h, 6),
                "max_possible": 8.0,  # log2(256)
                "normalized": round(h / 8.0, 4),
                "label": label,
            }

        return {
            "entropies": entropies,
            "data_size_bytes": len(data),
            "unique_byte_values": unique_symbols,
            "max_byte_values": 256,
            "byte_utilization": round(unique_symbols / 256.0, 4),
        }

    def detect_c2_traffic(self, payload: bytes, timing_intervals_ms: Optional[list[float]] = None) -> dict:
        """
        Detect C2 beacon traffic using collision entropy profiling.

        C2 beacons exhibit:
        1. High collision entropy (alpha=2) due to encrypted/encoded payloads
        2. Regular timing intervals (low coefficient of variation)
        3. Entropy profile matching known C2 frameworks
        """
        if len(payload) < 16:
            return {
                "is_c2": False,
                "confidence": 0.0,
                "reason": "payload_too_small",
                "matches": [],
            }

        probs = self._byte_distribution(payload)
        h2 = self._renyi_entropy(probs, 2.0)
        h1 = self._renyi_entropy(probs, 1.0)
        h_inf = self._renyi_entropy(probs, float("inf"))

        # Timing regularity analysis
        timing_regularity = 0.0
        timing_analysis = None
        if timing_intervals_ms and len(timing_intervals_ms) >= 3:
            intervals = np.array(timing_intervals_ms, dtype=np.float64)
            mean_interval = intervals.mean()
            if mean_interval > 0:
                cv = intervals.std() / mean_interval  # coefficient of variation
                # Low CV = highly regular = beacon-like
                timing_regularity = max(0.0, 1.0 - cv)
                timing_analysis = {
                    "mean_interval_ms": round(float(mean_interval), 2),
                    "std_interval_ms": round(float(intervals.std()), 2),
                    "coefficient_of_variation": round(float(cv), 4),
                    "regularity_score": round(timing_regularity, 4),
                }

        # Match against known C2 profiles
        matches = []
        for name, profile in C2_PROFILES.items():
            entropy_match = profile["h2_min"] <= h2 <= profile["h2_max"]
            timing_match = timing_regularity >= profile["regularity_min"] if timing_intervals_ms else False

            if entropy_match:
                confidence = 0.4  # entropy match alone
                if timing_match:
                    confidence = 0.85
                elif timing_intervals_ms:
                    confidence = 0.25  # entropy match but timing doesn't match
                matches.append({
                    "profile": name,
                    "confidence": round(confidence, 3),
                    "entropy_match": True,
                    "timing_match": timing_match,
                })

        matches.sort(key=lambda m: m["confidence"], reverse=True)
        best_confidence = matches[0]["confidence"] if matches else 0.0

        return {
            "is_c2": best_confidence >= self.c2_confidence_min,
            "confidence": round(best_confidence, 3),
            "entropy_profile": {
                "shannon_h1": round(h1, 4),
                "collision_h2": round(h2, 4),
                "min_entropy_hinf": round(h_inf, 4),
            },
            "timing_analysis": timing_analysis,
            "matches": matches,
            "payload_size": len(payload),
        }

    def detect_steganography(
        self,
        data: bytes,
        file_type: str = "application/octet-stream",
    ) -> dict:
        """
        Detect steganographic content using Renyi entropy deviation.

        Steganography embeds data into carrier files, shifting the entropy
        distribution. Alpha=0.5 (Hartley-like) is most sensitive to rare
        symbols introduced by embedding algorithms.

        Detection: if |observed_H - expected_H| / expected_std > z_threshold,
        the file likely contains hidden data.
        """
        if not data:
            return {"is_suspicious": False, "confidence": 0.0, "reason": "empty_data"}

        probs = self._byte_distribution(data)
        h_half = self._renyi_entropy(probs, 0.5)
        h1 = self._renyi_entropy(probs, 1.0)
        h2 = self._renyi_entropy(probs, 2.0)

        # Get expected entropy for file type
        expected = FILE_TYPE_ENTROPY.get(file_type, FILE_TYPE_ENTROPY["application/octet-stream"])
        expected_mean = expected["mean"]
        expected_std = expected["std"]

        # Z-score of the alpha=0.5 entropy (most sensitive to rare symbols)
        z_score_half = abs(h_half - expected_mean) / expected_std if expected_std > 0 else 0.0
        z_score_shannon = abs(h1 - expected_mean) / expected_std if expected_std > 0 else 0.0

        # Entropy spectrum flatness: steganography tends to flatten the
        # Renyi spectrum (all alpha orders converge toward the same value)
        spectrum_range = abs(h_half - h2)
        # For natural data, h_half > h1 > h2 with meaningful gaps
        # For stego data, the spectrum compresses
        spectrum_flat = spectrum_range < 0.3

        # Combined confidence
        z_primary = max(z_score_half, z_score_shannon)
        confidence = 0.0
        reasons = []

        if z_primary > self.stego_z_threshold:
            confidence += 0.5
            reasons.append(f"entropy_deviation_z={round(z_primary, 2)}")

        if spectrum_flat and h1 > 6.0:
            confidence += 0.3
            reasons.append(f"flat_spectrum_range={round(spectrum_range, 3)}")

        # Byte distribution uniformity check (LSB steganography pushes toward uniform)
        unique_symbols = int(np.count_nonzero(probs))
        if unique_symbols == 256 and h1 > 7.5:
            confidence += 0.2
            reasons.append("full_byte_utilization_high_entropy")

        confidence = min(confidence, 1.0)

        return {
            "is_suspicious": confidence >= 0.5,
            "confidence": round(confidence, 3),
            "reasons": reasons,
            "entropy_profile": {
                "h_0.5_rare_sensitive": round(h_half, 4),
                "h_1.0_shannon": round(h1, 4),
                "h_2.0_collision": round(h2, 4),
                "spectrum_range": round(spectrum_range, 4),
            },
            "file_type": file_type,
            "expected_entropy": {
                "mean": expected_mean,
                "std": expected_std,
            },
            "z_scores": {
                "alpha_0.5": round(z_score_half, 3),
                "alpha_1.0": round(z_score_shannon, 3),
            },
            "data_size_bytes": len(data),
        }

    def analyze_network_flow(self, flow_data: list[bytes]) -> dict:
        """
        Analyze entropy trend over time for a network connection.

        Encrypted C2 traffic has a different entropy evolution pattern than
        legitimate HTTPS:
        - HTTPS: high entropy after handshake, variable during content transfer
        - C2: consistently high entropy with low variance between packets
        """
        if not flow_data:
            return {"error": "no_flow_data", "packets_analyzed": 0}

        packet_entropies = []
        for packet in flow_data:
            if len(packet) < 4:
                continue
            probs = self._byte_distribution(packet)
            h1 = self._renyi_entropy(probs, 1.0)
            h2 = self._renyi_entropy(probs, 2.0)
            packet_entropies.append({
                "shannon": h1,
                "collision": h2,
                "size": len(packet),
            })

        if not packet_entropies:
            return {"error": "no_valid_packets", "packets_analyzed": 0}

        shannon_values = np.array([p["shannon"] for p in packet_entropies])
        collision_values = np.array([p["collision"] for p in packet_entropies])
        sizes = np.array([p["size"] for p in packet_entropies])

        shannon_mean = float(shannon_values.mean())
        shannon_std = float(shannon_values.std())
        collision_mean = float(collision_values.mean())
        collision_std = float(collision_values.std())

        # C2 indicator: consistently high entropy with low variance
        is_high_entropy = shannon_mean > 7.0
        is_low_variance = shannon_std < 0.3 if len(shannon_values) > 1 else False
        size_cv = float(sizes.std() / sizes.mean()) if sizes.mean() > 0 else 0.0
        is_uniform_size = size_cv < 0.2 if len(sizes) > 1 else False

        c2_indicators = sum([is_high_entropy, is_low_variance, is_uniform_size])
        c2_score = c2_indicators / 3.0

        # Entropy trend (linear regression slope)
        trend_slope = 0.0
        if len(shannon_values) >= 3:
            x = np.arange(len(shannon_values), dtype=np.float64)
            coeffs = np.polyfit(x, shannon_values, 1)
            trend_slope = float(coeffs[0])

        return {
            "packets_analyzed": len(packet_entropies),
            "entropy_stats": {
                "shannon_mean": round(shannon_mean, 4),
                "shannon_std": round(shannon_std, 4),
                "collision_mean": round(collision_mean, 4),
                "collision_std": round(collision_std, 4),
            },
            "size_stats": {
                "mean_bytes": round(float(sizes.mean()), 1),
                "std_bytes": round(float(sizes.std()), 1),
                "coefficient_of_variation": round(size_cv, 4),
            },
            "trend": {
                "slope": round(trend_slope, 6),
                "direction": "increasing" if trend_slope > 0.01 else "decreasing" if trend_slope < -0.01 else "stable",
            },
            "c2_indicators": {
                "high_entropy": is_high_entropy,
                "low_variance": is_low_variance,
                "uniform_packet_size": is_uniform_size,
                "score": round(c2_score, 3),
            },
            "per_packet": [
                {
                    "index": i,
                    "shannon": round(p["shannon"], 4),
                    "collision": round(p["collision"], 4),
                    "size": p["size"],
                }
                for i, p in enumerate(packet_entropies)
            ],
        }

    @staticmethod
    def _alpha_label(alpha: float) -> str:
        if alpha == float("inf"):
            return "min-entropy (worst-case predictability)"
        labels = {
            0.5: "Hartley-sensitive (rare symbol detection)",
            1.0: "Shannon entropy (standard randomness)",
            2.0: "collision entropy (C2/beacon detection)",
        }
        return labels.get(alpha, f"Renyi order {alpha}")
