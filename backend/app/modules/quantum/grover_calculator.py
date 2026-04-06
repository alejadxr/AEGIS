"""
Grover's Algorithm Quantum Cryptographic Assessment for AEGIS.

Models the impact of quantum computing on current cryptographic primitives:
- Grover's algorithm: O(2^(n/2)) search -> symmetric key strength halved
- Shor's algorithm: polynomial-time factoring -> RSA/ECC broken entirely
- Post-quantum alternatives: lattice-based (Kyber, Dilithium) remain safe

All year estimates are based on current quantum computing roadmaps
(IBM, Google, IonQ projected qubit scaling).
"""

import math
from datetime import datetime
from typing import Optional


# Operations per second estimates
CLASSICAL_OPS_PER_SEC = 1e12  # modern supercomputer cluster
QUANTUM_OPS_PER_SEC = 1e6  # projected fault-tolerant quantum computer (~2030s)

SECONDS_PER_YEAR = 365.25 * 24 * 3600

# Comprehensive cryptographic algorithm assessments
CRYPTO_ASSESSMENTS: dict[str, dict] = {
    # Symmetric ciphers — Grover's halves effective key length
    "AES-128": {
        "type": "symmetric",
        "classical_bits": 128,
        "quantum_bits": 64,
        "attack": "grover",
        "vulnerable_by_year": 2035,
        "status": "migrate",
        "recommendation": "Upgrade to AES-256",
    },
    "AES-192": {
        "type": "symmetric",
        "classical_bits": 192,
        "quantum_bits": 96,
        "attack": "grover",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Acceptable, but AES-256 preferred",
    },
    "AES-256": {
        "type": "symmetric",
        "classical_bits": 256,
        "quantum_bits": 128,
        "attack": "grover",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Quantum-resistant at 128-bit equivalent security",
    },
    "ChaCha20": {
        "type": "symmetric",
        "classical_bits": 256,
        "quantum_bits": 128,
        "attack": "grover",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Quantum-resistant at 128-bit equivalent security",
    },
    "3DES": {
        "type": "symmetric",
        "classical_bits": 112,
        "quantum_bits": 56,
        "attack": "grover",
        "vulnerable_by_year": 2028,
        "status": "critical",
        "recommendation": "Replace immediately with AES-256",
    },

    # Asymmetric — Shor's algorithm breaks these entirely
    "RSA-1024": {
        "type": "asymmetric",
        "classical_bits": 80,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2028,
        "status": "critical",
        "recommendation": "Replace with Kyber-768 or RSA-4096 minimum",
    },
    "RSA-2048": {
        "type": "asymmetric",
        "classical_bits": 112,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2030,
        "status": "critical",
        "recommendation": "Replace with Kyber-768 + Dilithium-3",
    },
    "RSA-4096": {
        "type": "asymmetric",
        "classical_bits": 128,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2032,
        "status": "migrate",
        "recommendation": "Replace with Kyber-1024 + Dilithium-5",
    },
    "ECDSA-256": {
        "type": "asymmetric",
        "classical_bits": 128,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2030,
        "status": "critical",
        "recommendation": "Replace with Dilithium-3 (NIST PQC standard)",
    },
    "ECDSA-384": {
        "type": "asymmetric",
        "classical_bits": 192,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2031,
        "status": "critical",
        "recommendation": "Replace with Dilithium-5",
    },
    "Ed25519": {
        "type": "asymmetric",
        "classical_bits": 128,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2030,
        "status": "critical",
        "recommendation": "Replace with Dilithium-3 or SPHINCS+-256f",
    },
    "X25519": {
        "type": "asymmetric",
        "classical_bits": 128,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2030,
        "status": "critical",
        "recommendation": "Replace with Kyber-768 for key exchange",
    },
    "DH-2048": {
        "type": "asymmetric",
        "classical_bits": 112,
        "quantum_bits": 0,
        "attack": "shor",
        "vulnerable_by_year": 2030,
        "status": "critical",
        "recommendation": "Replace with Kyber-768",
    },

    # Hash functions — Grover's halves collision resistance
    "SHA-256": {
        "type": "hash",
        "classical_bits": 256,
        "quantum_bits": 128,
        "attack": "grover",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Quantum-resistant for preimage attacks",
    },
    "SHA-384": {
        "type": "hash",
        "classical_bits": 384,
        "quantum_bits": 192,
        "attack": "grover",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Quantum-resistant",
    },
    "SHA-512": {
        "type": "hash",
        "classical_bits": 512,
        "quantum_bits": 256,
        "attack": "grover",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Quantum-resistant",
    },
    "MD5": {
        "type": "hash",
        "classical_bits": 128,
        "quantum_bits": 64,
        "attack": "grover",
        "vulnerable_by_year": 2020,
        "status": "critical",
        "recommendation": "Already broken classically. Replace with SHA-256+",
    },
    "SHA-1": {
        "type": "hash",
        "classical_bits": 160,
        "quantum_bits": 80,
        "attack": "grover",
        "vulnerable_by_year": 2025,
        "status": "critical",
        "recommendation": "Already broken classically. Replace with SHA-256+",
    },

    # Post-quantum algorithms (NIST PQC standards)
    "Kyber-512": {
        "type": "post_quantum_kem",
        "classical_bits": 128,
        "quantum_bits": 128,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "NIST PQC Level 1 KEM - quantum-safe",
    },
    "Kyber-768": {
        "type": "post_quantum_kem",
        "classical_bits": 192,
        "quantum_bits": 192,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "NIST PQC Level 3 KEM - recommended default",
    },
    "Kyber-1024": {
        "type": "post_quantum_kem",
        "classical_bits": 256,
        "quantum_bits": 256,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "NIST PQC Level 5 KEM - highest security",
    },
    "Dilithium-2": {
        "type": "post_quantum_sig",
        "classical_bits": 128,
        "quantum_bits": 128,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "NIST PQC Level 2 signature - quantum-safe",
    },
    "Dilithium-3": {
        "type": "post_quantum_sig",
        "classical_bits": 192,
        "quantum_bits": 192,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "NIST PQC Level 3 signature - recommended default",
    },
    "Dilithium-5": {
        "type": "post_quantum_sig",
        "classical_bits": 256,
        "quantum_bits": 256,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "NIST PQC Level 5 signature - highest security",
    },
    "SPHINCS+-256f": {
        "type": "post_quantum_sig",
        "classical_bits": 256,
        "quantum_bits": 256,
        "attack": "none_known",
        "vulnerable_by_year": None,
        "status": "safe",
        "recommendation": "Hash-based signature - conservative quantum-safe choice",
    },
}

# TLS cipher suite mapping to underlying algorithms
TLS_CIPHER_MAP = {
    "TLS_AES_128_GCM_SHA256": ["AES-128", "SHA-256"],
    "TLS_AES_256_GCM_SHA384": ["AES-256", "SHA-384"],
    "TLS_CHACHA20_POLY1305_SHA256": ["ChaCha20", "SHA-256"],
    "ECDHE-RSA-AES128-GCM-SHA256": ["ECDSA-256", "RSA-2048", "AES-128", "SHA-256"],
    "ECDHE-RSA-AES256-GCM-SHA384": ["ECDSA-256", "RSA-2048", "AES-256", "SHA-384"],
    "ECDHE-ECDSA-AES128-GCM-SHA256": ["ECDSA-256", "AES-128", "SHA-256"],
    "ECDHE-ECDSA-AES256-GCM-SHA384": ["ECDSA-256", "AES-256", "SHA-384"],
    "DHE-RSA-AES256-GCM-SHA384": ["DH-2048", "RSA-2048", "AES-256", "SHA-384"],
}


class GroverCalculator:
    """
    Quantum cryptographic assessment engine.

    Models the impact of Grover's and Shor's algorithms on cryptographic
    primitives used by scanned assets, providing vulnerability timelines
    and post-quantum migration recommendations.
    """

    def __init__(
        self,
        classical_ops_sec: float = CLASSICAL_OPS_PER_SEC,
        quantum_ops_sec: float = QUANTUM_OPS_PER_SEC,
    ):
        self.classical_ops_sec = classical_ops_sec
        self.quantum_ops_sec = quantum_ops_sec

    def assess_key_strength(self, algorithm: str, key_bits: Optional[int] = None) -> dict:
        """
        Assess a cryptographic algorithm's strength against quantum attacks.

        For Grover's attack (symmetric): effective bits halved -> O(2^(n/2))
        For Shor's attack (asymmetric): polynomial time -> effectively 0 bits
        """
        # Try exact match first, then construct the lookup key
        lookup = algorithm
        if key_bits and algorithm not in CRYPTO_ASSESSMENTS:
            lookup = f"{algorithm}-{key_bits}"

        assessment = CRYPTO_ASSESSMENTS.get(lookup)
        if not assessment:
            # Unknown algorithm — compute generic Grover impact
            bits = key_bits or 128
            return {
                "algorithm": algorithm,
                "known": False,
                "classical_bits": bits,
                "quantum_bits_grover": bits // 2,
                "years_classical": self._brute_force_years(bits, quantum=False),
                "years_quantum_grover": self._brute_force_years(bits // 2, quantum=True),
                "note": "Unknown algorithm. Showing generic Grover impact only. "
                        "If asymmetric, Shor's algorithm may break it entirely.",
            }

        years_classical = self._brute_force_years(assessment["classical_bits"], quantum=False)
        years_quantum = (
            self._brute_force_years(assessment["quantum_bits"], quantum=True)
            if assessment["quantum_bits"] > 0
            else 0.0
        )

        return {
            "algorithm": lookup,
            "known": True,
            "type": assessment["type"],
            "attack_vector": assessment["attack"],
            "classical_bits": assessment["classical_bits"],
            "quantum_bits": assessment["quantum_bits"],
            "years_classical": years_classical,
            "years_quantum": years_quantum,
            "vulnerable_by_year": assessment["vulnerable_by_year"],
            "status": assessment["status"],
            "recommendation": assessment["recommendation"],
        }

    def assess_asset(self, asset_data: dict) -> dict:
        """
        Assess an asset's cryptographic posture against quantum threats.

        Examines TLS version, cipher suite, key exchange, and certificates
        to build a comprehensive quantum vulnerability timeline.
        """
        results = {
            "asset": asset_data.get("hostname") or asset_data.get("ip_address", "unknown"),
            "assessed_at": datetime.utcnow().isoformat(),
            "algorithms_found": [],
            "vulnerabilities": [],
            "earliest_vulnerability_year": None,
            "overall_status": "safe",
            "recommendations": [],
        }

        algorithms_to_check = set()

        # Extract algorithms from TLS info
        tls_version = asset_data.get("tls_version", "")
        cipher_suite = asset_data.get("cipher_suite", "")
        key_exchange = asset_data.get("key_exchange", "")
        certificate_algo = asset_data.get("certificate_algorithm", "")

        if cipher_suite and cipher_suite in TLS_CIPHER_MAP:
            algorithms_to_check.update(TLS_CIPHER_MAP[cipher_suite])

        # Direct algorithm fields
        for field in ["encryption", "signature", "key_exchange_algorithm", "hash"]:
            algo = asset_data.get(field)
            if algo and algo in CRYPTO_ASSESSMENTS:
                algorithms_to_check.add(algo)

        if certificate_algo:
            algorithms_to_check.add(certificate_algo)

        # If nothing found, check common defaults based on TLS version
        if not algorithms_to_check:
            if tls_version in ("TLSv1.3", "TLS 1.3"):
                algorithms_to_check.update(["AES-256", "SHA-384", "X25519"])
            elif tls_version in ("TLSv1.2", "TLS 1.2"):
                algorithms_to_check.update(["AES-128", "SHA-256", "RSA-2048", "ECDSA-256"])
            elif tls_version:
                algorithms_to_check.update(["AES-128", "SHA-256", "RSA-2048"])

        # Assess each algorithm
        earliest_year = None
        status_priority = {"critical": 3, "migrate": 2, "safe": 1}
        worst_status = "safe"

        for algo in sorted(algorithms_to_check):
            assessment = self.assess_key_strength(algo)
            results["algorithms_found"].append(assessment)

            if assessment.get("status") in ("critical", "migrate"):
                results["vulnerabilities"].append({
                    "algorithm": algo,
                    "status": assessment["status"],
                    "vulnerable_by": assessment.get("vulnerable_by_year"),
                    "recommendation": assessment.get("recommendation", ""),
                })

                vuln_year = assessment.get("vulnerable_by_year")
                if vuln_year:
                    if earliest_year is None or vuln_year < earliest_year:
                        earliest_year = vuln_year

            algo_status = assessment.get("status", "safe")
            if status_priority.get(algo_status, 0) > status_priority.get(worst_status, 0):
                worst_status = algo_status

        results["earliest_vulnerability_year"] = earliest_year
        results["overall_status"] = worst_status

        # Generate recommendations
        if worst_status == "critical":
            results["recommendations"].append(
                "URGENT: This asset uses cryptographic algorithms that will be "
                "broken by quantum computers. Begin post-quantum migration immediately."
            )
        elif worst_status == "migrate":
            results["recommendations"].append(
                "This asset uses algorithms with reduced quantum security. "
                "Plan migration to post-quantum alternatives within 2 years."
            )

        if any(a.get("attack_vector") == "shor" for a in results["algorithms_found"]):
            results["recommendations"].append(
                "Asymmetric algorithms vulnerable to Shor's algorithm detected. "
                "Recommended replacements: Kyber (KEM), Dilithium (signatures)."
            )

        return results

    def get_vulnerability_timeline(self) -> dict:
        """
        Generate a timeline of when each cryptographic algorithm becomes
        vulnerable to quantum attacks.
        """
        timeline = {}
        for algo, info in sorted(CRYPTO_ASSESSMENTS.items()):
            year = info["vulnerable_by_year"]
            status = info["status"]
            entry = {
                "algorithm": algo,
                "type": info["type"],
                "attack": info["attack"],
                "classical_bits": info["classical_bits"],
                "quantum_bits": info["quantum_bits"],
                "status": status,
            }
            if year:
                timeline.setdefault(year, []).append(entry)
            else:
                timeline.setdefault("quantum_safe", []).append(entry)

        current_year = datetime.utcnow().year
        already_vulnerable = []
        upcoming = []
        safe = timeline.pop("quantum_safe", [])

        for year in sorted(k for k in timeline if isinstance(k, int)):
            items = timeline[year]
            if year <= current_year:
                already_vulnerable.extend(
                    {**item, "vulnerable_since": year} for item in items
                )
            else:
                upcoming.extend(
                    {**item, "vulnerable_by": year, "years_remaining": year - current_year}
                    for item in items
                )

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "current_year": current_year,
            "already_vulnerable": already_vulnerable,
            "upcoming_vulnerabilities": upcoming,
            "quantum_safe": safe,
            "summary": {
                "total_algorithms": len(CRYPTO_ASSESSMENTS),
                "already_vulnerable": len(already_vulnerable),
                "upcoming": len(upcoming),
                "quantum_safe": len(safe),
            },
        }

    def _brute_force_years(self, bits: int, quantum: bool = False) -> float:
        """Calculate years to brute force a key of given bit strength."""
        if bits <= 0:
            return 0.0
        ops = 2 ** bits
        ops_per_sec = self.quantum_ops_sec if quantum else self.classical_ops_sec
        seconds = ops / ops_per_sec
        years = seconds / SECONDS_PER_YEAR
        if years > 1e30:
            return float("inf")
        return round(years, 2) if years < 1e15 else float(years)
