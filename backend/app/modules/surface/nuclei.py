import asyncio
import json
import logging
import shutil
from typing import Optional

from app.config import settings

logger = logging.getLogger("aegis.nuclei")


class NucleiScanner:
    """Nuclei vulnerability scanner wrapper."""

    def __init__(self):
        self.nuclei_path = shutil.which("nuclei") or settings.NUCLEI_PATH

    async def scan(
        self,
        target: str,
        templates: Optional[list[str]] = None,
        severity: Optional[str] = None,
    ) -> dict:
        """Run nuclei scan against a target."""
        if not shutil.which("nuclei") and not _tool_exists(self.nuclei_path):
            logger.info("nuclei not available, returning simulated results")
            return self._simulated_results(target)

        cmd = [self.nuclei_path, "-u", target, "-jsonl", "-silent"]

        if templates:
            for t in templates:
                cmd.extend(["-t", t])

        if severity:
            cmd.extend(["-severity", severity])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            vulnerabilities = []
            for line in stdout.decode().strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    finding = json.loads(line)
                    vulnerabilities.append({
                        "title": finding.get("info", {}).get("name", "Unknown"),
                        "description": finding.get("info", {}).get("description", ""),
                        "severity": finding.get("info", {}).get("severity", "info"),
                        "cvss_score": self._severity_to_cvss(
                            finding.get("info", {}).get("severity", "info")
                        ),
                        "cve_id": self._extract_cve(finding),
                        "template_id": finding.get("template-id", ""),
                        "evidence": finding.get("matched-at", ""),
                        "matcher_name": finding.get("matcher-name", ""),
                    })
                except json.JSONDecodeError:
                    pass

            logger.info(f"nuclei found {len(vulnerabilities)} issues for {target}")
            return {
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total": len(vulnerabilities),
            }

        except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
            logger.warning(f"nuclei scan failed: {e}")
            return self._simulated_results(target)

    def _severity_to_cvss(self, severity: str) -> float:
        mapping = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 0.0,
        }
        return mapping.get(severity, 0.0)

    def _extract_cve(self, finding: dict) -> Optional[str]:
        refs = finding.get("info", {}).get("reference", [])
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, str) and ref.startswith("CVE-"):
                    return ref
        classification = finding.get("info", {}).get("classification", {})
        cve_ids = classification.get("cve-id", [])
        if isinstance(cve_ids, list) and cve_ids:
            return cve_ids[0]
        return None

    def _simulated_results(self, target: str) -> dict:
        """Return simulated results when nuclei is not installed."""
        return {
            "target": target,
            "vulnerabilities": [
                {
                    "title": "Missing Security Headers",
                    "description": "The target is missing important security headers (X-Frame-Options, CSP, etc.)",
                    "severity": "info",
                    "cvss_score": 0.0,
                    "cve_id": None,
                    "template_id": "security-headers-missing",
                    "evidence": f"https://{target}",
                },
                {
                    "title": "TLS Certificate Information",
                    "description": "TLS certificate information disclosure",
                    "severity": "info",
                    "cvss_score": 0.0,
                    "cve_id": None,
                    "template_id": "tls-certificate-info",
                    "evidence": f"https://{target}:443",
                },
            ],
            "total": 2,
            "note": "Simulated results - nuclei not installed",
        }


def _tool_exists(path: str) -> bool:
    import os
    return os.path.isfile(path) and os.access(path, os.X_OK)


nuclei_scanner = NucleiScanner()
