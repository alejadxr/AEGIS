"""
SBOM (Software Bill of Materials) scanner for AEGIS Surface module.

Inventories installed software across Python, Node, system packages, and Docker
images, then cross-references against the NVD CVE database. Outputs CycloneDX
JSON format.
"""

import asyncio
import hashlib
import json
import logging
import platform
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("aegis.sbom")

# ---------------------------------------------------------------------------
# CVE cache (in-memory, 24h TTL)
# ---------------------------------------------------------------------------

_cve_cache: dict[str, tuple[float, list[dict]]] = {}
_CVE_CACHE_TTL = 86400  # 24 hours


def _cache_key(package: str, version: str) -> str:
    return f"{package.lower()}:{version}"


def _get_cached_cves(package: str, version: str) -> list[dict] | None:
    key = _cache_key(package, version)
    if key in _cve_cache:
        ts, data = _cve_cache[key]
        if time.time() - ts < _CVE_CACHE_TTL:
            return data
        del _cve_cache[key]
    return None


def _set_cached_cves(package: str, version: str, cves: list[dict]) -> None:
    _cve_cache[_cache_key(package, version)] = (time.time(), cves)


# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple:
    """Crude numeric version tuple for comparison."""
    parts = []
    for seg in v.replace("-", ".").split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(seg)
    return tuple(parts)


def _version_in_range(version: str, start: str | None, end: str | None) -> bool:
    """Check if *version* falls within [start, end] inclusive."""
    v = _parse_version(version)
    if start and v < _parse_version(start):
        return False
    if end and v > _parse_version(end):
        return False
    return True


# ---------------------------------------------------------------------------
# SBOMScanner
# ---------------------------------------------------------------------------

class SBOMScanner:
    """Scans the host (or Docker images) for installed packages and known CVEs."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self) -> None:
        self._latest_results: dict | None = None
        self._latest_cves: list[dict] = []
        self._scan_running = False
        self._last_scan_at: str | None = None

    # ------------------------------------------------------------------
    # Package detection
    # ------------------------------------------------------------------

    async def scan_system(self) -> list[dict]:
        """Detect all installed packages on the current host."""
        packages: list[dict] = []

        # Run all detectors concurrently
        results = await asyncio.gather(
            self._detect_python(),
            self._detect_node(),
            self._detect_system(),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Package detection error: {result}")
                continue
            packages.extend(result)

        logger.info(f"SBOM scan found {len(packages)} packages")
        return packages

    async def scan_docker_image(self, image_name: str) -> list[dict]:
        """Inspect a Docker image for installed packages."""
        packages: list[dict] = []

        if not shutil.which("docker"):
            logger.warning("Docker not found on PATH; skipping Docker scan")
            return packages

        try:
            # Get image metadata
            proc = await asyncio.create_subprocess_exec(
                "docker", "inspect", image_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.warning(f"docker inspect failed: {stderr.decode()}")
                return packages

            inspect_data = json.loads(stdout.decode())
            if inspect_data:
                config = inspect_data[0].get("Config", {})
                env = config.get("Env", [])
                for e in env:
                    packages.append({
                        "name": f"env:{e.split('=')[0]}",
                        "version": e.split("=", 1)[1] if "=" in e else "unknown",
                        "source": "docker_env",
                        "image": image_name,
                    })

            # Try to list pip packages inside the container
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "--rm", "--entrypoint", "pip",
                image_name, "list", "--format", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                pip_pkgs = json.loads(stdout.decode())
                for pkg in pip_pkgs:
                    packages.append({
                        "name": pkg.get("name", "unknown"),
                        "version": pkg.get("version", "unknown"),
                        "source": "docker_pip",
                        "image": image_name,
                    })

            # Try to list npm packages inside the container
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "--rm", "--entrypoint", "npm",
                image_name, "list", "--json", "--depth=0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                npm_data = json.loads(stdout.decode())
                for dep_name, dep_info in npm_data.get("dependencies", {}).items():
                    packages.append({
                        "name": dep_name,
                        "version": dep_info.get("version", "unknown"),
                        "source": "docker_npm",
                        "image": image_name,
                    })

            # Try dpkg inside the container
            proc = await asyncio.create_subprocess_exec(
                "docker", "run", "--rm", "--entrypoint", "dpkg-query",
                image_name, "-W", "-f=${Package}\t${Version}\n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode().strip().split("\n"):
                    if "\t" in line:
                        name, version = line.split("\t", 1)
                        packages.append({
                            "name": name.strip(),
                            "version": version.strip(),
                            "source": "docker_dpkg",
                            "image": image_name,
                        })

        except Exception as exc:
            logger.error(f"Docker image scan failed: {exc}")

        logger.info(f"Docker scan of {image_name} found {len(packages)} packages")
        return packages

    # ------------------------------------------------------------------
    # CVE checking
    # ------------------------------------------------------------------

    async def check_cves(self, packages: list[dict]) -> list[dict]:
        """
        Check a list of packages against the NVD CVE database.
        Returns packages enriched with a `cves` list.
        """
        enriched: list[dict] = []

        # Batch packages to avoid hammering the NVD API
        async with httpx.AsyncClient(timeout=30.0) as client:
            for pkg in packages:
                name = pkg.get("name", "")
                version = pkg.get("version", "unknown")

                # Skip env vars, meta-packages, etc.
                if name.startswith("env:") or not name:
                    enriched.append({**pkg, "cves": []})
                    continue

                cached = _get_cached_cves(name, version)
                if cached is not None:
                    enriched.append({**pkg, "cves": cached})
                    continue

                cves = await self._query_nvd(client, name, version)
                _set_cached_cves(name, version, cves)
                enriched.append({**pkg, "cves": cves})

                # Rate-limit: NVD public API allows ~5 req/30s without a key
                await asyncio.sleep(0.8)

        return enriched

    async def _query_nvd(
        self, client: httpx.AsyncClient, package: str, version: str
    ) -> list[dict]:
        """Query NVD for CVEs matching a package name, filter by version."""
        cves: list[dict] = []
        try:
            resp = await client.get(
                self.NVD_API,
                params={"keywordSearch": package, "resultsPerPage": 20},
            )
            if resp.status_code == 403:
                logger.warning("NVD API rate-limited; skipping CVE check for %s", package)
                return cves
            if resp.status_code != 200:
                logger.warning("NVD API returned %d for %s", resp.status_code, package)
                return cves

            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract severity from CVSS metrics
                severity = "unknown"
                cvss_score = 0.0
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = m.get("baseSeverity", "unknown").lower()
                    cvss_score = m.get("baseScore", 0.0)
                elif "cvssMetricV2" in metrics:
                    m = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = m.get("baseScore", 0.0)
                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"

                # Extract description
                descriptions = cve.get("descriptions", [])
                description = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        description = d.get("value", "")
                        break

                # Check if our version is affected (best-effort match)
                affected = False
                configurations = cve.get("configurations", [])
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            criteria = cpe.get("criteria", "").lower()
                            if package.lower().replace("-", "_") in criteria.replace("-", "_"):
                                vs = cpe.get("versionStartIncluding")
                                ve = cpe.get("versionEndIncluding")
                                vee = cpe.get("versionEndExcluding")
                                if vs or ve or vee:
                                    end = ve or vee
                                    if _version_in_range(version, vs, end):
                                        affected = True
                                else:
                                    # No version range -- keyword match only
                                    affected = True

                if affected or not configurations:
                    cves.append({
                        "id": cve_id,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "description": description[:300],
                    })

        except httpx.TimeoutException:
            logger.warning("NVD API timeout for %s", package)
        except Exception as exc:
            logger.error("NVD query error for %s: %s", package, exc)

        return cves

    # ------------------------------------------------------------------
    # CycloneDX export
    # ------------------------------------------------------------------

    def generate_sbom(self, packages: list[dict], fmt: str = "cyclonedx") -> dict:
        """Generate a CycloneDX 1.5 JSON SBOM from a package list."""
        components = []
        for pkg in packages:
            purl = f"pkg:{pkg.get('source', 'generic')}/{pkg['name']}@{pkg.get('version', 'unknown')}"
            component: dict[str, Any] = {
                "type": "library",
                "name": pkg["name"],
                "version": pkg.get("version", "unknown"),
                "purl": purl,
                "bom-ref": hashlib.sha256(purl.encode()).hexdigest()[:12],
            }
            if pkg.get("source"):
                component["group"] = pkg["source"]

            # Attach vulnerabilities inline
            if pkg.get("cves"):
                component["vulnerabilities"] = [
                    {
                        "id": c["id"],
                        "severity": c.get("severity", "unknown"),
                        "cvss_score": c.get("cvss_score", 0),
                        "description": c.get("description", ""),
                    }
                    for c in pkg["cves"]
                ]

            components.append(component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "AEGIS",
                        "name": "SBOM Scanner",
                        "version": "1.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "aegis-host",
                    "version": "1.0.0",
                },
            },
            "components": components,
        }
        return sbom

    # ------------------------------------------------------------------
    # Full scan orchestration
    # ------------------------------------------------------------------

    async def full_scan(self, check_vulnerabilities: bool = True) -> dict:
        """Run a complete SBOM scan: detect packages, check CVEs, store results."""
        if self._scan_running:
            return {"status": "already_running"}

        self._scan_running = True
        try:
            packages = await self.scan_system()

            if check_vulnerabilities and packages:
                packages = await self.check_cves(packages)

            sbom = self.generate_sbom(packages)

            # Collect CVEs across all packages
            all_cves: list[dict] = []
            for pkg in packages:
                for cve in pkg.get("cves", []):
                    all_cves.append({
                        **cve,
                        "package": pkg["name"],
                        "package_version": pkg.get("version", "unknown"),
                        "source": pkg.get("source", "unknown"),
                    })

            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            all_cves.sort(key=lambda c: severity_order.get(c.get("severity", "unknown"), 5))

            self._latest_results = {
                "scan_id": str(uuid.uuid4()),
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "total_packages": len(packages),
                "packages_with_cves": sum(1 for p in packages if p.get("cves")),
                "total_cves": len(all_cves),
                "critical_cves": sum(1 for c in all_cves if c.get("severity") == "critical"),
                "high_cves": sum(1 for c in all_cves if c.get("severity") == "high"),
                "packages": packages,
                "sbom": sbom,
            }
            self._latest_cves = all_cves
            self._last_scan_at = datetime.now(timezone.utc).isoformat()

            logger.info(
                "SBOM scan complete: %d packages, %d CVEs (%d critical, %d high)",
                len(packages),
                len(all_cves),
                self._latest_results["critical_cves"],
                self._latest_results["high_cves"],
            )

            return self._latest_results
        finally:
            self._scan_running = False

    # ------------------------------------------------------------------
    # Result accessors
    # ------------------------------------------------------------------

    @property
    def latest_results(self) -> dict | None:
        return self._latest_results

    @property
    def latest_cves(self) -> list[dict]:
        return self._latest_cves

    @property
    def is_scanning(self) -> bool:
        return self._scan_running

    # ------------------------------------------------------------------
    # Private detectors
    # ------------------------------------------------------------------

    async def _detect_python(self) -> list[dict]:
        """Detect Python packages via pip."""
        packages: list[dict] = []
        pip_cmd = "pip3" if shutil.which("pip3") else "pip"
        if not shutil.which(pip_cmd):
            return packages

        try:
            proc = await asyncio.create_subprocess_exec(
                pip_cmd, "list", "--format", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                pip_list = json.loads(stdout.decode())
                for pkg in pip_list:
                    packages.append({
                        "name": pkg.get("name", "unknown"),
                        "version": pkg.get("version", "unknown"),
                        "source": "pip",
                    })
        except Exception as exc:
            logger.warning("pip detection error: %s", exc)
        return packages

    async def _detect_node(self) -> list[dict]:
        """Detect Node packages via npm (if package.json exists nearby)."""
        packages: list[dict] = []
        if not shutil.which("npm"):
            return packages

        # Check for package.json in common locations
        search_paths = [
            Path.cwd(),
            Path.cwd().parent,
            Path.cwd().parent / "frontend",
            Path.cwd().parent / "backend",
        ]

        for search_path in search_paths:
            pkg_json = search_path / "package.json"
            if not pkg_json.exists():
                continue

            try:
                proc = await asyncio.create_subprocess_exec(
                    "npm", "list", "--json", "--depth=0",
                    cwd=str(search_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                if stdout:
                    npm_data = json.loads(stdout.decode())
                    for dep_name, dep_info in npm_data.get("dependencies", {}).items():
                        version = dep_info.get("version", "unknown") if isinstance(dep_info, dict) else "unknown"
                        packages.append({
                            "name": dep_name,
                            "version": version,
                            "source": "npm",
                            "path": str(search_path),
                        })
            except Exception as exc:
                logger.warning("npm detection error in %s: %s", search_path, exc)

        return packages

    async def _detect_system(self) -> list[dict]:
        """Detect system packages (platform-dependent)."""
        packages: list[dict] = []
        system = platform.system()

        if system == "Darwin":
            packages.extend(await self._detect_brew())
        elif system == "Linux":
            packages.extend(await self._detect_dpkg())
        elif system == "Windows":
            packages.extend(await self._detect_wmic())

        return packages

    async def _detect_brew(self) -> list[dict]:
        """Detect Homebrew packages on macOS."""
        packages: list[dict] = []
        if not shutil.which("brew"):
            return packages

        try:
            proc = await asyncio.create_subprocess_exec(
                "brew", "list", "--versions",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode().strip().split("\n"):
                    if not line.strip():
                        continue
                    parts = line.strip().split()
                    name = parts[0]
                    version = parts[-1] if len(parts) > 1 else "unknown"
                    packages.append({
                        "name": name,
                        "version": version,
                        "source": "brew",
                    })
        except Exception as exc:
            logger.warning("brew detection error: %s", exc)
        return packages

    async def _detect_dpkg(self) -> list[dict]:
        """Detect dpkg packages on Linux."""
        packages: list[dict] = []
        if not shutil.which("dpkg-query"):
            return packages

        try:
            proc = await asyncio.create_subprocess_exec(
                "dpkg-query", "-W", "-f=${Package}\t${Version}\n",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode().strip().split("\n"):
                    if "\t" in line:
                        name, version = line.split("\t", 1)
                        packages.append({
                            "name": name.strip(),
                            "version": version.strip(),
                            "source": "dpkg",
                        })
        except Exception as exc:
            logger.warning("dpkg detection error: %s", exc)
        return packages

    async def _detect_wmic(self) -> list[dict]:
        """Detect installed software on Windows via wmic."""
        packages: list[dict] = []
        if not shutil.which("wmic"):
            return packages

        try:
            proc = await asyncio.create_subprocess_exec(
                "wmic", "product", "get", "Name,Version", "/format:csv",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode().strip().split("\n")[1:]:
                    parts = line.strip().split(",")
                    if len(parts) >= 3:
                        name = parts[1].strip()
                        version = parts[2].strip()
                        if name:
                            packages.append({
                                "name": name,
                                "version": version or "unknown",
                                "source": "wmic",
                            })
        except Exception as exc:
            logger.warning("wmic detection error: %s", exc)
        return packages


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

sbom_scanner = SBOMScanner()
