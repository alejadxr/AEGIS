"""AEGIS solution package manager — install/uninstall/validate solution bundles."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, field_validator

logger = logging.getLogger("aegis.solutions")

_SEMVER_RE = __import__("re").compile(
    r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$"
)

_STATE_FILE = Path.home() / ".aegis" / "installed_solutions.json"


class SolutionIncludes(BaseModel):
    rules: list[str] = []
    playbooks: list[str] = []
    parsers: list[str] = []
    honeypots: list[str] = []


class SolutionManifest(BaseModel):
    id: str
    name: str
    version: str
    description: str
    author: str
    includes: SolutionIncludes = SolutionIncludes()
    depends_on: list[str] = []

    @field_validator("version")
    @classmethod
    def validate_semver(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError(f"version '{v}' is not valid semver (expected X.Y.Z)")
        return v

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-z0-9-]+$", v):
            raise ValueError(f"solution id '{v}' must be kebab-case (lowercase letters, digits, hyphens)")
        return v


class Solution:
    def __init__(self, manifest: SolutionManifest, path: Path) -> None:
        self.id = manifest.id
        self.name = manifest.name
        self.version = manifest.version
        self.manifest = manifest
        self.path = path

    def __repr__(self) -> str:
        return f"Solution(id={self.id!r}, version={self.version!r}, path={self.path})"


class SolutionManager:
    def __init__(self, solutions_dir: Optional[Path] = None) -> None:
        if solutions_dir is None:
            solutions_dir = Path(__file__).parent.parent.parent.parent / "solutions"
        self._solutions_dir = Path(solutions_dir)
        self._state_file = _STATE_FILE

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(self, solutions_dir: Optional[Path] = None) -> dict[str, Solution]:
        base = Path(solutions_dir) if solutions_dir else self._solutions_dir
        found: dict[str, Solution] = {}
        if not base.exists():
            logger.warning("Solutions directory not found: %s", base)
            return found
        for subdir in base.iterdir():
            manifest_path = subdir / "manifest.yaml"
            if not subdir.is_dir() or not manifest_path.exists():
                continue
            try:
                manifest = self._load_manifest(manifest_path)
                found[manifest.id] = Solution(manifest=manifest, path=subdir)
            except Exception as exc:
                logger.warning("Skipping %s — invalid manifest: %s", subdir.name, exc)
        return found

    # ------------------------------------------------------------------
    # Install / uninstall
    # ------------------------------------------------------------------

    def install(self, solution_id: str, solutions_dir: Optional[Path] = None) -> None:
        solutions = self.discover(solutions_dir)
        if solution_id not in solutions:
            raise KeyError(f"Solution '{solution_id}' not found in {self._solutions_dir}")

        solution = solutions[solution_id]
        self.validate(solution.manifest, solutions)

        # Check dependencies first
        for dep_id in solution.manifest.depends_on:
            installed = self.list_installed()
            if dep_id not in installed:
                raise RuntimeError(
                    f"Cannot install '{solution_id}': depends on '{dep_id}' which is not installed. "
                    f"Run: aegis solution install {dep_id}"
                )

        state = self._load_state()
        if solution_id in state.get("installed", {}):
            logger.info("Solution '%s' is already installed — re-installing", solution_id)

        state.setdefault("installed", {})[solution_id] = {
            "version": solution.version,
            "path": str(solution.path),
            "rule_count": len(solution.manifest.includes.rules),
        }
        self._save_state(state)
        logger.info("Installed solution '%s' v%s", solution_id, solution.version)

    def uninstall(self, solution_id: str) -> None:
        state = self._load_state()
        if solution_id not in state.get("installed", {}):
            raise KeyError(f"Solution '{solution_id}' is not installed")

        # Check if any installed solution depends on this one
        solutions = self.discover()
        for other_id, other in solutions.items():
            if other_id == solution_id:
                continue
            if solution_id in other.manifest.depends_on and other_id in state.get("installed", {}):
                raise RuntimeError(
                    f"Cannot uninstall '{solution_id}': '{other_id}' depends on it. "
                    f"Uninstall '{other_id}' first."
                )

        del state["installed"][solution_id]
        self._save_state(state)
        logger.info("Uninstalled solution '%s'", solution_id)

    def update(self, solution_id: str, solutions_dir: Optional[Path] = None) -> None:
        """Re-install from local path (future: pull from registry)."""
        self.install(solution_id, solutions_dir)

    def list_installed(self) -> list[str]:
        state = self._load_state()
        return list(state.get("installed", {}).keys())

    def get_installed_rule_count(self) -> int:
        """Return total number of rules across all installed solutions."""
        state = self._load_state()
        return sum(
            entry.get("rule_count", 0)
            for entry in state.get("installed", {}).values()
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(
        self,
        manifest: SolutionManifest,
        available: Optional[dict[str, Solution]] = None,
    ) -> None:
        """Validate manifest: files exist, semver valid, deps resolvable, no cycles."""
        if available is None:
            available = self.discover()

        # version is validated by pydantic field_validator already
        # Check all referenced files exist
        solution_path = self._solutions_dir / manifest.id
        all_paths = (
            manifest.includes.rules
            + manifest.includes.playbooks
            + manifest.includes.parsers
            + manifest.includes.honeypots
        )
        for rel_path in all_paths:
            full = solution_path / rel_path
            if not full.exists():
                raise FileNotFoundError(
                    f"Manifest '{manifest.id}' references missing file: {rel_path}"
                )

        # Check dependency chain is not circular and deps exist
        self._check_deps(manifest.id, manifest.depends_on, available, visited=set())

    def _check_deps(
        self,
        root_id: str,
        deps: list[str],
        available: dict[str, Solution],
        visited: set[str],
    ) -> None:
        for dep_id in deps:
            if dep_id == root_id or dep_id in visited:
                raise RuntimeError(
                    f"Circular dependency detected: '{root_id}' -> '{dep_id}'"
                )
            if dep_id not in available:
                raise RuntimeError(
                    f"Dependency '{dep_id}' required by '{root_id}' is not available"
                )
            visited.add(dep_id)
            self._check_deps(
                root_id,
                available[dep_id].manifest.depends_on,
                available,
                visited.copy(),
            )

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load_state(self) -> dict:
        if not self._state_file.exists():
            return {"installed": {}}
        with open(self._state_file) as f:
            return json.load(f)

    def _save_state(self, state: dict) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._state_file, "w") as f:
            json.dump(state, f, indent=2)

    # ------------------------------------------------------------------
    # Manifest loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_manifest(path: Path) -> SolutionManifest:
        with open(path) as f:
            data = yaml.safe_load(f)
        return SolutionManifest.model_validate(data)
