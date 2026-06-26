"""Unit tests for the AEGIS solution manager."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
import yaml

from app.services.solution_manager import (
    Solution,
    SolutionManifest,
    SolutionManager,
)

# ---------------------------------------------------------------------------
# Helpers to build a minimal solutions tree in a tmp directory
# ---------------------------------------------------------------------------

_MINIMAL_MANIFEST = {
    "id": "test-solution",
    "name": "Test Solution",
    "version": "1.0.0",
    "description": "A test solution",
    "author": "Test",
    "includes": {
        "rules": ["rules/dummy_rule.yaml"],
        "playbooks": ["playbooks/dummy_playbook.yaml"],
        "parsers": [],
        "honeypots": [],
    },
    "depends_on": [],
}


def _create_solution(tmp: Path, sol_id: str, manifest_overrides: dict | None = None) -> Path:
    sol_dir = tmp / sol_id
    (sol_dir / "rules").mkdir(parents=True)
    (sol_dir / "playbooks").mkdir(parents=True)
    (sol_dir / "parsers").mkdir(parents=True)
    (sol_dir / "honeypots").mkdir(parents=True)

    manifest = dict(_MINIMAL_MANIFEST)
    manifest["id"] = sol_id
    manifest["includes"] = dict(manifest["includes"])
    if manifest_overrides:
        manifest.update(manifest_overrides)

    (sol_dir / "manifest.yaml").write_text(yaml.dump(manifest))
    (sol_dir / "rules" / "dummy_rule.yaml").write_text(
        yaml.dump({"id": "dummy_rule", "name": "Dummy", "severity": "low"})
    )
    (sol_dir / "playbooks" / "dummy_playbook.yaml").write_text(
        yaml.dump({"id": "dummy_playbook", "steps": []})
    )
    return sol_dir


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def solutions_tmp(tmp_path: Path) -> Path:
    """Create a temporary solutions directory with 3 solutions."""
    _create_solution(tmp_path, "alpha")
    _create_solution(tmp_path, "beta")
    _create_solution(tmp_path, "gamma")
    return tmp_path


@pytest.fixture()
def manager(solutions_tmp: Path, tmp_path: Path) -> SolutionManager:
    mgr = SolutionManager(solutions_dir=solutions_tmp)
    # Override state file to a temp location so tests don't pollute ~/.aegis
    mgr._state_file = tmp_path / ".aegis" / "installed_solutions.json"
    return mgr


# ---------------------------------------------------------------------------
# Starter solutions — real repo paths
# ---------------------------------------------------------------------------

@pytest.fixture()
def repo_solutions_dir() -> Path:
    return Path(__file__).parent.parent.parent.parent / "solutions"


def test_discover_starter_solutions(repo_solutions_dir: Path) -> None:
    """The 3 starter solutions must be discoverable."""
    manager = SolutionManager(solutions_dir=repo_solutions_dir)
    solutions = manager.discover()
    assert len(solutions) == 3, f"Expected 3 starter solutions, got {len(solutions)}: {list(solutions)}"
    assert "web-app-defense" in solutions
    assert "linux-server-hardening" in solutions
    assert "homelab-baseline" in solutions


def test_starter_solution_rule_counts(repo_solutions_dir: Path) -> None:
    """Each starter solution must have at least 5 rules."""
    manager = SolutionManager(solutions_dir=repo_solutions_dir)
    solutions = manager.discover()
    for sol_id, sol in solutions.items():
        assert len(sol.manifest.includes.rules) >= 5, (
            f"Solution '{sol_id}' has only {len(sol.manifest.includes.rules)} rules (need >= 5)"
        )


# ---------------------------------------------------------------------------
# Discover
# ---------------------------------------------------------------------------

def test_discover_count(manager: SolutionManager, solutions_tmp: Path) -> None:
    solutions = manager.discover()
    assert len(solutions) == 3


def test_discover_returns_solution_objects(manager: SolutionManager) -> None:
    solutions = manager.discover()
    for sol in solutions.values():
        assert isinstance(sol, Solution)
        assert sol.id
        assert sol.version


def test_discover_skips_invalid_manifest(manager: SolutionManager, solutions_tmp: Path) -> None:
    bad_dir = solutions_tmp / "broken"
    bad_dir.mkdir()
    (bad_dir / "manifest.yaml").write_text("id: !!invalid yaml {{{")
    solutions = manager.discover()
    assert "broken" not in solutions
    assert len(solutions) == 3


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def test_install_updates_state(manager: SolutionManager) -> None:
    manager.install("alpha")
    assert "alpha" in manager.list_installed()


def test_install_all_three(manager: SolutionManager) -> None:
    for sol_id in ("alpha", "beta", "gamma"):
        manager.install(sol_id)
    installed = manager.list_installed()
    assert set(installed) == {"alpha", "beta", "gamma"}


def test_install_increments_rule_count(manager: SolutionManager) -> None:
    before = manager.get_installed_rule_count()
    manager.install("alpha")
    after = manager.get_installed_rule_count()
    assert after > before


def test_install_unknown_raises(manager: SolutionManager) -> None:
    with pytest.raises(KeyError, match="not found"):
        manager.install("nonexistent-solution")


def test_install_missing_dependency_raises(
    manager: SolutionManager, solutions_tmp: Path
) -> None:
    """Installing a solution with an uninstalled dependency must fail."""
    _create_solution(
        solutions_tmp,
        "dependent",
        {"depends_on": ["alpha"]},
    )
    with pytest.raises(RuntimeError, match="depends on 'alpha'"):
        manager.install("dependent")


def test_install_dependency_satisfied(manager: SolutionManager, solutions_tmp: Path) -> None:
    """Installing dependency first allows dependent to install."""
    _create_solution(solutions_tmp, "dep-b", {"depends_on": ["alpha"]})
    manager.install("alpha")
    manager.install("dep-b")
    assert "dep-b" in manager.list_installed()


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

def test_uninstall_removes_from_state(manager: SolutionManager) -> None:
    manager.install("alpha")
    manager.uninstall("alpha")
    assert "alpha" not in manager.list_installed()


def test_uninstall_not_installed_raises(manager: SolutionManager) -> None:
    with pytest.raises(KeyError):
        manager.uninstall("alpha")


def test_uninstall_blocks_dependent(manager: SolutionManager, solutions_tmp: Path) -> None:
    """Cannot uninstall a solution that others depend on."""
    _create_solution(solutions_tmp, "dep-c", {"depends_on": ["alpha"]})
    manager.install("alpha")
    manager.install("dep-c")
    with pytest.raises(RuntimeError, match="dep-c.*depends on it"):
        manager.uninstall("alpha")


def test_uninstall_cleans_rule_count(manager: SolutionManager) -> None:
    manager.install("alpha")
    count_after_install = manager.get_installed_rule_count()
    manager.uninstall("alpha")
    count_after_uninstall = manager.get_installed_rule_count()
    assert count_after_uninstall < count_after_install


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

def test_validate_rejects_bad_semver() -> None:
    with pytest.raises(Exception, match="semver"):
        SolutionManifest(
            id="bad-ver",
            name="Bad",
            version="1.0",
            description="x",
            author="x",
        )


def test_validate_rejects_bad_id() -> None:
    with pytest.raises(Exception, match="kebab"):
        SolutionManifest(
            id="BadID_with_underscores",
            name="Bad",
            version="1.0.0",
            description="x",
            author="x",
        )


def test_validate_rejects_missing_file(manager: SolutionManager, solutions_tmp: Path) -> None:
    _create_solution(solutions_tmp, "missing-file")
    # Tamper with manifest to reference a missing file
    manifest_path = solutions_tmp / "missing-file" / "manifest.yaml"
    data = yaml.safe_load(manifest_path.read_text())
    data["includes"]["rules"].append("rules/does_not_exist.yaml")
    manifest_path.write_text(yaml.dump(data))
    solutions = manager.discover()
    with pytest.raises(FileNotFoundError, match="does_not_exist"):
        manager.validate(solutions["missing-file"].manifest)


def test_validate_detects_circular_dependency(
    manager: SolutionManager, solutions_tmp: Path
) -> None:
    _create_solution(solutions_tmp, "circ-a", {"depends_on": ["circ-b"]})
    _create_solution(solutions_tmp, "circ-b", {"depends_on": ["circ-a"]})
    solutions = manager.discover()
    with pytest.raises(RuntimeError, match="Circular"):
        manager.validate(solutions["circ-a"].manifest, solutions)


def test_validate_rejects_nonexistent_dependency(
    manager: SolutionManager, solutions_tmp: Path
) -> None:
    _create_solution(solutions_tmp, "dep-missing", {"depends_on": ["ghost-solution"]})
    solutions = manager.discover()
    with pytest.raises(RuntimeError, match="ghost-solution"):
        manager.validate(solutions["dep-missing"].manifest, solutions)
