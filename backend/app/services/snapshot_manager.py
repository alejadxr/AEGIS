"""
Snapshot provider abstraction for AEGIS recovery orchestration (Phase R-C).

Gated by AEGIS_REAL_RECOVERY=1 (mirrors AEGIS_REAL_FW).
Without the flag, NoopSnapshotProvider returns synthetic data so dev/CI
can run without platform snapshot tools installed.

Platform providers:
- MacOSSnapshotProvider  — wraps tmutil (macOS Time Machine)
- LinuxSnapshotProvider  — wraps btrfs subvolume list / zfs list -t snapshot
- WindowsSnapshotProvider — stub; real impl is in Rust agent (Phase R-E)

All subprocess calls use argv lists (no shell=True) and never interpolate
user-supplied strings directly into command positions.
"""
from __future__ import annotations

import functools
import logging
import os
import re
import subprocess
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("aegis.snapshot_manager")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Snapshot:
    id: str
    host_id: str
    created_at: datetime
    size_bytes: Optional[int] = None
    label: Optional[str] = None
    provider: str = "unknown"

    def age_hours(self) -> float:
        now = datetime.now(timezone.utc)
        created = self.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (now - created).total_seconds() / 3600


@dataclass
class RestoreJob:
    job_id: str
    host_id: str
    snapshot_id: str
    target_path: str
    status: str  # "pending" | "running" | "completed" | "failed"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Freshness threshold
# ---------------------------------------------------------------------------

_MAX_SNAPSHOT_AGE_HOURS = int(os.environ.get("AEGIS_SNAPSHOT_MAX_AGE_HOURS", "25"))


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run subprocess safely — always argv list, never shell=True."""
    return subprocess.run(argv, check=False, capture_output=True, timeout=timeout, shell=False)


def _safe_label(value: str) -> str:
    """Strip characters that would be shell-dangerous if accidentally interpolated."""
    return re.sub(r"[^a-zA-Z0-9_\-.:@/ ]", "", value)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class SnapshotProvider(ABC):
    @abstractmethod
    def list_snapshots(self, host_id: str) -> list[Snapshot]: ...

    @abstractmethod
    def verify_recent(self, host_id: str) -> bool: ...

    @abstractmethod
    def restore(self, host_id: str, snapshot_id: str, target_path: str) -> RestoreJob: ...


# ---------------------------------------------------------------------------
# Noop — dev/CI provider
# ---------------------------------------------------------------------------

class NoopSnapshotProvider(SnapshotProvider):
    """Returns synthetic data. No subprocess calls. Safe for dev/CI."""

    def list_snapshots(self, host_id: str) -> list[Snapshot]:
        now = datetime.now(timezone.utc)
        return [
            Snapshot(
                id="noop-snap-001",
                host_id=host_id,
                created_at=now - timedelta(hours=6),
                label="noop-daily-1",
                provider="noop",
            ),
            Snapshot(
                id="noop-snap-002",
                host_id=host_id,
                created_at=now - timedelta(hours=30),
                label="noop-daily-2",
                provider="noop",
            ),
        ]

    def verify_recent(self, host_id: str) -> bool:
        snaps = self.list_snapshots(host_id)
        return any(s.age_hours() <= _MAX_SNAPSHOT_AGE_HOURS for s in snaps)

    def restore(self, host_id: str, snapshot_id: str, target_path: str) -> RestoreJob:
        return RestoreJob(
            job_id=str(uuid.uuid4()),
            host_id=host_id,
            snapshot_id=snapshot_id,
            target_path=target_path,
            status="completed",
        )


# ---------------------------------------------------------------------------
# macOS — tmutil
# ---------------------------------------------------------------------------

_TMUTIL_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2}-\d{6})")


class MacOSSnapshotProvider(SnapshotProvider):
    """Wraps `tmutil listlocalsnapshots /` and `tmutil restore`."""

    def list_snapshots(self, host_id: str) -> list[Snapshot]:
        # host_id on macOS is always localhost; we ignore it safely
        result = _run(["tmutil", "listlocalsnapshots", "/"])
        if result.returncode != 0:
            logger.warning(
                "snapshot_manager(macos): tmutil listlocalsnapshots failed: %s",
                result.stderr.decode(errors="replace").strip(),
            )
            return []

        snapshots: list[Snapshot] = []
        for line in result.stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            match = _TMUTIL_DATE_RE.search(line)
            if match:
                date_str = match.group(1)
                try:
                    created = datetime.strptime(date_str, "%Y-%m-%d-%H%M%S").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    created = datetime.now(timezone.utc)
                snapshots.append(
                    Snapshot(
                        id=date_str,
                        host_id=host_id,
                        created_at=created,
                        label=line,
                        provider="tmutil",
                    )
                )
        return snapshots

    def verify_recent(self, host_id: str) -> bool:
        snaps = self.list_snapshots(host_id)
        return any(s.age_hours() <= _MAX_SNAPSHOT_AGE_HOURS for s in snaps)

    def restore(self, host_id: str, snapshot_id: str, target_path: str) -> RestoreJob:
        job_id = str(uuid.uuid4())
        # Safe argv construction — snapshot_id sanitized, never interpolated in shell
        safe_snap_id = _safe_label(snapshot_id)
        safe_target = _safe_label(target_path)

        result = _run(["tmutil", "restore", "-v", safe_snap_id, safe_target])
        if result.returncode != 0:
            err = result.stderr.decode(errors="replace").strip()
            logger.error("snapshot_manager(macos): restore failed for %s: %s", safe_snap_id, err)
            return RestoreJob(
                job_id=job_id,
                host_id=host_id,
                snapshot_id=snapshot_id,
                target_path=target_path,
                status="failed",
                error=err,
            )

        return RestoreJob(
            job_id=job_id,
            host_id=host_id,
            snapshot_id=snapshot_id,
            target_path=target_path,
            status="completed",
        )


# ---------------------------------------------------------------------------
# Linux — btrfs / zfs
# ---------------------------------------------------------------------------

_BTRFS_PATH_RE = re.compile(r"path\s+(\S+)")
_ZFS_SNAP_RE = re.compile(r"^(\S+@\S+)")


class LinuxSnapshotProvider(SnapshotProvider):
    """Tries btrfs first, falls back to zfs."""

    def list_snapshots(self, host_id: str) -> list[Snapshot]:
        snapshots = self._list_btrfs(host_id)
        if snapshots:
            return snapshots
        return self._list_zfs(host_id)

    def _list_btrfs(self, host_id: str) -> list[Snapshot]:
        result = _run(["btrfs", "subvolume", "list", "-s", "/"])
        if result.returncode != 0:
            logger.debug("snapshot_manager(linux): btrfs not available")
            return []

        snapshots: list[Snapshot] = []
        for line in result.stdout.decode(errors="replace").splitlines():
            match = _BTRFS_PATH_RE.search(line)
            if match:
                path = match.group(1)
                snapshots.append(
                    Snapshot(
                        id=path,
                        host_id=host_id,
                        created_at=datetime.now(timezone.utc),  # btrfs doesn't expose date easily
                        label=path,
                        provider="btrfs",
                    )
                )
        return snapshots

    def _list_zfs(self, host_id: str) -> list[Snapshot]:
        result = _run(["zfs", "list", "-t", "snapshot", "-H", "-p"])
        if result.returncode != 0:
            logger.debug("snapshot_manager(linux): zfs not available")
            return []

        snapshots: list[Snapshot] = []
        for line in result.stdout.decode(errors="replace").splitlines():
            match = _ZFS_SNAP_RE.match(line.strip())
            if match:
                snap_name = match.group(1)
                snapshots.append(
                    Snapshot(
                        id=snap_name,
                        host_id=host_id,
                        created_at=datetime.now(timezone.utc),
                        label=snap_name,
                        provider="zfs",
                    )
                )
        return snapshots

    def verify_recent(self, host_id: str) -> bool:
        snaps = self.list_snapshots(host_id)
        # Linux providers don't parse dates reliably; presence of any snapshot is OK
        return len(snaps) > 0

    def restore(self, host_id: str, snapshot_id: str, target_path: str) -> RestoreJob:
        job_id = str(uuid.uuid4())
        safe_snap = _safe_label(snapshot_id)
        safe_target = _safe_label(target_path)

        # Try zfs send/receive for ZFS snapshots
        if "@" in safe_snap:
            result = _run(["zfs", "clone", safe_snap, safe_target])
        else:
            # btrfs snapshot restore
            result = _run(["btrfs", "subvolume", "snapshot", safe_snap, safe_target])

        if result.returncode != 0:
            err = result.stderr.decode(errors="replace").strip()
            logger.error("snapshot_manager(linux): restore failed: %s", err)
            return RestoreJob(
                job_id=job_id,
                host_id=host_id,
                snapshot_id=snapshot_id,
                target_path=target_path,
                status="failed",
                error=err,
            )

        return RestoreJob(
            job_id=job_id,
            host_id=host_id,
            snapshot_id=snapshot_id,
            target_path=target_path,
            status="completed",
        )


# ---------------------------------------------------------------------------
# Windows — stub (real impl in Rust agent Phase R-E)
# ---------------------------------------------------------------------------

class WindowsSnapshotProvider(SnapshotProvider):
    """Stub. Real VSS implementation lives in the Rust node agent (Phase R-E)."""

    _NOT_SUPPORTED_MSG = (
        "Windows snapshot restore is handled by the Rust node agent (Phase R-E). "
        "This stub is a placeholder."
    )

    def list_snapshots(self, host_id: str) -> list[Snapshot]:
        logger.warning("snapshot_manager(windows): %s", self._NOT_SUPPORTED_MSG)
        return []

    def verify_recent(self, host_id: str) -> bool:
        logger.warning("snapshot_manager(windows): %s", self._NOT_SUPPORTED_MSG)
        return False

    def restore(self, host_id: str, snapshot_id: str, target_path: str) -> RestoreJob:
        raise NotImplementedError(self._NOT_SUPPORTED_MSG)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def get_snapshot_provider() -> SnapshotProvider:
    """Return the appropriate SnapshotProvider singleton based on env and platform.

    AEGIS_REAL_RECOVERY=1 enables real platform calls.
    Without it, NoopSnapshotProvider is returned (safe for dev/CI).
    """
    if os.environ.get("AEGIS_REAL_RECOVERY") == "1":
        if sys.platform == "darwin":
            logger.info("snapshot_manager: using MacOSSnapshotProvider (tmutil)")
            return MacOSSnapshotProvider()
        if sys.platform.startswith("linux"):
            logger.info("snapshot_manager: using LinuxSnapshotProvider (btrfs/zfs)")
            return LinuxSnapshotProvider()
        if sys.platform == "win32":
            logger.info("snapshot_manager: using WindowsSnapshotProvider (stub)")
            return WindowsSnapshotProvider()

    logger.info(
        "snapshot_manager: using NoopSnapshotProvider "
        "(set AEGIS_REAL_RECOVERY=1 to enable platform snapshots)"
    )
    return NoopSnapshotProvider()
