"""Auto-updater service for AEGIS.

Checks GitHub releases for new AEGIS versions, notifies the user, and
optionally performs automatic updates via docker compose pull + restart.

Runs in the background on startup. Users configure update behavior
in client.settings:
    {
        "auto_update": {
            "enabled": true,           # Check for updates periodically
            "check_interval_hours": 6, # How often to check
            "auto_install": false,     # Apply updates automatically (risky)
            "notify_on_available": true
        }
    }
"""
import asyncio
import logging
import os
import subprocess
from datetime import datetime, timedelta
from typing import Optional

import httpx

logger = logging.getLogger("aegis.auto_updater")

GITHUB_REPO = "alejandxr/AEGIS"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
CURRENT_VERSION = "1.4.0"

# Path to the AEGIS install directory (where docker-compose.yml lives)
INSTALL_DIR = os.environ.get("AEGIS_INSTALL_DIR", "/app")


class UpdateStatus:
    """Current state of the auto-updater."""
    def __init__(self):
        self.current_version: str = CURRENT_VERSION
        self.latest_version: Optional[str] = None
        self.update_available: bool = False
        self.last_checked: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.release_notes: Optional[str] = None
        self.release_url: Optional[str] = None
        self.is_updating: bool = False


class AutoUpdater:
    """Periodic GitHub release checker with optional auto-install."""

    def __init__(self):
        self.status = UpdateStatus()
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def check_for_updates(self) -> UpdateStatus:
        """Query GitHub for the latest release and compare versions."""
        self.status.last_checked = datetime.utcnow()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    GITHUB_RELEASES_API,
                    headers={"Accept": "application/vnd.github+json"},
                )
                if resp.status_code == 404:
                    # No releases published yet — not an error
                    self.status.last_error = None
                    return self.status
                resp.raise_for_status()
                data = resp.json()

            latest = data.get("tag_name", "").lstrip("v")
            self.status.latest_version = latest
            self.status.release_notes = data.get("body", "")
            self.status.release_url = data.get("html_url", "")
            self.status.update_available = self._is_newer(latest, CURRENT_VERSION)
            self.status.last_error = None

            if self.status.update_available:
                logger.info(
                    f"[AutoUpdater] New version available: {latest} "
                    f"(current: {CURRENT_VERSION})"
                )
            else:
                logger.debug(f"[AutoUpdater] Up to date ({CURRENT_VERSION})")

        except Exception as e:
            self.status.last_error = str(e)
            logger.warning(f"[AutoUpdater] Check failed: {e}")

        return self.status

    def _is_newer(self, latest: str, current: str) -> bool:
        """Compare semver strings: returns True if latest > current."""
        try:
            latest_parts = tuple(int(x) for x in latest.split(".")[:3])
            current_parts = tuple(int(x) for x in current.split(".")[:3])
            # Pad to 3 elements
            latest_parts = latest_parts + (0,) * (3 - len(latest_parts))
            current_parts = current_parts + (0,) * (3 - len(current_parts))
            return latest_parts > current_parts
        except (ValueError, AttributeError):
            return False

    async def perform_update(self) -> dict:
        """Execute the update: git pull + docker compose up -d --build.

        Returns a dict with success status and logs.
        Only runs if auto_install is enabled in client settings.
        """
        if self.status.is_updating:
            return {"success": False, "error": "Update already in progress"}

        if not self.status.update_available:
            return {"success": False, "error": "No update available"}

        self.status.is_updating = True
        try:
            logger.info(f"[AutoUpdater] Starting update to {self.status.latest_version}")

            # Notify via event bus so dashboard shows progress
            try:
                from app.core.events import event_bus
                await event_bus.publish("update_started", {
                    "from": CURRENT_VERSION,
                    "to": self.status.latest_version,
                })
            except Exception:
                pass

            # Run git pull in the install directory
            git_result = await self._run_command(
                ["git", "pull", "origin", "main"],
                cwd=INSTALL_DIR,
            )
            if not git_result["success"]:
                return {"success": False, "step": "git_pull", **git_result}

            # Run docker compose build + up
            compose_result = await self._run_command(
                ["docker", "compose", "up", "-d", "--build"],
                cwd=INSTALL_DIR,
                timeout=600,
            )
            if not compose_result["success"]:
                return {"success": False, "step": "docker_compose", **compose_result}

            logger.info(f"[AutoUpdater] Update to {self.status.latest_version} complete")

            try:
                from app.core.events import event_bus
                await event_bus.publish("update_completed", {
                    "version": self.status.latest_version,
                })
            except Exception:
                pass

            return {
                "success": True,
                "from": CURRENT_VERSION,
                "to": self.status.latest_version,
                "git": git_result,
                "docker": compose_result,
            }
        except Exception as e:
            logger.error(f"[AutoUpdater] Update failed: {e}")
            return {"success": False, "error": str(e)}
        finally:
            self.status.is_updating = False

    async def _run_command(
        self,
        cmd: list,
        cwd: str,
        timeout: int = 120,
    ) -> dict:
        """Run a subprocess command asynchronously with timeout."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode(errors="replace")[-2000:],
                "stderr": stderr.decode(errors="replace")[-2000:],
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Command timed out after {timeout}s"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def start(self):
        """Start the background check loop."""
        if self._task is not None:
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._loop())
        logger.info("[AutoUpdater] Started background update checker")

    async def stop(self):
        """Stop the background check loop."""
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
        logger.info("[AutoUpdater] Stopped")

    async def _loop(self):
        """Background loop: check every N hours based on client settings."""
        # Initial check after 30s (let app finish starting)
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=30)
            return
        except asyncio.TimeoutError:
            pass

        while not self._stop_event.is_set():
            try:
                # Read check interval from any enabled client
                interval_hours = await self._get_check_interval()
                await self.check_for_updates()

                # Check if any client has auto_install enabled
                if self.status.update_available:
                    await self._maybe_auto_install()

            except Exception as e:
                logger.error(f"[AutoUpdater] Loop error: {e}")

            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=interval_hours * 3600,
                )
            except asyncio.TimeoutError:
                pass

    async def _get_check_interval(self) -> int:
        """Read check interval from client settings (default 6 hours)."""
        try:
            from app.database import async_session
            from app.models.client import Client
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(select(Client))
                clients = result.scalars().all()
                intervals = []
                for client in clients:
                    cfg = (client.settings or {}).get("auto_update", {})
                    if cfg.get("enabled", True):
                        intervals.append(int(cfg.get("check_interval_hours", 6)))
                if intervals:
                    return min(intervals)
        except Exception as e:
            logger.debug(f"[AutoUpdater] Could not read client settings: {e}")
        return 6

    async def _maybe_auto_install(self):
        """Check if any client has auto_install enabled and install if so."""
        try:
            from app.database import async_session
            from app.models.client import Client
            from sqlalchemy import select

            async with async_session() as db:
                result = await db.execute(select(Client))
                clients = result.scalars().all()
                for client in clients:
                    cfg = (client.settings or {}).get("auto_update", {})
                    if cfg.get("auto_install", False):
                        logger.info(
                            f"[AutoUpdater] Auto-install enabled for {client.name}, "
                            f"applying update {self.status.latest_version}"
                        )
                        await self.perform_update()
                        return
        except Exception as e:
            logger.debug(f"[AutoUpdater] Auto-install check failed: {e}")


# Singleton
auto_updater = AutoUpdater()
