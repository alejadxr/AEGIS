"""Updates API — check for new AEGIS versions and trigger installs."""
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.auth import AuthContext, require_admin, require_viewer
from app.database import get_db
from app.services.auto_updater import auto_updater, CURRENT_VERSION

logger = logging.getLogger("aegis.api.updates")

router = APIRouter(prefix="/updates", tags=["updates"])


class UpdateStatusResponse(BaseModel):
    current_version: str
    latest_version: str | None
    update_available: bool
    last_checked: str | None
    last_error: str | None
    release_notes: str | None
    release_url: str | None
    is_updating: bool


class AutoUpdateConfig(BaseModel):
    enabled: bool = True
    check_interval_hours: int = 6
    auto_install: bool = False
    notify_on_available: bool = True


@router.get("/status", response_model=UpdateStatusResponse)
async def get_update_status(auth: AuthContext = Depends(require_viewer)):
    """Return the current update status from the background checker."""
    s = auto_updater.status
    return UpdateStatusResponse(
        current_version=s.current_version,
        latest_version=s.latest_version,
        update_available=s.update_available,
        last_checked=s.last_checked.isoformat() if s.last_checked else None,
        last_error=s.last_error,
        release_notes=s.release_notes,
        release_url=s.release_url,
        is_updating=s.is_updating,
    )


@router.post("/check", response_model=UpdateStatusResponse)
async def check_now(auth: AuthContext = Depends(require_admin)):
    """Force an immediate update check against GitHub."""
    s = await auto_updater.check_for_updates()
    return UpdateStatusResponse(
        current_version=s.current_version,
        latest_version=s.latest_version,
        update_available=s.update_available,
        last_checked=s.last_checked.isoformat() if s.last_checked else None,
        last_error=s.last_error,
        release_notes=s.release_notes,
        release_url=s.release_url,
        is_updating=s.is_updating,
    )


@router.post("/install")
async def install_update(auth: AuthContext = Depends(require_admin)):
    """Manually trigger the update install (git pull + docker compose up -d --build)."""
    if not auto_updater.status.update_available:
        raise HTTPException(400, "No update available. Run /updates/check first.")
    if auto_updater.status.is_updating:
        raise HTTPException(409, "Update already in progress.")
    result = await auto_updater.perform_update()
    if not result.get("success"):
        raise HTTPException(500, f"Update failed: {result.get('error', 'unknown')}")
    return result


@router.get("/config", response_model=AutoUpdateConfig)
async def get_config(auth: AuthContext = Depends(require_admin)):
    """Get the auto-update config for this client."""
    cfg = (auth.client.settings or {}).get("auto_update", {})
    return AutoUpdateConfig(
        enabled=cfg.get("enabled", True),
        check_interval_hours=int(cfg.get("check_interval_hours", 6)),
        auto_install=cfg.get("auto_install", False),
        notify_on_available=cfg.get("notify_on_available", True),
    )


@router.put("/config", response_model=AutoUpdateConfig)
async def update_config(
    body: AutoUpdateConfig,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update the auto-update config for this client."""
    client = auth.client
    settings = dict(client.settings or {})
    settings["auto_update"] = body.model_dump()
    client.settings = settings
    flag_modified(client, "settings")
    await db.commit()
    return body
