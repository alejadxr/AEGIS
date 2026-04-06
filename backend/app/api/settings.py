from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy.orm.attributes import flag_modified

from app.database import get_db
from app.core.auth import AuthContext, require_admin, require_viewer
from app.core.audit import log_audit
from app.core.openrouter import MODEL_ROUTING, MODEL_DESCRIPTIONS, MODEL_ORDER
from app.models.client import Client

router = APIRouter(prefix="/settings", tags=["settings"])


# --- Schemas ---

class ClientSettings(BaseModel):
    id: str
    name: str
    slug: str
    api_key: str
    settings: dict


class ClientSettingsUpdate(BaseModel):
    name: str | None = None
    settings: dict | None = None


class ModelRoutingItem(BaseModel):
    task_type: str
    model: str
    description: str | None = None


class NotificationConfig(BaseModel):
    webhook_url: str
    email_enabled: bool
    email_recipients: list[str]
    notify_on_critical: bool
    notify_on_high: bool
    notify_on_actions: bool
    channels: list[str]
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


class NotificationUpdate(BaseModel):
    webhook_url: str | None = None
    email_enabled: bool | None = None
    email_recipients: list[str] | None = None
    notify_on_critical: bool | None = None
    notify_on_high: bool | None = None
    notify_on_actions: bool | None = None
    channels: list[str] | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


# --- Routes ---

@router.get("/client", response_model=ClientSettings)
async def get_client_settings(auth: AuthContext = Depends(require_admin)):
    """Get client settings. Admin only."""
    client = auth.client
    return ClientSettings(
        id=client.id,
        name=client.name,
        slug=client.slug,
        api_key=client.api_key,
        settings=client.settings or {},
    )


@router.put("/client", response_model=ClientSettings)
async def update_client_settings(
    body: ClientSettingsUpdate,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update client settings. Admin only."""
    client = auth.client
    if body.name is not None:
        client.name = body.name
    if body.settings is not None:
        current = dict(client.settings or {})
        current.update(body.settings)
        client.settings = current
        flag_modified(client, "settings")
    await log_audit(
        db, "settings_change",
        f"Client settings updated (name={body.name is not None}, settings={body.settings is not None})",
        client_id=client.id,
        user_id=auth.user_id,
    )
    await db.commit()
    await db.refresh(client)

    return ClientSettings(
        id=client.id,
        name=client.name,
        slug=client.slug,
        api_key=client.api_key,
        settings=client.settings or {},
    )


@router.get("/models", response_model=list[ModelRoutingItem])
async def get_model_routing(auth: AuthContext = Depends(require_viewer)):
    """Get available AI models and routing configuration."""
    client = auth.client
    client_routing = (client.settings or {}).get("model_routing", MODEL_ROUTING)

    ordered_items: list[ModelRoutingItem] = []
    seen = set()
    for task_type in MODEL_ORDER:
        if task_type in client_routing:
            ordered_items.append(
                ModelRoutingItem(
                    task_type=task_type,
                    model=client_routing[task_type],
                    description=MODEL_DESCRIPTIONS.get(task_type),
                )
            )
            seen.add(task_type)

    for task_type, model in client_routing.items():
        if task_type in seen:
            continue
        ordered_items.append(
            ModelRoutingItem(
                task_type=task_type,
                model=model,
                description=MODEL_DESCRIPTIONS.get(task_type),
            )
        )

    return ordered_items


@router.put("/models", response_model=list[ModelRoutingItem])
async def update_model_routing(
    body: list[ModelRoutingItem],
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update model routing configuration. Admin only."""
    client = auth.client
    current_settings = dict(client.settings or {})
    routing = {item.task_type: item.model for item in body}
    current_settings["model_routing"] = routing
    client.settings = current_settings
    flag_modified(client, "settings")
    await db.commit()

    return [
        ModelRoutingItem(
            task_type=item.task_type,
            model=item.model,
            description=MODEL_DESCRIPTIONS.get(item.task_type),
        )
        for item in body
    ]


@router.get("/notifications", response_model=NotificationConfig)
async def get_notifications(auth: AuthContext = Depends(require_admin)):
    """Get notification configuration. Admin only."""
    settings = auth.client.settings or {}
    return NotificationConfig(
        webhook_url=settings.get("webhook_url", ""),
        email_enabled=settings.get("email_enabled", False),
        email_recipients=settings.get("email_recipients", []),
        notify_on_critical=settings.get("notify_on_critical", True),
        notify_on_high=settings.get("notify_on_high", True),
        notify_on_actions=settings.get("notify_on_actions", True),
        channels=settings.get("notification_channels", ["webhook"]),
        telegram_bot_token=settings.get("telegram_bot_token"),
        telegram_chat_id=settings.get("telegram_chat_id"),
    )


@router.put("/notifications", response_model=NotificationConfig)
async def update_notifications(
    body: NotificationUpdate,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update notification configuration. Admin only."""
    client = auth.client
    current_settings = dict(client.settings or {})
    if body.webhook_url is not None:
        current_settings["webhook_url"] = body.webhook_url
    if body.email_enabled is not None:
        current_settings["email_enabled"] = body.email_enabled
    if body.email_recipients is not None:
        current_settings["email_recipients"] = body.email_recipients
    if body.notify_on_critical is not None:
        current_settings["notify_on_critical"] = body.notify_on_critical
    if body.notify_on_high is not None:
        current_settings["notify_on_high"] = body.notify_on_high
    if body.notify_on_actions is not None:
        current_settings["notify_on_actions"] = body.notify_on_actions
    if body.channels is not None:
        current_settings["notification_channels"] = body.channels
    if body.telegram_bot_token is not None:
        current_settings["telegram_bot_token"] = body.telegram_bot_token
    if body.telegram_chat_id is not None:
        current_settings["telegram_chat_id"] = body.telegram_chat_id
    client.settings = current_settings
    flag_modified(client, "settings")
    await db.commit()

    return NotificationConfig(
        webhook_url=current_settings.get("webhook_url", ""),
        email_enabled=current_settings.get("email_enabled", False),
        email_recipients=current_settings.get("email_recipients", []),
        notify_on_critical=current_settings.get("notify_on_critical", True),
        notify_on_high=current_settings.get("notify_on_high", True),
        notify_on_actions=current_settings.get("notify_on_actions", True),
        channels=current_settings.get("notification_channels", ["webhook"]),
        telegram_bot_token=current_settings.get("telegram_bot_token"),
        telegram_chat_id=current_settings.get("telegram_chat_id"),
    )


# --- Intel Sharing Toggle ---

class IntelSharingUpdate(BaseModel):
    enabled: bool


class IntelSharingStatus(BaseModel):
    enabled: bool


@router.get("/intel-sharing", response_model=IntelSharingStatus)
async def get_intel_sharing(auth: AuthContext = Depends(require_admin)):
    """Get current intel sharing status."""
    settings = auth.client.settings or {}
    return IntelSharingStatus(enabled=settings.get("intel_sharing_enabled", False))


@router.put("/intel-sharing", response_model=IntelSharingStatus)
async def update_intel_sharing(
    body: IntelSharingUpdate,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Toggle threat intel sharing for this organization."""
    client = auth.client
    current_settings = dict(client.settings or {})
    current_settings["intel_sharing_enabled"] = body.enabled
    client.settings = current_settings
    flag_modified(client, "settings")
    await db.commit()
    return IntelSharingStatus(enabled=body.enabled)
