import time
import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy.orm.attributes import flag_modified

from app.database import get_db
from app.core.auth import AuthContext, require_admin, require_viewer
from app.core.audit import log_audit
from app.core.openrouter import MODEL_ROUTING, MODEL_DESCRIPTIONS, MODEL_ORDER
from app.models.client import Client

logger = logging.getLogger("aegis.settings")

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
    webhook_format: str = "generic"
    email_enabled: bool
    email_recipients: list[str]
    notify_on_critical: bool
    notify_on_high: bool
    notify_on_actions: bool
    notify_on_scan_completed: bool = False
    channels: list[str]
    telegram_enabled: bool = False
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    telegram_connected: bool = False


class NotificationUpdate(BaseModel):
    webhook_url: str | None = None
    webhook_format: str | None = None
    email_enabled: bool | None = None
    email_recipients: list[str] | None = None
    notify_on_critical: bool | None = None
    notify_on_high: bool | None = None
    notify_on_actions: bool | None = None
    notify_on_scan_completed: bool | None = None
    channels: list[str] | None = None
    telegram_enabled: bool | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None


class ModelTestRequest(BaseModel):
    task_type: str
    model: str


class ModelTestResponse(BaseModel):
    success: bool
    response: str
    latency_ms: int


class NotificationTestRequest(BaseModel):
    test: bool = True
    channel: str = "webhook"


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
        webhook_format=settings.get("webhook_format", "generic"),
        email_enabled=settings.get("email_enabled", False),
        email_recipients=settings.get("email_recipients", []),
        notify_on_critical=settings.get("notify_on_critical", True),
        notify_on_high=settings.get("notify_on_high", True),
        notify_on_actions=settings.get("notify_on_actions", True),
        notify_on_scan_completed=settings.get("notify_on_scan_completed", False),
        channels=settings.get("notification_channels", ["webhook"]),
        telegram_enabled=settings.get("telegram_enabled", False),
        telegram_bot_token=settings.get("telegram_bot_token"),
        telegram_chat_id=settings.get("telegram_chat_id"),
        telegram_connected=settings.get("telegram_connected", False),
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
    if body.webhook_format is not None:
        current_settings["webhook_format"] = body.webhook_format
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
    if body.notify_on_scan_completed is not None:
        current_settings["notify_on_scan_completed"] = body.notify_on_scan_completed
    if body.channels is not None:
        current_settings["notification_channels"] = body.channels
    if body.telegram_enabled is not None:
        current_settings["telegram_enabled"] = body.telegram_enabled
    if body.telegram_bot_token is not None:
        current_settings["telegram_bot_token"] = body.telegram_bot_token
    if body.telegram_chat_id is not None:
        current_settings["telegram_chat_id"] = body.telegram_chat_id
    client.settings = current_settings
    flag_modified(client, "settings")
    await db.commit()

    return NotificationConfig(
        webhook_url=current_settings.get("webhook_url", ""),
        webhook_format=current_settings.get("webhook_format", "generic"),
        email_enabled=current_settings.get("email_enabled", False),
        email_recipients=current_settings.get("email_recipients", []),
        notify_on_critical=current_settings.get("notify_on_critical", True),
        notify_on_high=current_settings.get("notify_on_high", True),
        notify_on_actions=current_settings.get("notify_on_actions", True),
        notify_on_scan_completed=current_settings.get("notify_on_scan_completed", False),
        channels=current_settings.get("notification_channels", ["webhook"]),
        telegram_enabled=current_settings.get("telegram_enabled", False),
        telegram_bot_token=current_settings.get("telegram_bot_token"),
        telegram_chat_id=current_settings.get("telegram_chat_id"),
        telegram_connected=current_settings.get("telegram_connected", False),
    )


# --- Model Test ---

@router.post("/models/test", response_model=ModelTestResponse)
async def test_model(
    body: ModelTestRequest,
    auth: AuthContext = Depends(require_admin),
):
    """Send a test query to verify a model is reachable."""
    from app.core.openrouter import OpenRouterClient

    client = OpenRouterClient()
    test_messages = [
        {"role": "user", "content": "Respond with exactly: OK. Do not add anything else."}
    ]
    start = time.monotonic()
    try:
        result = await client.query(
            messages=test_messages,
            task_type=body.task_type,
            temperature=0.0,
            max_tokens=32,
            client_settings={"model_routing": {body.task_type: body.model}},
        )
        latency = int((time.monotonic() - start) * 1000)
        content = result.get("content", result.get("response", ""))
        if isinstance(content, str) and len(content) > 0:
            return ModelTestResponse(success=True, response=content[:200], latency_ms=latency)
        return ModelTestResponse(success=False, response="Empty response from model", latency_ms=latency)
    except Exception as e:
        latency = int((time.monotonic() - start) * 1000)
        logger.warning(f"Model test failed for {body.model}: {e}")
        return ModelTestResponse(success=False, response=str(e)[:200], latency_ms=latency)


# --- Notification Test ---

@router.post("/notifications", response_model=dict)
async def test_notification(
    body: NotificationTestRequest,
    auth: AuthContext = Depends(require_admin),
):
    """Send a test notification to verify channel connectivity."""
    settings = auth.client.settings or {}

    if body.channel == "telegram":
        bot_token = settings.get("telegram_bot_token", "")
        chat_id = settings.get("telegram_chat_id", "")
        if not bot_token or not chat_id:
            return {"success": False, "message": "Telegram bot token and chat ID are required"}
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    json={"chat_id": chat_id, "text": "AEGIS test notification - connection verified!", "parse_mode": "HTML"},
                )
                if resp.status_code == 200:
                    return {"success": True, "message": "Test message sent to Telegram"}
                return {"success": False, "message": f"Telegram API error: {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)[:100]}"}

    elif body.channel == "webhook":
        webhook_url = settings.get("webhook_url", "")
        if not webhook_url:
            return {"success": False, "message": "No webhook URL configured"}
        import httpx
        try:
            async with httpx.AsyncClient(timeout=10) as http:
                resp = await http.post(
                    webhook_url,
                    json={"text": "AEGIS test notification", "content": "AEGIS test notification - connection verified!"},
                )
                if 200 <= resp.status_code < 300:
                    return {"success": True, "message": "Webhook test delivered"}
                return {"success": False, "message": f"Webhook returned HTTP {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)[:100]}"}

    return {"success": False, "message": f"Unknown channel: {body.channel}"}


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
