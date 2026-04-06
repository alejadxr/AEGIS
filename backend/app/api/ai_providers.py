"""
API routes for managing AI providers in AEGIS.

Endpoints:
  GET    /api/v1/ai/providers              - list all registered providers
  POST   /api/v1/ai/providers/test         - test a provider connection
  PUT    /api/v1/ai/providers/active       - set active provider
  GET    /api/v1/ai/providers/{name}/models - list models for a provider
  PUT    /api/v1/ai/providers/{name}/config - configure API key for a provider
"""

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_admin, require_viewer
from app.core.ai_manager import ai_manager

router = APIRouter(prefix="/ai/providers", tags=["ai-providers"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ProviderInfo(BaseModel):
    name: str
    display_name: str
    active: bool
    type: str
    has_client_key: bool = False


class ProviderTestRequest(BaseModel):
    provider: str  # e.g. "openrouter", "anthropic", "openai", "ollama"


class ProviderTestResponse(BaseModel):
    ok: bool
    provider: str
    detail: str
    models_count: int = 0


class SetActiveRequest(BaseModel):
    provider: str


class SetActiveResponse(BaseModel):
    active_provider: str
    message: str


class ModelInfo(BaseModel):
    id: str
    name: str


class ProviderConfigRequest(BaseModel):
    api_key: Optional[str] = None   # API key (or Ollama base URL)
    base_url: Optional[str] = None  # optional custom base URL


class ProviderConfigResponse(BaseModel):
    provider: str
    configured: bool
    message: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=list[ProviderInfo])
async def list_providers(auth: AuthContext = Depends(require_viewer)):
    """List all registered AI providers with status."""
    client = auth.client
    client_settings = client.settings or {}
    ai_keys = client_settings.get("ai_keys", {})

    providers = await ai_manager.get_available_providers()
    result = []
    for p in providers:
        has_key = bool(ai_keys.get(p["name"]))
        result.append(
            ProviderInfo(
                name=p["name"],
                display_name=p["display_name"],
                active=p["name"] == client_settings.get("ai_provider", ai_manager.active_provider),
                type=p["type"],
                has_client_key=has_key,
            )
        )
    return result


@router.post("/test", response_model=ProviderTestResponse)
async def test_provider(
    body: ProviderTestRequest,
    auth: AuthContext = Depends(require_admin),
):
    """Test connectivity for a provider using the client's stored key."""
    client = auth.client
    client_settings = client.settings or {}

    result = await ai_manager.test_provider(body.provider, client_settings)
    return ProviderTestResponse(
        ok=result.get("ok", False),
        provider=result.get("provider", body.provider),
        detail=result.get("detail", ""),
        models_count=result.get("models_count", 0),
    )


@router.put("/active", response_model=SetActiveResponse)
async def set_active_provider(
    body: SetActiveRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Set the active AI provider for this client.

    The selection is stored in client.settings so each client can use
    a different provider.
    """
    client = auth.client

    # Validate provider exists
    provider_names = [p["name"] for p in await ai_manager.get_available_providers()]
    if body.provider not in provider_names:
        return SetActiveResponse(
            active_provider=client.settings.get("ai_provider", ai_manager.active_provider)
            if client.settings
            else ai_manager.active_provider,
            message=f"Unknown provider '{body.provider}'. Available: {', '.join(provider_names)}",
        )

    current_settings = client.settings or {}
    current_settings["ai_provider"] = body.provider
    client.settings = current_settings
    await db.commit()

    return SetActiveResponse(
        active_provider=body.provider,
        message=f"Active provider set to '{body.provider}'",
    )


@router.get("/{name}/models", response_model=list[ModelInfo])
async def get_provider_models(
    name: str,
    auth: AuthContext = Depends(require_viewer),
):
    """List available models for a given provider."""
    client = auth.client
    client_settings = client.settings or {}

    try:
        models = await ai_manager.get_models_for_provider(name, client_settings)
    except ValueError as exc:
        return []

    return [ModelInfo(id=m["id"], name=m.get("name", m["id"])) for m in models]


@router.put("/{name}/config", response_model=ProviderConfigResponse)
async def configure_provider(
    name: str,
    body: ProviderConfigRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Store API key (or Ollama URL) for a provider in client settings.

    Keys are saved in ``client.settings.ai_keys.<provider_name>``.
    For Ollama, the ``api_key`` field stores the base URL instead.
    """
    client = auth.client

    # Validate provider exists
    provider_names = [p["name"] for p in await ai_manager.get_available_providers()]
    if name not in provider_names:
        return ProviderConfigResponse(
            provider=name,
            configured=False,
            message=f"Unknown provider '{name}'. Available: {', '.join(provider_names)}",
        )

    current_settings = client.settings or {}
    ai_keys = current_settings.get("ai_keys", {})

    if name == "ollama":
        # For Ollama the "key" is the base URL
        ai_keys[name] = body.base_url or body.api_key or "http://localhost:11434"
    else:
        if body.api_key:
            ai_keys[name] = body.api_key
        else:
            # Remove key if empty
            ai_keys.pop(name, None)

    current_settings["ai_keys"] = ai_keys
    client.settings = current_settings
    await db.commit()

    configured = bool(ai_keys.get(name))
    return ProviderConfigResponse(
        provider=name,
        configured=configured,
        message=f"Provider '{name}' {'configured' if configured else 'key removed'}",
    )
