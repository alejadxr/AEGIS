"""
AI Manager -- central hub for multi-provider AI access in AEGIS.

Manages provider registration, active provider selection, fallback chains,
and per-client API key resolution.  The rest of the codebase continues to
call ``openrouter_client.query()`` which delegates here transparently.
"""

import logging
import os
from typing import Optional

from app.core.ai_providers import (
    AIProvider,
    OpenRouterProvider,
    AnthropicProvider,
    OpenAIProvider,
    OllamaProvider,
    InceptionProvider,
    GeminiProvider,
    create_provider,
    PROVIDER_CLASSES,
)

logger = logging.getLogger("aegis.ai_manager")


class AIManager:
    """Singleton that owns every registered AI provider instance."""

    def __init__(self):
        self.providers: dict[str, AIProvider] = {}
        self.active_provider: str = "inception"
        # task_type -> provider name override  (e.g. {"code_analysis": "anthropic"})
        self.task_routing: dict[str, str] = {}
        # ordered fallback chain of provider names
        self.fallback_chain: list[str] = ["inception", "openrouter", "openai", "anthropic", "ollama"]

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_provider(self, name: str, provider: AIProvider) -> None:
        self.providers[name] = provider
        logger.info(f"AI provider registered: {name}")

    def set_active_provider(self, name: str) -> None:
        if name not in self.providers:
            raise ValueError(f"Provider '{name}' is not registered")
        self.active_provider = name
        logger.info(f"Active AI provider set to: {name}")

    # ------------------------------------------------------------------
    # Provider resolution (per-client keys)
    # ------------------------------------------------------------------

    def _resolve_provider(
        self,
        provider_name: str,
        client_settings: Optional[dict] = None,
    ) -> AIProvider:
        """Return a provider instance, optionally re-keyed from client settings.

        If the client has stored their own API key for this provider we create
        a *temporary* provider instance with that key.  Otherwise we fall back
        to the globally-registered (env-based) provider.
        """
        if client_settings:
            ai_keys: dict = client_settings.get("ai_keys", {})
            client_key = ai_keys.get(provider_name)

            if client_key and provider_name != "ollama":
                # Build a one-off provider with the client's key
                kwargs = {"api_key": client_key}
                # Preserve custom base_url if the client stored one
                if provider_name == "ollama":
                    kwargs = {"base_url": client_key}
                return create_provider(provider_name, **kwargs)
            elif provider_name == "ollama" and client_key:
                # For Ollama the "key" is actually the base URL
                return create_provider("ollama", base_url=client_key)

        # Fall back to globally-registered provider
        provider = self.providers.get(provider_name)
        if provider is None:
            raise ValueError(f"Provider '{provider_name}' is not registered and client has no key")
        return provider

    # ------------------------------------------------------------------
    # Chat (main entry point)
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        task_type: str = "general",
        client_settings: Optional[dict] = None,
    ) -> dict:
        """Send a chat request through the active (or task-routed) provider.

        Tries the designated provider first, then walks the fallback chain.
        """
        # Short-circuit when AI is disabled. Accepts {disabled, offline, off, none}
        # so existing deployments using AEGIS_AI_MODE=offline keep working.
        _mode = os.environ.get("AEGIS_AI_MODE", "optional").strip().lower()
        if _mode in {"disabled", "offline", "off", "none"}:
            return {
                "content": "",
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
                "provider": "disabled",
                "model": "disabled",
                "task_type": task_type,
            }

        # Determine which provider to try first
        primary_name = self.task_routing.get(task_type, None)
        if client_settings:
            primary_name = primary_name or client_settings.get("ai_provider")
        primary_name = primary_name or self.active_provider

        # Build ordered list of providers to attempt
        providers_to_try = [primary_name]
        for fb in self.fallback_chain:
            if fb not in providers_to_try:
                providers_to_try.append(fb)

        last_error: Exception | None = None
        for pname in providers_to_try:
            try:
                provider = self._resolve_provider(pname, client_settings)
            except ValueError:
                continue

            try:
                result = await provider.chat(
                    messages=messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                result["provider"] = pname
                return result
            except Exception as exc:
                logger.warning(f"Provider {pname} failed for task_type={task_type}: {exc}")
                last_error = exc

        logger.error(f"All providers failed for task_type={task_type}: {last_error}")
        return {
            "content": f"AI analysis unavailable: {last_error}",
            "tokens_used": 0,
            "cost_usd": 0.0,
            "latency_ms": 0,
            "provider": "none",
            "error": True,
        }

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    async def get_available_providers(self) -> list[dict]:
        """Return metadata about every registered provider."""
        result = []
        for name, provider in self.providers.items():
            info = {
                "name": name,
                "display_name": provider.get_name(),
                "active": name == self.active_provider,
                "type": type(provider).__name__,
            }
            result.append(info)
        return result

    async def test_provider(
        self,
        name: str,
        client_settings: Optional[dict] = None,
    ) -> dict:
        """Test connectivity for a provider (optionally with client keys)."""
        try:
            provider = self._resolve_provider(name, client_settings)
        except ValueError as exc:
            return {"ok": False, "provider": name, "detail": str(exc)}

        result = await provider.test_connection()
        result["provider"] = name
        return result

    async def get_models_for_provider(
        self,
        name: str,
        client_settings: Optional[dict] = None,
    ) -> list[dict]:
        """List available models for a provider."""
        provider = self._resolve_provider(name, client_settings)
        return await provider.get_models()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close_all(self) -> None:
        for name, provider in self.providers.items():
            try:
                await provider.close()
            except Exception as exc:
                logger.warning(f"Error closing provider {name}: {exc}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

ai_manager = AIManager()


def init_default_providers(
    openrouter_api_key: str = "",
    openrouter_base_url: str = "https://openrouter.ai/api/v1",
    inception_api_key: str = "",
    inception_base_url: str = "https://api.inceptionlabs.ai/v1",
    gemini_api_key: str = "",
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta",
) -> AIManager:
    """Register the default set of providers using env-level keys.

    Called once during app startup.  Client-specific keys are resolved
    at request time from client.settings.
    """
    # Inception Labs Mercury-2 (primary -- diffusion LLM, structured outputs)
    ai_manager.register_provider(
        "inception",
        InceptionProvider(api_key=inception_api_key, base_url=inception_base_url),
    )
    # OpenRouter (fallback -- 500+ models via single key)
    ai_manager.register_provider(
        "openrouter",
        OpenRouterProvider(api_key=openrouter_api_key, base_url=openrouter_base_url),
    )
    # Anthropic (no env key by default -- clients supply their own)
    ai_manager.register_provider("anthropic", AnthropicProvider())
    # OpenAI (no env key by default)
    ai_manager.register_provider("openai", OpenAIProvider())
    # Ollama (local, no key needed)
    ai_manager.register_provider("ollama", OllamaProvider())
    # Google Gemini (cheap+fast hot-path enrichment)
    ai_manager.register_provider(
        "gemini",
        GeminiProvider(api_key=gemini_api_key, base_url=gemini_base_url),
    )

    # Set active provider precedence: Inception → OpenRouter → Gemini
    if inception_api_key:
        ai_manager.set_active_provider("inception")
    elif openrouter_api_key:
        ai_manager.set_active_provider("openrouter")
    elif gemini_api_key:
        ai_manager.set_active_provider("gemini")

    logger.info(
        f"AI Manager initialized with {len(ai_manager.providers)} providers. "
        f"Active: {ai_manager.active_provider}"
    )
    return ai_manager
