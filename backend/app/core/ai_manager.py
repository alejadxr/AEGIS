"""
AI Manager -- central hub for multi-provider AI access in AEGIS.

Manages provider registration, active provider selection, fallback chains,
and per-client API key resolution.  The rest of the codebase continues to
call ``openrouter_client.query()`` which delegates here transparently.
"""

import logging
import os
import time
from typing import Optional

# Skip a provider for this many seconds after it signals quota exhaustion
# (HTTP 402/429, "free_tier", "quota"). Without this the manager pays the
# round-trip on every request and floods logs with the same WARNING.
_QUARANTINE_TTL_SECONDS = 3600

_QUOTA_ERROR_MARKERS = (
    "402",
    "free_tier",
    "payment required",
    "insufficient_quota",
)

# 429 alone is NOT enough to quarantine: a single OpenRouter free model can be
# upstream-throttled while other free models on the same key still work. We
# only quarantine on hard-quota errors. Per-model 429s are caught and we try
# the next model in the same provider before moving on.
_TRANSIENT_ERROR_MARKERS = (
    "429",
    "rate-limited",
    "rate limited",
    "temporarily",
    "retry shortly",
    "too many requests",
    "404",                       # model not found / no endpoints → try next model
    "no endpoints found",
    "model_not_found",
    "model not found",
    "503",                       # service unavailable
    "502",                       # bad gateway
)


def _is_quota_error(exc: BaseException) -> bool:
    """Hard quota / auth error — quarantine the provider."""
    msg = str(exc).lower()
    if any(marker in msg for marker in _QUOTA_ERROR_MARKERS):
        return True
    # "quota" but NOT "free_tier_quota_exceeded" handled above — keep generic
    # "quota" too for OpenAI-style insufficient_quota messages.
    if "quota" in msg and "rate" not in msg:
        return True
    return False


def _is_transient_error(exc: BaseException) -> bool:
    """Transient throttle — try next model first, don't quarantine yet."""
    msg = str(exc).lower()
    return any(marker in msg for marker in _TRANSIENT_ERROR_MARKERS)

from app.core.ai_providers import (
    AIProvider,
    OpenRouterProvider,
    OmniRouteProvider,
    AnthropicProvider,
    OpenAIProvider,
    OllamaProvider,
    InceptionProvider,
    create_provider,
    PROVIDER_CLASSES,
)

try:
    from app.core.ai_providers import GeminiProvider  # type: ignore
except ImportError:
    GeminiProvider = None  # type: ignore[assignment]

logger = logging.getLogger("aegis.ai_manager")


class AIManager:
    """Singleton that owns every registered AI provider instance."""

    def __init__(self):
        self.providers: dict[str, AIProvider] = {}
        self.active_provider: str = "inception"
        # task_type -> provider name override  (e.g. {"code_analysis": "anthropic"})
        # ip_threat_brief: route to openrouter (cheap free model) by default; the
        # full fallback chain still applies if quarantined / errors.
        self.task_routing: dict[str, str] = {
            "ip_threat_brief": "openrouter",
        }
        # task_type -> default model id list (provider-specific). Used only
        # when the caller does not pass `model`. Multiple models per provider
        # are tried in order; if all fail transiently the manager moves to the
        # next provider in the fallback chain.
        # Accepts either a single string (legacy) or a list of strings.
        self.task_model_defaults: dict[str, dict[str, list[str] | str]] = {
            "ip_threat_brief": {
                # Try several free OpenRouter models — when one is upstream-
                # throttled (HTTP 429), the next is tried before quarantining
                # the entire provider. Order = best-quality short-brief first.
                "openrouter": [
                    "meta-llama/llama-3.3-70b-instruct:free",
                    "qwen/qwen3-next-80b-a3b-instruct:free",
                    "openai/gpt-oss-20b:free",
                    "openai/gpt-oss-120b:free",
                    "google/gemma-4-26b-a4b-it:free",
                    "deepseek/deepseek-v4-flash:free",
                    "nvidia/nemotron-nano-9b-v2:free",
                    "meta-llama/llama-3.2-3b-instruct:free",
                    "z-ai/glm-4.5-air:free",
                ],
                "inception": "mercury-2",
                "gemini": "gemini-flash-lite-latest",
            },
        }
        # ordered fallback chain of provider names
        self.fallback_chain: list[str] = ["inception", "openrouter", "openai", "anthropic", "ollama"]
        # provider name -> unix timestamp until which the provider is skipped
        self._quarantined: dict[str, float] = {}

    def _is_quarantined(self, name: str) -> bool:
        until = self._quarantined.get(name)
        if until is None:
            return False
        if time.time() >= until:
            self._quarantined.pop(name, None)
            return False
        return True

    def _quarantine(self, name: str, reason: str) -> None:
        self._quarantined[name] = time.time() + _QUARANTINE_TTL_SECONDS
        logger.warning(
            f"Provider {name} quarantined for {_QUARANTINE_TTL_SECONDS}s: {reason}"
        )

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
            if self._is_quarantined(pname):
                continue
            try:
                provider = self._resolve_provider(pname, client_settings)
            except ValueError:
                continue

            # Build a list of candidate models for this provider. If the
            # caller passed `model`, that's the only candidate. Otherwise we
            # consult task_model_defaults which may yield a list.
            if model:
                model_candidates: list[str | None] = [model]
            else:
                default_entry = self.task_model_defaults.get(task_type, {}).get(pname)
                if isinstance(default_entry, list):
                    model_candidates = list(default_entry)
                elif default_entry:
                    model_candidates = [default_entry]
                else:
                    model_candidates = [None]  # let provider pick its own default

            provider_exhausted = False
            for effective_model in model_candidates:
                try:
                    result = await provider.chat(
                        messages=messages,
                        model=effective_model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    )
                    result["provider"] = pname
                    if not result.get("model") and effective_model:
                        result["model"] = effective_model
                    return result
                except Exception as exc:
                    logger.warning(
                        f"Provider {pname} model={effective_model} failed for "
                        f"task_type={task_type}: {exc}"
                    )
                    last_error = exc
                    if _is_quota_error(exc):
                        self._quarantine(pname, f"quota error: {exc}")
                        provider_exhausted = True
                        break  # skip remaining models for this provider
                    # transient (429 etc.) — try the next model under same provider
                    if not _is_transient_error(exc):
                        # Other error class (timeout, connect, auth) — move on
                        # to next provider; no point retrying more models.
                        break
            if provider_exhausted:
                continue

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
    omniroute_url: str = "",
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
    # Google Gemini (cheap+fast hot-path enrichment) — only if the provider
    # class is available in this build of ai_providers.
    if GeminiProvider is not None:
        ai_manager.register_provider(
            "gemini",
            GeminiProvider(api_key=gemini_api_key, base_url=gemini_base_url),
        )

    # OmniRoute self-hosted gateway (optional PRIMARY). When AEGIS_OMNIROUTE_URL
    # is set, it becomes the first provider tried for every task; the direct
    # providers registered above stay in the fallback chain, so a slow/exhausted
    # or down gateway transparently degrades to Inception/OpenRouter/Gemini.
    if omniroute_url:
        ai_manager.register_provider(
            "omniroute",
            OmniRouteProvider(api_key="omniroute-local", base_url=omniroute_url.rstrip("/")),
        )
        # Prepend to the fallback chain and make it the active primary.
        ai_manager.fallback_chain = ["omniroute"] + [
            p for p in ai_manager.fallback_chain if p != "omniroute"
        ]
        # Route the hot enrichment task through the gateway's fast combo, and
        # override any task that was hard-pinned to another provider.
        ai_manager.task_routing = {k: "omniroute" for k in ai_manager.task_routing}
        ai_manager.task_routing["ip_threat_brief"] = "omniroute"
        ai_manager.task_model_defaults.setdefault("ip_threat_brief", {})["omniroute"] = ["auto/cheap"]

    # Set active provider precedence: OmniRoute → Inception → OpenRouter → Gemini
    if omniroute_url:
        ai_manager.set_active_provider("omniroute")
    elif inception_api_key:
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
