"""
Multi-provider AI adapter for AEGIS.

Defines the abstract AIProvider interface and concrete implementations
for OpenRouter, Anthropic, OpenAI, and Ollama.
All providers return responses in a unified format compatible with the
existing openrouter_client.query() return shape:
  {
    "content": str,
    "tokens_used": int,
    "cost_usd": float,
    "latency_ms": int,
    "model_used": str,
    "task_type": str,
  }
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Optional

import httpx

logger = logging.getLogger("aegis.ai_providers")


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class AIProvider(ABC):
    """Common interface every AI backend must implement."""

    @abstractmethod
    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict:
        """Send a chat-completion request.

        Returns a dict with at least:
          content, tokens_used, cost_usd, latency_ms
        """
        ...

    @abstractmethod
    async def get_models(self) -> list[dict]:
        """Return available models as [{"id": ..., "name": ...}, ...]."""
        ...

    @abstractmethod
    def get_name(self) -> str:
        """Human-readable provider name."""
        ...

    async def test_connection(self) -> dict:
        """Quick connectivity check. Returns {"ok": bool, "detail": str}."""
        try:
            models = await self.get_models()
            return {
                "ok": True,
                "detail": f"{len(models)} model(s) available",
                "models_count": len(models),
            }
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}

    async def close(self):
        """Release underlying HTTP resources (optional override)."""
        pass


# ---------------------------------------------------------------------------
# OpenRouter
# ---------------------------------------------------------------------------

class OpenRouterProvider(AIProvider):
    """OpenRouter (500+ models via single API key)."""

    def __init__(self, api_key: str = "", base_url: str = "https://openrouter.ai/api/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def get_name(self) -> str:
        return "openrouter"

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict:
        if not self.api_key:
            return {
                "content": '{"note": "OpenRouter API key not configured. Using mock response."}',
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
            }

        model = model or "openai/gpt-oss-20b:free"
        client = await self._get_client()
        start = time.time()

        resp = await client.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "https://github.com/aegis-defense/aegis",
                "X-Title": "AEGIS Defense Platform",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code != 200:
            raise Exception(f"OpenRouter returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        return {
            "content": content,
            "tokens_used": usage.get("total_tokens", 0),
            "cost_usd": 0.0,
            "latency_ms": latency_ms,
        }

    async def get_models(self) -> list[dict]:
        client = await self._get_client()
        if not self.api_key:
            return []
        resp = await client.get(
            f"{self.base_url}/models",
            headers={"Authorization": f"Bearer {self.api_key}"},
        )
        if resp.status_code != 200:
            raise Exception(f"OpenRouter /models returned {resp.status_code}")
        data = resp.json().get("data", [])
        return [{"id": m["id"], "name": m.get("name", m["id"])} for m in data[:100]]


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class AnthropicProvider(AIProvider):
    """Direct Anthropic Messages API."""

    KNOWN_MODELS = [
        {"id": "claude-sonnet-4-6", "name": "Claude Sonnet 4.6"},
        {"id": "claude-opus-4-6", "name": "Claude Opus 4.6"},
        {"id": "claude-haiku-4-5", "name": "Claude Haiku 4.5"},
    ]

    def __init__(self, api_key: str = "", base_url: str = "https://api.anthropic.com"):
        self.api_key = api_key
        self.base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def get_name(self) -> str:
        return "anthropic"

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict:
        if not self.api_key:
            return {
                "content": '{"note": "Anthropic API key not configured."}',
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
            }

        model = model or "claude-sonnet-4-6"
        client = await self._get_client()

        # Convert OpenAI message format to Anthropic format:
        # - Extract system message(s) into top-level `system` param
        # - Keep user/assistant messages in the `messages` list
        system_parts: list[str] = []
        anthropic_messages: list[dict] = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                system_parts.append(content)
            else:
                anthropic_messages.append({"role": role, "content": content})

        # Anthropic requires at least one user message
        if not anthropic_messages:
            anthropic_messages = [{"role": "user", "content": "Hello."}]

        payload: dict = {
            "model": model,
            "messages": anthropic_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)

        start = time.time()
        resp = await client.post(
            f"{self.base_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code != 200:
            raise Exception(f"Anthropic returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        # Anthropic response: {"content": [{"type": "text", "text": "..."}], "usage": {...}}
        content_blocks = data.get("content", [])
        content = "".join(
            block.get("text", "") for block in content_blocks if block.get("type") == "text"
        )
        usage = data.get("usage", {})

        return {
            "content": content,
            "tokens_used": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            "cost_usd": 0.0,
            "latency_ms": latency_ms,
        }

    async def get_models(self) -> list[dict]:
        return list(self.KNOWN_MODELS)


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------

class OpenAIProvider(AIProvider):
    """Direct OpenAI Chat Completions API."""

    KNOWN_MODELS = [
        {"id": "gpt-4o", "name": "GPT-4o"},
        {"id": "gpt-4o-mini", "name": "GPT-4o Mini"},
        {"id": "gpt-4.1", "name": "GPT-4.1"},
    ]

    def __init__(self, api_key: str = "", base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def get_name(self) -> str:
        return "openai"

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict:
        if not self.api_key:
            return {
                "content": '{"note": "OpenAI API key not configured."}',
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
            }

        model = model or "gpt-4o-mini"
        client = await self._get_client()
        start = time.time()

        resp = await client.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code != 200:
            raise Exception(f"OpenAI returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        return {
            "content": content,
            "tokens_used": usage.get("total_tokens", 0),
            "cost_usd": 0.0,
            "latency_ms": latency_ms,
        }

    async def get_models(self) -> list[dict]:
        if not self.api_key:
            return list(self.KNOWN_MODELS)
        try:
            client = await self._get_client()
            resp = await client.get(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                gpt_models = [
                    {"id": m["id"], "name": m["id"]}
                    for m in data
                    if "gpt" in m["id"] or "o1" in m["id"] or "o3" in m["id"]
                ]
                return gpt_models if gpt_models else list(self.KNOWN_MODELS)
        except Exception:
            pass
        return list(self.KNOWN_MODELS)


# ---------------------------------------------------------------------------
# Ollama (local / air-gapped)
# ---------------------------------------------------------------------------

class OllamaProvider(AIProvider):
    """Local Ollama instance -- no API key required."""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=300.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def get_name(self) -> str:
        return "ollama"

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict:
        model = model or "llama3"
        client = await self._get_client()
        start = time.time()

        resp = await client.post(
            f"{self.base_url}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
        )
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code != 200:
            raise Exception(f"Ollama returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        content = data.get("message", {}).get("content", "")
        prompt_tokens = data.get("prompt_eval_count", 0)
        completion_tokens = data.get("eval_count", 0)

        return {
            "content": content,
            "tokens_used": prompt_tokens + completion_tokens,
            "cost_usd": 0.0,
            "latency_ms": latency_ms,
        }

    async def get_models(self) -> list[dict]:
        client = await self._get_client()
        resp = await client.get(f"{self.base_url}/api/tags")
        if resp.status_code != 200:
            raise Exception(f"Ollama /api/tags returned {resp.status_code}")
        models = resp.json().get("models", [])
        return [
            {"id": m["name"], "name": m.get("name", m["name"])}
            for m in models
        ]


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

PROVIDER_CLASSES: dict[str, type[AIProvider]] = {
    "openrouter": OpenRouterProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
}


def create_provider(name: str, **kwargs) -> AIProvider:
    """Instantiate a provider by name.

    kwargs are forwarded to the provider constructor (api_key, base_url, etc.).
    """
    cls = PROVIDER_CLASSES.get(name)
    if cls is None:
        raise ValueError(f"Unknown AI provider: {name}")
    return cls(**kwargs)
