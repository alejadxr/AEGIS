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
# Inception Labs (Mercury-2 diffusion LLM)
# ---------------------------------------------------------------------------

class InceptionProvider(AIProvider):
    """Inception Labs Mercury-2 — diffusion-based LLM.

    Mercury-2 is a diffusion language model that generates text in parallel
    (not token-by-token like autoregressive models). This makes it potentially
    faster for short, structured responses like security triage.

    Special features:
    - reasoning_effort: "instant" | "low" | "medium" | "high"
      "instant" = fastest (best for triage), "high" = deepest reasoning
    - Structured outputs via response_format with JSON schema enforcement
    - Streaming with optional diffusing=true to see refinement process
    - Free tier: 10M tokens
    """

    KNOWN_MODELS = [
        {"id": "mercury-2", "name": "Mercury-2 (Diffusion LLM)"},
    ]

    # Map AEGIS task types to Mercury reasoning effort levels
    TASK_REASONING: dict[str, str] = {
        "triage": "instant",        # Fastest — sub-second decisions
        "quick_decision": "instant",
        "classification": "medium",
        "risk_scoring": "medium",
        "healing": "medium",
        "investigation": "high",    # Deepest reasoning
        "code_analysis": "high",
        "report": "high",
        "decoy_content": "medium",
        "red_team": "high",
        "counter_attack": "high",
        "payload_analysis": "high",
    }

    def __init__(self, api_key: str = "", base_url: str = "https://api.inceptionlabs.ai/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def get_name(self) -> str:
        return "inception"

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.75,
        max_tokens: int = 8192,
        task_type: str = "triage",
        **kwargs,
    ) -> dict:
        if not self.api_key:
            return {
                "content": '{"note": "Inception Labs API key not configured."}',
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
            }

        model = model or "mercury-2"
        reasoning = self.TASK_REASONING.get(task_type, "medium")
        client = await self._get_client()
        start = time.time()

        payload: dict = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "reasoning_effort": reasoning,
        }

        # For triage/classification tasks, enforce structured JSON output
        if task_type in ("triage", "classification", "risk_scoring", "quick_decision"):
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "SecurityAnalysis",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "threat_type": {"type": "string"},
                            "mitre_technique": {"type": "string"},
                            "mitre_tactic": {"type": "string"},
                            "summary": {"type": "string"},
                            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        },
                        "required": ["severity", "threat_type", "summary", "confidence"],
                    },
                },
            }

        resp = await client.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code != 200:
            raise Exception(f"Inception returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        return {
            "content": content,
            "tokens_used": usage.get("total_tokens", 0),
            "cost_usd": 0.0,
            "latency_ms": latency_ms,
            "reasoning_effort": reasoning,
            "reasoning_tokens": usage.get("reasoning_tokens", 0),
        }

    async def get_models(self) -> list[dict]:
        return list(self.KNOWN_MODELS)


# ---------------------------------------------------------------------------
# Google Gemini (Generative Language API)
# ---------------------------------------------------------------------------

class GeminiProvider(AIProvider):
    """Google Gemini via Generative Language REST API.

    Default model: gemini-flash-lite-latest (cheap + fast, suitable for
    enrichment + triage on the AEGIS hot path).
    """

    KNOWN_MODELS = [
        {"id": "gemini-flash-lite-latest", "name": "Gemini Flash Lite (latest)"},
        {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash"},
        {"id": "gemini-2.0-flash-lite", "name": "Gemini 2.0 Flash Lite"},
        {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro"},
    ]

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def get_name(self) -> str:
        return "gemini"

    @staticmethod
    def _to_gemini_contents(messages: list[dict]) -> tuple[list[dict], Optional[str]]:
        """Translate OpenAI-style messages → Gemini `contents` + system_instruction.

        Gemini's role names are "user" and "model" (not "assistant").
        System messages are merged into a single system_instruction string.
        """
        system_parts: list[str] = []
        contents: list[dict] = []
        for m in messages:
            role = m.get("role", "user")
            text = m.get("content", "")
            if not text:
                continue
            if role == "system":
                system_parts.append(text)
                continue
            gemini_role = "model" if role == "assistant" else "user"
            contents.append({"role": gemini_role, "parts": [{"text": text}]})
        system_instruction = "\n\n".join(system_parts) if system_parts else None
        return contents, system_instruction

    async def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> dict:
        if not self.api_key:
            return {
                "content": '{"note": "Gemini API key not configured."}',
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
            }

        model = model or "gemini-flash-lite-latest"
        client = await self._get_client()
        contents, system_instruction = self._to_gemini_contents(messages)

        body: dict = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }
        if system_instruction:
            body["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        start = time.time()
        resp = await client.post(
            f"{self.base_url}/models/{model}:generateContent",
            params={"key": self.api_key},
            headers={"Content-Type": "application/json"},
            json=body,
        )
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code != 200:
            raise Exception(f"Gemini returned {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        candidates = data.get("candidates", []) or []
        if not candidates:
            content = ""
        else:
            parts = candidates[0].get("content", {}).get("parts", []) or []
            content = "".join(p.get("text", "") for p in parts)

        usage = data.get("usageMetadata", {}) or {}
        tokens_used = (
            usage.get("totalTokenCount")
            or (usage.get("promptTokenCount", 0) + usage.get("candidatesTokenCount", 0))
            or 0
        )

        return {
            "content": content,
            "tokens_used": tokens_used,
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
                params={"key": self.api_key},
            )
            if resp.status_code == 200:
                models = resp.json().get("models", []) or []
                out = [
                    {
                        "id": m["name"].removeprefix("models/"),
                        "name": m.get("displayName") or m["name"],
                    }
                    for m in models
                    if "generateContent" in (m.get("supportedGenerationMethods") or [])
                ]
                return out if out else list(self.KNOWN_MODELS)
        except Exception:
            pass
        return list(self.KNOWN_MODELS)


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

PROVIDER_CLASSES: dict[str, type[AIProvider]] = {
    "openrouter": OpenRouterProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "ollama": OllamaProvider,
    "inception": InceptionProvider,
    "gemini": GeminiProvider,
}


def create_provider(name: str, **kwargs) -> AIProvider:
    """Instantiate a provider by name.

    kwargs are forwarded to the provider constructor (api_key, base_url, etc.).
    """
    cls = PROVIDER_CLASSES.get(name)
    if cls is None:
        raise ValueError(f"Unknown AI provider: {name}")
    return cls(**kwargs)
