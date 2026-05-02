"""Unit tests for GeminiProvider — message translation, no-key fallback,
factory registration, and HTTP shape via httpx mock."""
from __future__ import annotations

import json as _json

import pytest
import httpx

from app.core.ai_providers import (
    GeminiProvider,
    PROVIDER_CLASSES,
    create_provider,
)


def test_factory_registers_gemini():
    assert "gemini" in PROVIDER_CLASSES
    inst = create_provider("gemini", api_key="dummy")
    assert inst.get_name() == "gemini"
    assert inst.api_key == "dummy"


def test_known_models_include_flash_lite_latest():
    g = GeminiProvider()
    ids = [m["id"] for m in g.KNOWN_MODELS]
    assert "gemini-flash-lite-latest" in ids


def test_message_translation_user_assistant_roles():
    contents, sysi = GeminiProvider._to_gemini_contents([
        {"role": "user", "content": "Hi"},
        {"role": "assistant", "content": "Hello."},
        {"role": "user", "content": "Triage."},
    ])
    assert [c["role"] for c in contents] == ["user", "model", "user"]
    assert contents[0]["parts"] == [{"text": "Hi"}]
    assert sysi is None


def test_message_translation_collapses_system_messages():
    contents, sysi = GeminiProvider._to_gemini_contents([
        {"role": "system", "content": "You are AEGIS."},
        {"role": "system", "content": "Be terse."},
        {"role": "user", "content": "Hi"},
    ])
    assert sysi == "You are AEGIS.\n\nBe terse."
    assert len(contents) == 1


def test_message_translation_skips_empty():
    contents, sysi = GeminiProvider._to_gemini_contents([
        {"role": "user", "content": ""},
        {"role": "user", "content": "Hi"},
    ])
    assert len(contents) == 1


@pytest.mark.asyncio
async def test_chat_no_key_returns_stub_without_http():
    g = GeminiProvider(api_key="")
    out = await g.chat([{"role": "user", "content": "Hi"}])
    assert out["tokens_used"] == 0
    assert "key not configured" in out["content"]


@pytest.mark.asyncio
async def test_chat_happy_path_via_mock_transport(monkeypatch):
    """End-to-end shape: request body matches Gemini API, response parsed."""
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["json"] = _json.loads(req.content)
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {"content": {"parts": [{"text": "deterministic"}]}}
                ],
                "usageMetadata": {"totalTokenCount": 42},
            },
        )

    g = GeminiProvider(api_key="testkey")
    g._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    out = await g.chat(
        [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}],
        model="gemini-flash-lite-latest",
        temperature=0.1,
        max_tokens=128,
    )

    assert out["content"] == "deterministic"
    assert out["tokens_used"] == 42
    # URL should embed the model and key
    assert "gemini-flash-lite-latest:generateContent" in captured["url"]
    assert "key=testkey" in captured["url"]
    body = captured["json"]
    assert body["systemInstruction"]["parts"][0]["text"] == "S"
    assert body["contents"][0]["role"] == "user"
    assert body["generationConfig"]["temperature"] == 0.1
    assert body["generationConfig"]["maxOutputTokens"] == 128


@pytest.mark.asyncio
async def test_chat_propagates_http_error(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="Forbidden")

    g = GeminiProvider(api_key="bad")
    g._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    with pytest.raises(Exception, match="Gemini returned 403"):
        await g.chat([{"role": "user", "content": "Hi"}])
