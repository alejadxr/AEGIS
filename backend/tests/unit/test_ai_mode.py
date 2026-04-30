"""Tests for app.core.ai_mode — flag parsing and degrade_or_call dispatch."""
import os
import importlib
import pytest


def _reload_module(mode_value: str):
    """Reload ai_mode with a specific env var value."""
    os.environ["AEGIS_AI_MODE"] = mode_value
    import app.core.ai_mode as m
    importlib.reload(m)
    return m


# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------

def test_parse_optional_by_default():
    os.environ.pop("AEGIS_AI_MODE", None)
    m = _reload_module("optional")
    assert m.MODE == m.AIMode.OPTIONAL


def test_parse_disabled():
    m = _reload_module("disabled")
    assert m.MODE == m.AIMode.DISABLED


def test_parse_required():
    m = _reload_module("required")
    assert m.MODE == m.AIMode.REQUIRED


def test_parse_unknown_defaults_to_optional():
    m = _reload_module("banana")
    assert m.MODE == m.AIMode.OPTIONAL


def test_ai_available_optional():
    m = _reload_module("optional")
    assert m.ai_available() is True


def test_ai_available_disabled():
    m = _reload_module("disabled")
    assert m.ai_available() is False


def test_ai_available_required():
    m = _reload_module("required")
    assert m.ai_available() is True


# ---------------------------------------------------------------------------
# degrade_or_call dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disabled_runs_fallback_not_ai():
    m = _reload_module("disabled")

    calls = {"ai": 0, "fallback": 0}

    async def ai_fn(x):
        calls["ai"] += 1
        return "ai_result"

    def fallback_fn(x):
        calls["fallback"] += 1
        return "fallback_result"

    result = await m.degrade_or_call(ai_fn, fallback_fn, 42)
    assert result == "fallback_result"
    assert calls["ai"] == 0
    assert calls["fallback"] == 1


@pytest.mark.asyncio
async def test_optional_uses_ai_when_succeeds():
    m = _reload_module("optional")

    async def ai_fn(x):
        return "ai_result"

    def fallback_fn(x):
        return "fallback_result"

    result = await m.degrade_or_call(ai_fn, fallback_fn, 42)
    assert result == "ai_result"


@pytest.mark.asyncio
async def test_optional_falls_back_on_ai_error():
    m = _reload_module("optional")

    async def ai_fn(x):
        raise RuntimeError("OpenRouter unavailable")

    def fallback_fn(x):
        return "fallback_result"

    result = await m.degrade_or_call(ai_fn, fallback_fn, 42)
    assert result == "fallback_result"


@pytest.mark.asyncio
async def test_required_raises_on_ai_error():
    m = _reload_module("required")

    async def ai_fn(x):
        raise RuntimeError("OpenRouter unavailable")

    def fallback_fn(x):
        return "fallback_result"

    with pytest.raises(RuntimeError, match="OpenRouter unavailable"):
        await m.degrade_or_call(ai_fn, fallback_fn, 42)


@pytest.mark.asyncio
async def test_required_returns_ai_result_when_succeeds():
    m = _reload_module("required")

    async def ai_fn(x):
        return "ai_ok"

    def fallback_fn(x):
        return "should_not_reach"

    result = await m.degrade_or_call(ai_fn, fallback_fn, "input")
    assert result == "ai_ok"
