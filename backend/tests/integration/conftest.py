"""Minimal conftest for the integration test suite — Phase R-F.

Integration tests hit a LIVE backend (uvicorn) over HTTP.
They do NOT use SQLite/ASGI overrides — those belong to the unit suite.

Environment variables consumed here:
  AEGIS_API_URL    — defaults to http://127.0.0.1:8000
  AEGIS_API_KEY    — required when AEGIS_LIVEFIRE=1; skipped otherwise
  AEGIS_LIVEFIRE   — must be "1" for any livefire test to run
"""
from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# Session-scoped base URL
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def api_url() -> str:
    return os.getenv("AEGIS_API_URL", "http://127.0.0.1:8000")


@pytest.fixture(scope="session")
def api_key() -> str:
    key = os.getenv("AEGIS_API_KEY", "")
    return key


@pytest.fixture(scope="session")
def api_headers(api_key: str) -> dict:
    return {"X-API-Key": api_key, "Content-Type": "application/json"}
