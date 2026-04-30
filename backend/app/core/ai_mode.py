"""
Central AI mode flag for AEGIS.

AEGIS_AI_MODE ∈ {required, optional, disabled}  (default: optional)
  required  — AI must be available; fail hard if not
  optional  — try AI, fall back to deterministic logic on failure
  disabled  — never call AI; always use deterministic fallbacks
"""
import os
import logging
from enum import Enum
from typing import Callable, Any, Awaitable, TypeVar

logger = logging.getLogger("aegis.ai_mode")

T = TypeVar("T")


class AIMode(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    DISABLED = "disabled"


def _parse_mode() -> AIMode:
    raw = os.getenv("AEGIS_AI_MODE", "optional").strip().lower()
    try:
        return AIMode(raw)
    except ValueError:
        logger.warning(f"Unknown AEGIS_AI_MODE={raw!r}, defaulting to 'optional'")
        return AIMode.OPTIONAL


MODE: AIMode = _parse_mode()


def ai_available() -> bool:
    """Return True if AI calls are permitted in the current mode."""
    return MODE != AIMode.DISABLED


async def degrade_or_call(
    ai_fn: Callable[..., Awaitable[T]],
    fallback_fn: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """
    Call ai_fn(*args, **kwargs) unless AI mode is disabled or the call fails.

    - disabled → run fallback immediately, no AI call attempted.
    - optional  → try AI; on any exception run fallback.
    - required  → try AI; on exception re-raise (caller must handle).
    """
    if MODE == AIMode.DISABLED:
        return fallback_fn(*args, **kwargs)

    try:
        return await ai_fn(*args, **kwargs)
    except Exception as exc:
        if MODE == AIMode.REQUIRED:
            raise
        logger.debug(f"AI call failed, using fallback: {exc}")
        return fallback_fn(*args, **kwargs)
