"""Keep attacker-controlled text from forging log lines.

AEGIS tails its own log. A request path, a honeypot username or a node
hostname that contains a line break would otherwise write a SECOND line into
that log, and the watcher would read it as an event with whatever source IP the
attacker typed. Every record's message is therefore flattened to one line
before it is written. Tracebacks (``exc_info``) are left alone: they are
produced by the interpreter, not by the caller.
"""

from __future__ import annotations

import logging
import re

# Everything str.splitlines() treats as a line boundary, plus other C0 controls
# and ESC (terminal escape sequences in an operator's `pm2 logs` session).
_BREAKS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f\x85  ]")


def _escape(match: re.Match) -> str:
    ch = match.group(0)
    if ch == "\n":
        return "\\n"
    if ch == "\r":
        return "\\r"
    code = ord(ch)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


def flatten(text: str) -> str:
    """Escape line breaks and control characters in ``text``."""
    return _BREAKS.sub(_escape, text)


class SingleLineFilter(logging.Filter):
    """Collapse each record's rendered message to a single physical line."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # Bad format args: let logging report it the usual way.
            return True
        if _BREAKS.search(message):
            record.msg = flatten(message)
            record.args = None
        return True


_FILTER = SingleLineFilter()


def install() -> None:
    """Attach the filter to every handler currently configured.

    Filters on a *logger* do not see records from child loggers, so the filter
    goes on the handlers. Idempotent.
    """
    loggers = [logging.getLogger()] + [
        logging.getLogger(name) for name in ("uvicorn", "uvicorn.error", "uvicorn.access")
    ]
    for lg in loggers:
        for handler in lg.handlers:
            if _FILTER not in handler.filters:
                handler.addFilter(_FILTER)
