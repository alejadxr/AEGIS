"""Attacker text must not be able to write a second log line (audit A2)."""
import io
import logging

from app.core import log_sanitize


def _logger_with_buffer():
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
    handler.addFilter(log_sanitize.SingleLineFilter())
    lg = logging.getLogger("aegis.test.injection")
    lg.handlers[:] = [handler]
    lg.propagate = False
    lg.setLevel(logging.INFO)
    return lg, buf


FORGED = '198.51.100.7 - - [01/Jan/2026:00:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 200 12'


def test_newline_in_a_path_stays_on_one_line():
    lg, buf = _logger_with_buffer()
    lg.warning("[DETECT] ip=%s path=%s", "203.0.113.9", "/x\n" + FORGED)
    lines = buf.getvalue().splitlines()
    assert len(lines) == 1
    assert "\\n" in lines[0] and "[aegis.test.injection]" in lines[0]


def test_fstring_messages_and_every_line_separator_are_covered():
    lg, buf = _logger_with_buffer()
    for sep in ("\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x85", " ", " "):
        lg.info(f"login user=admin{sep}{FORGED}")
    assert len(buf.getvalue().splitlines()) == 9


def test_the_forged_line_never_reaches_the_normalizer_as_its_own_line():
    from app.services.event_normalizer import normalize

    lg, buf = _logger_with_buffer()
    lg.info("path=%s", "/a\n" + FORGED)
    for line in buf.getvalue().splitlines():
        event = normalize(line, source="cayde6-api")
        ip = getattr(event, "source_ip", None) if event is not None else None
        assert ip != "198.51.100.7"


def test_tracebacks_keep_their_lines():
    lg, buf = _logger_with_buffer()
    try:
        raise ValueError("boom")
    except ValueError:
        lg.exception("failed")
    assert "Traceback" in buf.getvalue() and len(buf.getvalue().splitlines()) > 2


def test_install_is_idempotent_and_covers_root_handlers():
    root = logging.getLogger()
    handler = logging.StreamHandler(io.StringIO())
    root.addHandler(handler)
    try:
        log_sanitize.install()
        log_sanitize.install()
        assert sum(isinstance(f, log_sanitize.SingleLineFilter) for f in handler.filters) == 1
    finally:
        root.removeHandler(handler)
