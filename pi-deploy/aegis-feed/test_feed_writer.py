import json
import os
import tempfile

from feed_writer import emit


def _tmp():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    os.environ["AEGIS_FEED_PATH"] = path
    return path


def test_emit_minimal():
    path = _tmp()
    emit(app="testapp", src_ip="1.2.3.4", method="GET", path="/x", status=200)
    rec = json.loads(open(path).readline())
    assert rec["app"] == "testapp"
    assert rec["src_ip"] == "1.2.3.4"
    assert rec["method"] == "GET"
    assert rec["status"] == 200
    assert "ts" in rec and rec["ts"].endswith("Z")
    os.unlink(path)


def test_emit_skips_empty_optionals():
    path = _tmp()
    emit(app="t", src_ip="1.2.3.4", method="GET", path="/", status=200, country="", ua=None, ref="x")
    rec = json.loads(open(path).readline())
    assert "country" not in rec
    assert "ua" not in rec
    assert rec["ref"] == "x"
    os.unlink(path)


def test_emit_never_raises_on_bad_path():
    os.environ["AEGIS_FEED_PATH"] = "/nonexistent/dir/feed.jsonl"
    emit(app="t", src_ip="1.2.3.4", method="GET", path="/", status=200)
