"""Tail must resume after the last processed line when a log is rewritten."""
import logging
import os

from app.services import log_watcher
from app.services.log_watcher import _TailFile


def _lines(prefix, a, b):
    return "".join(f"{prefix} request {i} año 🔥\n" for i in range(a, b))


def _drain(tf):
    return list(tf.iter_lines())


def _start_at_beginning(path):
    tf = _TailFile(str(path), from_end=False)
    _drain(tf)
    return tf


def test_in_place_trim_does_not_reprocess(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_lines("a", 0, 1000), encoding="utf-8")
    tf = _start_at_beginning(p)
    # proxy trims: drops the first 400 lines and rewrites with "w"
    with open(p, "w", encoding="utf-8") as f:
        f.write(_lines("a", 400, 1000))
    tf.check_rotation()
    assert _drain(tf) == []
    with open(p, "a", encoding="utf-8") as f:
        f.write(_lines("n", 0, 3))
    tf.check_rotation()
    assert _drain(tf) == [f"n request {i} año 🔥" for i in range(3)]
    tf.close()


def test_in_place_trim_with_new_lines_already_appended(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_lines("a", 0, 500), encoding="utf-8")
    tf = _start_at_beginning(p)
    with open(p, "w", encoding="utf-8") as f:
        f.write(_lines("a", 100, 500) + _lines("n", 0, 2))
    tf.check_rotation()
    assert _drain(tf) == ["n request 0 año 🔥", "n request 1 año 🔥"]
    tf.close()


def test_atomic_rename_rewrite_does_not_reprocess(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_lines("a", 0, 800), encoding="utf-8")
    tf = _start_at_beginning(p)
    old_inode = tf.inode
    tmp = tmp_path / "access.log.tmp"
    tmp.write_text(_lines("a", 300, 800) + _lines("n", 0, 2), encoding="utf-8")
    os.rename(tmp, p)
    tf.check_rotation()
    assert tf.inode != old_inode
    assert _drain(tf) == ["n request 0 año 🔥", "n request 1 año 🔥"]
    tf.close()


def test_genuine_copytruncate_reads_new_lines_from_start(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(_lines("a", 0, 200), encoding="utf-8")
    tf = _start_at_beginning(p)
    with open(p, "w") as f:
        pass  # truncated to empty
    tf.check_rotation()
    assert _drain(tf) == []
    with open(p, "a", encoding="utf-8") as f:
        f.write(_lines("n", 0, 3))
    tf.check_rotation()
    assert _drain(tf) == [f"n request {i} año 🔥" for i in range(3)]
    tf.close()


def test_missing_anchor_large_file_skips_to_eof_with_warning(tmp_path, caplog, monkeypatch):
    monkeypatch.setattr(log_watcher, "_RESUME_FALLBACK_MAX_BYTES", 10_000)
    p = tmp_path / "access.log"
    p.write_text(_lines("a", 0, 6000), encoding="utf-8")
    tf = _start_at_beginning(p)
    with open(p, "w", encoding="utf-8") as f:
        f.write(_lines("zzz", 0, 1000))  # unrelated content, > threshold
    with caplog.at_level(logging.WARNING, logger=log_watcher.logger.name):
        tf.check_rotation()
    assert _drain(tf) == []
    assert any("not found" in r.getMessage() for r in caplog.records)
    with open(p, "a", encoding="utf-8") as f:
        f.write(_lines("n", 0, 1))
    assert _drain(tf) == ["n request 0 año 🔥"]
    tf.close()


def test_multibyte_content_roundtrip_and_resume(tmp_path):
    p = tmp_path / "access.log"
    rows = ["ñandú ✓ café", "emoji 🔥🔥 línea", "日本語 ログ"] * 50
    p.write_text("".join(r + "\n" for r in rows), encoding="utf-8")
    tf = _TailFile(str(p), from_end=False)
    assert _drain(tf) == rows
    with open(p, "w", encoding="utf-8") as f:
        f.write("".join(r + "\n" for r in rows[60:]) + "nuevo ñ 🔥\n")
    tf.check_rotation()
    assert _drain(tf) == ["nuevo ñ 🔥"]
    tf.close()


def test_invalid_utf8_is_replaced_not_fatal(tmp_path):
    p = tmp_path / "access.log"
    p.write_bytes(b"ok line\nbad \xff\xfe bytes\n")
    tf = _TailFile(str(p), from_end=False)
    out = _drain(tf)
    assert out[0] == "ok line" and out[1].startswith("bad ")
    tf.close()


def test_scan_straddling_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr(log_watcher, "_RESUME_SCAN_CHUNK", 64)
    p = tmp_path / "access.log"
    p.write_text(_lines("a", 0, 300), encoding="utf-8")
    tf = _start_at_beginning(p)
    with open(p, "w", encoding="utf-8") as f:
        f.write(_lines("a", 150, 300) + _lines("n", 0, 1))
    tf.check_rotation()
    assert _drain(tf) == ["n request 0 año 🔥"]
    tf.close()
