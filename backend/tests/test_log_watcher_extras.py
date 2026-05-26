"""Tests for AEGIS_EXTRA_LOG_PATHS glob-expansion helper."""

import os

from app.services import log_watcher


def test_extra_paths_glob_expands(monkeypatch, tmp_path):
    f1 = tmp_path / "a-access.log"
    f1.write_text("")
    f2 = tmp_path / "b-access.log"
    f2.write_text("")
    monkeypatch.setenv("AEGIS_EXTRA_LOG_PATHS", str(tmp_path / "*-access.log"))
    paths = log_watcher._resolve_extra_log_paths()
    assert str(f1) in paths
    assert str(f2) in paths


def test_extra_paths_empty_returns_empty(monkeypatch):
    monkeypatch.delenv("AEGIS_EXTRA_LOG_PATHS", raising=False)
    assert log_watcher._resolve_extra_log_paths() == []


def test_extra_paths_colon_separated(monkeypatch, tmp_path):
    f1 = tmp_path / "feed-a.jsonl"
    f1.write_text("")
    f2 = tmp_path / "feed-b.jsonl"
    f2.write_text("")
    monkeypatch.setenv(
        "AEGIS_EXTRA_LOG_PATHS",
        f"{f1}:{f2}",
    )
    paths = log_watcher._resolve_extra_log_paths()
    assert str(f1) in paths
    assert str(f2) in paths


def test_extra_paths_nonexistent_filtered(monkeypatch, tmp_path):
    f1 = tmp_path / "real.log"
    f1.write_text("")
    monkeypatch.setenv(
        "AEGIS_EXTRA_LOG_PATHS",
        f"{f1}:/does/not/exist.log",
    )
    paths = log_watcher._resolve_extra_log_paths()
    assert paths == [str(f1)]
