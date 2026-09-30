"""AEGIS_EDR_TRUSTED_PARENTS: exact-path exclusion of a management agent's children."""
from __future__ import annotations

import logging

import pytest

from . import edr_payloads as P
from .test_edr_rule_feed import engine, feed, fired  # noqa: F401  (engine is a fixture)

TRUSTED = "C:\\Program Files\\Example Fleet\\fleet-agent.exe"
RULE = "sigma_c2_encoded_powershell"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("AEGIS_EDR_TRUSTED_PARENTS", raising=False)


def _batch(events):
    return {"events": [
        {**e, "client_id": P.CLIENT_ID, "agent_id": P.AGENT_ID, "hostname": P.HOST}
        for e in events
    ]}


def _parent(path, pid=1000):
    return P.tauri_event("process_start", pid=pid, ppid=4, name=path.split("\\")[-1], path=path,
                         cmd=path)


def _run(monkeypatch, engine, *events):
    feed(engine, _batch(events))
    return fired(engine)


def test_child_of_exact_trusted_path_is_excluded(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", TRUSTED)
    alerts = _run(monkeypatch, engine, _parent(TRUSTED), P.PS_ENC)
    assert RULE not in alerts


def test_match_is_case_and_slash_insensitive(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", TRUSTED.upper())
    alerts = _run(monkeypatch, engine, _parent(TRUSTED.lower().replace("\\", "/")), P.PS_ENC)
    assert RULE not in alerts


def test_untrusted_env_leaves_rule_firing(monkeypatch, engine):
    alerts = _run(monkeypatch, engine, _parent(TRUSTED), P.PS_ENC)
    assert RULE in alerts


def test_same_file_name_in_another_directory_is_not_excluded(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", TRUSTED)
    impostor = "C:\\Users\\public\\fleet-agent.exe"
    alerts = _run(monkeypatch, engine, _parent(impostor), P.PS_ENC)
    assert RULE in alerts


def test_unknown_parent_is_not_excluded(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", TRUSTED)
    alerts = _run(monkeypatch, engine, P.PS_ENC)  # parent pid 1000 never seen
    assert RULE in alerts


def test_exit_of_parent_forgets_its_path(monkeypatch, engine):
    monkeypatch.setenv("AEGIS_EDR_TRUSTED_PARENTS", TRUSTED)
    stop = P.tauri_event("process_stop", pid=1000, ppid=4, path=TRUSTED)
    alerts = _run(monkeypatch, engine, _parent(TRUSTED), stop, P.PS_ENC)
    assert RULE in alerts


@pytest.mark.parametrize("name", [
    "sshd.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "explorer.exe", "services.exe", "svchost.exe",
])
def test_forbidden_entries_rejected(name, caplog):
    from app.services.edr_trusted_parents import parse_trusted_parents

    with caplog.at_level(logging.WARNING, logger="aegis.edr"):
        got = parse_trusted_parents(f"C:\\Program Files\\Example\\{name.upper()}")
    assert got == frozenset()
    assert "rejected" in caplog.text


def test_relative_and_traversal_entries_rejected(caplog):
    from app.services.edr_trusted_parents import parse_trusted_parents

    with caplog.at_level(logging.WARNING, logger="aegis.edr"):
        got = parse_trusted_parents(
            "fleet-agent.exe,C:\\Program Files\\Example\\..\\..\\Temp\\x.exe,")
    assert got == frozenset()


def test_unprotected_directory_is_kept_but_warned(caplog):
    from app.services.edr_trusted_parents import parse_trusted_parents

    with caplog.at_level(logging.WARNING, logger="aegis.edr"):
        got = parse_trusted_parents(f"{TRUSTED}, C:\\Tools\\fleet.exe")
    assert got == frozenset({TRUSTED.lower(), "c:\\tools\\fleet.exe"})
    assert "Tools" in caplog.text
    assert "Example Fleet" not in caplog.text


def test_empty_by_default():
    from app.services.edr_trusted_parents import get_trusted_parents, is_trusted_parent

    assert get_trusted_parents() == frozenset()
    assert not is_trusted_parent(TRUSTED)


def test_value_from_settings_only_is_honoured(monkeypatch, engine):
    """backend/.env values land in pydantic settings, never in os.environ."""
    from app.config import settings
    import os
    monkeypatch.setattr(settings, "AEGIS_EDR_TRUSTED_PARENTS", TRUSTED, raising=False)
    assert "AEGIS_EDR_TRUSTED_PARENTS" not in os.environ
    alerts = _run(monkeypatch, engine, _parent(TRUSTED), P.PS_ENC)
    assert RULE not in alerts
