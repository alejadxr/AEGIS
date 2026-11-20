"""A scan target must never be parsed by nmap as an option (audit A6)."""
import pytest
from pydantic import ValidationError

from app.core.scan_target import validate_scan_target


@pytest.mark.parametrize("bad", [
    "-oN=/tmp/x", "--script=/tmp/evil.nse", "-iL=/etc/passwd", "-sC", " -oG /tmp/y",
    "10.0.0.1 -oN /tmp/x", "host;id", "host$(id)", "a b", "", " ", "10.0.0.0/99",
    "exa_mple.com", "-", "host\n-oN=/tmp/x", "x" * 300, None, 123, ["10.0.0.1"],
])
def test_option_shaped_or_malformed_targets_are_refused(bad):
    with pytest.raises(ValueError):
        validate_scan_target(bad)


@pytest.mark.parametrize("good,expected", [
    ("192.0.2.10", "192.0.2.10"),
    (" 192.0.2.10 ", "192.0.2.10"),
    ("192.0.2.0/24", "192.0.2.0/24"),
    ("192.0.2.7/24", "192.0.2.0/24"),
    ("2001:db8::1", "2001:db8::1"),
    ("Example.COM", "example.com"),
    ("scan-me.example.org.", "scan-me.example.org"),
    ("localhost", "localhost"),
])
def test_hosts_ips_and_cidrs_are_accepted(good, expected):
    assert validate_scan_target(good) == expected


def test_api_schemas_reject_option_injection():
    from app.api.setup import DiscoverRequest
    from app.api.surface import ScanRequest
    for model in (DiscoverRequest, ScanRequest):
        with pytest.raises(ValidationError):
            model(target="--script=/tmp/evil.nse")
        assert model(target="192.0.2.0/28").target == "192.0.2.0/28"


async def test_nmap_sinks_refuse_without_spawning_a_process(monkeypatch):
    import asyncio
    import subprocess
    from app.modules.surface import discovery
    from app.services.counter_attack import CounterAttackEngine

    def _boom(*a, **k):
        raise AssertionError("a scanner process was spawned for an option-shaped target")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/nmap")

    assert await discovery.discovery_engine._scan_ports("--script=/tmp/evil.nse") == []
    out = CounterAttackEngine._run_nmap(object(), "-iL=/etc/passwd")
    assert out.startswith("refused")
