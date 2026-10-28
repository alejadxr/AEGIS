"""Block expiry tests. Run: cd firewall-agent && python3 -m pytest tests -q"""
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main  # noqa: E402

IP_TEMP = "192.0.2.10"
IP_PERM = "198.51.100.20"


class FakeIptables:
    """Stateful stand-in for `iptables`: a set of DROPped source IPs."""

    def __init__(self):
        self.rules: set[str] = set()
        self.fail_delete = False

    def __call__(self, *args, check=True):
        out = ""
        rc = 0
        if args[:3] == ("-L", "INPUT", "-n"):
            out = "\n".join(f"DROP all -- {ip} 0.0.0.0/0" for ip in sorted(self.rules))
        elif args[0] == "-I" and args[1] == "INPUT":
            self.rules.add(args[3])
        elif args[0] == "-D":
            # FORWARD is not modelled: report "no such rule" so unblock_ip's
            # delete-until-failure loop terminates.
            if args[1] != "INPUT" or self.fail_delete or args[3] not in self.rules:
                rc = 1
            else:
                self.rules.discard(args[3])
        return subprocess.CompletedProcess(args, rc, stdout=out, stderr="")


@pytest.fixture
def env(monkeypatch, tmp_path):
    fake = FakeIptables()
    clock = {"t": 1_000_000.0}

    async def no_crawler(ip, text):
        return None

    monkeypatch.setattr(main, "_run_iptables", fake)
    monkeypatch.setattr(main, "_now_ts", lambda: clock["t"])
    monkeypatch.setattr(main, "_verify_crawler", no_crawler)
    monkeypatch.setattr(main, "BLOCKED_IPS_FILE", tmp_path / "blocked_ips.json")
    monkeypatch.setattr(main, "AEGIS_FIREWALL_SECRET", "")
    monkeypatch.setattr(main, "_PUBLIC_READ_PATHS", frozenset({"/blocked"}))
    main._block_expiry.clear()
    main._attackers.clear()
    client = TestClient(main.app, raise_server_exceptions=False)
    return client, fake, clock


def _block(client, ip, **extra):
    return client.post("/block", json={"ip": ip, "force": True, "reason": "test", **extra})


def test_duration_block_expires_but_permanent_does_not(env):
    client, fake, clock = env
    assert _block(client, IP_TEMP, duration=3600).status_code == 200
    assert _block(client, IP_PERM).status_code == 200
    assert set(client.get("/blocked").json()["blocked"]) == {IP_TEMP, IP_PERM}

    clock["t"] += 3601
    assert main.expire_blocks() == [IP_TEMP]
    assert fake.rules == {IP_PERM}
    assert client.get("/blocked").json()["blocked"] == [IP_PERM]


def test_not_expired_before_deadline(env):
    client, fake, clock = env
    _block(client, IP_TEMP, duration=3600)
    clock["t"] += 3599
    assert main.expire_blocks() == []
    assert IP_TEMP in fake.rules


def test_expired_entry_hidden_from_blocked_without_sweeper(env):
    client, fake, clock = env
    _block(client, IP_TEMP, duration=60)
    clock["t"] += 61
    # Sweeper never ran: the rule is still in iptables but must not be reported.
    assert IP_TEMP in fake.rules
    assert client.get("/blocked").json()["blocked"] == []


def test_negative_and_zero_duration_rejected(env):
    client, fake, _ = env
    assert _block(client, IP_TEMP, duration=-5).status_code == 400
    assert _block(client, IP_TEMP, duration=0).status_code == 400
    assert fake.rules == set()


def test_duration_is_capped(env):
    client, _, clock = env
    _block(client, IP_TEMP, duration=10 ** 12)
    assert main._block_expiry[IP_TEMP] == clock["t"] + main.MAX_BLOCK_DURATION


def test_temporary_request_does_not_downgrade_permanent(env):
    client, _, _ = env
    _block(client, IP_PERM)
    _block(client, IP_PERM, duration=60)
    assert IP_PERM not in main._block_expiry


def test_failed_unblock_keeps_record_and_retries(env):
    client, fake, clock = env
    _block(client, IP_TEMP, duration=60)
    clock["t"] += 61
    fake.fail_delete = True
    assert main.expire_blocks() == []
    assert IP_TEMP in main._block_expiry
    fake.fail_delete = False
    assert main.expire_blocks() == [IP_TEMP]
    assert fake.rules == set()


def test_delete_failure_returns_500(env):
    client, fake, _ = env
    _block(client, IP_TEMP)
    fake.fail_delete = True
    assert client.delete(f"/block/{IP_TEMP}").status_code == 500


def test_expiry_persisted_and_lapsed_block_not_restored(env):
    client, fake, clock = env
    _block(client, IP_TEMP, duration=100)
    _block(client, IP_PERM, duration=10_000)

    # Simulate restart: fresh memory, empty iptables, clock past the first expiry.
    main._block_expiry.clear()
    main._attackers.clear()
    fake.rules.clear()
    clock["t"] += 500
    main._restore_iptables_rules()

    assert fake.rules == {IP_PERM}
    assert IP_PERM in main._block_expiry and IP_TEMP not in main._block_expiry
