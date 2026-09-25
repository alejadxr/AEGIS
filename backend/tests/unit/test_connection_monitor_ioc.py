# backend/tests/unit/test_connection_monitor_ioc.py
"""IOC connection monitor: the event shape the network_connection rules read.

These tests exist because this codebase keeps shipping producers whose payload
field names no rule reads. Each test below asserts against the REAL loaded rule
set and the REAL CorrelationEngine.evaluate(), not against a mock of either, so
a rename on the rule side fails the test instead of silently going dead.
"""
import pytest

from app.modules.network.connection_monitor import (
    ConnectionMonitor,
    TOPIC,
    _is_routable_peer,
    _split_host_port,
)
from app.services.correlation_engine import (
    _CONNECTION_TOPIC,
    CorrelationEngine,
)

# One real `netstat -an` excerpt from macOS. Note the macOS format: the port is
# joined to the address with a dot, not a colon.
NETSTAT_SAMPLE = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.8000                 *.*                    LISTEN
tcp4       0      0  *.2222                 *.*                    LISTEN
tcp4       0      0  192.168.100.90.51858   142.11.206.73.8000     ESTABLISHED
tcp4       0      0  192.168.100.90.8000    85.11.187.8.44122      ESTABLISHED
tcp4       0      0  192.168.100.90.51845   151.101.193.91.443     ESTABLISHED
tcp4       0      0  100.64.0.11.51853   100.64.0.12.22       ESTABLISHED
tcp4       0      0  127.0.0.1.5432         127.0.0.1.51999        ESTABLISHED
udp4       0      0  *.52855                *.*
"""


class RecordingBus:
    """Minimal event bus that records publishes and dispatches to handlers."""

    def __init__(self):
        self.published = []
        self.handlers = {}

    def subscribe(self, topic, handler):
        self.handlers.setdefault(topic, []).append(handler)

    async def publish(self, topic, data=None, priority=2):
        self.published.append((topic, data))

    async def publish_high(self, topic, data=None):
        await self.publish(topic, data, 1)

    async def publish_critical(self, topic, data=None):
        await self.publish(topic, data, 0)

    def alerts(self):
        return [d for t, d in self.published if t == "correlation_triggered"]


@pytest.fixture
def engine():
    return CorrelationEngine()


@pytest.fixture
def monitor(engine):
    mon = ConnectionMonitor()
    mon.load_ioc_ips(engine._rules)
    return mon


# ---------------------------------------------------------------------------
# The IOC set comes from the rules, not from a second hardcoded list
# ---------------------------------------------------------------------------

def test_ioc_set_is_derived_from_the_loaded_rules(monitor):
    # A duplicated indicator list is how the alias table lost its second half.
    # These 13 IPs are declared only in the rules; the collector must find them
    # there. If a rule's indicator list changes, this set changes with it.
    expected = {
        "142.11.206.73",                                     # axios typosquat
        "23.254.164.92", "23.254.164.123",                   # mastra dropper
        "37.16.75.69",                                       # node-ipc
        "85.11.187.8",                                       # FortiBleed
        "45.77.149.152", "209.182.225.136", "38.60.157.139",  # Qilin
        "101.99.91.151", "101.99.94.173",
        "79.141.163.179", "111.90.146.237",                  # AyySSHush
    }
    assert expected <= monitor._ioc_ips, (
        f"missing from derived IOC set: {sorted(expected - monitor._ioc_ips)}"
    )


def test_ioc_set_ignores_disabled_rules_and_non_ip_values():
    mon = ConnectionMonitor()
    ips = mon.load_ioc_ips([
        {"enabled": True, "condition": {
            "event_type": "network_connection",
            "filter": {"destination_ip": ["1.2.3.4", "evil.example.com"]}}},
        {"enabled": False, "condition": {
            "event_type": "network_connection",
            "filter": {"destination_ip": ["9.9.9.9"]}}},
        {"enabled": True, "condition": {
            "event_type": "web_request",
            "filter": {"source_ip": ["5.6.7.8"]}}},
    ])
    assert ips == {"1.2.3.4"}, (
        "only IP literals on enabled connection rules are indicators; "
        "hostnames, disabled rules and other event types are not"
    )


def test_ioc_set_reads_substring_operators_as_shapes_not_indicators():
    mon = ConnectionMonitor()
    ips = mon.load_ioc_ips([
        {"enabled": True, "condition": {
            "event_type": "connection",
            "filter": {"destination_ip_contains": ["10."], "bytes_gt": 100}}},
    ])
    assert ips == set()


# ---------------------------------------------------------------------------
# netstat parsing (the only non-root connection source on the Mac Pro)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("token,expected", [
    ("192.168.100.90.51858", ("192.168.100.90", 51858)),
    ("*.8000", (None, 8000)),
    ("*.*", (None, None)),
    ("fe80::1%lo0.443", ("fe80::1%lo0", 443)),
    ("", (None, None)),
])
def test_split_host_port(token, expected):
    assert _split_host_port(token) == expected


def test_netstat_parser_infers_direction_from_listening_ports():
    mon = ConnectionMonitor()
    rows = mon._parse_netstat(NETSTAT_SAMPLE)
    by_peer = {r["remote_ip"]: r for r in rows}

    # LISTEN rows are not connections and must not appear as peers.
    assert None not in by_peer

    # Local port 51858 is ephemeral -> we dialled out.
    assert by_peer["142.11.206.73"]["direction"] == "outbound"
    assert by_peer["142.11.206.73"]["remote_port"] == 8000
    # Local port 8000 is a LISTEN socket -> the peer dialled us.
    assert by_peer["85.11.187.8"]["direction"] == "inbound"
    assert by_peer["85.11.187.8"]["local_port"] == 8000


def test_netstat_parser_survives_garbage():
    mon = ConnectionMonitor()
    assert mon._parse_netstat("") == []
    assert mon._parse_netstat("not a netstat table at all\n\n") == []


@pytest.mark.parametrize("ip,routable", [
    ("142.11.206.73", True),
    ("8.8.8.8", True),
    ("127.0.0.1", False),       # loopback
    ("192.168.1.10", False),    # RFC1918
    ("100.64.0.12", False),   # Tailscale CGNAT
    ("169.254.1.1", False),     # link-local
    ("not-an-ip", False),
    (None, False),
])
def test_only_routable_peers_are_ioc_candidates(ip, routable):
    assert _is_routable_peer(ip) is routable


# ---------------------------------------------------------------------------
# Only IOC peers are ever reported
# ---------------------------------------------------------------------------

def test_ordinary_traffic_yields_no_events(monitor):
    """The blast-radius guarantee: a clean host produces nothing.

    Feeding ordinary outbound HTTPS into the rules would let
    sigma_exfil_uncommon_port (protocol=tls, target_type=external, 5 in 300s)
    open an incident against OpenRouter or Cloudflare and firewall off AEGIS's
    own dependencies.
    """
    rows = monitor._parse_netstat(NETSTAT_SAMPLE)
    hits = {c["remote_ip"] for c in monitor.match_iocs(rows)}
    assert hits == {"142.11.206.73", "85.11.187.8"}
    assert "151.101.193.91" not in hits    # ordinary HTTPS
    assert "100.64.0.12" not in hits     # Tailscale peer
    assert "127.0.0.1" not in hits         # local postgres


def test_real_host_sample_produces_no_ioc_hits(monitor):
    """Run the real collector on this machine; it must find nothing."""
    connections = monitor.collect()
    if not connections:
        pytest.skip(f"no collector on this host: {monitor.get_stats()}")
    assert monitor.match_iocs(connections) == []


def test_emit_is_deduped_per_peer_and_direction(monitor):
    conn = {"remote_ip": "142.11.206.73", "remote_port": 8000, "direction": "outbound"}
    assert monitor._should_emit(conn, now=1000.0) is True
    assert monitor._should_emit(conn, now=1001.0) is False, "same peer within cooldown"
    assert monitor._should_emit(conn, now=1000.0 + monitor._cooldown_seconds + 1) is True
    # A different direction to the same peer is a different observation.
    assert monitor._should_emit(
        {**conn, "direction": "inbound"}, now=1001.0) is True


# ---------------------------------------------------------------------------
# Event shape — the part that has silently broken before
# ---------------------------------------------------------------------------

def test_build_event_puts_the_peer_in_source_ip(monitor):
    """Deliberate, and load-bearing.

    correlation_engine._on_rule_triggered drops any firing whose source_ip is
    internal, before confidence factors. The initiator of an outbound callback
    is always our own host, so naming it as source_ip makes every outbound C2
    rule unfireable. source_ip is also what the responder blocks, and for a
    confirmed callback the right thing to block is the C2, not the victim.
    """
    event = monitor.build_event({
        "remote_ip": "142.11.206.73", "remote_port": 8000, "direction": "outbound",
        "local_ip": "192.168.100.90", "local_port": 51858, "protocol": "tcp",
        "state": "ESTABLISHED", "process": "node",
    })
    assert event["event_type"] == "network_connection"
    assert event["source_ip"] == "142.11.206.73"
    assert event["destination_ip"] == "142.11.206.73"
    assert event["destination_port"] == 8000
    # The victim side is still recorded so the incident stays actionable.
    assert event["local_ip"] == "192.168.100.90"
    assert event["local_port"] == 51858
    assert event["process_name"] == "node"


def test_build_event_omits_target_type(monitor):
    """target_type is absent on purpose.

    "internal" is the semantically correct value for an inbound connection, but
    lateral_movement (event_type=connection, threshold 10, group_by source_ip,
    filter target_type=internal) would then fire on any busy external client.
    A field is only populated when this producer can state it truthfully AND the
    rules reading it mean what these events mean.
    """
    event = monitor.build_event({
        "remote_ip": "85.11.187.8", "remote_port": 44122, "direction": "inbound",
        "local_ip": "192.168.100.90", "local_port": 8000,
    })
    assert "target_type" not in event


# ---------------------------------------------------------------------------
# End to end through the real engine
# ---------------------------------------------------------------------------

IOC_CASES = [
    ("sigma_supply_axios_sfrclak_c2",    "142.11.206.73", 8000, "outbound"),
    ("sigma_supply_mastra_easyday_c2",   "23.254.164.92", 443,  "outbound"),
    ("sigma_supply_nodeipc_azure_c2",    "37.16.75.69",   443,  "outbound"),
    ("sigma_network_fortibleed_ioc",     "85.11.187.8",   8000, "inbound"),
    ("sigma_network_checkpoint_qilin_c2", "45.77.149.152", 8000, "inbound"),
    ("sigma_network_ayysshush_asus_c2",  "101.99.91.151", 2222, "inbound"),
]


@pytest.mark.parametrize("rule_id,ip,port,direction", IOC_CASES)
async def test_each_network_connection_rule_fires(rule_id, ip, port, direction):
    """Every network_connection rule must be reachable from this producer.

    Before this wiring all six loaded, validated, counted toward the rule total
    and could not receive an event.
    """
    bus = RecordingBus()
    eng = CorrelationEngine()
    eng.register_event_bus(bus)
    mon = ConnectionMonitor()
    mon.load_ioc_ips(eng._rules)

    conn = {
        "remote_ip": ip, "remote_port": port, "direction": direction,
        "protocol": "tcp", "state": "ESTABLISHED",
        "local_ip": "192.168.100.90",
        "local_port": 51999 if direction == "outbound" else port,
        "process": "node",
    }
    assert mon.match_iocs([conn]), f"{ip} is not in the derived IOC set"

    await eng._on_connection_event(mon.build_event(conn))

    fired = {a["rule_id"] for a in bus.alerts()}
    assert rule_id in fired, f"expected {rule_id}, fired: {sorted(fired) or 'nothing'}"


async def test_safelisted_peer_never_opens_an_incident():
    bus = RecordingBus()
    eng = CorrelationEngine()
    eng.register_event_bus(bus)
    await eng._on_connection_event({
        "event_type": "network_connection",
        "source_ip": "127.0.0.1",
        "destination_ip": "142.11.206.73",
        "severity": "critical",
    })
    assert bus.alerts() == []


async def test_payload_without_source_ip_is_dropped():
    bus = RecordingBus()
    eng = CorrelationEngine()
    eng.register_event_bus(bus)
    await eng._on_connection_event({"event_type": "network_connection"})
    await eng._on_connection_event("not a dict")
    assert bus.alerts() == []


async def test_internal_source_ip_cannot_open_an_incident():
    """Regression guard for the mapping in build_event.

    If someone "corrects" build_event to put the true initiator in source_ip,
    this is what happens: nothing. The engine's internal-IP drop is a
    deliberate false-positive guard and is not to be weakened; the producer
    adapts to it instead.
    """
    bus = RecordingBus()
    eng = CorrelationEngine()
    eng.register_event_bus(bus)
    await eng._on_connection_event({
        "event_type": "network_connection",
        "source_ip": "192.168.100.90",      # the real initiator of the callback
        "destination_ip": "142.11.206.73",
        "destination_port": 8000,
        "direction": "outbound",
        "severity": "critical",
    })
    assert bus.alerts() == [], (
        "an outbound rule grouped by source_ip cannot fire on an internal "
        "source — see build_event's docstring"
    )


async def test_engine_binds_the_topic_to_the_gated_handler():
    bus = RecordingBus()
    eng = CorrelationEngine()
    eng.register_event_bus(bus)
    await eng.start()
    try:
        assert _CONNECTION_TOPIC == TOPIC, (
            "producer and consumer must agree on the topic name"
        )
        assert eng._on_connection_event in bus.handlers.get(_CONNECTION_TOPIC, []), (
            "connection_monitor's topic must reach the safelist-gated handler, "
            "not the ungated _on_event"
        )
    finally:
        await eng.stop()


def test_collector_reports_why_it_is_unavailable_rather_than_failing_silently():
    """host_monitor's network section swallows AccessDenied into logger.debug.

    This collector records the reason in stats so an operator can see that it
    is enabled but blind, instead of reading an empty anomaly list as "clean".
    """
    mon = ConnectionMonitor()
    conns = mon.collect()
    stats = mon.get_stats()
    assert stats["collector"] in ("netstat", "psutil")
    if not conns:
        assert stats["unavailable_reason"], (
            "an empty sample must be explained, not silent"
        )
