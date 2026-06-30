"""
Unified log-line -> typed-event normalizer for AEGIS.

This module is the SINGLE source of truth for translating raw log lines
(PM2 stdout, journalctl entries, honeypot transcripts, EDR JSON, etc.) into
typed `NormalizedEvent` dicts that downstream consumers (correlation engine,
log watcher, AI engine) can evaluate.

Before this module existed, two parallel pattern tables lived in the codebase:

* `log_watcher.PATTERNS` -- used to raise individual incidents.
* `correlation_engine._LOG_PATTERNS` -- used to advance Sigma counters.

The two tables drifted over time (different regexes, different severities,
different naming), which produced silent detection gaps -- a pattern present
only in log_watcher would create incidents but never advance the correlation
sliding window, and vice versa. This module is the new shared definition.

Design contract (per the v1.6.x integration plan):

1. Every pattern is declared EXACTLY ONCE as a `LogPattern` dataclass.
2. `normalize(log_line, source)` is a PURE FUNCTION:
   * no database access, no event-bus publishing, no logging at WARN+;
   * no global mutable state;
   * deterministic for a given (log_line, source) pair.
3. Structural noise (PM2 dividers, ExceptionGroup headers, internal logger
   markers) returns `None` so that no counter is advanced by AEGIS's own
   diagnostic output -- this was the root cause of the v1.5 self-feedback
   loops.
4. The same HTTP 401 line is tagged differently depending on which surface
   produced it (operator dashboard vs. external API vs. honeypot SSH vs.
   real sshd). Callers decide whether to suppress dashboard 401s.

The module deliberately does NOT decide what to DO with an event. It only
classifies. Action policy (block / open incident / advance Sigma counter)
lives in the callers.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Pattern table -- ONE definition per detection signature.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogPattern:
    """A single log-line signature.

    Fields
    ------
    name
        Stable identifier used in dedup keys, metrics labels, and incident
        records. Must match across log_watcher and correlation_engine.
    regex
        Compiled pattern. Applied directly to the raw log line.
    event_type
        The typed event family the match belongs to. Sigma rules group
        events by this field (see correlation_engine.BUILT_IN_RULES).
        Examples: 'sql_injection', 'xss', 'auth_failure', 'web_request',
        'http_request', 'priv_escalation', 'server_error'.
    severity_base
        Default severity assigned to incidents created from this match.
        Callers may escalate (e.g. Tor exit recon -> high).
    threat_type
        Coarser MITRE-aligned label used in dashboards and dedup keys.
    protocol_hint
        Optional hint about the surface this signature is meant for
        ('http' / 'ssh' / 'dns' / 'edr'). When None the signature is
        protocol-agnostic and matches anywhere.
    required_signal_count
        How many independent matches of THIS pattern from the SAME source
        should be observed before the correlation engine considers it a
        real campaign. 1 = single hit suffices; 3+ = needs corroboration.
        Mirrors `count_threshold` on the corresponding Sigma rule, so the
        normalizer carries the hint forward to the engine without forcing
        a second lookup.
    port_hint
        Suggested destination port to attribute the event to when the log
        line itself does not include one (e.g. honeypot lines arriving on
        stderr). When None, the parser uses whatever port was extracted
        from the line, or leaves the field unset.
    """

    name: str
    regex: re.Pattern
    event_type: str
    severity_base: str
    threat_type: str
    protocol_hint: Optional[str] = None
    required_signal_count: int = 1
    port_hint: Optional[int] = None
    tags: tuple[str, ...] = field(default_factory=tuple)


# NOTE: keep the order roughly by specificity (IOC-based / very narrow regexes
# first, generic syntax matchers last) -- normalize() short-circuits on the
# first match, so narrower patterns must win over broader ones to preserve
# detection capability across the existing rule set.
PATTERNS: tuple[LogPattern, ...] = (
    # ----- IOC-based supply-chain / C2 patterns (very specific, very low FP).
    LogPattern(
        name="npm_supply_chain_worm",
        regex=re.compile(
            r"(0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976"
            r"|stealthProxyControl|checkethereumw|runmask|newdlocal"
            r"|updatenet\.work|npmjs\.help"
            r"|/tmp/bun_[a-zA-Z0-9]+|bun\s+setup\.mjs"
            r"|preinstall.*node\s+-e\s+eval"
            r"|postinstall.*child_process)"
        ),
        event_type="supply_chain",
        severity_base="critical",
        threat_type="supply_chain",
        tags=("ioc", "npm"),
    ),
    LogPattern(
        name="mastra_easyday_c2",
        regex=re.compile(r"23\.254\.164\.(?:92|123)"),
        event_type="c2",
        severity_base="critical",
        threat_type="supply_chain",
        tags=("ioc", "c2"),
    ),
    LogPattern(
        name="nodeipc_azure_c2",
        regex=re.compile(r"sh\.azurestaticprovider\.net|37\.16\.75\.69"),
        event_type="c2",
        severity_base="high",
        threat_type="supply_chain",
        tags=("ioc", "c2"),
    ),
    LogPattern(
        name="shai_hulud_miasma_anthropic_spoof",
        regex=re.compile(r"api\.anthropic\.com/v1/api(?:[/?\s\"]|$)"),
        event_type="supply_chain",
        severity_base="critical",
        threat_type="supply_chain",
        tags=("ioc",),
    ),
    LogPattern(
        name="solana_fakefix_telegram",
        regex=re.compile(r"api\.telegram\.org/bot[0-9A-Za-z:_-]+"),
        event_type="c2",
        severity_base="critical",
        threat_type="supply_chain",
        tags=("ioc",),
    ),
    LogPattern(
        name="fortibleed_ioc_ip",
        regex=re.compile(r"\b85\.11\.187\.8\b"),
        event_type="recon",
        severity_base="high",
        threat_type="reconnaissance",
        tags=("ioc",),
    ),
    LogPattern(
        name="shai_hulud_hades_firedalazer",
        regex=re.compile(r"github\.com/search/commits[^\s]*firedalazer"),
        event_type="supply_chain",
        severity_base="critical",
        threat_type="supply_chain",
        tags=("ioc",),
    ),
    LogPattern(
        name="checkpoint_qilin_c2",
        regex=re.compile(
            r"\b(?:45\.77\.149\.152|209\.182\.225\.136|38\.60\.157\.139)\b"
        ),
        event_type="c2",
        severity_base="critical",
        threat_type="c2",
        tags=("ioc",),
    ),
    LogPattern(
        name="ayysshush_asus_c2",
        regex=re.compile(
            r"\b(?:101\.99\.91\.151|101\.99\.94\.173|79\.141\.163\.179"
            r"|111\.90\.146\.237)\b|:53282\b"
        ),
        event_type="c2",
        severity_base="high",
        threat_type="c2",
        tags=("ioc",),
    ),
    LogPattern(
        name="axios_sfrclak_c2",
        regex=re.compile(r"sfrclak\.com|142\.11\.206\.73"),
        event_type="c2",
        severity_base="critical",
        threat_type="supply_chain",
        tags=("ioc",),
    ),
    # ----- Ransomware file-extension markers.
    LogPattern(
        name="prinz_eugen_ransomware",
        regex=re.compile(r"\.prinzeugen\b"),
        event_type="ransomware",
        severity_base="high",
        threat_type="ransomware",
    ),
    LogPattern(
        name="shinysp1d3r_ransomware",
        regex=re.compile(r"\.shinysp1d3r\b"),
        event_type="ransomware",
        severity_base="high",
        threat_type="ransomware",
    ),
    # ----- CVE-specific RCE / auth-bypass / SQLi endpoints (well-scoped).
    LogPattern(
        name="marimo_terminal_rce",
        regex=re.compile(r"/terminal/ws|/marimo/terminal"),
        event_type="http_request",
        severity_base="critical",
        threat_type="rce",
        protocol_hint="http",
        required_signal_count=2,
    ),
    LogPattern(
        name="jce_joomla_rce",
        regex=re.compile(r"option=com_jce&task=(?:profiles\.import|plugin\.rpc)"),
        event_type="http_request",
        severity_base="critical",
        threat_type="rce",
        protocol_hint="http",
    ),
    LogPattern(
        name="mirasvit_cachewarmer_deser",
        regex=re.compile(r"CacheWarmer=(?:Tz|Qz|YT)[A-Za-z0-9+/=]+"),
        event_type="http_request",
        severity_base="critical",
        threat_type="deserialization",
        protocol_hint="http",
    ),
    LogPattern(
        name="ivanti_sentry_cmdinject",
        regex=re.compile(
            r"/mics/api/v2/sentry/mics-config/handleMessage.*commandexec",
            re.IGNORECASE | re.DOTALL,
        ),
        event_type="http_request",
        severity_base="critical",
        threat_type="rce",
        protocol_hint="http",
    ),
    LogPattern(
        name="litellm_mcp_cmdinject",
        regex=re.compile(
            r"/mcp-rest/test/(?:connection|tools/list).*stdio.*\"command\"",
            re.DOTALL,
        ),
        event_type="http_request",
        severity_base="high",
        threat_type="rce",
        protocol_hint="http",
        required_signal_count=2,
    ),
    LogPattern(
        name="splunk_postgres_recovery_rce",
        regex=re.compile(r"/splunkd/__raw/v1/postgres/recovery/"),
        event_type="http_request",
        severity_base="critical",
        threat_type="rce",
        protocol_hint="http",
    ),
    LogPattern(
        name="sglang_rerank_ssti",
        regex=re.compile(r"/v1/rerank.*(?:\{\{|__import__|subprocess)", re.DOTALL),
        event_type="http_request",
        severity_base="critical",
        threat_type="rce",
        protocol_hint="http",
    ),
    LogPattern(
        name="aver_ptc_cgi_rce",
        regex=re.compile(r"cgi-bin/[^\s]+.*bash\s+-i", re.DOTALL),
        event_type="http_request",
        severity_base="critical",
        threat_type="rce",
        protocol_hint="http",
    ),
    LogPattern(
        name="panos_globalprotect_bypass",
        regex=re.compile(r"/ssl-vpn/(?:hipreport|getconfig)\.esp"),
        event_type="http_request",
        severity_base="critical",
        threat_type="auth_bypass",
        protocol_hint="http",
    ),
    LogPattern(
        name="cpanel_whm_crlf",
        regex=re.compile(r"whostmgrsession=[^\s;]*(?:\\r\\n|%0[dD]%0[aA])"),
        event_type="http_request",
        severity_base="critical",
        threat_type="header_injection",
        protocol_hint="http",
    ),
    LogPattern(
        name="drupal_jsonapi_sqli",
        regex=re.compile(
            r"/jsonapi/[^\s]*(?:UNION\s+SELECT|information_schema|pg_)",
            re.IGNORECASE,
        ),
        event_type="sql_injection",
        severity_base="critical",
        threat_type="sql_injection",
        protocol_hint="http",
    ),
    LogPattern(
        name="ghost_content_api_sqli",
        regex=re.compile(
            r"/ghost/api/[^\s]*slug:[^\s]*"
            r"(?:UNION|SELECT|information_schema|--|OR\s+1=1)",
            re.IGNORECASE,
        ),
        event_type="sql_injection",
        severity_base="critical",
        threat_type="sql_injection",
        protocol_hint="http",
    ),
    LogPattern(
        name="litellm_bearer_sqli",
        regex=re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9+/=._-]*'"),
        event_type="sql_injection",
        severity_base="critical",
        threat_type="sql_injection",
        protocol_hint="http",
        required_signal_count=2,
    ),
    LogPattern(
        name="nextjs_ws_ssrf",
        regex=re.compile(
            r'"GET\s+https?://[^\s"]+\s+HTTP/[\d.]+".*Upgrade:\s*websocket',
            re.IGNORECASE | re.DOTALL,
        ),
        event_type="http_request",
        severity_base="high",
        threat_type="ssrf",
        protocol_hint="http",
    ),
    LogPattern(
        name="schneider_saitel_traversal",
        regex=re.compile(r"saitel[^\s]*\.\./", re.IGNORECASE),
        event_type="web_request",
        severity_base="high",
        threat_type="path_traversal",
        protocol_hint="http",
    ),
    LogPattern(
        name="hf_malicious_model",
        regex=re.compile(
            r"(?i)(huggingface\.co/[^/\s]+/[^/\s]+/resolve/.*\.(pkl|pickle|bin)"
            r"|huggingface_hub.*snapshot_download.*revision=[a-f0-9]{40}"
            r"|trust_remote_code\s*=\s*True)"
        ),
        event_type="supply_chain",
        severity_base="high",
        threat_type="supply_chain",
        required_signal_count=2,
    ),
    # ----- Generic syntax matchers (broader, run last).
    LogPattern(
        name="sql_injection",
        # The bare `--\s*$` alternative was removed in v1.5.x because it matched
        # any log line ending in two or more dashes (Python traceback dividers
        # like `----------------------------------------`), producing a
        # self-amplifying false-positive loop. Real SQL comments always follow
        # a SQL keyword, so we require one before `--`.
        regex=re.compile(
            r"(?i)(union\s+select|or\s+1\s*=\s*1|;\s*select|drop\s+table"
            r"|information_schema|%27"
            r"|\b(?:SELECT|FROM|WHERE|OR|AND|UNION|ORDER|GROUP)\s+[^\n]*--\s*$"
            r"|'\s*OR\s*'|UNION\s+SELECT|OR\s+1=1)"
        ),
        event_type="sql_injection",
        severity_base="high",
        threat_type="sql_injection",
        required_signal_count=3,
    ),
    LogPattern(
        name="xss_attempt",
        regex=re.compile(
            r"(?i)(<script|alert\s*\(|onerror\s*=|onload\s*=|javascript:"
            r"|<img\s+src\s*=\s*x|<svg\s+onload|document\.cookie)"
        ),
        event_type="xss",
        severity_base="medium",
        threat_type="xss",
        required_signal_count=5,
    ),
    LogPattern(
        name="path_traversal",
        regex=re.compile(
            r"(\.\./|\.\.%2[fF]|%2[eE]%2[eE]|%252e%252e|\.\.[\\/]"
            r"|/etc/passwd|/etc/shadow|/proc/self|/windows/system32|/var/log)"
        ),
        event_type="web_request",
        severity_base="high",
        threat_type="path_traversal",
        tags=("path_traversal",),
    ),
    LogPattern(
        name="cmd_injection",
        # Mirrors correlation_engine's `priv_escalation` regex. Same signal,
        # both downstream consumers will read it.
        regex=re.compile(
            r"(?i)(;\s*cat\s+/etc|\|\s*whoami|&&\s*id\b|`id`|\$\(id\)"
            r"|;\s*ls\s|\|\s*cat\s|\bexec\s*\()"
        ),
        event_type="priv_escalation",
        severity_base="critical",
        threat_type="rce",
        required_signal_count=2,
    ),
    LogPattern(
        name="scanner_detect",
        # WARNING: this pattern has VERY HIGH false-positive risk -- it matches
        # any mention of a scanner tool name regardless of context. Callers
        # MUST require `required_signal_count` corroborating hits and SHOULD
        # suppress on dashboard / documentation surfaces. The `http_request`
        # event_type plus the `scanner` tag let downstream rules pick this up.
        regex=re.compile(
            r"(?i)(nmap|nikto|sqlmap|masscan|gobuster|dirbuster|wfuzz"
            r"|nuclei|zgrab|hydra|burpsuite|nmaplowercheck|/sdk|/evox|/HNAP1)"
        ),
        event_type="http_request",
        severity_base="low",
        threat_type="reconnaissance",
        required_signal_count=3,
        tags=("scanner",),
    ),
    LogPattern(
        name="auth_failure",
        regex=re.compile(
            r'"(?:GET|POST|PUT|DELETE)\s+\S+\s+HTTP/[\d.]+"\s+401\b'
        ),
        event_type="auth_failure",
        severity_base="medium",
        threat_type="brute_force",
        protocol_hint="http",
        required_signal_count=15,
    ),
    LogPattern(
        name="server_error",
        regex=re.compile(
            r'"(?:GET|POST|PUT|DELETE)\s+\S+\s+HTTP/[\d.]+"\s+500'
        ),
        event_type="http_request",
        severity_base="low",
        threat_type="error_spike",
        protocol_hint="http",
        required_signal_count=10,
        tags=("error_5xx",),
    ),
)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

# Matches the canonical PM2/uvicorn access-log shape:
#   INFO:     <ip>:<port> - "METHOD PATH HTTP/x.y" status ...
#   <ip>:<port> - - [date] "METHOD PATH HTTP/x.y" status size "ref" "ua"
# We capture: source_ip, source_port (optional), method, path, status (optional).
_ACCESS_LOG_RE = re.compile(
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?::(?P<sport>\d{1,5}))?"
    r"[^\"]*?"
    r"\"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+"
    r"(?P<path>\S+)\s+HTTP/[\d.]+\""
    r"(?:\s+(?P<status>\d{3}))?"
)

# Last quoted segment is conventionally the user-agent in combined log format.
_USER_AGENT_RE = re.compile(r'"([^"]+)"\s*$')

# Bare IP fallback when no access-log structure is present.
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Bare :port fallback (e.g. `connection from 1.2.3.4 to :22`).
_PORT_RE = re.compile(r":(\d{2,5})\b")

# Stand-alone HTTP status when not glued to a quoted request.
_STATUS_FALLBACK_RE = re.compile(r"\bHTTP/\d\.\d\"?\s+(\d{3})\b")


# ---------------------------------------------------------------------------
# Surface / protocol identification
# ---------------------------------------------------------------------------

# Substrings emitted by AEGIS itself. Any line carrying one of these is
# structural noise produced by our own loggers / Python tracebacks / PM2
# header banners -- it must NOT advance any detection counter, otherwise we
# get the self-feedback loop that v1.5 spent two weeks debugging.
_INTERNAL_SOURCE_MARKERS: tuple[str, ...] = (
    "aegis.scheduled_scanner",
    "aegis.scanner",
    "[aegis.",
    "[cayde6.",
    "[cayde6.log_watcher]",
    "[aegis.log_watcher]",
    "[aegis.correlation]",
    "[aegis.ai_engine]",
    "sqlalchemy.exc.",
    "ExceptionGroup:",
    "greenlet_spawn",
)

# Lines that are pure dividers or have no detection value.
_STRUCTURAL_LINE_RE = re.compile(r"^[\s\-=*_#]+$")

# How to map a `source` argument to a protocol label.
_SOURCE_PROTOCOL_MAP: tuple[tuple[str, str], ...] = (
    ("cayde6-frontend", "http_dashboard"),
    ("aegis-frontend", "http_dashboard"),
    ("frontend", "http_dashboard"),
    ("cayde6-api", "http_api"),
    ("aegis-api", "http_api"),
    ("uvicorn", "http_api"),
    ("nginx", "http_api"),
    ("apache2", "http_api"),
    ("honeypot_ssh", "ssh_honeypot"),
    ("honeypot-ssh", "ssh_honeypot"),
    ("ssh_honeypot", "ssh_honeypot"),
    ("phantom-ssh", "ssh_honeypot"),
    ("honeypot_http", "http_honeypot"),
    ("phantom-http", "http_honeypot"),
    ("sshd", "ssh_real"),
    ("auth.log", "ssh_real"),
    ("aegis-firewall", "firewall"),
    ("nodes_edr", "nodes_edr"),
    ("aegis-node", "nodes_edr"),
    ("edr", "nodes_edr"),
    ("aegis-feed", "feed"),
)


def _identify_protocol(source: str, line: str) -> str:
    """Map (source, line) to a protocol tag.

    Order:
    1. Explicit honeypot / SSH markers in the line itself (port 2222 / 22).
    2. Matching prefix in `source` argument.
    3. Presence of an HTTP request shape in the line -> http_api by default.
    4. 'unknown' fallback.
    """
    src = (source or "").lower()

    # 1. Strong line-level signals.
    if "honeypot" in src or "phantom" in src:
        if "ssh" in src or ":2222" in line:
            return "ssh_honeypot"
        if "http" in src:
            return "http_honeypot"
    if ":2222" in line and "ssh" in line.lower():
        return "ssh_honeypot"

    # 2. Source-prefix table.
    for needle, label in _SOURCE_PROTOCOL_MAP:
        if needle in src:
            return label

    # 3. HTTP shape fallback.
    if _ACCESS_LOG_RE.search(line):
        return "http_api"

    return "unknown"


# ---------------------------------------------------------------------------
# Structural-noise gate
# ---------------------------------------------------------------------------


def _is_structural(line: str) -> bool:
    """Return True for lines that must not advance any detection counter."""
    if not line or not line.strip():
        return True
    stripped = line.strip()
    if _STRUCTURAL_LINE_RE.match(stripped):
        return True
    # AEGIS internal logger output / Python traceback artifacts.
    for marker in _INTERNAL_SOURCE_MARKERS:
        if marker in line:
            return True
    # PM2 stream-header banner: e.g. `0|cayde6-api  | ...` is fine BUT
    # the row of `0|cayde6-a | --- ... ---` from PM2 separators is noise.
    if "PM2" in line and ("ready" in line or "online" in line or "stopped" in line):
        return True
    # Python ExceptionGroup / chained-exception headers.
    if stripped.startswith(("Traceback (", "+ Exception Group Traceback", "| ")):
        return True
    return False


def _is_internal_ip(ip: Optional[str]) -> bool:
    """Best-effort RFC1918 + CGNAT classifier. Used only for `is_internal_ip`
    annotation -- callers decide policy."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    try:
        if addr in ipaddress.ip_network("100.64.0.0/10"):  # Tailscale CGNAT
            return True
    except ValueError:
        pass
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize(log_line: str, source: str = "") -> Optional[dict[str, Any]]:
    """Normalize a single log line into a typed event dict.

    Parameters
    ----------
    log_line
        Raw line as read from a log source. Trailing newlines should already
        be stripped but the function tolerates whitespace.
    source
        Human-readable identifier of the producing surface. Examples:
        ``"cayde6-api"``, ``"cayde6-frontend"``, ``"honeypot_ssh"``,
        ``"sshd"``, ``"aegis-node:mac-pro"``, ``""``. Used to assign the
        ``protocol`` tag so that a 401 on the operator dashboard can be
        distinguished from a 401 on the public API.

    Returns
    -------
    dict | None
        ``None`` when the line is structural noise (PM2 dividers, AEGIS's
        own logger output, exception headers, blank lines). Otherwise a
        ``NormalizedEvent`` dict with the following keys::

            {
                "event_type": str,           # 'auth_failure', 'sql_injection', ...
                "source_ip": str | None,
                "source_port": int | None,
                "target_port": int | None,
                "protocol": str,              # 'http_api' | 'http_dashboard'
                                              # | 'ssh_honeypot' | 'ssh_real'
                                              # | 'nodes_edr' | 'unknown' | ...
                "request_path": str | None,
                "request_method": str | None,
                "response_status": int | None,
                "user_agent": str | None,
                "severity_base": str,         # 'low' | 'medium' | 'high' | 'critical'
                "threat_type": str,
                "pattern_name": str | None,   # None when no pattern matched
                "required_signal_count": int,
                "is_internal_ip": bool,
                "tags": list[str],
                "raw": str,                   # truncated original line
                "source": str,
            }

        When NO pattern matched but the line was still parseable as an HTTP
        access-log entry (e.g. a plain 200 OK), the dict is still returned
        with ``event_type='http_request'`` and ``pattern_name=None`` so that
        the correlation engine can still count it for rate-based rules.

    Notes
    -----
    This function is PURE -- no DB calls, no event-bus publishing, no side
    effects. Callers decide what to do with the event.
    """
    if log_line is None:
        return None
    line = log_line.rstrip("\r\n")
    if _is_structural(line):
        return None

    protocol = _identify_protocol(source, line)

    # ----- Parse the access-log envelope if present.
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    target_port: Optional[int] = None

    access_match = _ACCESS_LOG_RE.search(line)
    if access_match:
        source_ip = access_match.group("ip")
        sport = access_match.group("sport")
        if sport:
            try:
                source_port = int(sport)
            except ValueError:
                source_port = None
        method = access_match.group("method")
        path = access_match.group("path")
        status_raw = access_match.group("status")
        if status_raw:
            try:
                status = int(status_raw)
            except ValueError:
                status = None

    # Fallbacks for non-access-log lines.
    if source_ip is None:
        ip_match = _IP_RE.search(line)
        if ip_match:
            source_ip = ip_match.group(1)

    if status is None:
        sfb = _STATUS_FALLBACK_RE.search(line)
        if sfb:
            try:
                status = int(sfb.group(1))
            except ValueError:
                status = None

    # target_port heuristics: prefer the protocol convention, fall back to a
    # bare :port if the line carries one that is NOT the source_port.
    if protocol == "ssh_honeypot":
        target_port = 2222
    elif protocol == "ssh_real":
        target_port = 22
    elif protocol == "http_honeypot":
        target_port = 8888
    elif protocol in ("http_api", "http_dashboard"):
        # Default to the public AEGIS port; callers may override.
        target_port = 8000 if protocol == "http_api" else 3007

    if target_port is None:
        for port_match in _PORT_RE.finditer(line):
            try:
                cand = int(port_match.group(1))
            except ValueError:
                continue
            if cand == source_port:
                continue
            if 1 <= cand <= 65535:
                target_port = cand
                break

    # User-agent: last quoted segment.
    ua_match = _USER_AGENT_RE.search(line)
    user_agent = ua_match.group(1) if ua_match else None

    # ----- Pattern matching -- first hit wins (table ordered by specificity).
    matched: Optional[LogPattern] = None
    for pattern in PATTERNS:
        if pattern.regex.search(line):
            matched = pattern
            break

    # ----- Refine event classification when the pattern alone is ambiguous.
    if matched is None:
        # No security pattern matched, but the line is still a parseable
        # HTTP request -- emit a generic http_request event so that rate /
        # enumeration rules can count it. If not even that, drop the line.
        if access_match is None:
            return None
        event_type = "http_request"
        severity_base = "low"
        threat_type = "http_traffic"
        pattern_name = None
        required = 1
        tags: list[str] = []
        # Promote 4xx/5xx into more specific event types so Sigma rules
        # don't need to re-parse the status code.
        if status == 401:
            event_type = "auth_failure"
            severity_base = "medium"
            threat_type = "brute_force"
            required = 15
        elif status == 500:
            event_type = "http_request"
            severity_base = "low"
            threat_type = "error_spike"
            required = 10
            tags.append("error_5xx")
    else:
        event_type = matched.event_type
        severity_base = matched.severity_base
        threat_type = matched.threat_type
        pattern_name = matched.name
        required = matched.required_signal_count
        tags = list(matched.tags)

    # Protocol-aware refinement for auth_failure: a 401 on the operator
    # dashboard is almost always a typo, while a 401 on the public API may
    # be a real brute force. Encode that distinction as a tag so consumers
    # can apply suppression cheaply.
    if event_type == "auth_failure":
        if protocol == "http_dashboard":
            tags.append("dashboard_401")
        elif protocol == "ssh_honeypot":
            tags.append("honeypot_401")
        elif protocol == "ssh_real":
            tags.append("sshd_auth_fail")
        elif protocol == "http_api":
            tags.append("api_401")
        else:
            tags.append("unknown_surface_401")

    return {
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": source_port,
        "target_port": target_port,
        "protocol": protocol,
        "request_path": path,
        "request_method": method,
        "response_status": status,
        "user_agent": user_agent,
        "severity_base": severity_base,
        "threat_type": threat_type,
        "pattern_name": pattern_name,
        "required_signal_count": required,
        "is_internal_ip": _is_internal_ip(source_ip),
        "tags": tags,
        "raw": line[:1000],
        "source": source or "",
    }


# ---------------------------------------------------------------------------
# Convenience accessors -- consumed by log_watcher / correlation_engine to
# avoid duplicating the pattern table at import sites.
# ---------------------------------------------------------------------------


def pattern_by_name(name: str) -> Optional[LogPattern]:
    """Return the LogPattern whose ``.name`` equals ``name``, or None."""
    for pattern in PATTERNS:
        if pattern.name == name:
            return pattern
    return None


def pattern_names() -> tuple[str, ...]:
    """Stable tuple of all pattern names, in declaration order."""
    return tuple(p.name for p in PATTERNS)


__all__ = (
    "LogPattern",
    "PATTERNS",
    "normalize",
    "pattern_by_name",
    "pattern_names",
)
