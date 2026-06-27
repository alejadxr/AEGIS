"""
Attack chain detector — Sigma-lite rules over process ancestry + command-line regex.

Rules watch for known LOTL (Living-Off-The-Land) sequences in the ancestry
chain of any newly seen process. When a chain matches, we create a high or
critical Incident.

Windows rules:
  macro_malware, phishing_payload, creddump, lotl_download,
  office_child_shell, rundll32_abuse

macOS/Linux rules (cmd_pattern regex):
  reverse_shell, ssh_key_theft, cron_persistence, curl_download_exec,
  python_reverse_shell, sudo_escalation, passwd_modification,
  history_clearing, process_injection, data_exfil_curl,
  container_escape, miner_detection, port_forwarding, dns_exfil,
  defense_evasion
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.endpoint_agent import EndpointAgent
from app.services.correlation_engine import _is_internal_ip

logger = logging.getLogger("aegis.edr.chains")


@dataclass
class ChainMatch:
    rule_id: str
    title: str
    mitre_technique: str
    mitre_tactic: str
    severity: str
    description: str
    anchor_pid: int
    ancestry: list[str] = field(default_factory=list)


def _name(n: Optional[str]) -> str:
    return (n or "").lower().replace("\\", "/").split("/")[-1]


def _chain_names(ancestors: list[dict], anchor: dict) -> list[str]:
    # Root-most first
    names = [_name(a.get("name") or a.get("process_name")) for a in reversed(ancestors)]
    names.append(_name(anchor.get("name") or anchor.get("process_name")))
    return names


def _contains_sequence(chain: list[str], seq: list[str]) -> bool:
    """True if `seq` appears as an ordered (not necessarily contiguous) subsequence of `chain`."""
    i = 0
    for c in chain:
        if i < len(seq) and c == seq[i]:
            i += 1
    return i == len(seq)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: list[Callable[[dict, dict, list[dict]], Optional[ChainMatch]]] = []


def rule(fn):
    RULES.append(fn)
    return fn


@rule
def macro_malware(anchor: dict, _event: dict, ancestors: list[dict]) -> Optional[ChainMatch]:
    chain = _chain_names(ancestors, anchor)
    if _contains_sequence(chain, ["winword.exe", "cmd.exe", "powershell.exe"]):
        return ChainMatch(
            rule_id="macro_malware",
            title="Office macro -> cmd -> powershell (macro malware chain)",
            mitre_technique="T1059.001",
            mitre_tactic="execution",
            severity="critical",
            description="Word spawned cmd which spawned PowerShell — classic macro-malware pattern.",
            anchor_pid=int(anchor.get("pid") or 0),
            ancestry=chain,
        )
    return None


@rule
def phishing_payload(anchor: dict, event: dict, ancestors: list[dict]) -> Optional[ChainMatch]:
    chain = _chain_names(ancestors, anchor)
    if _contains_sequence(chain, ["outlook.exe", "wscript.exe"]):
        # Bonus signal: anchor dropped a network event shortly after
        return ChainMatch(
            rule_id="phishing_payload",
            title="Outlook -> wscript (phishing payload execution)",
            mitre_technique="T1566.001",
            mitre_tactic="initial_access",
            severity="high",
            description="Outlook launched WSH — phishing payload indicator.",
            anchor_pid=int(anchor.get("pid") or 0),
            ancestry=chain,
        )
    return None


@rule
def creddump(anchor: dict, event: dict, ancestors: list[dict]) -> Optional[ChainMatch]:
    # Detects a non-protected process opening lsass.exe (reported as target)
    target = (event.get("target") or "").lower()
    if "lsass.exe" in target:
        chain = _chain_names(ancestors, anchor)
        return ChainMatch(
            rule_id="creddump",
            title=f"Possible credential dump: {anchor.get('name')} accessed lsass.exe",
            mitre_technique="T1003.001",
            mitre_tactic="credential_access",
            severity="critical",
            description="A non-protected process touched lsass.exe — possible credential dumping.",
            anchor_pid=int(anchor.get("pid") or 0),
            ancestry=chain,
        )
    return None


@rule
def lotl_download(anchor: dict, _event: dict, ancestors: list[dict]) -> Optional[ChainMatch]:
    name = _name(anchor.get("name") or anchor.get("process_name"))
    cmd = (anchor.get("command_line") or "").lower()
    if name == "certutil.exe" and ("-urlcache" in cmd or "urlcache" in cmd or "-split" in cmd):
        chain = _chain_names(ancestors, anchor)
        return ChainMatch(
            rule_id="lotl_download",
            title="certutil.exe -urlcache (LOTL file download)",
            mitre_technique="T1105",
            mitre_tactic="command_and_control",
            severity="high",
            description="certutil invoked with -urlcache — remote file download via trusted binary.",
            anchor_pid=int(anchor.get("pid") or 0),
            ancestry=chain,
        )
    return None


@rule
def office_child_shell(anchor: dict, _event: dict, ancestors: list[dict]) -> Optional[ChainMatch]:
    name = _name(anchor.get("name") or anchor.get("process_name"))
    if name not in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
        return None
    if not ancestors:
        return None
    parent = _name(ancestors[0].get("name") or ancestors[0].get("process_name"))
    if parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"):
        chain = _chain_names(ancestors, anchor)
        return ChainMatch(
            rule_id="office_child_shell",
            title=f"{parent} spawned {name}",
            mitre_technique="T1204.002",
            mitre_tactic="execution",
            severity="high",
            description="Office app spawned a shell interpreter — likely malicious document.",
            anchor_pid=int(anchor.get("pid") or 0),
            ancestry=chain,
        )
    return None


@rule
def rundll32_abuse(anchor: dict, _event: dict, ancestors: list[dict]) -> Optional[ChainMatch]:
    name = _name(anchor.get("name") or anchor.get("process_name"))
    cmd = (anchor.get("command_line") or "").lower()
    if name == "rundll32.exe" and ("http://" in cmd or "https://" in cmd):
        chain = _chain_names(ancestors, anchor)
        return ChainMatch(
            rule_id="rundll32_abuse",
            title="rundll32.exe with remote URL",
            mitre_technique="T1218.011",
            mitre_tactic="defense_evasion",
            severity="high",
            description="rundll32 invoked with a remote URL — signed binary proxy execution.",
            anchor_pid=int(anchor.get("pid") or 0),
            ancestry=chain,
        )
    return None


# ---------------------------------------------------------------------------
# Command-line regex rules (macOS / Linux)
# ---------------------------------------------------------------------------

@dataclass
class CmdPatternRule:
    """A rule that matches directly on the command_line field via regex."""
    rule_id: str
    title: str
    cmd_pattern: re.Pattern
    mitre_technique: str
    mitre_tactic: str
    severity: str
    description: str


CMD_PATTERN_RULES: list[CmdPatternRule] = [
    CmdPatternRule(
        rule_id="reverse_shell",
        title="Reverse shell detected",
        cmd_pattern=re.compile(
            r"(bash\s+-i\s+.*(/dev/tcp|/dev/udp))"
            r"|(nc\s+.*-e\s+(/bin/(ba)?sh|/bin/zsh))"
            r"|(ncat\s+.*-e\s+)"
            r"|(socat\s+.*exec:)",
            re.IGNORECASE,
        ),
        mitre_technique="T1059.004",
        mitre_tactic="execution",
        severity="critical",
        description="Reverse shell pattern detected in command line (bash -i /dev/tcp or nc -e /bin/sh).",
    ),
    CmdPatternRule(
        rule_id="ssh_key_theft",
        title="SSH key access detected",
        cmd_pattern=re.compile(
            r"(cat|less|more|head|tail|cp|scp)\s+.*\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)",
            re.IGNORECASE,
        ),
        mitre_technique="T1552.004",
        mitre_tactic="credential_access",
        severity="high",
        description="Possible SSH private key theft — sensitive key file being read or copied.",
    ),
    CmdPatternRule(
        rule_id="cron_persistence",
        title="Cron persistence attempt",
        cmd_pattern=re.compile(
            r"(crontab\s+-(e|l|r))"
            r"|((echo|printf)\s+.*>>?\s*/etc/cron)"
            r"|((echo|printf)\s+.*>>?\s*/var/spool/cron)",
            re.IGNORECASE,
        ),
        mitre_technique="T1053.003",
        mitre_tactic="persistence",
        severity="high",
        description="Crontab modification detected — potential persistence mechanism.",
    ),
    CmdPatternRule(
        rule_id="curl_download_exec",
        title="Curl download-and-execute",
        cmd_pattern=re.compile(
            r"curl\s+.*\|\s*(ba)?sh"
            r"|wget\s+.*\|\s*(ba)?sh"
            r"|curl\s+.*-o\s+/tmp/.*&&.*chmod"
            r"|wget\s+.*-O\s+/tmp/.*&&.*chmod",
            re.IGNORECASE,
        ),
        mitre_technique="T1105",
        mitre_tactic="command_and_control",
        severity="critical",
        description="Download-and-execute pattern (curl/wget piped to shell or dropped to /tmp).",
    ),
    CmdPatternRule(
        rule_id="python_reverse_shell",
        title="Python reverse shell",
        cmd_pattern=re.compile(
            r"python[23]?\s+.*import\s+socket.*connect"
            r"|python[23]?\s+-c\s+.*socket"
            r"|python[23]?\s+-c\s+.*pty\.spawn",
            re.IGNORECASE,
        ),
        mitre_technique="T1059.006",
        mitre_tactic="execution",
        severity="critical",
        description="Python-based reverse shell detected (socket connect or pty.spawn).",
    ),
    CmdPatternRule(
        rule_id="sudo_escalation",
        title="Sudo privilege escalation",
        cmd_pattern=re.compile(
            r"sudo\s+(su|bash|sh|zsh)\b"
            r"|sudo\s+-i\b"
            r"|sudo\s+/bin/(ba)?sh",
            re.IGNORECASE,
        ),
        mitre_technique="T1548.003",
        mitre_tactic="privilege_escalation",
        severity="medium",
        description="Privilege escalation via sudo to root shell.",
    ),
    CmdPatternRule(
        rule_id="passwd_modification",
        title="Password file modification",
        cmd_pattern=re.compile(
            r"(echo|printf)\s+.*>>?\s*/etc/(passwd|shadow)"
            r"|useradd\s+"
            r"|usermod\s+.*-aG\s+(sudo|wheel|admin)",
            re.IGNORECASE,
        ),
        mitre_technique="T1136.001",
        mitre_tactic="persistence",
        severity="high",
        description="Modification of /etc/passwd or /etc/shadow, or user added to privileged group.",
    ),
    CmdPatternRule(
        rule_id="history_clearing",
        title="Command history clearing",
        cmd_pattern=re.compile(
            r"history\s+-c"
            r"|unset\s+HISTFILE"
            r"|export\s+HISTFILESIZE=0"
            r"|export\s+HISTSIZE=0"
            r"|rm\s+.*\.(bash_history|zsh_history)"
            r"|truncate\s+.*history",
            re.IGNORECASE,
        ),
        mitre_technique="T1070.003",
        mitre_tactic="defense_evasion",
        severity="high",
        description="Shell history being cleared — indicator of anti-forensics activity.",
    ),
    CmdPatternRule(
        rule_id="process_injection",
        title="Process injection attempt",
        cmd_pattern=re.compile(
            r"gdb\s+.*attach\s+\d+"
            r"|ptrace\b"
            r"|strace\s+-p\s+\d+"
            r"|gdb\s+-p\s+\d+",
            re.IGNORECASE,
        ),
        mitre_technique="T1055",
        mitre_tactic="defense_evasion",
        severity="high",
        description="Process injection via debugger attach (gdb/ptrace/strace).",
    ),
    CmdPatternRule(
        rule_id="data_exfil_curl",
        title="Data exfiltration via curl",
        cmd_pattern=re.compile(
            r"curl\s+.*(-d\s+@|-F\s+file=@|--data-binary\s+@|--upload-file)"
            r"|curl\s+.*POST\s+.*-d\s+@",
            re.IGNORECASE,
        ),
        mitre_technique="T1041",
        mitre_tactic="exfiltration",
        severity="high",
        description="Data exfiltration pattern — curl uploading local file to external server.",
    ),
    CmdPatternRule(
        rule_id="container_escape",
        title="Container escape attempt",
        cmd_pattern=re.compile(
            r"nsenter\s+.*-t\s+1"
            r"|chroot\s+/host"
            r"|docker\s+run\s+.*--privileged"
            r"|mount\s+.*cgroup",
            re.IGNORECASE,
        ),
        mitre_technique="T1611",
        mitre_tactic="privilege_escalation",
        severity="critical",
        description="Container escape technique detected (nsenter to PID 1, chroot /host, privileged docker run).",
    ),
    CmdPatternRule(
        rule_id="miner_detection",
        title="Cryptocurrency miner detected",
        cmd_pattern=re.compile(
            r"\b(xmrig|minerd|cgminer|bfgminer|cpuminer|cryptonight)\b"
            r"|stratum\+tcp://"
            r"|--donate-level",
            re.IGNORECASE,
        ),
        mitre_technique="T1496",
        mitre_tactic="impact",
        severity="critical",
        description="Cryptocurrency mining software or stratum protocol connection detected.",
    ),
    CmdPatternRule(
        rule_id="port_forwarding",
        title="SSH port forwarding / tunneling",
        cmd_pattern=re.compile(
            r"ssh\s+.*-[LRD]\s+"
            r"|ssh\s+.*-o\s+.*Tunnel"
            r"|socat\s+.*TCP-LISTEN.*TCP:",
            re.IGNORECASE,
        ),
        mitre_technique="T1572",
        mitre_tactic="command_and_control",
        severity="medium",
        description="SSH port forwarding or tunneling detected (-L/-R/-D flags).",
    ),
    CmdPatternRule(
        rule_id="dns_exfil",
        title="DNS-based data exfiltration",
        cmd_pattern=re.compile(
            r"dig\s+.*TXT\s+"
            r"|nslookup\s+.*-type=TXT"
            r"|host\s+-t\s+TXT"
            r"|dig\s+\+short\s+.*\.",
            re.IGNORECASE,
        ),
        mitre_technique="T1048.003",
        mitre_tactic="exfiltration",
        severity="high",
        description="DNS TXT query pattern consistent with DNS tunneling / data exfiltration.",
    ),
    CmdPatternRule(
        rule_id="defense_evasion",
        title="Security tool tampering",
        cmd_pattern=re.compile(
            r"(pkill|kill|killall)\s+.*(aegis|syslog|auditd|rsyslog|ossec|wazuh|falcon|clamd)"
            r"|systemctl\s+stop\s+(auditd|rsyslog|syslog|firewalld|ufw)"
            r"|service\s+(auditd|rsyslog|syslog)\s+stop",
            re.IGNORECASE,
        ),
        mitre_technique="T1562.001",
        mitre_tactic="defense_evasion",
        severity="critical",
        description="Attempt to kill or stop security monitoring software (AEGIS, auditd, syslog, etc.).",
    ),
]


# ---------------------------------------------------------------------------
# Evaluation entry point
# ---------------------------------------------------------------------------

async def evaluate_event(
    db: AsyncSession,
    agent: EndpointAgent,
    event: dict,
    ancestry_fetcher,
) -> list[ChainMatch]:
    """
    Run all chain rules against a single incoming EDR event. `ancestry_fetcher`
    is an async callable that returns the ancestor list for a given pid.

    Also runs cmd_pattern regex rules against the command_line field for
    immediate detection without needing a process ancestry chain.

    Creates Incident rows for each match.
    """
    anchor = {
        "pid": event.get("pid"),
        "name": event.get("process_name"),
        "path": event.get("process_path"),
        "command_line": event.get("command_line"),
    }
    if anchor["pid"] is None:
        return []

    ancestors = await ancestry_fetcher(int(anchor["pid"]))

    matches: list[ChainMatch] = []

    # --- Ancestry-based chain rules ---
    for r in RULES:
        try:
            m = r(anchor, event, ancestors)
        except Exception as e:  # pragma: no cover
            logger.debug("rule %s failed: %s", r.__name__, e)
            continue
        if m:
            matches.append(m)

    # --- Command-line regex rules ---
    cmd = anchor.get("command_line") or ""
    if cmd:
        for cpr in CMD_PATTERN_RULES:
            try:
                if cpr.cmd_pattern.search(cmd):
                    chain = _chain_names(ancestors, anchor)
                    matches.append(ChainMatch(
                        rule_id=cpr.rule_id,
                        title=cpr.title,
                        mitre_technique=cpr.mitre_technique,
                        mitre_tactic=cpr.mitre_tactic,
                        severity=cpr.severity,
                        description=cpr.description + f"\n\nMatched command: {cmd[:200]}",
                        anchor_pid=int(anchor.get("pid") or 0),
                        ancestry=chain,
                    ))
            except Exception as e:
                logger.debug("cmd_pattern rule %s failed: %s", cpr.rule_id, e)

    # --- Create incidents for all matches ---
    # Skip incident creation if the agent's source_ip is internal/Tailscale
    # — we still return the matches so the caller can log them, but we don't
    # persist false-positive incidents for localhost activity.
    source_ip = agent.ip_address
    if source_ip and _is_internal_ip(source_ip):
        logger.debug(f"Skipping chain incident from internal IP {source_ip}")
        return matches

    for m in matches:
        incident = Incident(
            client_id=agent.client_id,
            title=m.title,
            description=m.description
            + f"\n\nChain: {' -> '.join(m.ancestry)}",
            severity=m.severity,
            status="open",
            source=f"edr-chain:{m.rule_id}",
            mitre_technique=m.mitre_technique,
            mitre_tactic=m.mitre_tactic,
            source_ip=agent.ip_address,
            ai_analysis={"rule_id": m.rule_id, "chain": m.ancestry},
            raw_alert={"anchor": anchor, "event": event},
            detected_at=datetime.utcnow(),
        )
        db.add(incident)

    return matches
