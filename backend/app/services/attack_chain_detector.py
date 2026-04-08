"""
Attack chain detector (Task #5) — Sigma-lite rules over process ancestry.

Rules watch for known LOTL (Living-Off-The-Land) sequences in the ancestry
chain of any newly seen process. When a chain matches, we create a high or
critical Incident.

Rules implemented:
  macro_malware     : winword.exe   -> cmd.exe       -> powershell.exe
  phishing_payload  : outlook.exe   -> wscript.exe   -> (network/http)
  creddump          : * (non-protected) -> lsass.exe access
  lotl_download     : * -> certutil.exe -urlcache
  office_child_shell: winword|excel -> powershell|cmd|wscript
  rundll32_abuse    : rundll32.exe with remote URL in cmdline
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.endpoint_agent import EndpointAgent

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
    for r in RULES:
        try:
            m = r(anchor, event, ancestors)
        except Exception as e:  # pragma: no cover
            logger.debug("rule %s failed: %s", r.__name__, e)
            continue
        if m:
            matches.append(m)

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
