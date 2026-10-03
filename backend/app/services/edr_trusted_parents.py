"""Operator-declared trusted parent processes for endpoint process events.

Management tooling (a fleet agent, a deployment runner) legitimately launches
PowerShell with -EncodedCommand, which sigma_c2_encoded_powershell rightly
flags. `AEGIS_EDR_TRUSTED_PARENTS` lets an operator say "a process whose PARENT
is exactly this executable is not evaluated by the process-creation rules".

The exclusion is deliberately narrow:
  * comma-separated FULL Windows executable paths, compared case-insensitively
    and EXACTLY -- never by file name, never by prefix or wildcard;
  * empty by default;
  * shells and system binaries that an attacker can trivially be or spawn from
    (see FORBIDDEN_NAMES) are rejected at load, with a warning;
  * paths outside C:\\Program Files / C:\\Program Files (x86) are honoured but
    warned about, because a user-writable directory lets anyone plant the
    trusted binary.
An event whose parent path cannot be resolved is never excluded.

Trust follows ANCESTRY, not only the direct parent: a process whose chain of
parents (at most MAX_DEPTH hops, all within one agent) reaches a trusted
executable is trusted too, because a fleet agent launches `cmd /c`, which
launches `powershell`. Every hop must be resolved; the first unknown link ends
the walk with "not trusted".

Trusted processes are not invisible. They skip every rule EXCEPT the protected
ones (`is_protected_rule`: ransomware, credential dumping, canaries), and the
decision is recorded on the event as `trusted_by` / `trust_reason`.

`AEGIS_EDR_TRUSTED_INSTALLERS` + `AEGIS_EDR_PROVISIONING_GRACE_MIN` add a short,
explicit provisioning window: for the first N minutes after a node enrolled, a
process launched as `<interpreter> [switches] <installer script>` and all its
descendants are treated like children of a trusted parent. Off (0) by default.
"""
from __future__ import annotations

import logging
import ntpath
import os
import re
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("aegis.edr")

ENV_VAR = "AEGIS_EDR_TRUSTED_PARENTS"

FORBIDDEN_NAMES = frozenset({
    "sshd.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "explorer.exe", "services.exe", "svchost.exe",
})

_PROTECTED_PREFIXES = ("c:\\program files\\", "c:\\program files (x86)\\")
_ABS_WIN = re.compile(r"^[a-z]:\\")


def normalize_path(path) -> str:
    """Canonical comparison form: lower-case, backslashes, no quotes, no `..`."""
    if not isinstance(path, str):
        return ""
    p = path.strip().strip('"').strip("'").strip().replace("/", "\\").lower()
    return ntpath.normpath(p) if p else ""


def parse_trusted_parents(raw: Optional[str]) -> frozenset[str]:
    """Validate the env value; log and drop every entry that is not acceptable."""
    accepted: set[str] = set()
    for entry in (raw or "").split(","):
        if not entry.strip():
            continue
        if ".." in entry.replace("/", "\\").split("\\"):
            logger.warning("%s: rejected %r (contains '..')", ENV_VAR, entry.strip())
            continue
        norm = normalize_path(entry)
        if not _ABS_WIN.match(norm):
            logger.warning("%s: rejected %r (not a full Windows path)", ENV_VAR, entry.strip())
            continue
        name = ntpath.basename(norm)
        if name in FORBIDDEN_NAMES:
            logger.warning(
                "%s: rejected %r (%s must never be a trusted parent)",
                ENV_VAR, entry.strip(), name,
            )
            continue
        if not norm.startswith(_PROTECTED_PREFIXES):
            logger.warning(
                "%s: %r is not under C:\\Program Files or C:\\Program Files (x86); "
                "a user-writable location lets anyone plant the trusted binary",
                ENV_VAR, entry.strip(),
            )
        accepted.add(norm)
    return frozenset(accepted)


_cache: tuple[Optional[str], frozenset[str]] = (None, frozenset())


def _read_raw() -> str:
    """pydantic `settings` FIRST (values in backend/.env never reach os.environ),
    then os.environ for values exported by the process manager."""
    raw = ""
    try:
        from app.config import settings as _settings
        raw = str(getattr(_settings, ENV_VAR, "") or "")
    except Exception:  # pragma: no cover - defensive
        raw = ""
    return raw or os.environ.get(ENV_VAR, "")


def get_trusted_parents() -> frozenset[str]:
    """Parsed AEGIS_EDR_TRUSTED_PARENTS, re-parsed (and re-logged) only on change."""
    global _cache
    raw = _read_raw()
    if _cache[0] != raw:
        _cache = (raw, parse_trusted_parents(raw))
    return _cache[1]


def is_trusted_parent(parent_path) -> bool:
    """True only when `parent_path` exactly equals a configured trusted path."""
    trusted = get_trusted_parents()
    if not trusted or not parent_path:
        return False
    return normalize_path(parent_path) in trusted


INSTALLERS_ENV = "AEGIS_EDR_TRUSTED_INSTALLERS"
GRACE_ENV = "AEGIS_EDR_PROVISIONING_GRACE_MIN"

MAX_DEPTH = 6
# The agent can start reporting a little before the node row is created.
_WINDOW_LEAD = timedelta(minutes=2)
_MAX_GRACE_MIN = 120


def parse_trusted_installers(raw: Optional[str]) -> frozenset[str]:
    """Full paths of installer scripts / executables, same rules as parents."""
    accepted: set[str] = set()
    for entry in (raw or "").split(","):
        if not entry.strip():
            continue
        norm = normalize_path(entry)
        if ".." in entry.replace("/", "\\").split("\\") or not _ABS_WIN.match(norm):
            logger.warning("%s: rejected %r (not a clean full Windows path)", INSTALLERS_ENV, entry.strip())
            continue
        if ntpath.basename(norm) in FORBIDDEN_NAMES:
            logger.warning("%s: rejected %r (a shell or system binary)", INSTALLERS_ENV, entry.strip())
            continue
        accepted.add(norm)
    return frozenset(accepted)


def _read_setting(name: str) -> str:
    raw = ""
    try:
        from app.config import settings as _settings
        raw = str(getattr(_settings, name, "") or "")
    except Exception:  # pragma: no cover - defensive
        raw = ""
    return raw or os.environ.get(name, "")


_installer_cache: tuple[Optional[str], frozenset[str]] = (None, frozenset())


def get_trusted_installers() -> frozenset[str]:
    global _installer_cache
    raw = _read_setting(INSTALLERS_ENV)
    if _installer_cache[0] != raw:
        _installer_cache = (raw, parse_trusted_installers(raw))
    return _installer_cache[1]


def provisioning_grace_minutes() -> int:
    """AEGIS_EDR_PROVISIONING_GRACE_MIN, 0 (off) when unset or invalid."""
    try:
        minutes = int(_read_setting(GRACE_ENV).strip() or 0)
    except ValueError:
        return 0
    return max(0, min(minutes, _MAX_GRACE_MIN))


def trust_configured() -> bool:
    return bool(get_trusted_parents() or (get_trusted_installers() and provisioning_grace_minutes()))


def in_provisioning_window(enrolled_at: Optional[datetime], when: Optional[datetime]) -> bool:
    """True when `when` falls in the first AEGIS_EDR_PROVISIONING_GRACE_MIN
    minutes after `enrolled_at`. Off when the grace is 0 or either time is unknown."""
    grace = provisioning_grace_minutes()
    if not grace or enrolled_at is None or when is None:
        return False
    if enrolled_at.tzinfo is not None:
        enrolled_at = enrolled_at.replace(tzinfo=None)
    if when.tzinfo is not None:
        when = when.replace(tzinfo=None)
    return enrolled_at - _WINDOW_LEAD <= when <= enrolled_at + timedelta(minutes=grace)


# Rules that must keep firing for a trusted process: a compromised or abused
# management agent is exactly when they matter.
_PROTECTED_RULE_ID = re.compile(
    r"ransom|canary|lsass|mimikatz|cred(ential)?_?dump|sam_?dump|ntds|shadow_?cop|"
    r"(^|_)vss(_|$)|wbadmin|bcdedit"
)
_PROTECTED_MITRE = ("T1486", "T1490", "T1003")


def is_protected_rule(rule: dict) -> bool:
    if _PROTECTED_RULE_ID.search(str(rule.get("id", "")).lower()):
        return True
    mitre = rule.get("mitre") or []
    if isinstance(mitre, str):
        mitre = [mitre]
    return any(str(t).upper().startswith(_PROTECTED_MITRE) for t in mitre)


@dataclass(frozen=True)
class Trust:
    by: str       # normalized trusted path (parent exe or installer script)
    reason: str   # "parent" | "ancestor" | "installer"


def installer_in_cmdline(cmdline, installer: str) -> bool:
    """`<interpreter> [switches] <installer> [args]` and no command chaining.

    Anchoring the script right after the switches means `cmd /c echo <installer>`
    or a path merely mentioned later in a command line does not qualify. The
    interpreter is the first token, so one installed under a path with spaces
    is not recognised (the safe direction)."""
    if not isinstance(cmdline, str) or not cmdline:
        return False
    cl = cmdline.lower().replace('"', " ").strip()
    if re.search(r"[&|;<>^]", cl):
        return False
    pattern = (
        r"^\S+\s+(?:[/-]\S+\s+(?:(?:bypass|unrestricted|remotesigned)\s+)?)*"
        + re.escape(installer) + r"(?:\s|$)"
    )
    return bool(re.search(pattern, cl))


class TrustResolver:
    """Per-agent process index that propagates trust down the process tree.

    Entries are (path, ppid, root, kind, depth). `root` is the trusted path the
    process descends from, `depth` the number of hops below it. Bounded; a
    parent never seen (evicted, started before the agent) is unknown and the
    walk ends there, unless the event itself carries `parent_path`, which is
    consulted only when the server has no record of that parent."""

    def __init__(self, max_entries: int = 20000) -> None:
        self._max = max_entries
        self._procs: "OrderedDict[tuple, tuple]" = OrderedDict()
        self._misses: "OrderedDict[tuple, None]" = OrderedDict()

    def _put(self, key, value) -> None:
        self._procs[key] = value
        self._procs.move_to_end(key)
        while len(self._procs) > self._max:
            self._procs.popitem(last=False)

    def forget(self, agent_id, pid) -> None:
        self._procs.pop((agent_id, str(pid)), None)

    def knows(self, agent_id, pid) -> bool:
        return (agent_id, str(pid)) in self._procs

    def known_miss(self, agent_id, pid) -> bool:
        return (agent_id, str(pid)) in self._misses

    def note_miss(self, agent_id, pid) -> None:
        self._misses[(agent_id, str(pid))] = None
        while len(self._misses) > 2048:
            self._misses.popitem(last=False)

    def seed(self, agent_id, pid, path, ppid=None) -> None:
        """Record a process learned from storage rather than from the live stream."""
        if agent_id is None or pid in (None, ""):
            return
        self._observe_entry(agent_id, pid, ppid, path, None, None, False)

    def parent_path(self, agent_id, ppid) -> Optional[str]:
        entry = self._procs.get((agent_id, str(ppid))) if ppid not in (None, "") else None
        return entry[0] if entry and entry[0] else None

    def observe(self, agent_id, pid, ppid, path, cmdline=None, *, parent_path=None,
                provisioning: bool = False) -> Optional[Trust]:
        """Record a process start; return why it is trusted, or None."""
        if agent_id is None or pid in (None, ""):
            return None
        return self._observe_entry(agent_id, pid, ppid, path, cmdline, parent_path, provisioning)

    def _observe_entry(self, agent_id, pid, ppid, path, cmdline, parent_path, provisioning):
        trusted = get_trusted_parents()
        trust: Optional[Trust] = None
        root, kind, depth = None, None, 0

        parent = self._procs.get((agent_id, str(ppid))) if ppid not in (None, "") else None
        if parent is not None and parent[2] and parent[4] < MAX_DEPTH and (
            parent[3] != "installer" or provisioning
        ):
            # Ancestry through the server's own record of the parent.
            root, depth = parent[2], parent[4] + 1
            kind = parent[3]
            trust = Trust(root, "installer" if kind == "installer" else (
                "parent" if depth == 1 else "ancestor"))
        else:
            known_parent_path = (parent[0] if parent and parent[0] else None) or parent_path
            if known_parent_path and normalize_path(known_parent_path) in trusted:
                root, kind, depth = normalize_path(known_parent_path), "exe", 1
                trust = Trust(root, "parent")

        if trust is None and provisioning:
            for inst in get_trusted_installers():
                if normalize_path(path) == inst or installer_in_cmdline(cmdline, inst):
                    root, kind, depth = inst, "installer", 0
                    trust = Trust(inst, "installer")
                    break

        if trust is None and path and normalize_path(path) in trusted:
            # A trusted executable is the root of its subtree, not trusted itself.
            root, kind, depth = normalize_path(path), "exe", 0

        self._put((agent_id, str(pid)), (path or "", ppid, root, kind, depth))
        return trust


# Back-compat name for callers that only need pid -> path.
ProcessPathIndex = TrustResolver


async def resolve_parent_from_db(db, agent_id, ppid, before: Optional[datetime] = None,
                                 lookback: timedelta = timedelta(hours=12)):
    """(path, grandparent pid) of the most recent process_start of `ppid` for
    `agent_id` that is stored, or None. Used when the live index never saw the
    parent start (server restart, evicted entry)."""
    try:
        from sqlalchemy import select
        from app.models.endpoint_agent import AgentEvent, EventCategory

        when = before or datetime.utcnow()
        stmt = (
            select(AgentEvent.details)
            .where(
                AgentEvent.agent_id == agent_id,
                AgentEvent.category == EventCategory.process,
                AgentEvent.timestamp >= when - lookback,
                AgentEvent.timestamp <= when,
                AgentEvent.details["pid"].as_integer() == int(ppid),
                AgentEvent.details["kind"].as_string() == "process_start",
            )
            .order_by(AgentEvent.timestamp.desc())
            .limit(1)
        )
        row = (await db.execute(stmt)).first()
        d = row[0] if row else None
    except Exception as exc:  # detection must never fail ingest
        logger.debug("parent lookup for pid %s failed: %s", ppid, exc)
        return None
    if not isinstance(d, dict):
        return None
    return d.get("process_path"), d.get("ppid")
