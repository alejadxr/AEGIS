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
"""
from __future__ import annotations

import logging
import ntpath
import os
import re
from collections import OrderedDict
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


class ProcessPathIndex:
    """Recent pid -> executable path per agent, fed by the process events the
    engine already sees, so a parent can be resolved from ppid without a DB read.
    Bounded; a parent never seen (started before the engine, evicted) resolves
    to None and the event is simply not excluded."""

    def __init__(self, max_entries: int = 20000) -> None:
        self._max = max_entries
        self._paths: "OrderedDict[tuple, str]" = OrderedDict()

    def record(self, agent_id, pid, path) -> None:
        if agent_id is None or pid in (None, "") or not path:
            return
        key = (agent_id, str(pid))
        self._paths[key] = path
        self._paths.move_to_end(key)
        while len(self._paths) > self._max:
            self._paths.popitem(last=False)

    def forget(self, agent_id, pid) -> None:
        self._paths.pop((agent_id, str(pid)), None)

    def parent_path(self, agent_id, ppid) -> Optional[str]:
        if agent_id is None or ppid in (None, ""):
            return None
        return self._paths.get((agent_id, str(ppid)))
