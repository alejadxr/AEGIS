"""State of runtime-authored detection rules, read straight from their YAML.

Why this module exists
----------------------
Rules written at runtime (by the operator or by the AI) live OUTSIDE the repo
tree, in ``AEGIS_AUTHORED_RULES_DIR`` (default ``~/.aegis/authored_rules``).
Two reasons, both learned the hard way:

* the deploy recipe rsyncs ``backend/app/rules/`` with ``--delete`` so that
  removed shipped rules actually disappear. Anything authored in there would be
  wiped by the next release;
* a rule authored on the Mac Pro must not dirty a public git working tree.

``rules_loader.load_rules`` reads that directory too, so an authored rule is an
ordinary rule to the correlation engine.

What the registry answers
-------------------------
``block_policy``, ``guardrails`` and the responder need two cheap questions
about a rule id, and they must be answerable WITHOUT importing the authoring
service (it pulls the DB, the engine and the normalizer):

* ``is_alert_only(id)``  -- may a detection by this rule ever auto-block?
* ``is_confirmed(id)``   -- did an operator classify it as exploit-class
  (permanent block) rather than the default AMBIGUOUS?

The answer is recorded in the rule file itself (``authoring:`` block), so the
classification travels with the rule and needs no code edit. The loader's
pydantic models ignore the extra key.

Approval is bound to CONTENT, not to a flag
-------------------------------------------
``authoring.approved_hash`` is the hash of the rule body at the moment an
operator promoted it. If the body changes afterwards -- an AI "improving" the
filter, a hand edit, a revert -- the hash no longer matches and the rule is
alert-only again. A boolean ``approved: true`` would let an edit inherit the
trust earned by different content, which is exactly how a rule that was safe
when approved becomes the one that blocks the owner.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

logger = logging.getLogger("aegis.authored_rules")

# Authored ids live in their own namespace. block_policy decides CONFIRMED by
# exact id and by the ``sigma_cve_`` / ``sigma_ai_`` prefixes; a runtime rule
# that could pick one of those ids would be born permanent-block. The prefix
# makes that impossible by construction (validation refuses anything else).
AUTHORED_PREFIX = "authored_"

MODE_ALERT_ONLY = "alert_only"
MODE_BLOCKING = "blocking"
CLASS_AMBIGUOUS = "ambiguous"
CLASS_CONFIRMED = "confirmed"

# Keys that do not change what a rule detects, so toggling them must not
# invalidate an approval.
_HASH_EXCLUDED_KEYS = frozenset({"authoring", "enabled"})


def authored_dir() -> Path:
    raw = os.environ.get("AEGIS_AUTHORED_RULES_DIR") or "~/.aegis/authored_rules"
    return Path(os.path.expanduser(raw))


def history_dir() -> Path:
    return authored_dir() / ".history"


def rule_path(rule_id: str) -> Path:
    return authored_dir() / f"{rule_id}.yaml"


def content_hash(rule: dict) -> str:
    """Stable hash of what a rule DETECTS (everything but bookkeeping)."""
    body = {k: v for k, v in rule.items() if k not in _HASH_EXCLUDED_KEYS}
    blob = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthoredState:
    rule_id: str
    origin: str                 # "ai" | "operator"
    mode: str                   # recorded: alert_only | blocking
    block_class: str            # recorded: ambiguous | confirmed
    approved_valid: bool        # approved_hash matches the CURRENT body
    enabled: bool
    unverified: bool

    @property
    def effective_mode(self) -> str:
        """``blocking`` only while a matching operator approval is on file."""
        if self.mode == MODE_BLOCKING and self.approved_valid:
            return MODE_BLOCKING
        return MODE_ALERT_ONLY

    @property
    def effective_class(self) -> str:
        if self.effective_mode == MODE_BLOCKING and self.block_class == CLASS_CONFIRMED:
            return CLASS_CONFIRMED
        return CLASS_AMBIGUOUS


def state_from_dict(data: dict) -> Optional[AuthoredState]:
    rid = data.get("id")
    meta = data.get("authoring")
    if not isinstance(rid, str) or not isinstance(meta, dict):
        return None
    approved = meta.get("approved_hash")
    return AuthoredState(
        rule_id=rid,
        origin=str(meta.get("origin") or "ai"),
        mode=str(meta.get("mode") or MODE_ALERT_ONLY),
        block_class=str(meta.get("block_class") or CLASS_AMBIGUOUS),
        approved_valid=bool(approved) and approved == content_hash(data),
        enabled=bool(data.get("enabled", True)),
        unverified=bool(meta.get("unverified", False)),
    )


# (signature of the directory) -> parsed states. A rule file is tiny and the
# directory holds tens of files, so a scandir signature per lookup is cheaper
# than any invalidation protocol and also notices hand edits.
_cache: dict[str, Any] = {"sig": None, "states": {}}


def _signature(d: Path) -> tuple:
    try:
        with os.scandir(d) as it:
            return tuple(sorted(
                (e.name, e.stat().st_mtime_ns, e.stat().st_size)
                for e in it if e.is_file() and e.name.endswith(".yaml")
            ))
    except OSError:
        return ()


def states() -> dict[str, AuthoredState]:
    d = authored_dir()
    sig = (str(d), _signature(d))
    if _cache["sig"] == sig:
        return _cache["states"]
    out: dict[str, AuthoredState] = {}
    for name, _mt, _sz in sig[1]:
        try:
            data = yaml.safe_load((d / name).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            logger.warning(f"authored rule {name} unreadable: {exc}")
            continue
        if isinstance(data, dict):
            st = state_from_dict(data)
            if st is not None:
                out[st.rule_id] = st
    _cache["sig"], _cache["states"] = sig, out
    return out


def invalidate() -> None:
    _cache["sig"] = None


def get(rule_id: str) -> Optional[AuthoredState]:
    if not isinstance(rule_id, str):
        return None
    return states().get(rule_id) or states().get(rule_id.lower())


def is_authored(rule_id: str) -> bool:
    return get(rule_id) is not None


def is_alert_only(rule_id: str) -> bool:
    """True for an authored rule with no valid operator approval on file."""
    st = get(rule_id)
    return st is not None and st.effective_mode == MODE_ALERT_ONLY


def is_confirmed(rule_id: str) -> bool:
    st = get(rule_id)
    return st is not None and st.effective_class == CLASS_CONFIRMED


def alert_only_among(rule_ids: Iterable[str]) -> list[str]:
    """The subset of ``rule_ids`` that must never cause an automatic block."""
    if not states():
        return []
    return [r for r in rule_ids if isinstance(r, str) and is_alert_only(r)]


def blocking_held_by(rule_ids: Iterable[str]) -> list[str]:
    """Alert-only rules that withhold a block -- only when they are ALL that matched.

    The strongest matched signal wins. A scanner burst trips many rules at once,
    so if an alert-only authored rule could veto, one broad authored rule would
    park every genuine CVE / web-shell / SQLi block behind a human who is not
    awake at 03:00. An alert-only rule withholds blocking only when nothing else
    matched; any other rule id in the alert (CONFIRMED or merely AMBIGUOUS)
    lets the normal block policy decide.

    Only rule ids count, never the AI's threat_type: an AI that labels an
    authored rule's incident "sql_injection" must not turn it into a CONFIRMED
    permanent block.
    """
    ids = {r.lower() for r in rule_ids if isinstance(r, str) and r}
    if not ids or not states():
        return []
    held = sorted(r for r in ids if is_alert_only(r))
    return held if len(held) == len(ids) else []
