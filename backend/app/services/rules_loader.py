"""Hot-reloadable YAML rule pack loader for AEGIS correlation engine."""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from weakref import WeakValueDictionary

import yaml
from pydantic import ValidationError

from app.schemas.rule import ChainRule, Rule

logger = logging.getLogger("aegis.rules_loader")

_DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules"


@dataclass
class RulePack:
    rules: dict[str, list[Rule]] = field(default_factory=dict)
    chains: list[ChainRule] = field(default_factory=list)
    by_id: dict[str, Rule] = field(default_factory=dict)
    regex_cache: WeakValueDictionary[str, re.Pattern] = field(
        default_factory=WeakValueDictionary
    )

    @property
    def sigma_count(self) -> int:
        return sum(len(v) for v in self.rules.values())

    def compile_pattern(self, pattern: str) -> re.Pattern:
        """Return a compiled regex for *pattern*, reusing a cached version when possible."""
        cached = self.regex_cache.get(pattern)
        if cached is not None:
            return cached
        compiled = re.compile(pattern)
        self.regex_cache[pattern] = compiled
        return compiled


def _load_yaml_file(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            logger.warning(f"Skipping {path}: expected a YAML mapping, got {type(data)}")
            return None
        return data
    except yaml.YAMLError as exc:
        logger.warning(f"Skipping {path}: YAML parse error — {exc}")
        return None
    except OSError as exc:
        logger.warning(f"Skipping {path}: cannot read — {exc}")
        return None


def _parse_rule(data: dict, path: Path) -> Rule | ChainRule | None:
    kind = data.get("kind", "sigma")
    try:
        if kind == "chain":
            return ChainRule.model_validate(data)
        return Rule.model_validate(data)
    except ValidationError as exc:
        logger.warning(f"Skipping {path}: validation error — {exc}")
        return None


def _check_filter_vocabulary(rule: Rule, path: Path) -> int:
    """Warn about filter clauses the correlation engine cannot honour.

    Schema validation only proves the filter is a mapping; it says nothing
    about whether the engine implements each `<field><operator>` key. A key it
    does not implement (`ua_contains` before v1.6.4.x, `domain_age_days_lt`)
    degrades into an equality on a field nobody emits and the rule is dead
    without a trace. This is the one place that runs once per rule at load,
    so it is where that failure is made loud. The rule is still loaded — an
    operator fixing a typo should not lose the rest of the pack.

    The vocabulary lives next to the interpreter in correlation_engine (one
    table drives both). It is imported lazily: the engine imports this module
    inside CorrelationEngine.__init__, and a module-level import here would
    pull the whole engine in just to load YAML. Any failure to validate is
    swallowed — validation is a diagnostic, never a reason to drop rules.
    """
    filt = rule.condition.filter
    if not filt:
        return 0
    try:
        from app.services.correlation_engine import validate_filter
        problems = validate_filter(filt)
    except Exception as exc:  # pragma: no cover — diagnostic must never break loading
        logger.debug(f"Filter vocabulary check unavailable for {path}: {exc}")
        return 0
    for key, reason in problems:
        logger.warning(
            f"Rule '{rule.id}' ({path}): filter key '{key}' cannot be honoured "
            f"by the correlation engine — {reason}. The rule is loaded but this "
            f"clause will not match as intended."
        )
    return len(problems)


def load_rules(path: Path = _DEFAULT_RULES_PATH) -> RulePack:
    """Recursively load all *.yaml files under *path* and return a validated RulePack."""
    pack = RulePack()

    if not path.exists():
        logger.warning(f"Rules directory does not exist: {path}")
        return pack

    yaml_files = sorted(path.rglob("*.yaml"))
    logger.info(f"Loading rules from {path} — found {len(yaml_files)} YAML files")

    filter_problems = 0
    for yaml_path in yaml_files:
        data = _load_yaml_file(yaml_path)
        if data is None:
            continue

        rule = _parse_rule(data, yaml_path)
        if rule is None:
            continue

        if isinstance(rule, ChainRule):
            pack.chains.append(rule)
            pack.by_id[rule.id] = rule
        else:
            event_type = rule.condition.event_type
            pack.rules.setdefault(event_type, []).append(rule)
            pack.by_id[rule.id] = rule
            filter_problems += _check_filter_vocabulary(rule, yaml_path)

    logger.info(
        f"Rules loaded: {pack.sigma_count} sigma rules "
        f"({len(pack.rules)} event types), {len(pack.chains)} chains"
        + (f", {filter_problems} filter clause(s) the engine cannot honour (see warnings)"
           if filter_problems else "")
    )
    return pack


# ---------------------------------------------------------------------------
# Hot-reload watcher (optional — requires watchdog)
# ---------------------------------------------------------------------------

_WATCH_EVENT_TYPES = frozenset({"created", "modified", "deleted", "moved"})


def start_watcher(pack: RulePack, path: Path = _DEFAULT_RULES_PATH) -> Any:
    """
    Start a filesystem watcher that reloads rules on file change.
    Debounced to 500ms. Returns the watchdog Observer, or None if watchdog
    is not installed.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        logger.info("watchdog not installed — hot-reload disabled")
        return None

    _debounce_timer: list[threading.Timer] = [None]  # type: ignore[list-item]
    _lock = threading.Lock()

    class _Handler(FileSystemEventHandler):
        def on_any_event(self, event):
            if event.is_directory:
                return
            # Only real changes. inotify (Linux) also reports "opened" and
            # "closed_no_write" for plain reads, and load_rules() itself reads
            # every YAML — without this filter each reload triggers the next
            # one in an endless loop.
            if getattr(event, "event_type", "") not in _WATCH_EVENT_TYPES:
                return
            src = getattr(event, "src_path", "")
            if not src.endswith(".yaml"):
                return

            with _lock:
                if _debounce_timer[0] is not None:
                    _debounce_timer[0].cancel()

                def _reload():
                    logger.info(f"Hot-reloading rules (triggered by {src})")
                    try:
                        new_pack = load_rules(path)
                        pack.rules = new_pack.rules
                        pack.chains = new_pack.chains
                        pack.by_id = new_pack.by_id
                        logger.info(
                            f"Hot-reload complete: {new_pack.sigma_count} sigma, "
                            f"{len(new_pack.chains)} chains"
                        )
                    except Exception as exc:
                        logger.error(f"Hot-reload failed: {exc}")

                timer = threading.Timer(0.5, _reload)
                timer.daemon = True
                timer.start()
                _debounce_timer[0] = timer

    observer = Observer()
    observer.schedule(_Handler(), str(path), recursive=True)
    observer.daemon = True
    observer.start()
    logger.info(f"Rule watcher started on {path}")
    return observer
