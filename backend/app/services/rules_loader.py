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


def load_rules(path: Path = _DEFAULT_RULES_PATH) -> RulePack:
    """Recursively load all *.yaml files under *path* and return a validated RulePack."""
    pack = RulePack()

    if not path.exists():
        logger.warning(f"Rules directory does not exist: {path}")
        return pack

    yaml_files = sorted(path.rglob("*.yaml"))
    logger.info(f"Loading rules from {path} — found {len(yaml_files)} YAML files")

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

    logger.info(
        f"Rules loaded: {pack.sigma_count} sigma rules "
        f"({len(pack.rules)} event types), {len(pack.chains)} chains"
    )
    return pack


# ---------------------------------------------------------------------------
# Hot-reload watcher (optional — requires watchdog)
# ---------------------------------------------------------------------------

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
