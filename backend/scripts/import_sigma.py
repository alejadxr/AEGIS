#!/usr/bin/env python3
"""
Import Sigma rules from SigmaHQ YAML files into AEGIS correlation engine.

Usage:
    # Import from a directory of .yml Sigma rule files
    python scripts/import_sigma.py /path/to/sigma/rules/

    # Import from a single YAML file
    python scripts/import_sigma.py /path/to/rule.yml

    # Clone SigmaHQ and import all rules from a category
    git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
    python scripts/import_sigma.py /tmp/sigma/rules/linux/
    python scripts/import_sigma.py /tmp/sigma/rules/windows/
    python scripts/import_sigma.py /tmp/sigma/rules/network/

The script converts Sigma YAML format into AEGIS correlation engine rules
and adds them via the /api/v1/correlation/rules API endpoint.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required. Install with: pip install pyyaml")
    sys.exit(1)

try:
    import httpx
except ImportError:
    print("ERROR: httpx required. Install with: pip install httpx")
    sys.exit(1)

# Sigma severity -> AEGIS severity mapping
SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Sigma status filter: only import stable/test rules
ALLOWED_STATUS = {"stable", "test", "experimental"}

# MITRE ATT&CK tag extraction
MITRE_ATTACK_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
MITRE_TACTIC_RE = re.compile(
    r"attack\.(initial[_-]access|execution|persistence|privilege[_-]escalation|"
    r"defense[_-]evasion|credential[_-]access|discovery|lateral[_-]movement|"
    r"collection|exfiltration|command[_-]and[_-]control|impact|reconnaissance|"
    r"resource[_-]development)",
    re.IGNORECASE,
)


def parse_sigma_yaml(filepath: Path) -> dict | None:
    """Parse a single Sigma YAML rule file and convert to AEGIS format."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            sigma = yaml.safe_load(f)
    except Exception as e:
        print(f"  SKIP {filepath.name}: YAML parse error: {e}")
        return None

    if not isinstance(sigma, dict):
        return None

    # Required fields
    title = sigma.get("title")
    if not title:
        return None

    # Generate a stable rule ID from filename
    rule_id = f"sigma_{filepath.stem}"
    rule_id = re.sub(r"[^a-z0-9_]", "_", rule_id.lower())
    rule_id = re.sub(r"_+", "_", rule_id).strip("_")

    # Status filter
    status = sigma.get("status", "experimental")
    if status not in ALLOWED_STATUS:
        return None

    # Severity
    level = sigma.get("level", "medium")
    severity = SEVERITY_MAP.get(level, "medium")

    # Extract MITRE ATT&CK info from tags
    tags = sigma.get("tags", [])
    techniques = []
    tactics = []
    for tag in tags:
        tech_match = MITRE_ATTACK_RE.search(tag)
        if tech_match:
            techniques.append(tech_match.group(1).upper())
        tactic_match = MITRE_TACTIC_RE.search(tag)
        if tactic_match:
            tactics.append(tactic_match.group(1).replace("_", "-"))

    # Build condition from Sigma detection
    detection = sigma.get("detection", {})
    condition_filter = _build_condition(detection, sigma.get("logsource", {}))

    # Build the AEGIS rule
    aegis_rule = {
        "id": rule_id,
        "title": title[:120],
        "description": sigma.get("description", "")[:500],
        "severity": severity,
        "source": "sigma",
        "sigma_status": status,
        "sigma_level": level,
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "condition": condition_filter,
        "tags": tags[:10],
        "references": sigma.get("references", [])[:5],
        "author": sigma.get("author", "SigmaHQ")[:100],
        "sigma_date": str(sigma.get("date", "")),
    }

    return aegis_rule


def _build_condition(detection: dict, logsource: dict) -> dict:
    """Convert Sigma detection block to AEGIS condition filter."""
    condition = {}

    # Map logsource to event_type
    category = logsource.get("category", "")
    product = logsource.get("product", "")
    service = logsource.get("service", "")

    if category:
        condition["event_type"] = category
    elif product:
        condition["event_type"] = product
    elif service:
        condition["event_type"] = service
    else:
        condition["event_type"] = "generic"

    # Extract selection fields from detection
    selection = detection.get("selection", {})
    if isinstance(selection, dict):
        for key, value in selection.items():
            # Sigma field modifiers
            if "|contains" in key:
                field = key.split("|")[0]
                condition[f"{field}_contains"] = value if isinstance(value, list) else [value]
            elif "|endswith" in key:
                field = key.split("|")[0]
                condition[f"{field}_endswith"] = value if isinstance(value, list) else [value]
            elif "|startswith" in key:
                field = key.split("|")[0]
                condition[f"{field}_startswith"] = value if isinstance(value, list) else [value]
            elif "|re" in key:
                field = key.split("|")[0]
                condition[f"{field}_regex"] = value
            else:
                condition[key] = value

    # Timeframe and count from condition string
    timeframe = detection.get("timeframe")
    if timeframe:
        seconds = _parse_timeframe(timeframe)
        if seconds:
            condition["time_window_seconds"] = seconds

    # Count conditions
    condition_str = detection.get("condition", "")
    if isinstance(condition_str, str):
        count_match = re.search(r"count\s*[>(]=?\s*(\d+)", condition_str)
        if count_match:
            condition["count_threshold"] = int(count_match.group(1))

    return condition


def _parse_timeframe(tf: str) -> int | None:
    """Parse Sigma timeframe string (e.g., '5m', '1h', '30s') to seconds."""
    match = re.match(r"(\d+)\s*(s|m|h|d)", tf.strip())
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers.get(unit, 60)


def import_rules(
    path: Path,
    api_url: str,
    api_key: str,
    max_rules: int = 0,
    dry_run: bool = False,
) -> dict:
    """Import Sigma rules from a path (file or directory) into AEGIS."""
    stats = {"parsed": 0, "imported": 0, "skipped": 0, "errors": 0, "duplicates": 0}

    # Collect YAML files
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(path.rglob("*.yml"))
    else:
        print(f"ERROR: {path} is not a file or directory")
        return stats

    print(f"Found {len(files)} YAML files in {path}")

    for filepath in files:
        if max_rules and stats["imported"] >= max_rules:
            print(f"Reached max_rules limit ({max_rules})")
            break

        rule = parse_sigma_yaml(filepath)
        if not rule:
            stats["skipped"] += 1
            continue

        stats["parsed"] += 1

        if dry_run:
            print(f"  [DRY] {rule['id']}: {rule['title']} ({rule['severity']})")
            stats["imported"] += 1
            continue

        # POST to correlation API
        try:
            resp = httpx.post(
                f"{api_url}/api/v1/correlation/rules",
                json=rule,
                headers={"X-API-Key": api_key},
                timeout=10,
            )
            if resp.status_code == 201:
                stats["imported"] += 1
                print(f"  [OK]  {rule['id']}: {rule['title']}")
            elif resp.status_code == 409:
                stats["duplicates"] += 1
            else:
                stats["errors"] += 1
                print(f"  [ERR] {rule['id']}: HTTP {resp.status_code} - {resp.text[:100]}")
        except Exception as e:
            stats["errors"] += 1
            print(f"  [ERR] {rule['id']}: {e}")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Import Sigma rules into AEGIS correlation engine"
    )
    parser.add_argument("path", type=Path, help="Path to Sigma YAML file or directory")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("AEGIS_API_URL", "http://localhost:8000"),
        help="AEGIS API base URL (default: from AEGIS_API_URL env var or localhost)",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="API key for authentication (reads from AEGIS_API_KEY env if not set)",
    )
    parser.add_argument(
        "--max-rules",
        type=int,
        default=0,
        help="Maximum number of rules to import (0 = unlimited)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse rules without sending to API",
    )

    args = parser.parse_args()

    import os

    api_key = args.api_key or os.environ.get("AEGIS_API_KEY", "")
    if not api_key and not args.dry_run:
        print("ERROR: API key required. Use --api-key or set AEGIS_API_KEY env var")
        sys.exit(1)

    print(f"Importing Sigma rules from: {args.path}")
    print(f"API URL: {args.api_url}")
    print(f"Dry run: {args.dry_run}")
    print()

    stats = import_rules(
        path=args.path,
        api_url=args.api_url,
        api_key=api_key,
        max_rules=args.max_rules,
        dry_run=args.dry_run,
    )

    print()
    print("=== Import Summary ===")
    print(f"  Parsed:     {stats['parsed']}")
    print(f"  Imported:   {stats['imported']}")
    print(f"  Duplicates: {stats['duplicates']}")
    print(f"  Skipped:    {stats['skipped']}")
    print(f"  Errors:     {stats['errors']}")


if __name__ == "__main__":
    main()
