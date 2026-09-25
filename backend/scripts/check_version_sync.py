#!/usr/bin/env python3
"""Fail if any version declaration has drifted from backend/app/version.py.

Four versions once coexisted in this repo (1.4.0, 1.6.3.9, 1.6.4.9, 1.6.5.1),
and two of them caused real misbehaviour rather than just confusion. Python
code now imports a single constant, but a few files must keep their own copy
because another tool owns them -- npm owns package.json, the README badge is
rendered by GitHub. This check is what keeps those honest.

Run from backend/:  python3 scripts/check_version_sync.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from app.version import __version__ as CANON  # noqa: E402

problems = []

pkg = ROOT / "frontend/package.json"
if pkg.exists():
    got = json.loads(pkg.read_text()).get("version")
    if got != CANON:
        problems.append(f"frontend/package.json says {got!r}, expected {CANON!r}")

readme = ROOT / "README.md"
if readme.exists():
    text = readme.read_text()
    badge = re.search(r"badge/version-([0-9][0-9A-Za-z.\-]*)-", text)
    if badge and badge.group(1) != CANON:
        problems.append(f"README version badge says {badge.group(1)!r}, expected {CANON!r}")
    schema = re.search(r'"softwareVersion":\s*"([^"]+)"', text)
    if schema and schema.group(1) != CANON:
        problems.append(f'README softwareVersion says {schema.group(1)!r}, expected {CANON!r}')

if problems:
    print(f"version drift against backend/app/version.py ({CANON}):")
    for p in problems:
        print(f"  - {p}")
    raise SystemExit(1)

print(f"all version declarations agree: {CANON}")
