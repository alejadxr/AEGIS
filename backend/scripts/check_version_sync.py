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

# The Tauri desktop app names its installers from these, so a stale copy ships
# as AEGIS_1.6.2_* on a 1.7.x release. node-tauri/ (the endpoint agent) is
# deliberately NOT checked: it has its own independent version (0.1.0).
desktop = ROOT / "desktop-tauri"
if (desktop / "package.json").exists():
    got = json.loads((desktop / "package.json").read_text()).get("version")
    if got != CANON:
        problems.append(f"desktop-tauri/package.json says {got!r}, expected {CANON!r}")
conf = desktop / "src-tauri/tauri.conf.json"
if conf.exists():
    got = json.loads(conf.read_text()).get("version")
    if got != CANON:
        problems.append(f"desktop-tauri/src-tauri/tauri.conf.json says {got!r}, expected {CANON!r}")
cargo = desktop / "src-tauri/Cargo.toml"
if cargo.exists():
    m = re.search(r'^\[package\].*?^version\s*=\s*"([^"]+)"', cargo.read_text(), re.S | re.M)
    if m and m.group(1) != CANON:
        problems.append(f"desktop-tauri/src-tauri/Cargo.toml says {m.group(1)!r}, expected {CANON!r}")

readme = ROOT / "README.md"
if readme.exists():
    text = readme.read_text()
    badge = re.search(r"badge/version-([0-9][0-9A-Za-z.\-]*)-", text)
    if badge and badge.group(1) != CANON:
        problems.append(f"README version badge says {badge.group(1)!r}, expected {CANON!r}")
    schema = re.search(r'"softwareVersion":\s*"([^"]+)"', text)
    if schema and schema.group(1) != CANON:
        problems.append(f'README softwareVersion says {schema.group(1)!r}, expected {CANON!r}')

# Python code must import the version, never restate it. The first pass at a
# single source of truth missed app/__init__.py and two /health payloads in
# main.py, so /health kept reporting 1.6.4.9 after the release shipped as 1.7.0.
LITERAL = re.compile(r"""(?:__version__|["']version["'])\s*[:=]\s*["'](\d+\.\d+\.\d+(?:\.\d+)?)["']""")
# Literals that are deliberately not the AEGIS release, kept out of the source
# files themselves where an inline marker would be awkward.
EXEMPT = {("backend/app/api/threats.py", "1.0.0")}  # hub protocol version

for py in sorted((ROOT / "backend/app").rglob("*.py")):
    if py.name == "version.py":
        continue
    for n, line in enumerate(py.read_text(errors="ignore").splitlines(), 1):
        m = LITERAL.search(line)
        # A literal that is deliberately not the AEGIS release (a protocol
        # version, a honeypot's fake identity) is exempted in place, with a reason.
        if m and m.group(1) != CANON and "version-literal-ok:" not in line \
                and (str(py.relative_to(ROOT)), m.group(1)) not in EXEMPT:
            problems.append(f"{py.relative_to(ROOT)}:{n} hardcodes {m.group(1)!r}")

if problems:
    print(f"version drift against backend/app/version.py ({CANON}):")
    for p in problems:
        print(f"  - {p}")
    raise SystemExit(1)

print(f"all version declarations agree: {CANON}")
