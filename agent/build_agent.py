#!/usr/bin/env python3
"""
Build the AEGIS agent as a standalone binary using PyInstaller.

Usage:
    python build_agent.py

Output:
    dist/aegis-agent  (or aegis-agent.exe on Windows)

The resulting binary can be used as:
    - Tauri sidecar (bundled inside the desktop app)
    - Standalone agent on remote machines
"""

import sys
import PyInstaller.__main__

args = [
    "aegis_agent.py",
    "--onefile",
    "--name", "aegis-agent",
    "--hidden-import", "psutil",
    "--hidden-import", "watchdog",
    "--hidden-import", "httpx",
    "--hidden-import", "httpcore",
    "--hidden-import", "anyio",
    "--hidden-import", "sniffio",
    "--hidden-import", "certifi",
    "--hidden-import", "h11",
    "--hidden-import", "idna",
    "--add-data", "config.py:.",
    "--add-data", "network_discovery.py:.",
    "--clean",
]

# On Windows, also bundle the Windows config module
if sys.platform == "win32":
    args.extend(["--hidden-import", "win32evtlog"])
    args.extend(["--hidden-import", "win32evtlogutil"])
    args.extend(["--add-data", "config_windows.py:."])

print(f"Building aegis-agent with PyInstaller...")
print(f"Platform: {sys.platform}")
PyInstaller.__main__.run(args)
print("Build complete. Binary at: dist/aegis-agent")
