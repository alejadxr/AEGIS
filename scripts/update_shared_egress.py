#!/usr/bin/env python3
"""Regenerate backend/app/data/icloud_private_relay_egress.txt from Apple's feed.

Apple publishes the iCloud Private Relay egress ranges as a CSV and rotates
them, so the vendored copy goes stale. Run this occasionally and commit the
result. Stdlib only.
"""
import csv
import io
import ipaddress
import sys
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
OUT = Path(__file__).resolve().parent.parent / "backend" / "app" / "data" / "icloud_private_relay_egress.txt"


def main() -> int:
    with urllib.request.urlopen(URL, timeout=60) as resp:
        text = resp.read().decode("utf-8")
    nets = []
    for row in csv.reader(io.StringIO(text)):
        if row and row[0].strip():
            try:
                nets.append(ipaddress.ip_network(row[0].strip(), strict=False))
            except ValueError:
                continue
    if len(nets) < 1000:  # a truncated/error response must not wipe the file
        print(f"refusing to write: only {len(nets)} ranges parsed", file=sys.stderr)
        return 1
    lines = []
    for version in (4, 6):
        lines += [str(n) for n in ipaddress.collapse_addresses(n for n in nets if n.version == version)]
    header = (
        "# iCloud Private Relay egress ranges, collapsed (adjacent/contained CIDRs merged)\n"
        "# and stripped of the geolocation columns.\n"
        f"# Source: {URL} (published by Apple;\n"
        "# see https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/)\n"
        f"# Fetched: {date.today().isoformat()}. Regenerate with: python scripts/update_shared_egress.py\n"
    )
    OUT.write_text(header + "\n".join(lines) + "\n")
    print(f"wrote {len(lines)} ranges to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
