#!/usr/bin/env python3
"""
One-off repair: merge duplicate ``assets`` rows created by the auto-discovery
mutation bug in ``app/main.py::_auto_discover_localhost``.

Background
----------
``_auto_discover_localhost`` loads every existing ``(client_id, ip_address)``
asset into a single Python list ONCE per boot, then mutates
``matched_asset.ports`` in place while iterating discovered services. That
mutation corrupts the in-memory list for the rest of the boot's matching, so
the next service on the same host can no longer find its own asset in the
(now-truncated) list and a brand-new duplicate ``Asset`` row is created
instead of an update. Repeated across ``cayde6-api`` restarts, hosts that
expose more than one port have accumulated many duplicate rows, each
holding only a fragment of the host's true port list, and a stale,
disagreeing ``risk_score`` (auto_discovery's legacy 0-100 heuristic, not
``asset_risk.score_asset``'s deterministic ``service_weighted_v1`` model).

This script is DATA REPAIR ONLY. It does not touch application code and
does not change the auto-discovery code path itself (that is a separate,
parallel fix to ``app/main.py``).

What it does
------------
For every ``(client_id, ip_address, hostname)`` group with more than one
row:
  1. Union every row's ``ports`` entries, keyed by port number. When two
     rows disagree on the metadata for the same port, keep whichever entry
     has more non-empty fields (service/version/protocol/state); ties keep
     the earliest sighting (rows are read oldest -> newest).
  2. Recompute ``risk_score`` for the merged port list via
     ``app.services.asset_risk.score_asset()`` (``service_weighted_v1`` --
     the same function ``app/api/surface.py`` calls live for the
     dashboard), with no ``host_index`` -- this is a single-asset write,
     matching the convention documented in ``asset_risk.py`` for the
     write path (the read path is the one that supplies fleet-wide
     damping).
  3. Write the merged ``ports`` + ``risk_score`` onto the OLDEST row in the
     group (by ``created_at``) -- its ``id`` is stable and is what every
     other table would already be pointing at, if anything pointed at
     these rows at all.
  4. Delete every other row in the group.

Grouping key -- why ``hostname`` is part of it
------------------------------------------------
The originating write-up for this fix describes the group key as just
``(client_id, ip_address)``. On THIS database that key is useless in
isolation: confirmed on prod (2026-07-21) that 83 of 84 asset rows share
one ``client_id`` and ``ip_address='127.0.0.1'`` -- virtually the entire
fleet is discovered on localhost. Grouping on ``client_id + ip_address``
ALONE would merge dozens of genuinely distinct hosts/services (e.g. the
"python-8099" service and the "eppc-3031" service, which just happen to
share a loopback IP) into one Frankenstein row -- exactly the destructive
collapse this repair exists to undo, not a smaller copy of it.

``hostname`` is what the auto-discovery bug's duplicates actually agree
on in practice: ``good_hostname = f"{service}-{port}"`` is deterministic
for a given real service on the host, so every duplicate spawned for that
service carries the same hostname string every time. Confirmed on prod:

    GROUP BY client_id, ip_address                    HAVING count(*)>1
        -> 1 group, 83 rows (useless -- see above)
    GROUP BY client_id, ip_address, hostname           HAVING count(*)>1
        -> 17 groups, 56 rows total -- exact row-for-row match to the
           sweep's own examples (eppc-3031 x11, unknown-7000 x6,
           unknown-7001 x4, unknown-4000 x4, python-8099 x3, ...)

So ``(client_id, ip_address, hostname)`` is the key this script uses.

Safety
------
  * Defaults to a dry run: prints the full merge/delete plan and writes
    nothing.
  * Every invocation (dry or applied) first writes a CSV snapshot of the
    pre-repair state of every row that would be touched (updated OR
    deleted) to ``~/aegis_repair_backups/assets_dup_repair_<UTC
    timestamp>.csv``.
  * ``--apply`` additionally creates a full-table Postgres backup
    (``CREATE TABLE IF NOT EXISTS assets_backup_<UTC date> AS SELECT *
    FROM assets``) before the first write, then performs every UPDATE and
    DELETE inside a single transaction (all-or-nothing; rolled back
    automatically on any error).

Usage
-----
    cd backend && source venv/bin/activate
    python scripts/repair_duplicate_assets.py              # dry run
    python scripts/repair_duplicate_assets.py --apply       # real repair
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make `import app...` work regardless of the caller's cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select, text  # noqa: E402

from app.database import async_session  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.services import asset_risk  # noqa: E402

BACKUP_DIR = Path(os.path.expanduser("~/aegis_repair_backups"))


def _entry_completeness(entry: dict) -> int:
    """Count non-empty metadata fields on one port entry."""
    return sum(1 for k in ("service", "version", "protocol", "state") if entry.get(k))


def merge_group_ports(rows: list[Asset]) -> list[dict]:
    """Union every row's ``ports`` keyed by port number.

    ``rows`` must already be sorted oldest -> newest by ``created_at`` so
    that ties in completeness keep the earliest sighting.
    """
    merged: dict[int, dict] = {}
    for row in rows:
        for entry in row.ports or []:
            if not isinstance(entry, dict):
                continue
            port = entry.get("port")
            if not isinstance(port, int) or isinstance(port, bool):
                continue
            current = merged.get(port)
            if current is None or _entry_completeness(entry) > _entry_completeness(current):
                merged[port] = entry
    return [merged[p] for p in sorted(merged)]


def _csv_row(row: Asset, action: str) -> dict:
    return {
        "action": action,
        "id": row.id,
        "client_id": row.client_id,
        "hostname": row.hostname,
        "ip_address": row.ip_address,
        "ports": row.ports,
        "risk_score": row.risk_score,
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "last_scan_at": row.last_scan_at.isoformat() if row.last_scan_at else "",
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually perform the backup + merge + delete. Without this flag, only prints the plan.",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    backup_table = f"assets_backup_{now.strftime('%Y%m%d')}"
    csv_path = BACKUP_DIR / f"assets_dup_repair_{now.strftime('%Y%m%dT%H%M%SZ')}.csv"

    async with async_session() as db:
        result = await db.execute(select(Asset))
        all_assets = list(result.scalars().all())

        groups: dict[tuple[str, str | None, str | None], list[Asset]] = {}
        for a in all_assets:
            key = (a.client_id, a.ip_address, a.hostname)
            groups.setdefault(key, []).append(a)

        dup_groups = {k: v for k, v in groups.items() if len(v) > 1}

        if not dup_groups:
            print("No duplicate (client_id, ip_address, hostname) groups found. Nothing to do.")
            return

        total_before = len(all_assets)
        total_dup_rows = sum(len(v) for v in dup_groups.values())
        print(f"Total assets: {total_before}")
        print(f"Duplicate groups: {len(dup_groups)} ({total_dup_rows} rows involved)\n")

        plan = []  # (kept_row, old_ports_len, new_ports, new_risk, old_risk, delete_rows)
        csv_rows: list[dict] = []

        for (client_id, ip_address, hostname), rows in sorted(dup_groups.items(), key=lambda kv: -len(kv[1])):
            rows_sorted = sorted(rows, key=lambda r: r.created_at or datetime.min)
            kept = rows_sorted[0]
            to_delete = rows_sorted[1:]

            merged_ports = merge_group_ports(rows_sorted)
            scored = asset_risk.score_asset(ports=merged_ports, ip_address=ip_address, hostname=hostname)
            new_risk = scored["risk_score"]

            old_ports_len = len(kept.ports or [])
            old_risk = kept.risk_score

            plan.append((kept, old_ports_len, merged_ports, new_risk, old_risk, to_delete))

            csv_rows.append(_csv_row(kept, "KEEP_UPDATED"))
            for d in to_delete:
                csv_rows.append(_csv_row(d, "DELETED"))

            print(
                f"[{hostname!r} @ {ip_address}] {len(rows)} rows -> keep {kept.id} "
                f"(created {kept.created_at}): ports {old_ports_len} -> {len(merged_ports)}, "
                f"risk {old_risk} -> {new_risk}; delete {len(to_delete)} row(s): "
                f"{[d.id for d in to_delete]}"
            )

        # --- CSV snapshot of every touched row, written BEFORE any DB write ---
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["action", "id", "client_id", "hostname", "ip_address", "ports", "risk_score", "created_at", "last_scan_at"],
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"\nCSV snapshot of every touched row written to: {csv_path}")

        if not args.apply:
            print("\nDry run only -- no database changes made. Re-run with --apply to perform the repair.")
            return

        # --- Full-table Postgres backup (idempotent: keeps the FIRST backup of the day) ---
        await db.execute(text(f"CREATE TABLE IF NOT EXISTS {backup_table} AS SELECT * FROM assets"))
        await db.commit()
        print(f"Postgres backup table ready: {backup_table} (CREATE TABLE IF NOT EXISTS -- kept as-is if it already existed)")

        # --- Apply merges + deletes in one transaction ---
        deleted_count = 0
        for kept, _old_len, merged_ports, new_risk, _old_risk, to_delete in plan:
            kept.ports = merged_ports
            kept.risk_score = new_risk
            for d in to_delete:
                await db.delete(d)
                deleted_count += 1
        await db.commit()

        result = await db.execute(select(Asset))
        total_after = len(result.scalars().all())
        print(f"\nApplied. Rows deleted: {deleted_count}. Total assets: {total_before} -> {total_after}.")
        print(f"Reversible via: DROP TABLE assets; ALTER TABLE {backup_table} RENAME TO assets; (then re-add indexes/constraints).")


if __name__ == "__main__":
    asyncio.run(main())
