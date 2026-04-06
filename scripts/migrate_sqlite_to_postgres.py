#!/usr/bin/env python3
"""
Migrate all data from SQLite (aegis.db) to PostgreSQL.

Usage:
    python scripts/migrate_sqlite_to_postgres.py \
        --sqlite backend/aegis.db \
        --postgres postgresql://aegis:changeme@localhost:5432/aegis

Requires: psycopg2-binary, sqlite3 (stdlib)
"""

import argparse
import json
import sqlite3
import sys
from contextlib import closing

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2-binary is required. Install with: pip install psycopg2-binary")
    sys.exit(1)


# Tables in dependency order (parents before children)
TABLE_ORDER = [
    "clients",
    "assets",
    "threat_intel",
    "attacker_profiles",
    "vulnerabilities",
    "incidents",
    "users",
    "honeypots",
    "actions",
    "audit_log",
    "honeypot_interactions",
]

# Columns that store JSON (need json.loads for SQLite -> dict -> json.dumps for PG)
JSON_COLUMNS = {
    "clients": ["settings", "guardrails"],
    "assets": ["ports", "technologies", "metadata"],
    "actions": ["parameters", "result"],
    "attacker_profiles": ["known_ips", "tools_used", "techniques", "geo_data"],
    "honeypots": ["config"],
    "honeypot_interactions": ["commands", "credentials_tried", "payloads"],
    "incidents": ["ai_analysis", "raw_alert"],
    "threat_intel": ["tags"],
}


def get_sqlite_tables(sqlite_conn) -> list[str]:
    """Get list of tables that actually exist in the SQLite database."""
    cursor = sqlite_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    return [row[0] for row in cursor.fetchall()]


def get_columns(sqlite_conn, table: str) -> list[str]:
    cursor = sqlite_conn.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]


def convert_json_value(value):
    """Convert a SQLite JSON string to a Python object for PostgreSQL JSONB insertion."""
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value


def migrate_table(sqlite_conn, pg_conn, table: str):
    columns = get_columns(sqlite_conn, table)
    if not columns:
        print(f"  SKIP {table}: no columns found")
        return 0

    json_cols = set(JSON_COLUMNS.get(table, []))

    cursor = sqlite_conn.execute(f"SELECT * FROM {table}")
    rows = cursor.fetchall()

    if not rows:
        print(f"  {table}: 0 rows (empty)")
        return 0

    col_list = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))
    insert_sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"

    converted_rows = []
    for row in rows:
        converted = []
        for i, col in enumerate(columns):
            val = row[i]
            if col in json_cols:
                val = convert_json_value(val)
                # psycopg2 needs Json wrapper for dict/list values
                if isinstance(val, (dict, list)):
                    val = psycopg2.extras.Json(val)
            converted.append(val)
        converted_rows.append(tuple(converted))

    with pg_conn.cursor() as pg_cur:
        for row_data in converted_rows:
            try:
                pg_cur.execute(insert_sql, row_data)
            except Exception as e:
                pg_conn.rollback()
                print(f"  ERROR inserting into {table}: {e}")
                print(f"  Row: {row_data[:3]}...")
                raise

    pg_conn.commit()
    count = len(converted_rows)
    print(f"  {table}: {count} rows migrated")
    return count


def main():
    parser = argparse.ArgumentParser(description="Migrate AEGIS data from SQLite to PostgreSQL")
    parser.add_argument(
        "--sqlite",
        default="backend/aegis.db",
        help="Path to SQLite database file (default: backend/aegis.db)",
    )
    parser.add_argument(
        "--postgres",
        default="postgresql://aegis:changeme@localhost:5432/aegis",
        help="PostgreSQL connection string",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without writing",
    )
    args = parser.parse_args()

    print(f"Source:  {args.sqlite}")
    print(f"Target:  {args.postgres}")
    print()

    # Connect
    sqlite_conn = sqlite3.connect(args.sqlite)
    existing_tables = set(get_sqlite_tables(sqlite_conn))

    if args.dry_run:
        print("DRY RUN -- no data will be written\n")
        for table in TABLE_ORDER:
            if table in existing_tables:
                cursor = sqlite_conn.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"  {table}: {count} rows")
            else:
                print(f"  {table}: not found in SQLite")
        sqlite_conn.close()
        return

    pg_conn = psycopg2.connect(args.postgres)

    total = 0
    print("Migrating tables...")
    for table in TABLE_ORDER:
        if table not in existing_tables:
            print(f"  SKIP {table}: not in SQLite database")
            continue
        total += migrate_table(sqlite_conn, pg_conn, table)

    print(f"\nDone. {total} total rows migrated.")

    sqlite_conn.close()
    pg_conn.close()


if __name__ == "__main__":
    main()
