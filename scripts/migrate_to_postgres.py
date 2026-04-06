#!/usr/bin/env python3
"""
Migrate AEGIS data from SQLite to PostgreSQL.

Usage:
    python scripts/migrate_to_postgres.py

Environment:
    SQLITE_PATH   - Path to SQLite file (default: backend/aegis.db)
    PG_HOST       - PostgreSQL host (default: localhost)
    PG_PORT       - PostgreSQL port (default: 5432)
    PG_USER       - PostgreSQL user (default: aegis)
    PG_PASSWORD   - PostgreSQL password (default: empty)
    PG_DATABASE   - PostgreSQL database (default: aegis)
"""

import sqlite3
import json
import os
import sys
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime

# --- Configuration ---
SQLITE_PATH = os.environ.get("SQLITE_PATH", "backend/aegis.db")
PG_HOST = os.environ.get("PG_HOST", "localhost")
PG_PORT = int(os.environ.get("PG_PORT", "5432"))
PG_USER = os.environ.get("PG_USER", "aegis")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "")
PG_DATABASE = os.environ.get("PG_DATABASE", "aegis")

# Migration order respects FK dependencies
TABLE_ORDER = [
    "clients",
    "threat_intel",
    "assets",
    "honeypots",
    "attacker_profiles",
    "vulnerabilities",
    "incidents",
    "honeypot_interactions",
    "actions",
    "audit_log",
]


def connect_sqlite(path):
    if not os.path.exists(path):
        print(f"ERROR: SQLite file not found: {path}")
        sys.exit(1)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def connect_postgres():
    kwargs = {
        "host": PG_HOST,
        "port": PG_PORT,
        "user": PG_USER,
        "database": PG_DATABASE,
    }
    if PG_PASSWORD:
        kwargs["password"] = PG_PASSWORD
    return psycopg2.connect(**kwargs)


def get_table_columns(sqlite_conn, table):
    cur = sqlite_conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return [row["name"] for row in cur.fetchall()]


def get_boolean_columns(sqlite_conn, table):
    """Return set of column names declared as BOOLEAN in SQLite."""
    cur = sqlite_conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cur.fetchall() if "BOOL" in (row["type"] or "").upper()}


def read_sqlite_table(sqlite_conn, table):
    cur = sqlite_conn.cursor()
    cur.execute(f"SELECT * FROM {table}")
    return cur.fetchall()


def coerce_row(row, columns, bool_cols=None):
    """Convert sqlite3.Row to a plain tuple.

    - SQLite stores JSON as TEXT -> wrapped in psycopg2.extras.Json
    - SQLite stores BOOLEAN as INTEGER (0/1) -> converted to Python bool
    """
    if bool_cols is None:
        bool_cols = set()

    result = []
    for col in columns:
        val = row[col]

        # Boolean coercion: SQLite stores 0/1 for BOOLEAN columns
        if col in bool_cols and isinstance(val, int):
            val = bool(val)
        elif isinstance(val, str):
            stripped = val.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or \
               (stripped.startswith("[") and stripped.endswith("]")):
                try:
                    parsed = json.loads(stripped)
                    val = Json(parsed)
                except (json.JSONDecodeError, ValueError):
                    pass
        elif isinstance(val, (dict, list)):
            val = Json(val)

        result.append(val)
    return tuple(result)


def truncate_table(pg_conn, table):
    with pg_conn.cursor() as cur:
        cur.execute(f'TRUNCATE TABLE "{table}" CASCADE')


def insert_table(pg_conn, sqlite_conn, table, columns, rows):
    if not rows:
        print(f"  {table}: 0 rows (skipping)")
        return 0

    bool_cols = get_boolean_columns(sqlite_conn, table)
    col_sql = ", ".join(f'"{c}"' for c in columns)
    insert_sql = f'INSERT INTO "{table}" ({col_sql}) VALUES %s ON CONFLICT DO NOTHING'

    coerced = [coerce_row(row, columns, bool_cols) for row in rows]

    with pg_conn.cursor() as cur:
        execute_values(cur, insert_sql, coerced)

    return len(coerced)


def verify_counts(sqlite_conn, pg_conn):
    print("\n--- Verification ---")
    all_ok = True
    with pg_conn.cursor() as cur:
        for table in TABLE_ORDER:
            sqlite_cur = sqlite_conn.cursor()
            sqlite_cur.execute(f"SELECT COUNT(*) FROM {table}")
            sqlite_count = sqlite_cur.fetchone()[0]

            cur.execute(f'SELECT COUNT(*) FROM "{table}"')
            pg_count = cur.fetchone()[0]

            status = "OK" if sqlite_count == pg_count else "MISMATCH"
            if status == "MISMATCH":
                all_ok = False
            print(f"  {table:30s} SQLite={sqlite_count:5d}  PG={pg_count:5d}  {status}")

    return all_ok


def main():
    print(f"=== AEGIS SQLite -> PostgreSQL Migration ===")
    print(f"SQLite: {SQLITE_PATH}")
    print(f"PostgreSQL: {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DATABASE}")
    print()

    sqlite_conn = connect_sqlite(SQLITE_PATH)
    print("Connected to SQLite.")

    pg_conn = connect_postgres()
    pg_conn.autocommit = False
    print("Connected to PostgreSQL.")
    print()

    try:
        # Truncate in reverse order to avoid FK violations
        print("Truncating existing PostgreSQL data (reverse FK order)...")
        for table in reversed(TABLE_ORDER):
            truncate_table(pg_conn, table)
        pg_conn.commit()
        print("Truncation done.")
        print()

        print("Migrating tables...")
        for table in TABLE_ORDER:
            columns = get_table_columns(sqlite_conn, table)
            rows = read_sqlite_table(sqlite_conn, table)
            count = insert_table(pg_conn, sqlite_conn, table, columns, rows)
            print(f"  {table:30s} {count} rows migrated")

        pg_conn.commit()
        print("\nMigration committed.")

        all_ok = verify_counts(sqlite_conn, pg_conn)
        if all_ok:
            print("\nAll counts match. Migration successful.")
        else:
            print("\nWARNING: Some counts do not match. Check for ON CONFLICT skips.")

    except Exception as e:
        pg_conn.rollback()
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        sqlite_conn.close()
        pg_conn.close()


if __name__ == "__main__":
    main()
