#!/usr/bin/env python3
"""
migrate_sqlite_to_pg.py — One-shot migration: SQLite → PostgreSQL

Usage (run from inside the backend container or with correct env vars):

    # With docker compose
    docker compose exec crowdefik-backend python migrate_sqlite_to_pg.py \
        --sqlite /data/crowdefik.db \
        --pg "postgresql+psycopg2://crowdefik:PASSWORD@crowdefik-db/crowdefik"

    # Or set env vars first
    SQLITE_URL=sqlite:////data/crowdefik.db \
    PG_URL=postgresql+psycopg2://crowdefik:PASSWORD@crowdefik-db/crowdefik \
    python migrate_sqlite_to_pg.py

The script:
  1. Creates all tables in PostgreSQL via SQLAlchemy metadata
  2. Copies every row from SQLite → PostgreSQL, table by table
  3. Resets all PostgreSQL sequences so auto-increment IDs continue from the
     right value after the migration
  4. Reports row counts per table

All data is copied in a single transaction per table; if a table fails the
script aborts but does NOT roll back already-committed tables — simply re-run
with --skip-tables to skip the ones that already succeeded.
"""
import argparse
import os
import sys
from datetime import datetime

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

# ---------------------------------------------------------------------------
# Ensure the app package is importable when running directly
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))

from app.models import Base  # noqa: E402  (must come after sys.path tweak)


def _make_engine(url: str):
    if url.startswith("sqlite"):
        from sqlalchemy.pool import NullPool
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=NullPool)
    return create_engine(url, pool_pre_ping=True)


def migrate(sqlite_url: str, pg_url: str, skip_tables: list[str], dry_run: bool) -> None:
    print(f"[migrate] Source  : {sqlite_url}")
    print(f"[migrate] Target  : {pg_url}")
    if dry_run:
        print("[migrate] DRY RUN — no data will be written to PostgreSQL")

    src_engine = _make_engine(sqlite_url)
    dst_engine = _make_engine(pg_url)

    # Create schema in PostgreSQL (idempotent)
    print("[migrate] Creating schema in PostgreSQL…")
    Base.metadata.create_all(bind=dst_engine)

    src_session = sessionmaker(bind=src_engine)()
    dst_session = sessionmaker(bind=dst_engine)()

    # Ordered list of tables respecting FK dependencies
    table_order = [
        "users",
        "user_router_scopes",
        "instance_settings",
        "stored_alerts",
        "stored_decisions",
        "ip_geo_cache",
        "audit_log",
        "allowlist",
        "service_policies",
    ]

    # Add any tables present in DB but not in our explicit order (forward-compat)
    insp = inspect(src_engine)
    all_tables = set(insp.get_table_names())
    for t in all_tables:
        if t not in table_order:
            table_order.append(t)

    totals: dict[str, int] = {}

    for table_name in table_order:
        if table_name not in all_tables:
            print(f"  [skip] {table_name!r} not in source DB")
            continue
        if table_name in skip_tables:
            print(f"  [skip] {table_name!r} (--skip-tables)")
            continue

        rows = src_session.execute(text(f"SELECT * FROM {table_name}")).mappings().all()
        if not rows:
            print(f"  [copy] {table_name!r} — 0 rows (empty, skipping INSERT)")
            totals[table_name] = 0
            continue

        print(f"  [copy] {table_name!r} — {len(rows)} rows…", end=" ", flush=True)

        if not dry_run:
            # Disable triggers / FK checks during bulk insert (PostgreSQL)
            dst_session.execute(text(f"ALTER TABLE {table_name} DISABLE TRIGGER ALL"))

            # Delete existing rows to make re-runs safe
            dst_session.execute(text(f"DELETE FROM {table_name}"))

            # Bulk insert using raw dicts (works for any column set)
            cols = list(rows[0].keys())
            col_list = ", ".join(f'"{c}"' for c in cols)
            placeholders = ", ".join(f":{c}" for c in cols)
            insert_sql = text(f'INSERT INTO "{table_name}" ({col_list}) VALUES ({placeholders})')

            # Convert Row → plain dict, handle datetime serialisation
            plain_rows = []
            for r in rows:
                d = dict(r)
                for k, v in d.items():
                    if isinstance(v, datetime):
                        d[k] = v  # psycopg2 handles datetime natively
                plain_rows.append(d)

            dst_session.execute(insert_sql, plain_rows)
            dst_session.execute(text(f"ALTER TABLE {table_name} ENABLE TRIGGER ALL"))
            dst_session.commit()

        totals[table_name] = len(rows)
        print("OK")

    # Reset sequences so future INSERTs don't collide with migrated IDs
    if not dry_run:
        print("[migrate] Resetting PostgreSQL sequences…")
        for table_name, count in totals.items():
            if count == 0:
                continue
            try:
                # Find primary-key column (assumes single integer PK)
                pk_cols = [
                    c["name"]
                    for c in inspect(dst_engine).get_columns(table_name)
                    if inspect(dst_engine).get_pk_constraint(table_name)["constrained_columns"]
                    and c["name"] in inspect(dst_engine).get_pk_constraint(table_name)["constrained_columns"]
                ]
                if not pk_cols:
                    continue
                pk = pk_cols[0]
                dst_session.execute(
                    text(
                        f"SELECT setval(pg_get_serial_sequence('{table_name}', '{pk}'), "
                        f"COALESCE((SELECT MAX({pk}) FROM {table_name}), 1))"
                    )
                )
                dst_session.commit()
            except Exception as exc:
                print(f"  [warn] Could not reset sequence for {table_name}.{pk}: {exc}")

    src_session.close()
    dst_session.close()

    print("\n[migrate] Summary:")
    for table, count in totals.items():
        print(f"  {table:30s} {count:>8} rows")
    print(f"\n[migrate] Done {'(DRY RUN — nothing written)' if dry_run else '✓'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate Crowdefik data from SQLite to PostgreSQL")
    parser.add_argument("--sqlite", default=os.getenv("SQLITE_URL", "sqlite:////data/crowdefik.db"),
                        help="SQLite URL (default: sqlite:////data/crowdefik.db)")
    parser.add_argument("--pg", default=os.getenv("PG_URL", ""),
                        help="PostgreSQL URL (e.g. postgresql+psycopg2://user:pass@host/db)")
    parser.add_argument("--skip-tables", nargs="*", default=[],
                        help="Table names to skip (already migrated)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Read source data but do not write to PostgreSQL")
    args = parser.parse_args()

    if not args.pg:
        print("ERROR: --pg or PG_URL is required", file=sys.stderr)
        sys.exit(1)

    migrate(args.sqlite, args.pg, args.skip_tables, args.dry_run)
