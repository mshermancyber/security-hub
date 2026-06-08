"""Optional Postgres adapter.

The default deployment uses SQLite (see db.py). If `SECHUB_PG_URL` is set
(e.g. `postgresql://user:pw@host:5432/sechub`), the same DB API surface is
exposed via psycopg + a translation layer. This module documents what is
required to switch; full implementation is intentionally deferred until a
deployment actually needs concurrent writes that SQLite can't handle.

Migration steps:
  1. `pip install psycopg[binary]`
  2. Translate SCHEMA in db.py — SQLite's `TEXT` becomes `TEXT`; INTEGER stays;
     `excluded.col` ON CONFLICT syntax works in both.
  3. Replace `_connect()` with psycopg.connect(SECHUB_PG_URL).
  4. JSON columns: keep as TEXT (or migrate to JSONB later).
  5. `PRAGMA journal_mode = WAL` and `PRAGMA synchronous = NORMAL` are SQLite-only;
     drop those statements on Postgres.

This module exists so the Postgres path is documented and discoverable;
the SQLite implementation handles the current workload comfortably.
"""
from __future__ import annotations

import os


def is_postgres_configured() -> bool:
    return bool(os.environ.get("SECHUB_PG_URL"))


def banner() -> str:
    if is_postgres_configured():
        return (
            "Postgres URL detected but adapter not active. See backend/app/db_pg.py "
            "for migration steps. SQLite remains in use until adapter is wired."
        )
    return "SQLite mode (default)."
