"""SQLite backup task. Uses the sqlite3 .backup API (online, safe under WAL).

Drops to `backend/data/backups/sechub.<UTC-ISO>.sqlite` and prunes to the
last 7. Runs every 24h via the scheduler.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from ..db import get_conn, record_feed_health

log = logging.getLogger("sechub.ingest.db_backup")

KEEP = 7
SUFFIX = ".sqlite"


def _backup_dir() -> Path:
    d = config.DB_PATH.parent / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _prune(d: Path) -> int:
    files = sorted(d.glob(f"*{SUFFIX}"), key=lambda p: p.stat().st_mtime, reverse=True)
    pruned = 0
    for old in files[KEEP:]:
        old.unlink()
        pruned += 1
    return pruned


async def backup_db() -> int:
    """Run a hot online backup. Returns 1 on success, 0 on failure."""
    try:
        d = _backup_dir()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        out = d / f"sechub.{ts}{SUFFIX}"
        src = get_conn()
        dst = sqlite3.connect(out)
        try:
            src.backup(dst)
        finally:
            dst.close()
        # Force flush to disk so the snapshot survives power loss.
        import os
        fd = os.open(out, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        pruned = _prune(d)
        log.info("db backup: wrote %s (fsynced, pruned %d)", out.name, pruned)
        record_feed_health("db-backup", "SQLite backup", ok=True, items=1)
        return 1
    except Exception as e:
        log.exception("db backup failed")
        record_feed_health("db-backup", "SQLite backup", ok=False, error=str(e))
        return 0
