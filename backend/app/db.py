"""SQLite persistence layer. Synchronous sqlite3 wrapped for FastAPI use."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

from .config import DB_PATH

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# Per-thread connections. `sqlite3.Connection` is not safe to share across
# threads even with `check_same_thread=False` — cursor descriptions get
# clobbered when concurrent threads share one. WAL handles cross-connection
# reader concurrency natively. Schema init runs once globally.
_thread_local = threading.local()
_schema_initialized = False
_init_lock = threading.Lock()


def get_conn() -> sqlite3.Connection:
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = _connect()
        _thread_local.conn = conn
    global _schema_initialized
    if not _schema_initialized:
        with _init_lock:
            if not _schema_initialized:
                _init_schema(conn)
                _schema_initialized = True
    return conn


@contextmanager
def tx():
    """Serialized write transaction. SQLite WAL allows concurrent reads."""
    conn = get_conn()
    with _lock:
        conn.execute("BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


SCHEMA = """
CREATE TABLE IF NOT EXISTS news (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    source_name   TEXT NOT NULL,
    title         TEXT NOT NULL,
    summary       TEXT,
    url           TEXT NOT NULL,
    published_at  TEXT NOT NULL,
    fetched_at    TEXT NOT NULL,
    reliability   INTEGER NOT NULL,
    severity      INTEGER NOT NULL DEFAULT 0,
    priority      INTEGER NOT NULL DEFAULT 0,
    tags_json     TEXT NOT NULL DEFAULT '[]',
    entities_json TEXT NOT NULL DEFAULT '{}',
    cves_json     TEXT NOT NULL DEFAULT '[]',
    industry_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_news_published ON news(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_news_priority  ON news(priority DESC);

CREATE TABLE IF NOT EXISTS cves (
    cve_id        TEXT PRIMARY KEY,
    published_at  TEXT NOT NULL,
    last_modified TEXT NOT NULL,
    description   TEXT NOT NULL,
    cvss_score    REAL,
    cvss_severity TEXT,
    cvss_vector   TEXT,
    epss_score    REAL,
    epss_percentile REAL,
    is_kev        INTEGER NOT NULL DEFAULT 0,
    kev_added     TEXT,
    kev_ransomware TEXT,
    priority      INTEGER NOT NULL DEFAULT 0,
    entities_json TEXT NOT NULL DEFAULT '{}',
    refs_json     TEXT NOT NULL DEFAULT '[]',
    cwe_json      TEXT NOT NULL DEFAULT '[]',
    raw_json      TEXT
);
CREATE INDEX IF NOT EXISTS idx_cve_published ON cves(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_priority  ON cves(priority DESC);
CREATE INDEX IF NOT EXISTS idx_cve_kev       ON cves(is_kev DESC);

CREATE TABLE IF NOT EXISTS feed_health (
    source_id     TEXT PRIMARY KEY,
    source_name   TEXT NOT NULL,
    last_success  TEXT,
    last_error    TEXT,
    last_error_at TEXT,
    items_total   INTEGER NOT NULL DEFAULT 0,
    last_items    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    ioc_value     TEXT NOT NULL,
    ioc_type      TEXT NOT NULL,
    threat_type   TEXT,
    malware       TEXT,
    malware_printable TEXT,
    confidence    INTEGER,
    first_seen    TEXT,
    last_seen     TEXT,
    tags_json     TEXT NOT NULL DEFAULT '[]',
    raw_json      TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_first ON iocs(first_seen DESC);
"""


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    # additive migrations
    cols = {r[1] for r in conn.execute("PRAGMA table_info(news)").fetchall()}
    if "industry_json" not in cols:
        conn.execute("ALTER TABLE news ADD COLUMN industry_json TEXT NOT NULL DEFAULT '{}'")
    if "cluster_key" not in cols:
        conn.execute("ALTER TABLE news ADD COLUMN cluster_key TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_news_cluster ON news(cluster_key)")
    if "simhash" not in cols:
        conn.execute("ALTER TABLE news ADD COLUMN simhash INTEGER")
    if "acknowledged_at" not in cols:
        conn.execute("ALTER TABLE news ADD COLUMN acknowledged_at TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_news_ack ON news(acknowledged_at)")
    # ensure iocs table exists (in case schema was created before this migration was added)
    conn.execute("""CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY, source TEXT NOT NULL, ioc_value TEXT NOT NULL,
        ioc_type TEXT NOT NULL, threat_type TEXT, malware TEXT, malware_printable TEXT,
        confidence INTEGER, first_seen TEXT, last_seen TEXT,
        tags_json TEXT NOT NULL DEFAULT '[]', raw_json TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(ioc_value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_first ON iocs(first_seen DESC)")
    conn.execute("""CREATE TABLE IF NOT EXISTS ai_summaries (
        key          TEXT PRIMARY KEY,
        kind         TEXT NOT NULL,
        subject_id   TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        provider     TEXT,
        model        TEXT,
        body         TEXT NOT NULL,
        sources_json TEXT NOT NULL DEFAULT '[]',
        created_at   TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_kind_subj ON ai_summaries(kind, subject_id)")
    conn.execute("""CREATE TABLE IF NOT EXISTS ransom_postings (
        id           TEXT PRIMARY KEY,
        group_name   TEXT NOT NULL,
        actor_id     TEXT,
        victim       TEXT,
        country      TEXT,
        sector_hint  TEXT,
        domain       TEXT,
        attack_date  TEXT,
        discovered   TEXT NOT NULL,
        description  TEXT,
        claim_url    TEXT,
        raw_json     TEXT
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ransom_disc  ON ransom_postings(discovered DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ransom_group ON ransom_postings(group_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ransom_actor ON ransom_postings(actor_id)")
    # --- analyst workspace tables (saved views, stars, annotations) ---
    conn.execute("""CREATE TABLE IF NOT EXISTS saved_searches (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        kind        TEXT NOT NULL,
        params_json TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        last_used   TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS starred_items (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        kind        TEXT NOT NULL,
        subject_id  TEXT NOT NULL,
        note        TEXT,
        starred_at  TEXT NOT NULL,
        UNIQUE(kind, subject_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_starred_kind ON starred_items(kind, starred_at DESC)")
    conn.execute("""CREATE TABLE IF NOT EXISTS annotations (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        kind        TEXT NOT NULL,
        subject_id  TEXT NOT NULL,
        body        TEXT NOT NULL,
        tags_json   TEXT NOT NULL DEFAULT '[]',
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_anno_kind ON annotations(kind, subject_id)")
    # --- denormalized entity index ---
    # Lets us do indexed lookups for entity / CVE filters instead of
    # `entities_json LIKE '%...%'` full scans.
    conn.execute("""CREATE TABLE IF NOT EXISTS news_refs (
        news_id  TEXT NOT NULL,
        kind     TEXT NOT NULL,   -- cve | vendor | actor | org | ai_company | malware | sector
        ref_id   TEXT NOT NULL,
        PRIMARY KEY (news_id, kind, ref_id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_news_refs_lookup ON news_refs(kind, ref_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_news_refs_news   ON news_refs(news_id)")
    # --- analyst watchlist ---
    conn.execute("""CREATE TABLE IF NOT EXISTS watchlist (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        kind        TEXT NOT NULL DEFAULT 'text',
        query       TEXT NOT NULL,
        min_priority INTEGER NOT NULL DEFAULT 0,
        enabled     INTEGER NOT NULL DEFAULT 1,
        slack       INTEGER NOT NULL DEFAULT 0,
        created_at  TEXT NOT NULL,
        last_hit    TEXT,
        hits        INTEGER NOT NULL DEFAULT 0,
        UNIQUE(name)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_watchlist_enabled ON watchlist(enabled)")


def fetchall(sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
    return get_conn().execute(sql, tuple(params)).fetchall()


def fetchone(sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
    return get_conn().execute(sql, tuple(params)).fetchone()


def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    out = dict(row)
    for k, v in list(out.items()):
        if k.endswith("_json") and isinstance(v, str):
            try:
                out[k[:-5]] = json.loads(v)
                del out[k]
            except Exception:
                pass
    return out


def kv_get(key: str, default: Any = None) -> Any:
    row = fetchone("SELECT value FROM kv WHERE key = ?", (key,))
    if row is None:
        return default
    try:
        return json.loads(row["value"])
    except Exception:
        return row["value"]


def kv_set(key: str, value: Any) -> None:
    with tx() as conn:
        conn.execute(
            "INSERT INTO kv(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value, default=str)),
        )


def record_feed_health(source_id: str, source_name: str, *, ok: bool, items: int = 0, error: str | None = None) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        existing = conn.execute("SELECT items_total FROM feed_health WHERE source_id = ?", (source_id,)).fetchone()
        items_total = (existing["items_total"] if existing else 0) + (items if ok else 0)
        if ok:
            # Clear last_error / last_error_at on a successful fetch — otherwise
            # a feed that errored once stays "red" on the dashboard forever even
            # after recovery (this was the root cause of stale red status dots).
            conn.execute(
                "INSERT INTO feed_health(source_id, source_name, last_success, items_total, last_items, last_error, last_error_at) "
                "VALUES (?, ?, ?, ?, ?, NULL, NULL) "
                "ON CONFLICT(source_id) DO UPDATE SET last_success = excluded.last_success, "
                "items_total = excluded.items_total, last_items = excluded.last_items, "
                "source_name = excluded.source_name, "
                "last_error = NULL, last_error_at = NULL",
                (source_id, source_name, now, items_total, items),
            )
        else:
            # Truncate so a megabyte-long traceback doesn't bloat the
            # dashboard payload, and avoid the useless "unknown" fallback
            # when `str(exc)` is empty (some httpx errors stringify blank).
            err_text = (error or "").strip()
            if not err_text:
                err_text = "(empty error — likely network reset or empty exception message)"
            if len(err_text) > 500:
                err_text = err_text[:500] + "…"
            conn.execute(
                "INSERT INTO feed_health(source_id, source_name, last_error, last_error_at, items_total) "
                "VALUES (?, ?, ?, ?, 0) "
                "ON CONFLICT(source_id) DO UPDATE SET last_error = excluded.last_error, "
                "last_error_at = excluded.last_error_at, source_name = excluded.source_name",
                (source_id, source_name, err_text, now),
            )


_taxonomy_cache: dict[str, Any] = {}
_taxonomy_cache_lock = threading.Lock()
# Reject path-traversal at the load_taxonomy boundary. Filenames are
# alphanumeric + underscore + hyphen by convention.
_TAXONOMY_NAME_RE = __import__("re").compile(r"^[A-Za-z0-9_\-]+$")


def load_taxonomy(name: str) -> dict:
    """Hot-reload friendly taxonomy load — checks mtime.

    Defense in depth: refuse names containing slashes, dots, or other
    path-traversal characters so a future caller that forwards request
    input here can't read arbitrary `.json` files via `../../etc/passwd`.
    """
    if not _TAXONOMY_NAME_RE.match(name):
        raise ValueError(f"invalid taxonomy name: {name!r}")
    from .config import TAXONOMY_DIR
    path = TAXONOMY_DIR / f"{name}.json"
    mtime = path.stat().st_mtime
    with _taxonomy_cache_lock:
        cached = _taxonomy_cache.get(name)
        if cached and cached["mtime"] == mtime:
            return cached["data"]
        data = json.loads(path.read_text())
        _taxonomy_cache[name] = {"mtime": mtime, "data": data}
        return data
