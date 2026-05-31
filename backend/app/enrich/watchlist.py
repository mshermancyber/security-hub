"""Watchlist matcher — fires on each newly-ingested news batch.

Each watchlist entry is a small query (free-text substring or regex)
that matches against title + summary. When a new item matches, we
broadcast a `watchlist.hit` WS event and bump the hit counter.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from ..db import fetchall, tx
from ..ws import bus

log = logging.getLogger("sechub.watchlist")


def _compile_query(q: str, kind: str) -> re.Pattern | None:
    if kind == "regex":
        try:
            return re.compile(q, re.IGNORECASE)
        except re.error:
            log.warning("invalid regex in watchlist: %r", q)
            return None
    # text mode: word-boundary-ish, escape regex chars
    return re.compile(r"(?<!\w)" + re.escape(q) + r"(?!\w)", re.IGNORECASE)


def check_batch(items: list[dict]) -> int:
    """Check a batch of newly-ingested news items against the watchlist.

    Each item dict should have `id`, `title`, `summary`, `priority`,
    `url`, `source_name`. Returns count of hits emitted.
    """
    if not items:
        return 0
    rows = fetchall(
        "SELECT id, name, kind, query, min_priority, slack "
        "FROM watchlist WHERE enabled = 1"
    )
    if not rows:
        return 0
    compiled = []
    for r in rows:
        rx = _compile_query(r["query"], r["kind"])
        if rx:
            compiled.append((dict(r), rx))

    hits = 0
    bumps: dict[int, int] = {}
    now = datetime.now(timezone.utc).isoformat()
    for item in items:
        if not item:
            continue
        blob = (item.get("title") or "") + " " + (item.get("summary") or "")
        prio = item.get("priority", 0) or 0
        for w, rx in compiled:
            if prio < w["min_priority"]:
                continue
            if rx.search(blob):
                bus.broadcast_sync({
                    "type": "watchlist.hit",
                    "watch_id": w["id"],
                    "watch_name": w["name"],
                    "item": {
                        "id": item.get("id"),
                        "title": item.get("title"),
                        "url": item.get("url"),
                        "source_name": item.get("source_name"),
                        "priority": prio,
                        "published_at": item.get("published_at"),
                    },
                    "slack": bool(w["slack"]),
                })
                bumps[w["id"]] = bumps.get(w["id"], 0) + 1
                hits += 1

    if bumps:
        with tx() as conn:
            for wid, n in bumps.items():
                conn.execute(
                    "UPDATE watchlist SET hits = hits + ?, last_hit = ? WHERE id = ?",
                    (n, now, wid),
                )
    return hits
