"""Backfill entity extraction over existing rows.

Used when taxonomy is extended (e.g. new orgs added) so historical news/CVEs
pick up the new entity matches without re-ingesting from source.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from ..db import get_conn, tx
from .cluster import cluster_key, simhash
from .entities import extract_entities, extract_tags
from .industry import INDUSTRY_TAGS, extract_industry
from .refs import index_news_refs

log = logging.getLogger("sechub.backfill")


def backfill_news(limit: int | None = None) -> int:
    """Re-run entity + industry extraction + cluster_key on stored news."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, title, summary, tags_json, entities_json, industry_json, cluster_key, simhash FROM news"
    ).fetchall()
    if limit:
        rows = rows[:limit]
    updated = 0
    with tx() as conn:
        for r in rows:
            blob = f"{r['title']}\n{r['summary'] or ''}"
            new_ents = extract_entities(blob)
            new_industry = extract_industry(blob, new_ents)
            new_tags = extract_tags(blob)
            for kind in new_industry:
                tag = INDUSTRY_TAGS.get(kind)
                if tag and tag not in new_tags:
                    new_tags.append(tag)
            new_ckey = cluster_key(r["title"], r["summary"] or "", new_ents)
            new_shash = simhash(r["title"], r["summary"] or "")
            ents_str = json.dumps(new_ents)
            tags_str = json.dumps(new_tags)
            industry_str = json.dumps(new_industry)
            old_ents = r["entities_json"] or "{}"
            old_tags = r["tags_json"] or "[]"
            old_industry = r["industry_json"] or "{}"
            old_ckey = r["cluster_key"] or ""
            old_shash = r["simhash"]
            if (ents_str != old_ents) or (tags_str != old_tags) \
                    or (industry_str != old_industry) or (new_ckey != old_ckey) \
                    or (new_shash != old_shash):
                conn.execute(
                    "UPDATE news SET entities_json = ?, tags_json = ?, "
                    "industry_json = ?, cluster_key = ?, simhash = ? WHERE id = ?",
                    (ents_str, tags_str, industry_str, new_ckey, new_shash, r["id"]),
                )
                updated += 1
            # Always refresh the denormalized index — cheap and keeps it in
            # sync even when entities_json didn't change but new entities
            # were just added to the taxonomy.
            index_news_refs(conn, r["id"], new_ents, new_ents.get("cves") or [])
    log.info("backfill_news: %d rows updated of %d", updated, len(rows))
    return updated


def backfill_cves(limit: int | None = None) -> int:
    """Re-run entity extraction on stored CVEs (description-based)."""
    conn = get_conn()
    rows = conn.execute("SELECT cve_id, description, entities_json FROM cves").fetchall()
    if limit:
        rows = rows[:limit]
    updated = 0
    with tx() as conn:
        for r in rows:
            new_ents = extract_entities(r["description"] or "")
            old_str = r["entities_json"] or "{}"
            new_str = json.dumps(new_ents)
            if old_str != new_str:
                conn.execute("UPDATE cves SET entities_json = ? WHERE cve_id = ?", (new_str, r["cve_id"]))
                updated += 1
    log.info("backfill_cves: %d rows updated of %d", updated, len(rows))
    return updated


def backfill_all() -> dict:
    t0 = datetime.now(timezone.utc)
    n = backfill_news()
    c = backfill_cves()
    return {"news_updated": n, "cves_updated": c,
            "took_sec": (datetime.now(timezone.utc) - t0).total_seconds()}
