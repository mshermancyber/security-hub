"""Helpers for the denormalized news_refs index.

The index lets us replace `entities_json LIKE '%"id": "x"%'` scans with
`JOIN news_refs ON kind=? AND ref_id=?` lookups. Two writers maintain it:

  - `index_news_refs(conn, news_id, entities, cves)` at insert time in
    `ingest/rss.py`
  - The backfill in `enrich/backfill.py` re-applies it for every news row
"""
from __future__ import annotations


# entity kind in the JSON (plural) → ref kind in the index (singular)
_KIND_MAP = {
    "vendors":       "vendor",
    "ai_companies":  "ai_company",
    "threat_actors": "actor",
    "malware":       "malware",
    "sectors":       "sector",
    "orgs":          "org",
}


def index_news_refs(conn, news_id: str, entities: dict, cves: list[str]) -> None:
    """Replace the existing refs for `news_id` with the new set."""
    conn.execute("DELETE FROM news_refs WHERE news_id = ?", (news_id,))
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for json_kind, ref_kind in _KIND_MAP.items():
        for ent in entities.get(json_kind) or []:
            ent_id = ent.get("id") if isinstance(ent, dict) else None
            if not ent_id:
                continue
            key = (ref_kind, ent_id)
            if key in seen:
                continue
            seen.add(key)
            rows.append((news_id, ref_kind, ent_id))
    for cve in cves or []:
        key = ("cve", cve)
        if key in seen:
            continue
        seen.add(key)
        rows.append((news_id, "cve", cve))
    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO news_refs (news_id, kind, ref_id) VALUES (?, ?, ?)",
            rows,
        )
