"""Global search + command palette backend."""
from __future__ import annotations

from fastapi import APIRouter, Query

from ..db import fetchall, load_taxonomy, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like as _esc_like

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
def search(q: str, limit: int = Query(30, ge=1, le=500)):
    q = q.strip()
    if not q:
        return {"news": [], "cves": [], "entities": []}
    like_pattern = f"%{_esc_like(q)}%"

    # Entity matches (vendors, AI cos, threat actors, sectors)
    entities: list[dict] = []
    qlc = q.lower()
    for taxon, key in [("vendors", "vendors"), ("ai_companies", "ai_companies"),
                       ("threat_actors", "threat_actors"), ("sectors", "sectors")]:
        try:
            doc = load_taxonomy(taxon)
        except FileNotFoundError:
            continue
        for entry in doc.get(key, []):
            hay = " ".join([entry["name"].lower(), *(a.lower() for a in entry.get("aliases", []))])
            if qlc in hay:
                entities.append({"kind": taxon, "id": entry["id"], "name": entry["name"],
                                 "category": entry.get("category") or entry.get("type")})

    news = fetchall(
        f"SELECT id, source_name, title, url, published_at, priority FROM news "
        f"WHERE title LIKE ? {ESCAPE_CLAUSE} OR summary LIKE ? {ESCAPE_CLAUSE} "
        f"ORDER BY priority DESC, published_at DESC LIMIT ?",
        (like_pattern, like_pattern, limit),
    )
    cves = fetchall(
        f"SELECT cve_id, description, cvss_score, cvss_severity, is_kev, priority FROM cves "
        f"WHERE cve_id LIKE ? {ESCAPE_CLAUSE} OR description LIKE ? {ESCAPE_CLAUSE} "
        f"ORDER BY priority DESC LIMIT ?",
        (like_pattern, like_pattern, limit),
    )
    return {
        "entities": entities[:limit],
        "news": [row_to_dict(r) for r in news],
        "cves": [row_to_dict(r) for r in cves],
    }
