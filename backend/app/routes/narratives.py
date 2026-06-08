"""Threat narrative engine — correlate events into timelines.

A 'narrative' is currently anchored on a CVE: the CVE + KEV status + chronological
news mentions form an evolving operational story.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Query

from ..db import fetchall, fetchone, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like

router = APIRouter(prefix="/api/narratives", tags=["narratives"])

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,8}$")


@router.get("")
def list_narratives(limit: int = Query(12, ge=1, le=500)):
    """Top operational narratives — highest-priority CVEs that have news coverage."""
    # CVEs with at least one news mention, ordered by priority
    rows = fetchall(
        """SELECT c.cve_id, c.description, c.cvss_score, c.cvss_severity, c.epss_score,
                  c.is_kev, c.kev_added, c.kev_ransomware, c.priority, c.entities_json,
                  COUNT(n.id) AS news_count, MAX(n.published_at) AS last_seen
           FROM cves c
           LEFT JOIN news_refs r ON r.kind = 'cve' AND r.ref_id = c.cve_id
           LEFT JOIN news n ON n.id = r.news_id
           GROUP BY c.cve_id
           HAVING news_count > 0 OR c.is_kev = 1
           ORDER BY (c.priority + news_count * 4) DESC, last_seen DESC
           LIMIT ?""",
        (limit,),
    )
    out = []
    for r in rows:
        item = row_to_dict(r)
        item["news_count"] = r["news_count"]
        item["last_seen"] = r["last_seen"]
        out.append(item)
    return {"items": out}


@router.get("/{cve_id}")
def narrative(cve_id: str):
    cve_id = (cve_id or "").upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(400, "invalid CVE id")
    cve_row = fetchone(
        "SELECT cve_id, description, cvss_score, cvss_severity, cvss_vector, epss_score, epss_percentile, "
        "is_kev, kev_added, kev_ransomware, priority, entities_json, refs_json, published_at, last_modified "
        "FROM cves WHERE cve_id = ?",
        (cve_id,),
    )
    if cve_row is None:
        return {"cve": None, "timeline": []}
    cve = row_to_dict(cve_row)
    news_rows = fetchall(
        f"SELECT id, source_name, title, summary, url, published_at, priority, tags_json "
        f"FROM news WHERE cves_json LIKE ? {ESCAPE_CLAUSE} ORDER BY published_at ASC LIMIT 500",
        (f"%{like(cve_id)}%",),
    )
    timeline: list[dict] = []
    timeline.append({
        "kind": "cve_published",
        "at": cve["published_at"],
        "title": f"{cve_id} published",
        # description may be NULL for freshly-published CVEs that lack any
        # vendor / ADP enrichment yet.
        "detail": (cve.get("description") or "")[:240],
    })
    if cve["is_kev"] and cve.get("kev_added"):
        timeline.append({
            "kind": "kev_added",
            "at": cve["kev_added"],
            "title": "Added to CISA KEV catalog",
            "detail": f"Ransomware use: {cve.get('kev_ransomware') or 'unknown'}",
        })
    for n in news_rows:
        nd = row_to_dict(n)
        timeline.append({
            "kind": "news",
            "at": nd["published_at"],
            "title": nd["title"],
            "detail": nd.get("summary") or "",
            "source": nd["source_name"],
            "url": nd["url"],
            "tags": nd.get("tags", []),
        })
    timeline.sort(key=lambda x: x["at"])
    return {"cve": cve, "timeline": timeline}
