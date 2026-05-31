"""Intel-depth endpoints: narrative graph, velocity, source-conflict."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Query

from ..enrich.conflict import detect_conflicts
from ..enrich.graph import narrative_graph
from ..enrich.velocity import epss_distribution, industry_velocity, kev_velocity, news_volume

router = APIRouter(prefix="/api/intel", tags=["intel"])

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,8}$")


@router.get("/graph/{cve_id}")
def graph(cve_id: str):
    cve_id = (cve_id or "").upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(400, "invalid CVE id")
    return narrative_graph(cve_id)


@router.get("/velocity/kev")
def velocity_kev(days: int = Query(60, ge=1, le=365)):
    return kev_velocity(days)


@router.get("/velocity/news")
def velocity_news(days: int = Query(14, ge=1, le=365)):
    return news_volume(days)


@router.get("/velocity/industry")
def velocity_industry(days: int = Query(30, ge=1, le=365)):
    return industry_velocity(days)


@router.get("/velocity/epss")
def velocity_epss():
    return epss_distribution()


@router.get("/conflicts")
def conflicts(days: int = Query(30, ge=1, le=365)):
    return {"window_days": days, "conflicts": detect_conflicts(days)}


@router.get("/kev-watch")
def kev_watch(limit: int = Query(40, ge=1, le=500),
              min_epss: float = Query(0.5, ge=0.0, le=1.0),
              min_cvss: float = Query(7.5, ge=0.0, le=10.0)):
    """Predicted-KEV: CVEs that look likely to be added to CISA KEV next.

    Criteria:
      - Not yet in KEV
      - EPSS ≥ min_epss (default 0.5)
      - CVSS ≥ min_cvss (default 7.5)
      - At least one of: news with `active-exploitation` tag, news count ≥ 2.
    """
    from ..db import fetchall, row_to_dict
    rows = fetchall(
        """SELECT c.cve_id, c.description, c.cvss_score, c.cvss_severity,
                  c.epss_score, c.epss_percentile, c.priority, c.published_at,
                  c.entities_json, c.refs_json,
                  COUNT(DISTINCT n.id) AS news_count,
                  SUM(CASE WHEN n.tags_json LIKE '%active-exploitation%' THEN 1 ELSE 0 END) AS active_news,
                  MAX(n.priority) AS news_max_priority,
                  MAX(n.published_at) AS last_news
           FROM cves c
           LEFT JOIN news_refs r ON r.kind = 'cve' AND r.ref_id = c.cve_id
           LEFT JOIN news n ON n.id = r.news_id
           WHERE c.is_kev = 0
             AND c.cvss_score >= ?
             AND c.epss_score >= ?
           GROUP BY c.cve_id
           ORDER BY c.epss_score DESC, c.cvss_score DESC
           LIMIT ?""",
        (min_cvss, min_epss, limit),
    )
    items = []
    for r in rows:
        d = row_to_dict(r)
        d["news_count"] = r["news_count"]
        d["active_news"] = r["active_news"]
        d["news_max_priority"] = r["news_max_priority"]
        d["last_news"] = r["last_news"]
        conf = float(d.get("epss_score") or 0) * 60
        conf += min(20, int(r["news_count"]) * 4)
        conf += 20 if (r["active_news"] or 0) > 0 else 0
        d["predicted_kev_confidence"] = round(min(100, conf), 1)
        items.append(d)
    items.sort(key=lambda x: x["predicted_kev_confidence"], reverse=True)
    return {"items": items, "criteria": {"min_epss": min_epss, "min_cvss": min_cvss}}
