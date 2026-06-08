"""CVE / vulnerability intelligence endpoints."""
from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Query

from ..db import fetchall, fetchone, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like

router = APIRouter(prefix="/api/vulns", tags=["vulnerabilities"])

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,8}$")
_VALID_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@router.get("")
def list_vulns(
    limit: int = Query(80, ge=1, le=300),
    min_priority: int = Query(0, ge=0, le=100),
    only_kev: bool = False,
    severity: str | None = Query(None, max_length=16),
    q: str | None = Query(None, max_length=200),
):
    where = ["priority >= ?"]
    params: list = [min_priority]
    if only_kev:
        where.append("is_kev = 1")
    if severity:
        sev = severity.upper()
        if sev not in _VALID_SEVERITY:
            raise HTTPException(400, "invalid severity (LOW|MEDIUM|HIGH|CRITICAL)")
        where.append("cvss_severity = ?")
        params.append(sev)
    if q:
        esc = like(q)
        where.append(f"(cve_id LIKE ? {ESCAPE_CLAUSE} OR description LIKE ? {ESCAPE_CLAUSE})")
        params.extend([f"%{esc}%", f"%{esc}%"])
    where_sql = " AND ".join(where)
    rows = fetchall(
        f"SELECT cve_id, published_at, last_modified, description, cvss_score, cvss_severity, "
        f"epss_score, epss_percentile, is_kev, kev_added, kev_ransomware, priority, entities_json, "
        f"refs_json, cwe_json FROM cves WHERE {where_sql} "
        f"ORDER BY priority DESC, published_at DESC LIMIT ?",
        (*params, limit),
    )
    return {"items": [row_to_dict(r) for r in rows]}


@router.get("/kev")
def kev_only(limit: int = Query(200, ge=1, le=500)):
    rows = fetchall(
        "SELECT cve_id, description, cvss_score, cvss_severity, epss_score, kev_added, kev_ransomware, "
        "priority, entities_json FROM cves WHERE is_kev = 1 ORDER BY kev_added DESC LIMIT ?",
        (limit,),
    )
    return {"items": [row_to_dict(r) for r in rows]}


@router.get("/{cve_id}/score-breakdown")
def cve_score_breakdown(cve_id: str):
    """Return the priority components for a CVE — used by the
    "why prioritized?" tooltip on KEV/Vuln rows."""
    cve_id = (cve_id or "").upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(400, "invalid CVE id")
    from ..enrich.scoring import cve_priority_breakdown
    row = fetchone(
        "SELECT cvss_score, epss_score, is_kev, kev_ransomware FROM cves WHERE cve_id = ?",
        (cve_id,),
    )
    if row is None:
        raise HTTPException(404, "Not found")
    n_row = fetchone(
        "SELECT COUNT(*) AS n FROM news_refs WHERE kind='cve' AND ref_id = ?",
        (cve_id,),
    )
    n = n_row["n"] if n_row else 0
    return cve_priority_breakdown(
        cvss=row["cvss_score"], epss=row["epss_score"],
        is_kev=bool(row["is_kev"]), kev_ransomware=row["kev_ransomware"],
        mentioned_in_news=n,
    )


@router.get("/{cve_id}")
def get_cve(cve_id: str):
    cve_id = (cve_id or "").upper()
    if not _CVE_RE.match(cve_id):
        raise HTTPException(400, "invalid CVE id")
    row = fetchone(
        "SELECT cve_id, published_at, last_modified, description, cvss_score, cvss_severity, cvss_vector, "
        "epss_score, epss_percentile, is_kev, kev_added, kev_ransomware, priority, entities_json, "
        "refs_json, cwe_json FROM cves WHERE cve_id = ?",
        (cve_id,),
    )
    if row is None:
        raise HTTPException(404, "Not found")
    item = row_to_dict(row)
    related = fetchall(
        f"SELECT id, source_name, title, url, published_at, priority FROM news "
        f"WHERE cves_json LIKE ? {ESCAPE_CLAUSE} ORDER BY published_at DESC LIMIT 20",
        (f"%{like(cve_id)}%",),
    )
    item["news"] = [row_to_dict(r) for r in related]
    return item
