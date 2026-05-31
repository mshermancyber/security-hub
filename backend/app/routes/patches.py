"""Patch advisory view — Microsoft Patch Tuesday + RHEL + Amazon Linux."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query

from ..db import fetchall, row_to_dict

router = APIRouter(prefix="/api/patches", tags=["patches"])


_VENDOR_SOURCES = {
    "microsoft":    {"sources": ["msrc"],                    "label": "Microsoft", "monthly": True},
    # Pull both the blog (commentary) AND the security-data API (actual CVE details).
    "redhat":       {"sources": ["rhsa-blog", "redhat-cve"],  "label": "Red Hat",   "monthly": False},
    "amazon-linux": {"sources": ["alas-al2", "alas-al2023"], "label": "Amazon Linux", "monthly": False},
    "cisco":        {"sources": ["cisco-psirt"],             "label": "Cisco",     "monthly": False},
    "atlassian":    {"sources": ["atlassian-psirt"],         "label": "Atlassian", "monthly": False},
    "apple":        {"sources": ["apple-security"],          "label": "Apple",     "monthly": False},
    "ivanti":       {"sources": ["ivanti-psirt"],            "label": "Ivanti",    "monthly": False},
    "aws":          {"sources": ["aws-bulletins"],           "label": "AWS",       "monthly": False},
    "google":       {"sources": ["google-security"],         "label": "Google",    "monthly": False},
}


def _vendor_filter(vendor: str) -> tuple[list[str], dict]:
    cfg = _VENDOR_SOURCES.get(vendor)
    if not cfg:
        return [], {}
    return cfg["sources"], cfg


@router.get("")
def list_patches(vendor: str = "microsoft", days: int = Query(60, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    """Vendor advisories grouped by month. Microsoft uses MSRC; RHEL uses
    the RHSA blog feed; Amazon Linux uses the ALAS RSS."""
    sources, cfg = _vendor_filter(vendor)
    if not sources:
        return {"vendor": vendor, "items": [], "groups": []}
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    qmarks = ",".join("?" for _ in sources)
    rows = fetchall(
        f"SELECT id, source, source_name, title, summary, url, published_at, priority, "
        f"       tags_json, cves_json, severity "
        f"FROM news WHERE source IN ({qmarks}) AND published_at >= ? "
        f"ORDER BY published_at DESC LIMIT ?",
        (*sources, since, limit),
    )
    items = [row_to_dict(r) for r in rows]
    # Group by year-month
    groups: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        ym = (it.get("published_at") or "")[:7]  # YYYY-MM
        groups[ym].append(it)
    grouped = [
        {"month": k, "count": len(v), "items": v}
        for k, v in sorted(groups.items(), reverse=True)
    ]
    return {
        "vendor": vendor,
        "label": cfg.get("label"),
        "monthly": cfg.get("monthly", False),
        "window_days": days,
        "total": len(items),
        "groups": grouped,
    }


@router.get("/summary")
def patch_summary(days: int = Query(60, ge=1, le=365)):
    """Cross-vendor summary — counts per vendor for status-bar / overview."""
    out = []
    for vendor, cfg in _VENDOR_SOURCES.items():
        sources = cfg["sources"]
        qmarks = ",".join("?" for _ in sources)
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        row = fetchall(
            f"SELECT COUNT(*) AS n, MAX(published_at) AS latest FROM news "
            f"WHERE source IN ({qmarks}) AND published_at >= ?",
            (*sources, since),
        )[0]
        out.append({
            "vendor": vendor, "label": cfg["label"],
            "count": row["n"], "latest": row["latest"],
        })
    return {"window_days": days, "vendors": out}
