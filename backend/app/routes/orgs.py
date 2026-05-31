"""Organization monitoring routes.

For each configured org we surface:
  - direct mentions (news entities.orgs contains org id)
  - tech-stack CVE intersection (CVEs whose entities.vendors overlap org.tech_stack)
  - watch-keyword hits (phishing, breach, outage, etc.)
  - signal counts: breaches, ransomware, phishing, vuln mentions
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Query

from ..db import fetchall, load_taxonomy, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like as _esc_like

router = APIRouter(prefix="/api/orgs", tags=["orgs"])


def _org_or_404(org_id: str) -> dict:
    for o in load_taxonomy("orgs")["orgs"]:
        if o["id"] == org_id:
            return o
    raise HTTPException(404, f"Unknown org {org_id}")


def _direct_news(org_id: str, days: int, limit: int = 200) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    safe_id = _esc_like(org_id)
    rows = fetchall(
        f"SELECT * FROM news WHERE entities_json LIKE ? {ESCAPE_CLAUSE} AND published_at >= ? "
        "ORDER BY priority DESC, published_at DESC LIMIT ?",
        (f'%"orgs":%"id": "{safe_id}"%', since, limit),
    )
    # Fallback: SQLite LIKE pattern above is fragile against JSON spacing; use a looser match
    if not rows:
        rows = fetchall(
            f"SELECT * FROM news WHERE entities_json LIKE ? {ESCAPE_CLAUSE} AND published_at >= ? "
            "ORDER BY priority DESC, published_at DESC LIMIT ?",
            (f'%"id": "{safe_id}"%', since, limit),
        )
    return [row_to_dict(r) for r in rows]


def _stack_cves(org: dict, limit: int = 50) -> list[dict]:
    """CVEs that touch any vendor in the org's tech_stack."""
    stack = org.get("tech_stack", [])
    if not stack:
        return []
    parts = " OR ".join([f"entities_json LIKE ? {ESCAPE_CLAUSE}"] * len(stack))
    params = [f'%"id": "{_esc_like(v)}"%' for v in stack]
    rows = fetchall(
        f"SELECT cve_id, description, cvss_score, cvss_severity, epss_score, is_kev, "
        f"kev_added, kev_ransomware, priority, entities_json "
        f"FROM cves WHERE {parts} "
        f"ORDER BY priority DESC, is_kev DESC LIMIT ?",
        (*params, limit),
    )
    return [row_to_dict(r) for r in rows]


def _keyword_news(org: dict, days: int, limit: int = 50) -> list[dict]:
    """News titles/summaries containing watch keywords."""
    kws = org.get("watch_keywords", [])
    if not kws:
        return []
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    parts = " OR ".join([f"LOWER(title) LIKE ? {ESCAPE_CLAUSE}" for _ in kws]) + " OR " + \
            " OR ".join([f"LOWER(summary) LIKE ? {ESCAPE_CLAUSE}" for _ in kws])
    params = [f"%{_esc_like(k.lower())}%" for k in kws] * 2
    rows = fetchall(
        f"SELECT * FROM news WHERE ({parts}) AND published_at >= ? "
        f"ORDER BY priority DESC, published_at DESC LIMIT ?",
        (*params, since, limit),
    )
    return [row_to_dict(r) for r in rows]


def _signal_breakdown(news_items: list[dict]) -> dict[str, int]:
    counter: Counter = Counter()
    for n in news_items:
        for t in n.get("tags", []) or []:
            counter[t] += 1
    return dict(counter)


@router.get("/health")
def all_orgs_health(days: int = Query(90, ge=1, le=365)):
    from ..enrich.health import all_health
    return {"window_days": days, "orgs": all_health(days)}


@router.get("")
def list_orgs(days: int = Query(14, ge=1, le=365)):
    orgs_doc = load_taxonomy("orgs")["orgs"]
    out = []
    for o in orgs_doc:
        direct = _direct_news(o["id"], days=days, limit=30)
        kw = _keyword_news(o, days=days, limit=30)
        # dedupe keyword hits already present in direct
        direct_ids = {n["id"] for n in direct}
        kw_only = [n for n in kw if n["id"] not in direct_ids]
        signals = _signal_breakdown(direct + kw_only)
        stack = _stack_cves(o, limit=20)
        kev_stack = [c for c in stack if c.get("is_kev")]
        out.append({
            "id": o["id"],
            "name": o["name"],
            "sector": o.get("sector"),
            "country": o.get("country"),
            "ticker": o.get("ticker"),
            "brand_count": len(o.get("brands", [])),
            "subsidiary_count": len(o.get("subsidiaries", [])),
            "domain_count": len(o.get("domains", [])),
            "direct_mentions": len(direct),
            "keyword_hits": len(kw_only),
            "max_priority": max((n["priority"] for n in direct + kw_only), default=0),
            "signals": signals,
            "stack_cves": len(stack),
            "stack_kev": len(kev_stack),
            "latest": (direct + kw_only)[:5],
        })
    out.sort(key=lambda x: (x["stack_kev"], x["max_priority"], x["direct_mentions"]), reverse=True)
    return {"window_days": days, "orgs": out}


@router.get("/{org_id}")
def org_overview(org_id: str, days: int = Query(14, ge=1, le=365)):
    org = _org_or_404(org_id)
    return {
        "org": org,
        "window_days": days,
        "direct_mentions": _direct_news(org_id, days=days, limit=30),
        "keyword_hits": _keyword_news(org, days=days, limit=30),
        "stack_cves": _stack_cves(org, limit=40),
    }


@router.get("/{org_id}/health")
def org_health(org_id: str, days: int = Query(90, ge=1, le=365)):
    from ..enrich.health import compute
    h = compute(org_id, days=days)
    if h is None:
        raise HTTPException(404, f"Unknown org {org_id}")
    return h


@router.get("/{org_id}/execs")
def org_exec_mentions(org_id: str, days: int = Query(30, ge=1, le=365), limit: int = Query(20, ge=1, le=500)):
    """News items mentioning any executive in this org's key_executives list."""
    org = _org_or_404(org_id)
    execs = org.get("key_executives") or []
    if not execs:
        return {"org": {"id": org["id"], "name": org["name"]}, "executives": [],
                "mentions": []}
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows: list = []
    for name in execs:
        pat = f"%{_esc_like(name)}%"
        rs = fetchall(
            f"SELECT id, source_name, title, url, published_at, priority "
            f"FROM news WHERE published_at >= ? AND (title LIKE ? {ESCAPE_CLAUSE} OR summary LIKE ? {ESCAPE_CLAUSE}) "
            f"ORDER BY published_at DESC LIMIT ?",
            (since, pat, pat, limit),
        )
        for r in rs:
            d = row_to_dict(r)
            d["matched_exec"] = name
            rows.append(d)
    rows.sort(key=lambda x: x["published_at"], reverse=True)
    return {
        "org": {"id": org["id"], "name": org["name"]},
        "window_days": days,
        "executives": execs,
        "mentions": rows[:limit * 2],
    }


@router.get("/{org_id}/industry")
def org_industry(org_id: str, days: int = Query(90, ge=1, le=365)):
    """Industry events (layoffs / funding / acquisitions / exec changes) that
    mention the org via direct entity match or watch keyword."""
    import json as _json
    org = _org_or_404(org_id)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    direct = fetchall(
        f"SELECT * FROM news WHERE entities_json LIKE ? {ESCAPE_CLAUSE} AND industry_json != '{{}}' AND published_at >= ? "
        "ORDER BY published_at DESC LIMIT 100",
        (f'%"id": "{_esc_like(org_id)}"%', since),
    )
    # also keyword hits (e.g. "acme-corp breach")
    kws = org.get("watch_keywords", [])
    kw_rows = []
    if kws:
        parts = " OR ".join([f"LOWER(title) LIKE ? {ESCAPE_CLAUSE}" for _ in kws]) + " OR " + \
                " OR ".join([f"LOWER(summary) LIKE ? {ESCAPE_CLAUSE}" for _ in kws])
        params = [f"%{_esc_like(k.lower())}%" for k in kws] * 2
        kw_rows = fetchall(
            f"SELECT * FROM news WHERE ({parts}) AND industry_json != '{{}}' AND published_at >= ? "
            f"ORDER BY published_at DESC LIMIT 50",
            (*params, since),
        )
    seen: set[str] = set()
    items: list[dict] = []
    for r in list(direct) + list(kw_rows):
        d = row_to_dict(r)
        if d["id"] in seen:
            continue
        seen.add(d["id"])
        try:
            ind = _json.loads(r["industry_json"] or "{}")
        except Exception:
            ind = {}
        d["industry"] = ind
        items.append(d)
    # bucket by kind
    buckets: dict[str, list[dict]] = {}
    for it in items:
        for kind in it["industry"]:
            buckets.setdefault(kind, []).append(it)
    return {
        "org": {"id": org["id"], "name": org["name"]},
        "window_days": days,
        "events": items,
        "buckets": {k: len(v) for k, v in buckets.items()},
    }


@router.get("/{org_id}/alerts")
def org_alerts(org_id: str, days: int = Query(14, ge=1, le=365), limit: int = Query(60, ge=1, le=500)):
    """Unified prioritized alert feed for the org."""
    org = _org_or_404(org_id)
    direct = _direct_news(org_id, days=days, limit=limit)
    kw = _keyword_news(org, days=days, limit=limit)
    seen = {n["id"] for n in direct}
    items = list(direct)
    for n in kw:
        if n["id"] not in seen:
            n["_match"] = "keyword"
            items.append(n)
        seen.add(n["id"])
    for n in direct:
        n["_match"] = "direct"

    # tag stack-cve alerts
    stack = _stack_cves(org, limit=30)
    stack_alerts = [{
        "kind": "cve",
        "cve_id": c["cve_id"],
        "description": c.get("description", ""),
        "cvss_score": c.get("cvss_score"),
        "is_kev": c.get("is_kev"),
        "kev_added": c.get("kev_added"),
        "kev_ransomware": c.get("kev_ransomware"),
        "priority": c.get("priority"),
        "vendors": [v["name"] for v in (c.get("entities", {}).get("vendors") or [])
                    if v["id"] in org.get("tech_stack", [])],
    } for c in stack]

    return {
        "org": {"id": org["id"], "name": org["name"], "sector": org.get("sector"),
                "country": org.get("country"), "ticker": org.get("ticker")},
        "window_days": days,
        "news_alerts": sorted(items, key=lambda x: x["priority"], reverse=True)[:limit],
        "stack_alerts": sorted(stack_alerts, key=lambda x: (x.get("is_kev") or 0, x.get("priority") or 0), reverse=True),
        "signals": _signal_breakdown(items),
    }
