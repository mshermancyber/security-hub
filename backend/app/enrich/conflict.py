"""Source-conflict detection.

Cluster news items that talk about the same event (same CVE, same layoff
subject, etc.) and flag when the extracted numbers disagree across
independent sources.

Examples surfaced:
  - One source reports "5,000 layoffs", another reports "10,000"
  - Funding amount differs between TechCrunch and HN
  - Breach confirmed vs. denied by different feeds
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from ..db import fetchall, row_to_dict


def _norm_company(item: dict) -> str | None:
    ents = item.get("entities") or {}
    for kind in ("ai_companies", "vendors", "orgs"):
        arr = ents.get(kind) or []
        if arr:
            return arr[0]["name"]
    return None


def _ratio(a: int | float, b: int | float) -> float:
    if not a or not b:
        return 0.0
    return min(a, b) / max(a, b)


def detect_conflicts(days: int = 30) -> list[dict]:
    """Return conflict clusters."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = fetchall(
        "SELECT id, source, source_name, title, url, published_at, "
        "       priority, cves_json, entities_json, industry_json "
        "FROM news WHERE published_at >= ? AND industry_json != '{}' "
        "ORDER BY published_at DESC",
        (since,),
    )
    items = [row_to_dict(r) for r in rows]

    # Bucket layoff events by company name
    layoff_buckets: dict[str, list[dict]] = defaultdict(list)
    funding_buckets: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        ind = it.get("industry") or {}
        co = _norm_company(it)
        if not co:
            continue
        if "layoff" in ind:
            layoff_buckets[co].append(it)
        if "funding" in ind:
            funding_buckets[co].append(it)

    conflicts: list[dict] = []

    # Layoff headcount disagreement
    for co, bucket in layoff_buckets.items():
        sources = {it["source"]: it for it in bucket}
        if len(sources) < 2:
            continue
        hc = []
        for it in sources.values():
            n = ((it.get("industry") or {}).get("layoff") or {}).get("headcount")
            if n:
                hc.append((it, n))
        if len(hc) < 2:
            continue
        nums = [n for _, n in hc]
        mn, mx = min(nums), max(nums)
        if mn == mx:
            continue
        ratio = _ratio(mn, mx)
        if ratio < 0.85:  # >15% disagreement
            conflicts.append({
                "kind": "layoff_headcount",
                "subject": co,
                "agreement": round(ratio, 2),
                "values": [{"source": it["source_name"], "value": n,
                            "news_id": it["id"], "url": it.get("url"),
                            "title": it.get("title")}
                           for it, n in hc],
            })

    # Funding amount disagreement
    for co, bucket in funding_buckets.items():
        sources = {it["source"]: it for it in bucket}
        if len(sources) < 2:
            continue
        amts = []
        for it in sources.values():
            a = ((it.get("industry") or {}).get("funding") or {}).get("amount_usd")
            if a:
                amts.append((it, a))
        if len(amts) < 2:
            continue
        vals = [a for _, a in amts]
        mn, mx = min(vals), max(vals)
        if mn == mx:
            continue
        ratio = _ratio(mn, mx)
        if ratio < 0.9:
            conflicts.append({
                "kind": "funding_amount",
                "subject": co,
                "agreement": round(ratio, 2),
                "values": [{"source": it["source_name"], "value": a,
                            "news_id": it["id"], "url": it.get("url"),
                            "title": it.get("title")}
                           for it, a in amts],
            })

    # CVE coverage conflict — items mention same CVE but one calls it "actively
    # exploited" and another doesn't carry the tag (signal: under-reporting)
    cve_buckets: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        for cve in it.get("cves") or []:
            cve_buckets[cve].append(it)
    for cve, bucket in cve_buckets.items():
        if len(bucket) < 2:
            continue
        sources = {it["source"]: it for it in bucket}
        if len(sources) < 2:
            continue
        with_active = [it for it in sources.values() if "active-exploitation" in (it.get("tags") or [])]
        without = [it for it in sources.values() if "active-exploitation" not in (it.get("tags") or [])]
        if with_active and without and len(with_active) <= len(without) - 2:
            conflicts.append({
                "kind": "exploitation_claim_divergence",
                "subject": cve,
                "agreement": round(len(with_active) / len(sources), 2),
                "values": [
                    *({"source": it["source_name"], "value": "actively-exploited",
                       "news_id": it["id"], "url": it.get("url"), "title": it.get("title")}
                      for it in with_active),
                    *({"source": it["source_name"], "value": "no exploit claim",
                       "news_id": it["id"], "url": it.get("url"), "title": it.get("title")}
                      for it in without[:3]),
                ],
            })

    conflicts.sort(key=lambda c: c["agreement"])
    return conflicts
