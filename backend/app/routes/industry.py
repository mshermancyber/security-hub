"""Tech industry intelligence endpoints.

All driven by news.industry_json (populated at ingest) + news.tags_json.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Query

from ..db import fetchall, row_to_dict

router = APIRouter(prefix="/api/industry", tags=["industry"])


def _since(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _rows_with_kind(kind: str, days: int, limit: int = 200) -> list[dict]:
    """Pull news rows whose industry_json contains a top-level key `kind`,
    deduped so multiple stories about the same event collapse into one.

    Dedup key: (primary-company-id, event-amount-bucket). Two stories
    about "Anthropic raises $65B" become one entry with `also_seen_in`
    listing the sibling sources.
    """
    # Over-fetch so we can dedup without losing the head of the list
    rows = fetchall(
        "SELECT * FROM news WHERE industry_json LIKE ? AND published_at >= ? "
        "ORDER BY published_at DESC LIMIT ?",
        (f'%"{kind}"%', _since(days), limit * 3),
    )
    parsed: list[dict] = []
    for r in rows:
        try:
            ind = json.loads(r["industry_json"] or "{}")
        except Exception:
            continue
        if kind not in ind:
            continue
        item = row_to_dict(r)
        item["event"] = ind[kind]
        parsed.append(item)

    # Build dedup key per item; collapse siblings
    by_key: dict[str, dict] = {}
    out: list[dict] = []
    for item in parsed:
        k = _event_dedup_key(kind, item)
        if k and k in by_key:
            parent = by_key[k]
            # Always count the merge so cluster_size reflects reality, even
            # when multiple stories from the same source pile on (e.g.
            # 8 HN submissions about the same SpaceX IPO).
            parent["cluster_size"] = (parent.get("cluster_size") or 1) + 1
            seen = {parent.get("source")} | {
                a.get("source") for a in (parent.get("also_seen_in") or [])
            }
            src = item.get("source")
            if src and src not in seen:
                parent.setdefault("also_seen_in", []).append({
                    "source": item.get("source"),
                    "source_name": item.get("source_name"),
                    "url": item.get("url"),
                    "published_at": item.get("published_at"),
                })
        else:
            out.append(item)
            if k:
                by_key[k] = item
    return out[:limit]


import re as _re_dedup

_TITLE_STOPWORDS = {
    "the", "a", "an", "how", "why", "did", "was", "this", "that", "what",
    "when", "who", "are", "is", "for", "with", "from", "and", "but", "or",
    "ask", "show", "yes", "no", "after", "before", "amid", "into", "over",
    "ahead", "behind", "up", "down", "in", "on", "at", "to", "of", "as",
    "more", "less", "new", "old", "big", "small", "ai", "tech",
}


def _company_from_title(title: str) -> str | None:
    """Heuristic: first capitalized 'word-like' token in title that isn't
    a stopword. Strips trailing possessive `'s` / `’s`. Returns a
    lowercased company-guess token for dedup keying — not a real entity
    ID, just stable enough to collapse 6 SpaceX-IPO headlines into one
    cluster.

    NOTE: `rstrip("'s")` is wrong — it's a character set, so "Pegasus"
    becomes "pegasu". Use a real suffix strip.
    """
    if not title:
        return None
    for raw in _re_dedup.findall(r"[A-Za-z][A-Za-z0-9'\-]+", title):
        if not raw[0].isupper():
            continue
        # Strip the possessive `'s` suffix; leave other 's intact.
        clean = _re_dedup.sub(r"['’]s$", "", raw).lower()
        clean = clean.rstrip("'’")
        if len(clean) < 3 or clean in _TITLE_STOPWORDS:
            continue
        return f"title:{clean}"
    return None


def _event_dedup_key(kind: str, item: dict) -> str | None:
    """Cluster key for industry events. Returns None when there's no
    primary company entity — those rows stay as-is.

    Dedup granularity is kind-aware:
      - Story-arc events (one per company, ever): ipo, stealth, yc,
        acquisition. Key = (kind|company) — every article about
        "SpaceX IPO" collapses into one entry no matter the angle.
      - Multi-event kinds (funding rounds, layoff waves, exec changes,
        product launches, outages, EOL): Key includes a magnitude
        bucket when present, otherwise a month bucket so distinct
        rounds / waves don't merge across time.
    """
    ents = item.get("entities") or {}
    company = None
    for ek in ("ai_companies", "vendors", "orgs"):
        arr = ents.get(ek) or []
        if arr:
            company = f"{ek}:{arr[0].get('id', '')}"
            break
    if not company:
        # Fallback: pull a company-name guess from the title's first
        # significant capitalized token. Handles companies we don't track
        # in taxonomy (SpaceX, Quantinuum, fresh startups, etc.) so they
        # still collapse across reworded headlines.
        company = _company_from_title(item.get("title") or "")
        if not company:
            return None

    # One-arc-per-company events: aggressive collapse
    if kind in ("ipo", "stealth", "yc", "acquisition", "bankruptcy"):
        return f"{kind}|{company}"

    ev = item.get("event") or {}
    # Bucket the magnitude to nearest order of magnitude so $65B and $65.0B match
    amt = ev.get("amount_usd") or ev.get("valuation_usd") or ev.get("headcount")
    if amt:
        try:
            n = float(amt)
        except (TypeError, ValueError):
            n = 0
        if n >= 1e12:    bucket = f"{round(n/1e12)}t"
        elif n >= 1e9:   bucket = f"{round(n/1e9)}b"
        elif n >= 1e6:   bucket = f"{round(n/1e6)}m"
        elif n >= 1e3:   bucket = f"{round(n/1e3)}k"
        else:            bucket = "small"
        return f"{kind}|{company}|{bucket}"
    # Fall back to month bucket (not day) — multiple stories about the
    # same exec change / outage spread over a week still collapse.
    sub = ev.get("round") or (item.get("published_at") or "")[:7]
    return f"{kind}|{company}|{sub}"


def _company_for(item: dict, prefer: list[str]) -> dict | None:
    ents = item.get("entities") or {}
    for kind in prefer:
        arr = ents.get(kind) or []
        if arr:
            return {"kind": kind, **arr[0]}
    return None


@router.get("/layoffs")
def layoffs(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(200, ge=1, le=500),
    min_headcount: int = Query(0, ge=0, le=10_000_000, description="Hide events below this headcount. 3000+ surfaces big-tech / large-company waves only."),
    sort: str = Query("date", description="date | headcount"),
):
    items = _rows_with_kind("layoff", days=days, limit=limit)
    if min_headcount > 0:
        items = [
            it for it in items
            if ((it.get("event") or {}).get("headcount") or 0) >= min_headcount
        ]
    if sort == "headcount":
        items.sort(key=lambda it: (it.get("event") or {}).get("headcount") or 0, reverse=True)
    total_headcount = 0
    with_headcount = 0
    ai_driven = 0
    freeze_only = 0
    by_company: Counter = Counter()
    for it in items:
        ev = it["event"]
        if ev.get("headcount"):
            total_headcount += ev["headcount"]
            with_headcount += 1
        if ev.get("ai_driven"):
            ai_driven += 1
        if ev.get("hiring_freeze") and not ev.get("headcount"):
            freeze_only += 1
        co = _company_for(it, ["ai_companies", "vendors", "orgs"])
        if co:
            by_company[(co["name"], co.get("kind"))] += 1
    return {
        "window_days": days,
        "items": items,
        "totals": {
            "events": len(items),
            "total_headcount": total_headcount,
            "events_with_headcount": with_headcount,
            "ai_driven_events": ai_driven,
            "hiring_freezes": freeze_only,
        },
        "top_companies": [
            {"name": n, "kind": k, "events": c} for (n, k), c in by_company.most_common(10)
        ],
    }


@router.get("/funding")
def funding(days: int = Query(30, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    items = _rows_with_kind("funding", days=days, limit=limit)
    total_raised = 0.0
    by_company: Counter = Counter()
    by_round: Counter = Counter()
    for it in items:
        ev = it["event"]
        if ev.get("amount_usd"):
            total_raised += ev["amount_usd"]
        if ev.get("round"):
            by_round[ev["round"]] += 1
        co = _company_for(it, ["ai_companies", "vendors", "orgs"])
        if co:
            by_company[(co["name"], co.get("kind"))] += 1
    return {
        "window_days": days,
        "items": items,
        "totals": {
            "events": len(items),
            "total_raised_usd": total_raised,
            "rounds": dict(by_round),
        },
        "top_companies": [
            {"name": n, "kind": k, "events": c} for (n, k), c in by_company.most_common(10)
        ],
    }


@router.get("/acquisitions")
def acquisitions(days: int = Query(60, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    items = _rows_with_kind("acquisition", days=days, limit=limit)
    total_value = 0.0
    deals_with_amount = 0
    for it in items:
        ev = it["event"]
        if ev.get("amount_usd"):
            total_value += ev["amount_usd"]
            deals_with_amount += 1
    return {
        "window_days": days,
        "items": items,
        "totals": {
            "events": len(items),
            "total_value_usd": total_value,
            "deals_with_amount": deals_with_amount,
        },
    }


@router.get("/execs")
def execs(days: int = Query(60, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    items = _rows_with_kind("exec_change", days=days, limit=limit)
    by_role: Counter = Counter()
    by_dir: Counter = Counter()
    by_company: Counter = Counter()
    for it in items:
        ev = it["event"]
        if ev.get("role"):      by_role[ev["role"]] += 1
        if ev.get("direction"): by_dir[ev["direction"]] += 1
        co = _company_for(it, ["vendors", "ai_companies", "orgs"])
        if co:
            by_company[(co["name"], co.get("kind"))] += 1
    return {
        "window_days": days,
        "items": items,
        "totals": {
            "events": len(items),
            "by_role": dict(by_role),
            "by_direction": dict(by_dir),
        },
        "top_companies": [
            {"name": n, "kind": k, "events": c} for (n, k), c in by_company.most_common(10)
        ],
    }


@router.get("/products")
def products(days: int = Query(30, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    """Combined product events: launch, EOL, outage."""
    launches = _rows_with_kind("product_launch", days=days, limit=limit)
    eols     = _rows_with_kind("eol", days=days, limit=limit)
    outages  = _rows_with_kind("outage", days=days, limit=limit)
    return {
        "window_days": days,
        "launches": launches,
        "eols": eols,
        "outages": outages,
        "totals": {
            "launches": len(launches), "eols": len(eols), "outages": len(outages),
        },
    }


@router.get("/ipos")
def ipos(days: int = Query(60, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    items = _rows_with_kind("ipo", days=days, limit=limit)
    return {"window_days": days, "items": items, "totals": {"events": len(items)}}


@router.get("/bankruptcy")
def bankruptcy(days: int = Query(90, ge=1, le=365), limit: int = Query(200, ge=1, le=500),
               sort: str = Query("date", description="date | debt")):
    items = _rows_with_kind("bankruptcy", days=days, limit=limit)
    if sort == "debt":
        items.sort(key=lambda it: (it.get("event") or {}).get("debt_usd") or 0, reverse=True)
    total_debt = 0.0
    by_chapter: Counter = Counter()
    for it in items:
        ev = it.get("event") or {}
        if ev.get("debt_usd"):
            total_debt += ev["debt_usd"]
        if ev.get("chapter"):
            by_chapter[f"chapter-{ev['chapter']}"] += 1
    return {
        "window_days": days,
        "items": items,
        "totals": {
            "events": len(items),
            "total_debt_usd": total_debt,
            "by_chapter": dict(by_chapter),
        },
    }


@router.get("/crypto-scams")
def crypto_scams(days: int = Query(30, ge=1, le=365), limit: int = Query(200, ge=1, le=500),
                 sort: str = Query("date", description="date | amount")):
    items = _rows_with_kind("crypto_scam", days=days, limit=limit)
    if sort == "amount":
        items.sort(key=lambda it: (it.get("event") or {}).get("amount_usd") or 0, reverse=True)
    total_stolen = 0.0
    by_kind: Counter = Counter()
    by_asset: Counter = Counter()
    for it in items:
        ev = it.get("event") or {}
        if ev.get("amount_usd"):
            total_stolen += ev["amount_usd"]
        if ev.get("kind"):
            by_kind[ev["kind"]] += 1
        for a in (ev.get("assets") or []):
            by_asset[a] += 1
    return {
        "window_days": days,
        "items": items,
        "totals": {
            "events": len(items),
            "total_stolen_usd": total_stolen,
            "by_kind": dict(by_kind),
            "by_asset": dict(by_asset),
        },
    }


@router.get("/startups")
def startups(days: int = Query(60, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    """Startup discovery — stealth emergence + YC announcements + seed-stage funding."""
    stealth = _rows_with_kind("stealth", days=days, limit=limit)
    yc      = _rows_with_kind("yc", days=days, limit=limit)
    # seed-stage funding from funding events
    funding_items = _rows_with_kind("funding", days=days, limit=limit)
    seed = [it for it in funding_items
            if (it["event"].get("round") or "").lower().startswith(("seed", "pre"))]
    return {
        "window_days": days,
        "stealth": stealth,
        "yc": yc,
        "seed_rounds": seed,
        "totals": {
            "stealth": len(stealth), "yc": len(yc), "seed_rounds": len(seed),
        },
    }


@router.get("/signals")
def signals(days: int = Query(30, ge=1, le=365)):
    """One-shot summary of all industry signals for status-bar / overview chips."""
    return {
        "window_days": days,
        "layoffs":      len(_rows_with_kind("layoff", days=days)),
        "funding":      len(_rows_with_kind("funding", days=days)),
        "acquisitions": len(_rows_with_kind("acquisition", days=days)),
        "execs":        len(_rows_with_kind("exec_change", days=days)),
        "launches":     len(_rows_with_kind("product_launch", days=days)),
        "eols":         len(_rows_with_kind("eol", days=days)),
        "outages":      len(_rows_with_kind("outage", days=days)),
        "ipos":         len(_rows_with_kind("ipo", days=days)),
        "stealth":      len(_rows_with_kind("stealth", days=days)),
        "yc":           len(_rows_with_kind("yc", days=days)),
        "bankruptcy":   len(_rows_with_kind("bankruptcy", days=days)),
        "crypto_scams": len(_rows_with_kind("crypto_scam", days=days)),
    }
