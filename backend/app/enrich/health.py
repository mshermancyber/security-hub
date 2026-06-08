"""Per-organization composite health scoring.

Inputs (90-day window unless noted):
  - layoff events on / about the org           (negative)
  - hiring freezes                              (negative)
  - executive departures                        (mildly negative; "out" only)
  - funding rounds                              (positive)
  - acquisitions naming the org as acquirer     (positive)
  - direct breach / phishing / ransomware tags  (sharply negative)
  - outages with org name                       (negative)
  - KEV CVEs affecting tech_stack               (negative weight)
  - news mention volume                         (saturating; high volume + neutral tags = mildly positive)

Output:
  score: int 0–100 (higher = healthier)
  state: STABLE / GROWING / DISTRESSED / UNDER ATTACK / HIGH RISK
  factors: contribution breakdown for transparency
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..db import fetchall, fetchone, load_taxonomy, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like


def _direct_news_rows(org_id: str, days: int):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    return fetchall(
        f"SELECT id, source_name, title, priority, tags_json, industry_json, published_at "
        f"FROM news WHERE entities_json LIKE ? {ESCAPE_CLAUSE} AND published_at >= ? "
        f"ORDER BY priority DESC LIMIT 200",
        (f'%"id": "{like(org_id)}"%', since),
    )


def _stack_kev(org: dict):
    stack = org.get("tech_stack") or []
    if not stack:
        return []
    parts = " OR ".join([f"entities_json LIKE ? {ESCAPE_CLAUSE}"] * len(stack))
    params = [f'%"id": "{like(v)}"%' for v in stack]
    return fetchall(
        f"SELECT cve_id, priority, is_kev FROM cves WHERE is_kev=1 AND ({parts}) ORDER BY priority DESC LIMIT 50",
        tuple(params),
    )


def compute(org_id: str, *, days: int = 90) -> dict | None:
    orgs = load_taxonomy("orgs").get("orgs", [])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if org is None:
        return None

    news = [row_to_dict(r) for r in _direct_news_rows(org_id, days)]
    stack_kev = [dict(r) for r in _stack_kev(org)]

    layoff_events = 0
    layoff_headcount = 0
    freezes = 0
    exec_out = 0
    funding_events = 0
    acquisitions_as_acquirer = 0
    breach_mentions = 0
    phishing_mentions = 0
    ransomware_mentions = 0
    outages = 0
    ai_driven_cuts = 0

    for n in news:
        tags = set(n.get("tags") or [])
        ind = n.get("industry") or {}
        if "layoff" in tags or "layoff" in ind:
            layoff_events += 1
            lay = ind.get("layoff") or {}
            if lay.get("headcount"):  layoff_headcount += int(lay["headcount"])
            if lay.get("hiring_freeze"): freezes += 1
            if lay.get("ai_driven"):  ai_driven_cuts += 1
        if "exec_change" in ind and (ind["exec_change"] or {}).get("direction") == "out":
            exec_out += 1
        if "funding" in ind:
            funding_events += 1
        if "acquisition" in ind:
            acq = ind["acquisition"] or {}
            if (acq.get("acquirer") or "").lower().find(org["name"].lower()) >= 0:
                acquisitions_as_acquirer += 1
        if "breach" in tags:        breach_mentions += 1
        if "phishing" in tags:      phishing_mentions += 1
        if "ransomware" in tags:    ransomware_mentions += 1
        if "outage" in ind:         outages += 1

    kev_stack = len(stack_kev)

    # Score: start at 70 (neutral) and adjust.
    score = 70.0
    factors: list[dict] = []

    def add(label: str, delta: float):
        nonlocal score
        score += delta
        if abs(delta) >= 0.5:
            factors.append({"label": label, "delta": round(delta, 1)})

    # Negative pressures
    add("layoff events", -3 * layoff_events)
    add("layoff headcount > 1000", -8 if layoff_headcount >= 1000 else 0)
    add("ai-driven workforce cuts", -3 * ai_driven_cuts)
    add("hiring freezes", -2 * freezes)
    add("exec departures", -2 * exec_out)
    add("confirmed breach mentions", -8 * breach_mentions)
    add("phishing campaigns", -2 * phishing_mentions)
    add("ransomware mentions", -10 * ransomware_mentions)
    add("outages", -3 * outages)
    add("KEV CVEs on tech stack", -0.4 * min(kev_stack, 25))

    # Positive pressures
    add("funding rounds", +4 * funding_events)
    add("acquisitions as acquirer", +3 * acquisitions_as_acquirer)

    # Saturating mention volume bonus (small)
    add("news visibility", min(4.0, len(news) * 0.05))

    score = max(0, min(100, round(score)))

    # State
    if score >= 80:
        if funding_events >= 2 or acquisitions_as_acquirer >= 1:
            state = "GROWING"
        else:
            state = "STABLE"
    elif score >= 60:
        state = "STABLE"
    elif score >= 40:
        state = "DISTRESSED"
    elif breach_mentions or ransomware_mentions:
        state = "UNDER ATTACK"
    else:
        state = "HIGH RISK"

    return {
        "org_id": org["id"],
        "org_name": org["name"],
        "window_days": days,
        "score": int(score),
        "state": state,
        "factors": sorted(factors, key=lambda f: f["delta"]),
        "counts": {
            "layoff_events": layoff_events,
            "layoff_headcount": layoff_headcount,
            "ai_driven_cuts": ai_driven_cuts,
            "hiring_freezes": freezes,
            "exec_departures": exec_out,
            "funding_events": funding_events,
            "acquisitions_as_acquirer": acquisitions_as_acquirer,
            "breach_mentions": breach_mentions,
            "phishing_mentions": phishing_mentions,
            "ransomware_mentions": ransomware_mentions,
            "outages": outages,
            "kev_stack": kev_stack,
            "total_mentions": len(news),
        },
    }


def all_health(days: int = 90) -> list[dict]:
    out = []
    for o in load_taxonomy("orgs").get("orgs", []):
        h = compute(o["id"], days=days)
        if h:
            out.append(h)
    out.sort(key=lambda x: x["score"])
    return out
