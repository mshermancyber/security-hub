"""Priority scoring — turns raw items into ranked operational intelligence."""
from __future__ import annotations

import re


def cve_priority(*, cvss: float | None, epss: float | None, is_kev: bool, kev_ransomware: str | None,
                 has_public_poc: bool = False, mentioned_in_news: int = 0) -> int:
    """0-100 priority for a CVE. Operational, not academic."""
    score = 0
    if cvss is not None:
        score += int(cvss * 4)  # 0-40
    if epss is not None:
        score += int(epss * 25)  # 0-25
    if is_kev:
        score += 30
    if kev_ransomware and kev_ransomware.lower() == "known":
        score += 15
    if has_public_poc:
        score += 10
    score += min(15, mentioned_in_news * 3)
    return max(0, min(100, score))


def cve_priority_breakdown(*, cvss, epss, is_kev, kev_ransomware,
                           has_public_poc=False, mentioned_in_news=0) -> dict:
    """Return the same total + a labeled breakdown for tooltips."""
    parts = []
    if cvss is not None: parts.append({"label": f"CVSS {cvss}",            "value": int(cvss * 4)})
    if epss is not None: parts.append({"label": f"EPSS {round(epss*100,1)}%", "value": int(epss * 25)})
    if is_kev:           parts.append({"label": "KEV listed",              "value": 30})
    if kev_ransomware and kev_ransomware.lower() == "known":
        parts.append({"label": "Known ransomware use", "value": 15})
    if has_public_poc:   parts.append({"label": "Public PoC available",    "value": 10})
    if mentioned_in_news > 0:
        parts.append({"label": f"News mentions ({mentioned_in_news})", "value": min(15, mentioned_in_news * 3)})
    total = max(0, min(100, sum(p["value"] for p in parts)))
    return {"total": total, "parts": parts}


# ----- magnitude bumps for news -----------------------------------------

_RECORDS_RE = re.compile(
    r"(\d+(?:[,\.]\d{3})*(?:\.\d+)?)\s*(thousand|k|million|m|mn|billion|b|bn)?\s*"
    r"(?:customer|user|account|patient|individual|employee|record|user\s+record|customer\s+record)s?",
    re.IGNORECASE,
)
_RANSOM_USD_RE = re.compile(
    r"(?:ransom(?:\s+demand|\s+payment)?\s+of|paid|demanded|sought)\s+\$?(\d+(?:\.\d+)?)\s*"
    r"(thousand|k|million|m|bn|billion|b)?",
    re.IGNORECASE,
)


def _to_scale(n: str, unit: str | None) -> float:
    try:
        v = float(n.replace(",", ""))
    except Exception:
        return 0
    u = (unit or "").lower()
    return v * {"k": 1_000, "thousand": 1_000,
                "m": 1_000_000, "mn": 1_000_000, "million": 1_000_000,
                "b": 1_000_000_000, "bn": 1_000_000_000, "billion": 1_000_000_000}.get(u, 1)


def magnitude_bump(text: str) -> dict:
    """Detect a breach record count or ransom amount in text and return
    a priority bump suggestion with a labeled component."""
    if not text:
        return {"bump": 0, "parts": []}
    parts = []
    bump = 0
    m = _RECORDS_RE.search(text)
    if m:
        scale = _to_scale(m.group(1), m.group(2))
        if scale >= 100_000_000:
            bump = max(bump, 35); parts.append({"label": f"breach ≥ 100M records ({scale:,.0f})", "value": 35})
        elif scale >= 10_000_000:
            bump = max(bump, 25); parts.append({"label": f"breach ≥ 10M records ({scale:,.0f})", "value": 25})
        elif scale >= 1_000_000:
            bump = max(bump, 15); parts.append({"label": f"breach ≥ 1M records ({scale:,.0f})", "value": 15})
        elif scale >= 100_000:
            bump = max(bump, 8);  parts.append({"label": f"breach ≥ 100k records ({scale:,.0f})", "value": 8})
    r = _RANSOM_USD_RE.search(text)
    if r:
        amount = _to_scale(r.group(1), r.group(2))
        if amount >= 100_000_000:
            bump += 20; parts.append({"label": f"ransom ≥ $100M (${amount:,.0f})", "value": 20})
        elif amount >= 10_000_000:
            bump += 12; parts.append({"label": f"ransom ≥ $10M (${amount:,.0f})", "value": 12})
        elif amount >= 1_000_000:
            bump += 6;  parts.append({"label": f"ransom ≥ $1M (${amount:,.0f})", "value": 6})
    return {"bump": bump, "parts": parts}


# ----- news priority -----------------------------------------------------


def news_priority(*, reliability: int, severity: int, recency_hours: float,
                  entity_hits: int, feed_bump: int = 0, magnitude_bump: int = 0) -> int:
    """0-100 priority for a news item. `feed_bump` is the per-source bonus
    from sources.json; `magnitude_bump` is the breach-size / ransom-amount
    bonus from the news body."""
    score = 0
    score += severity // 2                  # up to 50 from severity
    score += reliability // 4               # up to ~24 from source
    if recency_hours <= 1:    score += 20
    elif recency_hours <= 6:  score += 14
    elif recency_hours <= 24: score += 8
    elif recency_hours <= 72: score += 3
    score += min(15, entity_hits * 3)
    score += feed_bump
    score += magnitude_bump
    return max(0, min(100, score))


def severity_label(score: int) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 45: return "ELEVATED"
    if score >= 20: return "GUARDED"
    return "LOW"
