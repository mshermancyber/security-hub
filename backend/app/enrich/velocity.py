"""Time-series aggregations: KEV adds, EPSS shifts, news volume."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..db import fetchall


def kev_velocity(days: int = 60) -> dict:
    """KEV additions per day for the last N days."""
    rows = fetchall(
        "SELECT substr(kev_added, 1, 10) AS day, COUNT(*) AS n, "
        "       SUM(CASE WHEN kev_ransomware = 'Known' THEN 1 ELSE 0 END) AS ransom "
        "FROM cves WHERE is_kev = 1 AND kev_added IS NOT NULL "
        "GROUP BY day ORDER BY day"
    )
    today = datetime.now(timezone.utc).date()
    cutoff = today - timedelta(days=days)
    rows = [(r["day"], r["n"], r["ransom"]) for r in rows if r["day"] and r["day"] >= cutoff.isoformat()]
    # Densify (fill missing days with zero)
    day_map = {d: (n, r) for d, n, r in rows}
    out = []
    for i in range(days, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        n, ransom = day_map.get(d, (0, 0))
        out.append({"day": d, "kev_adds": n, "ransomware_use": ransom})
    return {"window_days": days, "series": out,
            "total_kev_adds": sum(p["kev_adds"] for p in out),
            "total_ransom": sum(p["ransomware_use"] for p in out)}


def news_volume(days: int = 14) -> dict:
    """High-priority news count per day."""
    rows = fetchall(
        "SELECT substr(published_at, 1, 10) AS day, COUNT(*) AS n, "
        "       SUM(CASE WHEN priority >= 70 THEN 1 ELSE 0 END) AS hi, "
        "       AVG(priority) AS avg_prio "
        "FROM news WHERE published_at >= ? GROUP BY day ORDER BY day",
        ((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),),
    )
    today = datetime.now(timezone.utc).date()
    rows = {r["day"]: (r["n"], r["hi"], r["avg_prio"]) for r in rows if r["day"]}
    out = []
    for i in range(days, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        n, hi, avgp = rows.get(d, (0, 0, 0))
        out.append({"day": d, "items": n, "high_priority": hi, "avg_priority": round(avgp or 0, 1)})
    return {"window_days": days, "series": out}


def epss_distribution() -> dict:
    """Bucket CVEs by EPSS percentile for the histogram."""
    rows = fetchall("SELECT epss_score FROM cves WHERE epss_score IS NOT NULL")
    buckets = [0] * 10
    for r in rows:
        v = r["epss_score"]
        b = min(9, int((v or 0) * 10))
        buckets[b] += 1
    return {"buckets": [{"range": f"{i*10}-{(i+1)*10}%", "count": c} for i, c in enumerate(buckets)],
            "total": sum(buckets)}


def industry_velocity(days: int = 30) -> dict:
    """Daily counts of layoff, funding, and exec-change events."""
    today = datetime.now(timezone.utc).date()
    cutoff = (today - timedelta(days=days)).isoformat()
    rows = fetchall(
        "SELECT substr(published_at, 1, 10) AS day, industry_json "
        "FROM news WHERE published_at >= ? AND industry_json != '{}'",
        (cutoff,),
    )
    import json
    daily: dict[str, dict[str, int]] = {}
    for r in rows:
        try:
            ind = json.loads(r["industry_json"])
        except Exception:
            continue
        d = r["day"]
        bucket = daily.setdefault(d, {"layoff": 0, "funding": 0, "exec_change": 0, "acquisition": 0, "outage": 0})
        for k in ("layoff", "funding", "exec_change", "acquisition", "outage"):
            if k in ind:
                bucket[k] += 1
    out = []
    for i in range(days, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        b = daily.get(d, {"layoff": 0, "funding": 0, "exec_change": 0, "acquisition": 0, "outage": 0})
        out.append({"day": d, **b})
    return {"window_days": days, "series": out}
