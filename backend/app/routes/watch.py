"""Watchlist endpoints — AI companies, vendors, threat actors. Powered by taxonomy + news."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Query

from ..db import fetchall, load_taxonomy, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like as _esc_like

router = APIRouter(prefix="/api/watch", tags=["watch"])


def _activity_for(needle_id: str, days: int = 7) -> tuple[int, list[dict], int, dict[str, int]]:
    """Return (count, latest_items, max_priority, tag_breakdown) for an entity id."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = fetchall(
        f"SELECT id, source_name, title, url, published_at, priority, tags_json FROM news "
        f"WHERE entities_json LIKE ? {ESCAPE_CLAUSE} AND published_at >= ? "
        f"ORDER BY published_at DESC LIMIT 50",
        (f'%"id": "{_esc_like(needle_id)}"%', since),
    )
    items = [row_to_dict(r) for r in rows]
    max_prio = max((i["priority"] for i in items), default=0)
    tag_counter: Counter = Counter()
    for it in items:
        for t in it.get("tags", []):
            tag_counter[t] += 1
    return len(items), items[:6], max_prio, dict(tag_counter)


@router.get("/ai")
def ai_watch(days: int = Query(14, ge=1, le=365)):
    """AI company watch — recent mentions / incidents / signals."""
    taxonomy = load_taxonomy("ai_companies")["ai_companies"]
    out = []
    for c in taxonomy:
        count, items, max_prio, tags = _activity_for(c["id"], days=days)
        out.append({
            "id": c["id"],
            "name": c["name"],
            "category": c.get("category"),
            "mentions": count,
            "max_priority": max_prio,
            "tags": tags,
            "latest": items,
        })
    out.sort(key=lambda x: (x["max_priority"], x["mentions"]), reverse=True)
    return {"window_days": days, "companies": out}


@router.get("/vendors")
def vendor_watch(days: int = Query(7, ge=1, le=365)):
    taxonomy = load_taxonomy("vendors")["vendors"]
    out = []
    for v in taxonomy:
        count, items, max_prio, tags = _activity_for(v["id"], days=days)
        # also enrich with CVE counts
        cve_rows = fetchall(
            f"SELECT cve_id, cvss_score, is_kev, priority FROM cves "
            f"WHERE entities_json LIKE ? {ESCAPE_CLAUSE} ORDER BY priority DESC LIMIT 10",
            (f'%"id": "{_esc_like(v["id"])}"%',),
        )
        out.append({
            "id": v["id"],
            "name": v["name"],
            "category": v.get("category"),
            "mentions": count,
            "max_priority": max_prio,
            "tags": tags,
            "open_cves": len(cve_rows),
            "kev_cves": sum(1 for r in cve_rows if r["is_kev"]),
            "top_cves": [dict(r) for r in cve_rows[:5]],
            "latest_news": items[:4],
        })
    out.sort(key=lambda x: (x["kev_cves"], x["max_priority"], x["mentions"]), reverse=True)
    return {"window_days": days, "vendors": out}


def _load_actors() -> list[dict]:
    actors: list[dict] = list(load_taxonomy("threat_actors")["threat_actors"])
    try:
        mitre = load_taxonomy("threat_actors_mitre").get("threat_actors", [])
        existing = {a["id"] for a in actors}
        actors.extend(a for a in mitre if a["id"] not in existing)
    except FileNotFoundError:
        pass
    return actors


def _ransom_postings_by_actor(days: int) -> dict[str, dict]:
    """Count ransom_postings per actor_id in window. Returns {id: {count, last_seen, victims}}"""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = fetchall(
        "SELECT actor_id, COUNT(*) AS n, MAX(discovered) AS latest, "
        "       GROUP_CONCAT(victim, '||') AS victims "
        "FROM ransom_postings WHERE discovered >= ? AND actor_id IS NOT NULL "
        "GROUP BY actor_id",
        (since,),
    )
    out: dict[str, dict] = {}
    for r in rows:
        victims = (r["victims"] or "").split("||")
        out[r["actor_id"]] = {
            "count": r["n"],
            "last_seen": r["latest"],
            "victims": [v for v in victims if v][:8],
        }
    return out


def _iocs_by_malware() -> dict[str, int]:
    """Active IOC count per malware family name (lowercased) from ThreatFox."""
    rows = fetchall(
        "SELECT LOWER(malware_printable) AS m, COUNT(*) AS n FROM iocs "
        "WHERE malware_printable IS NOT NULL GROUP BY LOWER(malware_printable)"
    )
    return {r["m"]: r["n"] for r in rows}


def _malware_to_actor_map() -> dict[str, str]:
    """Build {malware_family_name_lower → actor_id} via taxonomy aliases."""
    out: dict[str, str] = {}
    for taxon in ("threat_actors", "threat_actors_mitre"):
        try:
            doc = load_taxonomy(taxon)
        except FileNotFoundError:
            continue
        # If malware entries carry an actor reference, use that. Otherwise we
        # rely on the IOC's own malware label to fuzzy-match into the actor index.
        # (MITRE doesn't directly link malware to a single actor — many overlap.)
        pass  # placeholder for explicit links if added later
    return out


@router.get("/actors")
def actor_watch(days: int = Query(30, ge=1, le=365), include_silent: bool = True):
    """Threat actor activity, fused from three signals:
       1. News mentions of the actor or its aliases
       2. Ransomware leak-site postings (ransomware.live)
       3. ThreatFox IOCs tagged with a malware family known to be the actor's
    """
    actors = _load_actors()
    ransom_map = _ransom_postings_by_actor(days)
    ioc_by_malware = _iocs_by_malware()

    # Build a per-actor IOC count by checking each actor's alias set against
    # the malware names in the IOC index. Cheap (≤200 actors × few aliases).
    actor_ioc_counts: dict[str, int] = {}
    for a in actors:
        total = 0
        for alias in a.get("aliases", []):
            n = ioc_by_malware.get(alias.lower())
            if n:
                total += n
        # Also try the actor name itself
        if not total:
            total = ioc_by_malware.get(a["name"].lower(), 0)
        if total:
            actor_ioc_counts[a["id"]] = total

    active: list[dict] = []
    silent: list[dict] = []
    for a in actors:
        count, items, max_prio, tags = _activity_for(a["id"], days=days)
        ransom = ransom_map.get(a["id"], {})
        ransom_count = ransom.get("count", 0)
        ioc_count = actor_ioc_counts.get(a["id"], 0)
        # Combined activity score for sort ordering
        signal_score = count + (ransom_count * 4) + (1 if ioc_count else 0)
        entry = {
            "id": a["id"],
            "name": a["name"],
            "type": a.get("type"),
            "origin": a.get("origin"),
            "attack_id": a.get("attack_id"),
            "mentions": count,
            "max_priority": max_prio,
            "tags": tags,
            "latest": items[:5],
            "ransom_postings": ransom_count,
            "ransom_victims": ransom.get("victims", []),
            "ransom_last_seen": ransom.get("last_seen"),
            "ioc_count": ioc_count,
            "signal_score": signal_score,
        }
        (active if signal_score > 0 else silent).append(entry)
    active.sort(key=lambda x: (x["signal_score"], x["ransom_postings"],
                               x["mentions"], x["max_priority"]), reverse=True)
    silent.sort(key=lambda x: x["name"])
    return {
        "window_days": days,
        "actors": active + (silent if include_silent else []),
        "active_count": len(active),
        "silent_count": len(silent),
    }


@router.get("/actors/{actor_id}/timeline")
def actor_timeline(actor_id: str, days: int = Query(90, ge=1, le=365), limit: int = Query(200, ge=1, le=500)):
    """Chronological merge of news mentions + ransomware leak-site postings
    + IOC associations for a single threat actor."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    events: list[dict] = []
    # News mentions
    news_rows = fetchall(
        "SELECT n.id, n.source_name, n.title, n.url, n.priority, n.published_at, n.tags_json "
        "FROM news n JOIN news_refs r ON r.news_id = n.id "
        "WHERE r.kind = 'actor' AND r.ref_id = ? AND n.published_at >= ? "
        "ORDER BY n.published_at DESC LIMIT ?",
        (actor_id, since, limit),
    )
    for r in news_rows:
        events.append({
            "kind": "news",
            "at": r["published_at"],
            "title": r["title"], "url": r["url"],
            "source": r["source_name"], "priority": r["priority"],
        })
    # Ransomware leak-site postings tied to this actor
    rp_rows = fetchall(
        "SELECT victim, country, discovered, attack_date, claim_url, description "
        "FROM ransom_postings WHERE actor_id = ? AND discovered >= ? "
        "ORDER BY discovered DESC LIMIT ?",
        (actor_id, since, limit),
    )
    for r in rp_rows:
        events.append({
            "kind": "leak_post",
            "at": r["discovered"], "title": f"Leak-site victim: {r['victim']}",
            "url": r["claim_url"], "country": r["country"],
            "attack_date": r["attack_date"],
            "detail": (r["description"] or "")[:200] or None,
        })
    events.sort(key=lambda e: e["at"], reverse=True)
    return {
        "actor_id": actor_id, "window_days": days,
        "events": events[:limit],
        "counts": {
            "news": len([e for e in events if e["kind"] == "news"]),
            "leak_posts": len([e for e in events if e["kind"] == "leak_post"]),
        },
    }


@router.get("/ransomware")
def ransomware_feed(days: int = Query(30, ge=1, le=365), limit: int = Query(100, ge=1, le=500)):
    """Recent ransomware leak-site postings, newest first."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = fetchall(
        "SELECT id, group_name, actor_id, victim, country, domain, attack_date, "
        "       discovered, description, claim_url "
        "FROM ransom_postings WHERE discovered >= ? "
        "ORDER BY discovered DESC LIMIT ?",
        (since, limit),
    )
    # also a summary by group
    summary_rows = fetchall(
        "SELECT group_name, actor_id, COUNT(*) AS n, MAX(discovered) AS last_seen "
        "FROM ransom_postings WHERE discovered >= ? "
        "GROUP BY group_name ORDER BY n DESC LIMIT 50",
        (since,),
    )
    return {
        "window_days": days,
        "postings": [dict(r) for r in rows],
        "by_group": [dict(r) for r in summary_rows],
    }


@router.get("/sectors")
def sector_heatmap(days: int = Query(30, ge=1, le=365)):
    sectors = load_taxonomy("sectors")["sectors"]
    out = []
    for s in sectors:
        count, items, max_prio, tags = _activity_for(s["id"], days=days)
        out.append({
            "id": s["id"],
            "name": s["name"],
            "mentions": count,
            "max_priority": max_prio,
            "ransomware": tags.get("ransomware", 0),
            "breaches": tags.get("breach", 0),
            "tags": tags,
        })
    out.sort(key=lambda x: x["mentions"], reverse=True)
    return {"window_days": days, "sectors": out}
