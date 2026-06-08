"""News feed endpoints."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query

from ..db import fetchall, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like

router = APIRouter(prefix="/api/news", tags=["news"])


# Default `priority` sort applies a recency BOOST (not decay) so any item
# from the last few hours outranks a stale high-priority writeup. Items
# beyond the 30/90d age-out are filtered out separately by `quality=filtered`,
# so we don't need a decay term here.
#
#   effective = priority + recency_boost
#       < 2h  → +50  (always wins vs anything older)
#       < 6h  → +35
#       <12h  → +25
#       <24h  → +15
#       < 3d  → +5
#       else  → 0
#
# Within the same recency tier, raw priority + published_at tie-break.
_RECENCY_BOOST_SQL = (
    "CASE "
    "  WHEN julianday('now') - julianday(published_at) < 0.083 THEN 50 "  # < 2h
    "  WHEN julianday('now') - julianday(published_at) < 0.25  THEN 35 "  # < 6h
    "  WHEN julianday('now') - julianday(published_at) < 0.5   THEN 25 "  # < 12h
    "  WHEN julianday('now') - julianday(published_at) < 1     THEN 15 "  # < 24h
    "  WHEN julianday('now') - julianday(published_at) < 3     THEN 5  "  # < 3d
    "  ELSE 0 "
    "END"
)
_SORT_OPTIONS = {
    "priority": (
        f"(priority + {_RECENCY_BOOST_SQL}) DESC, "
        "published_at DESC, priority DESC"
    ),
    "date":     "published_at DESC, priority DESC",
    "severity": "severity DESC, published_at DESC, priority DESC",
    "priority-raw": "priority DESC, published_at DESC",
}

# Tags that keep an item past the age-out window
_DURABLE_TAGS = ("active-exploitation", "zero-day", "ransomware", "breach", "supply-chain")

# Even durable items drop eventually — keep at most 30 days for ordinary
# durable tags, and 90 days for KEV-CVE-linked items (covers the realistic
# "recently exploited" window without resurfacing year-old retrospectives).
_DURABLE_HARD_CAP_DAYS = 10
_KEV_LINKED_CAP_DAYS = 14
# Tags that count as "high signal" for the quality gate
_SIGNAL_TAGS = ("zero-day", "active-exploitation", "ransomware", "breach",
                "supply-chain", "nation-state", "vulnerability", "phishing",
                "ai-incident", "patch", "malware")


@router.get("")
def list_news(
    limit: int = Query(80, ge=1, le=300),
    min_priority: int = Query(0, ge=0, le=100),
    source: str | None = None,
    tag: str | None = None,
    q: str | None = None,
    sort: str = Query("priority", description="priority | date | severity"),
    sector: str | None = None,
    org: str | None = None,
    vendor: str | None = None,
    actor: str | None = None,
    quality: str = Query("filtered", description="filtered | all"),
    days: int = Query(10, ge=1, le=365, description="age-out window in days (non-durable items)"),
    cluster: bool = Query(True, description="group cross-source duplicates by cluster_key"),
    include_acked: bool = Query(False, description="include items the analyst already acknowledged"),
):
    """Default behavior:

      - Items must have at least one of: a CVE mention, a vendor/threat-actor/
        org/AI-company entity, or a security tag (the "quality gate").
      - Items older than `days` are dropped UNLESS they reference a KEV CVE or
        carry a durable tag (active-exploitation, zero-day, ransomware, breach,
        supply-chain).
      - `quality=all` disables both filters.
    """
    where = ["priority >= ?"]
    params: list = [min_priority]

    if not include_acked:
        where.append("acknowledged_at IS NULL")

    if source:
        where.append("source = ?")
        params.append(source)
    if tag:
        where.append(f"tags_json LIKE ? {ESCAPE_CLAUSE}")
        params.append(f'%"{like(tag)}"%')
    if q:
        esc = like(q)
        where.append(f"(title LIKE ? {ESCAPE_CLAUSE} OR summary LIKE ? {ESCAPE_CLAUSE})")
        params.extend([f"%{esc}%", f"%{esc}%"])
    for kind, val in (("sector", sector), ("org", org), ("vendor", vendor), ("actor", actor)):
        if val:
            where.append(
                "EXISTS (SELECT 1 FROM news_refs r WHERE r.news_id = news.id AND r.kind = ? AND r.ref_id = ?)"
            )
            params.extend([kind, val])

    if quality == "filtered":
        # Quality gate: at least one signal source
        signal_tag_clause = " OR ".join(["tags_json LIKE ?" for _ in _SIGNAL_TAGS])
        signal_tag_params = [f'%"{t}"%' for t in _SIGNAL_TAGS]
        has_signal = (
            "(cves_json != '[]' "
            f"  OR ({signal_tag_clause}) "
            "  OR entities_json LIKE '%\"vendors\": [{%' "
            "  OR entities_json LIKE '%\"threat_actors\": [{%' "
            "  OR entities_json LIKE '%\"orgs\": [{%' "
            "  OR entities_json LIKE '%\"ai_companies\": [{%' "
            "  OR entities_json LIKE '%\"malware\": [{%' "
            ")"
        )
        where.append(has_signal)
        params.extend(signal_tag_params)

        # Age-out (three tiers):
        #   - normal items: drop after `days`
        #   - durable-tagged items (zero-day / ransomware / breach / ...): drop after 30d
        #   - KEV-CVE-linked items: drop after 90d
        # `quality=all` skips all of these.
        cutoff_recent     = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cutoff_durable    = (datetime.now(timezone.utc) - timedelta(days=_DURABLE_HARD_CAP_DAYS)).isoformat()
        cutoff_kev_linked = (datetime.now(timezone.utc) - timedelta(days=_KEV_LINKED_CAP_DAYS)).isoformat()
        durable_tag_clause = " OR ".join(["tags_json LIKE ?" for _ in _DURABLE_TAGS])
        durable_tag_params = [f'%"{t}"%' for t in _DURABLE_TAGS]
        survives = (
            "(published_at >= ? "
            f"  OR (published_at >= ? AND ({durable_tag_clause})) "
            "  OR (published_at >= ? AND EXISTS (SELECT 1 FROM news_refs r JOIN cves k ON k.cve_id = r.ref_id "
            "             WHERE r.kind = 'cve' AND r.news_id = news.id AND k.is_kev = 1))"
            ")"
        )
        where.append(survives)
        params.append(cutoff_recent)
        params.append(cutoff_durable)
        params.extend(durable_tag_params)
        params.append(cutoff_kev_linked)

    where_sql = " AND ".join(where)
    order_sql = _SORT_OPTIONS.get(sort, _SORT_OPTIONS["priority"])
    # Over-fetch when clustering since we'll collapse duplicates.
    fetch_limit = limit * 4 if cluster else limit
    rows = fetchall(
        f"SELECT * FROM news WHERE {where_sql} ORDER BY {order_sql} LIMIT ?",
        (*params, fetch_limit),
    )
    items = [row_to_dict(r) for r in rows]

    if cluster:
        items = _collapse_clusters(items, limit)
    else:
        items = items[:limit]

    return {"items": items, "clustered": cluster}


def _collapse_clusters(items: list[dict], limit: int) -> list[dict]:
    """Group items by cluster_key first (exact dup), then run a SimHash
    near-duplicate merge pass so reworded headlines also collapse.

    Crucially: the SQL has already ordered rows according to the user's
    chosen sort. We must NOT re-sort by raw priority afterwards — that
    would override `date` and erase the recency-boost in `priority` mode.
    Instead we tag each row with its original position and use that as the
    canonical order; the primary of each cluster is the row with the lowest
    (= best by SQL rank) position.
    """
    from ..enrich.cluster import NEAR_DUP_THRESHOLD, hamming

    for i, it in enumerate(items):
        it["_pos"] = i

    # ---- pass 1: exact-key grouping ----
    by_key: dict[str, list[dict]] = {}
    untagged: list[dict] = []
    for it in items:
        ck = it.get("cluster_key")
        if not ck:
            untagged.append(it)
            continue
        by_key.setdefault(ck, []).append(it)

    primary_list: list[dict] = []
    for group in by_key.values():
        # Lowest _pos = highest SQL rank under the chosen sort
        group.sort(key=lambda x: x["_pos"])
        primary = dict(group[0])
        primary["cluster_size"] = len(group)
        primary["also_seen_in"] = [
            {"source": g["source"], "source_name": g["source_name"],
             "url": g["url"], "published_at": g["published_at"]}
            for g in group[1:]
        ]
        primary_list.append(primary)
    primary_list.extend(untagged)
    # Preserve SQL order across all primaries + untagged singletons
    primary_list.sort(key=lambda x: x["_pos"])

    # ---- pass 2: SimHash near-duplicate merge across clusters ----
    # Walk primaries in SQL-rank order; merge each item into the first
    # earlier primary whose SimHash distance is ≤ threshold AND whose
    # existing source set doesn't already contain this item's source.
    merged: list[dict] = []
    for it in primary_list:
        sh = it.get("simhash")
        if sh is None:
            merged.append(it)
            continue
        absorbed = False
        for parent in merged:
            psh = parent.get("simhash")
            if psh is None:
                continue
            if hamming(int(sh), int(psh)) <= NEAR_DUP_THRESHOLD:
                # Merge this whole cluster (primary + its own also_seen_in)
                # into the parent's also_seen_in.
                seen_sources = {parent.get("source")} | {
                    a.get("source") for a in (parent.get("also_seen_in") or [])
                }
                new_entries = []
                for cand in [it] + (it.get("also_seen_in") or []):
                    src = cand.get("source")
                    if src and src not in seen_sources:
                        new_entries.append({
                            "source": cand.get("source"),
                            "source_name": cand.get("source_name"),
                            "url": cand.get("url"),
                            "published_at": cand.get("published_at"),
                        })
                        seen_sources.add(src)
                parent.setdefault("also_seen_in", []).extend(new_entries)
                parent["cluster_size"] = (parent.get("cluster_size") or 1) + (it.get("cluster_size") or 1)
                absorbed = True
                break
        if not absorbed:
            merged.append(it)

    # ---- pass 3: entity + magnitude collapse ----
    # The SimHash bag-of-tokens fingerprint misses headlines that share a
    # subject + dollar amount but phrase the action differently
    # (e.g. "Anthropic raises $65B" vs "Anthropic overtakes OpenAI as the
    # most valuable AI startup" — both about the same funding round). If
    # two primaries share both a primary entity AND a numerical magnitude
    # (dollar amount / record count), collapse them.
    pass3: list[dict] = []
    by_em: dict[str, dict] = {}
    for it in merged:
        em_key = _entity_magnitude_key(it)
        if em_key and em_key in by_em:
            parent = by_em[em_key]
            seen_sources = {parent.get("source")} | {
                a.get("source") for a in (parent.get("also_seen_in") or [])
            }
            for cand in [it] + (it.get("also_seen_in") or []):
                src = cand.get("source")
                if src and src not in seen_sources:
                    parent.setdefault("also_seen_in", []).append({
                        "source": cand.get("source"),
                        "source_name": cand.get("source_name"),
                        "url": cand.get("url"),
                        "published_at": cand.get("published_at"),
                    })
                    seen_sources.add(src)
            parent["cluster_size"] = (parent.get("cluster_size") or 1) + (it.get("cluster_size") or 1)
        else:
            pass3.append(it)
            if em_key:
                by_em[em_key] = it

    for it in pass3:
        it.pop("_pos", None)
    return pass3[:limit]


# ----- entity + magnitude collapse helpers -----

# Normalized magnitudes for cluster matching. Capture group: number + unit.
_MAG_DOLLARS_RE = re.compile(
    r"\$\s*(\d+(?:\.\d+)?)\s*(b|bn|billion|m|mn|million|k|thousand|t|tn|trillion)\b",
    re.IGNORECASE,
)
_MAG_RECORDS_RE = re.compile(
    r"(\d+(?:[,\.]\d{3})*(?:\.\d+)?)\s*(thousand|k|million|m|mn|billion|b|bn)?\s*"
    r"(?:customer|user|account|patient|individual|employee|record)s?",
    re.IGNORECASE,
)
_UNIT_SCALE = {
    "k": 1_000, "thousand": 1_000,
    "m": 1_000_000, "mn": 1_000_000, "million": 1_000_000,
    "b": 1_000_000_000, "bn": 1_000_000_000, "billion": 1_000_000_000,
    "t": 1_000_000_000_000, "tn": 1_000_000_000_000, "trillion": 1_000_000_000_000,
}


def _normalize_magnitude(num: str, unit: str | None) -> str | None:
    """Return a bucketed magnitude token like '$65b' or '4.9m-records'.
    Rounds to nearest order-of-magnitude so $65B and $65.0B collide."""
    try:
        v = float(num.replace(",", ""))
    except ValueError:
        return None
    scale = _UNIT_SCALE.get((unit or "").lower(), 1)
    total = v * scale
    if total >= 1e12:
        return f"{round(total / 1e12)}t"
    if total >= 1e9:
        return f"{round(total / 1e9)}b"
    if total >= 1e6:
        return f"{round(total / 1e6)}m"
    if total >= 1e3:
        return f"{round(total / 1e3)}k"
    return None  # ignore sub-thousand magnitudes (noise)


def _primary_entity(entities: dict) -> str | None:
    """Pick the most specific entity to anchor a cluster key on. Prefer
    AI companies (funding stories), then orgs, then threat actors,
    then named malware, then vendors."""
    if not entities:
        return None
    for kind in ("ai_companies", "orgs", "threat_actors", "malware", "vendors"):
        arr = entities.get(kind) or []
        if arr:
            ent = arr[0]
            return f"{kind[:-1] if kind.endswith('s') else kind}:{ent.get('id', '')}"
    return None


def _entity_magnitude_key(item: dict) -> str | None:
    """Return 'entity-kind:entity-id|magnitude-token' or None when either
    component is missing. Two items sharing this key are about the same
    underlying event."""
    ent_key = _primary_entity(item.get("entities") or {})
    if not ent_key:
        return None
    blob = f"{item.get('title', '')} {item.get('summary', '')}"
    # Dollar amount has priority (funding, ransom, valuation)
    m = _MAG_DOLLARS_RE.search(blob)
    if m:
        token = _normalize_magnitude(m.group(1), m.group(2))
        if token:
            return f"{ent_key}|${token}"
    # Otherwise: record count (breach stories)
    m = _MAG_RECORDS_RE.search(blob)
    if m:
        token = _normalize_magnitude(m.group(1), m.group(2))
        if token:
            return f"{ent_key}|{token}-records"
    return None


_BY_ENTITY_KINDS = {"vendors", "ai_companies", "threat_actors", "malware", "sectors", "orgs"}
_ENTITY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_\-:.]{0,80}$")


@router.get("/by-entity/{kind}/{entity_id}")
def by_entity(kind: str, entity_id: str,
              limit: int = Query(50, ge=1, le=300)):
    """kind = vendors | ai_companies | threat_actors | malware | sectors | orgs"""
    if kind not in _BY_ENTITY_KINDS:
        raise HTTPException(400, f"invalid kind (expected one of {sorted(_BY_ENTITY_KINDS)})")
    if not _ENTITY_ID_RE.match(entity_id):
        raise HTTPException(400, "invalid entity id")
    needle = f'"id": "{like(entity_id)}"'
    rows = fetchall(
        f"SELECT * FROM news WHERE entities_json LIKE ? {ESCAPE_CLAUSE} "
        "ORDER BY published_at DESC LIMIT ?",
        (f"%{needle}%", limit),
    )
    return {"items": [row_to_dict(r) for r in rows]}


# --- acknowledged state -------------------------------------------------

from ..db import tx


@router.post("/{news_id}/ack")
def ack_news(news_id: str):
    """Mark a news item as 'I've seen this, dismiss from active'."""
    if not news_id or len(news_id) > 200:
        raise HTTPException(400, "invalid news id")
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        cur = conn.execute(
            "UPDATE news SET acknowledged_at = ? WHERE id = ? AND acknowledged_at IS NULL",
            (now, news_id),
        )
        if cur.rowcount == 0:
            # check if it exists at all
            r = conn.execute("SELECT 1 FROM news WHERE id = ?", (news_id,)).fetchone()
            if not r:
                raise HTTPException(404, "not found")
    return {"ok": True, "acknowledged_at": now}


@router.delete("/{news_id}/ack")
def unack_news(news_id: str):
    """Re-surface a previously-acknowledged item."""
    if not news_id or len(news_id) > 200:
        raise HTTPException(400, "invalid news id")
    with tx() as conn:
        cur = conn.execute(
            "UPDATE news SET acknowledged_at = NULL WHERE id = ?",
            (news_id,),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "not found")
    return {"ok": True}


@router.post("/ack-cluster")
def ack_cluster(cluster_key: str = Query(..., min_length=1, max_length=200)):
    """Ack every news item sharing a cluster_key — useful when an analyst
    wants to dismiss a whole story across all source duplicates."""
    now = datetime.now(timezone.utc).isoformat()
    with tx() as conn:
        cur = conn.execute(
            "UPDATE news SET acknowledged_at = ? WHERE cluster_key = ? AND acknowledged_at IS NULL",
            (now, cluster_key),
        )
        return {"ok": True, "acknowledged_count": cur.rowcount}
