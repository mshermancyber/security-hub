"""ransomware.live ingestion — leak-site victim postings per group.

Pulls fresh victim entries from the public v2 API and stores them in the
ransom_postings table. Each posting is auto-linked to a threat actor id
when the group name matches an alias in our (now MITRE-expanded) actor
taxonomy.

Goes from "no signal unless a journalist writes a story" to "every
victim posting on every active ransomware leak site as soon as it
appears", refreshed every ~30 min.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone

import httpx

from .. import config
from ..db import load_taxonomy, record_feed_health, tx

log = logging.getLogger("sechub.ingest.ransomwatch")

API_RECENT = "https://api.ransomware.live/v2/recentvictims"


import threading as _threading

_actor_alias_cache: dict[str, str] | None = None
_alias_cache_lock = _threading.Lock()


def _refresh_alias_index() -> dict[str, str]:
    """Build {lowercase alias → actor id} from both taxonomy files.

    Builds into a local dict first, then assigns the global atomically so
    a concurrent reader can iterate the old dict without RuntimeError.
    """
    global _actor_alias_cache
    idx: dict[str, str] = {}
    for taxon in ("threat_actors", "threat_actors_mitre"):
        try:
            doc = load_taxonomy(taxon)
        except FileNotFoundError:
            continue
        for a in doc.get("threat_actors", []):
            for alias in a.get("aliases", []):
                idx.setdefault(alias.lower().strip(), a["id"])
            # also map the actor id itself
            idx.setdefault(a["id"].lower(), a["id"])
            idx.setdefault(a["name"].lower(), a["id"])
    with _alias_cache_lock:
        _actor_alias_cache = idx
    return idx


def _match_actor(group_name: str) -> str | None:
    """Find an actor id for a ransomware.live group label."""
    if not group_name:
        return None
    idx = _actor_alias_cache or _refresh_alias_index()
    key = group_name.lower().strip()
    if key in idx:
        return idx[key]
    # try normalized variants — strip suffixes like "team", "group", "ransomware"
    key2 = re.sub(r"\b(team|group|ransomware|gang|crew|locker|leak)\b", "", key)
    key2 = re.sub(r"\s+", " ", key2).strip()
    if key2 and key2 in idx:
        return idx[key2]
    # try collapsed (alphabetic-only)
    collapsed = re.sub(r"[^a-z0-9]", "", key)
    for alias, aid in idx.items():
        if re.sub(r"[^a-z0-9]", "", alias) == collapsed:
            return aid
    return None


def _hash_id(group: str, victim: str, discovered: str) -> str:
    h = hashlib.sha1(f"{group}|{victim}|{discovered}".encode()).hexdigest()
    return h[:16]


async def fetch_ransomwatch() -> int:
    """Fetch recent ransomware victim postings and upsert into ransom_postings."""
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True,
                                     max_redirects=3,
                                     headers={"User-Agent": config.USER_AGENT}) as cx:
            r = await safe_get(cx, API_RECENT, max_bytes=16 * 1024 * 1024)
            items = r.json()
    except Exception as e:
        record_feed_health("ransomware-live", "ransomware.live", ok=False, error=str(e))
        return 0

    _refresh_alias_index()
    inserted = 0
    with tx() as conn:
        for it in items:
            group = (it.get("group") or "").strip()
            victim = (it.get("victim") or "").strip()
            discovered = it.get("discovered") or datetime.now(timezone.utc).isoformat()
            if not group or not victim:
                continue
            pid = _hash_id(group, victim, discovered)
            actor_id = _match_actor(group)
            conn.execute(
                """INSERT INTO ransom_postings (id, group_name, actor_id, victim, country,
                                                domain, attack_date, discovered, description, claim_url, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       actor_id    = excluded.actor_id,
                       victim      = excluded.victim,
                       country     = excluded.country,
                       domain      = excluded.domain,
                       attack_date = excluded.attack_date,
                       discovered  = excluded.discovered,
                       description = excluded.description,
                       claim_url   = excluded.claim_url""",
                (
                    pid, group, actor_id, victim,
                    (it.get("country") or "").strip() or None,
                    (it.get("domain") or "").strip() or None,
                    it.get("attackdate"),
                    discovered,
                    (it.get("description") or "")[:2000] or None,
                    it.get("claim_url"),
                    json.dumps(it)[:8000],
                ),
            )
            inserted += 1
    record_feed_health("ransomware-live", "ransomware.live", ok=True, items=inserted)
    log.info("ransomware.live ingest: %d postings", inserted)
    return inserted
