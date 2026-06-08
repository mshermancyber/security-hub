"""Microsoft Patch Tuesday ingestion via the MSRC CVRF API.

MSRC publishes monthly CVRF documents (2nd Tuesday). The API
`/cvrf/v3.0/Updates` returns the list of releases; each release
points at a CVRF document with the CVE details.

We pull the last two months' CVEs and add them to the news table
as a `msrc` source so they show up in the patch panel alongside
the RSS-based RHSA/ALAS advisories.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx

from .. import config
from ..db import record_feed_health, tx
from ..enrich.cluster import cluster_key, simhash
from ..enrich.entities import extract_entities, extract_tags, severity_from_tags
from ..enrich.industry import INDUSTRY_TAGS, extract_industry
from ..enrich.refs import index_news_refs
from ..enrich.scoring import news_priority

log = logging.getLogger("sechub.ingest.msrc")

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates"


def _hash_id(source_id: str, key: str) -> str:
    return hashlib.sha1(f"{source_id}|{key}".encode()).hexdigest()[:16]


async def fetch_msrc(limit_releases: int = 2) -> int:
    """Pull the most recent N Patch Tuesday releases, store the CVE entries
    as news rows tagged 'patch'+'patch-tuesday'. Returns inserted count."""
    headers = {"Accept": "application/json", "User-Agent": config.USER_AGENT}
    try:
        from ..safe_http import safe_get, is_public_url
        async with httpx.AsyncClient(timeout=30, headers=headers,
                                     follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, UPDATES_URL, max_bytes=8 * 1024 * 1024)
            doc = r.json()
            releases = (doc.get("value") or [])[:limit_releases]
            if not releases:
                record_feed_health("msrc-cvrf", "Microsoft MSRC CVRF", ok=True, items=0)
                return 0

            inserted = 0
            now_iso = datetime.now(timezone.utc).isoformat()
            for rel in releases:
                rid = rel.get("ID")
                if not rid:
                    continue
                cvrf_url = rel.get("CvrfUrl")
                # CvrfUrl is attacker-controlled in the sense that whoever
                # serves api.msrc.microsoft.com sets it. Reject anything
                # that doesn't point at a public host before we GET it.
                if not cvrf_url or not is_public_url(cvrf_url):
                    continue
                try:
                    r2 = await safe_get(cx, cvrf_url, max_bytes=16 * 1024 * 1024,
                                        headers={"Accept": "application/json"})
                except Exception:
                    continue
                cvrf = r2.json()
                released = (
                    cvrf.get("DocumentTracking", {})
                       .get("InitialReleaseDate") or now_iso
                )
                try:
                    rel_dt = datetime.fromisoformat(released.replace("Z", "+00:00"))
                    if rel_dt.tzinfo is None:
                        rel_dt = rel_dt.replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - rel_dt).days > 10:
                        continue
                except Exception:
                    continue
                # Each CVE is a `Vulnerability` entry
                for vuln in cvrf.get("Vulnerability", []) or []:
                    cve = vuln.get("CVE")
                    if not cve:
                        continue
                    title = (vuln.get("Title", {}) or {}).get("Value") or cve
                    summary = ""
                    for n in vuln.get("Notes", []) or []:
                        if n.get("Type") == 2 and n.get("Value"):  # 2 = Description
                            summary = n["Value"]
                            break
                    # Affected product names → comma-joined
                    products = []
                    for ps in vuln.get("ProductStatuses", []) or []:
                        for pid in ps.get("ProductID") or []:
                            products.append(pid)
                    full_title = f"[{cve}] {title}"
                    full_summary = (summary[:500] + f"  · Affected: {', '.join(products[:8])}").strip()

                    blob = f"{full_title}\n{full_summary}"
                    tags = extract_tags(blob)
                    if "patch" not in tags:
                        tags.append("patch")
                    if "patch-tuesday" not in tags:
                        tags.append("patch-tuesday")
                    entities = extract_entities(blob)
                    # Ensure CVE shows up even if regex missed
                    if cve not in entities.get("cves", []):
                        entities["cves"].append(cve)
                    industry = extract_industry(blob, entities)
                    for kind in industry:
                        tag = INDUSTRY_TAGS.get(kind)
                        if tag and tag not in tags:
                            tags.append(tag)
                    severity = severity_from_tags(tags)
                    prio = news_priority(
                        reliability=96, severity=severity,
                        recency_hours=0, entity_hits=len(products) + len(entities["cves"]),
                        feed_bump=4,
                    )
                    nid = _hash_id("msrc", f"{rid}|{cve}")
                    url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
                    ckey = cluster_key(full_title, full_summary, entities)
                    shash = simhash(full_title, full_summary)
                    with tx() as conn:
                        conn.execute(
                            """INSERT INTO news (id, source, source_name, title, summary, url, published_at, fetched_at,
                                                  reliability, severity, priority, tags_json, entities_json, cves_json,
                                                  industry_json, cluster_key, simhash)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                               ON CONFLICT(id) DO UPDATE SET
                                 source_name = excluded.source_name,
                                 title = excluded.title,
                                 summary = excluded.summary,
                                 url = excluded.url,
                                 published_at = excluded.published_at,
                                 reliability = excluded.reliability,
                                 priority = excluded.priority,
                                 severity = excluded.severity,
                                 tags_json = excluded.tags_json,
                                 entities_json = excluded.entities_json,
                                 cves_json = excluded.cves_json,
                                 industry_json = excluded.industry_json,
                                 cluster_key = excluded.cluster_key,
                                 simhash = excluded.simhash,
                                 fetched_at = excluded.fetched_at""",
                            (nid, "msrc", "Microsoft MSRC", full_title, full_summary, url,
                             released, now_iso, 96, severity, prio,
                             json.dumps(tags), json.dumps(entities),
                             json.dumps(entities["cves"]),
                             json.dumps(industry), ckey, shash),
                        )
                        index_news_refs(conn, nid, entities, entities["cves"])
                    inserted += 1
        record_feed_health("msrc-cvrf", "Microsoft MSRC CVRF", ok=True, items=inserted)
        log.info("msrc ingest: %d advisories", inserted)
        return inserted
    except Exception as e:
        log.exception("msrc fetch failed")
        # Some httpx errors stringify to "" — fall back to the type name so
        # the dashboard shows something actionable.
        msg = str(e) or type(e).__name__
        record_feed_health("msrc-cvrf", "Microsoft MSRC CVRF", ok=False, error=msg)
        return 0
