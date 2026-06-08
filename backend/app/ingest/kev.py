"""CISA Known Exploited Vulnerabilities catalog."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

from .. import config
from ..db import record_feed_health, tx, fetchone
from ..ws import push_kev_batch


async def fetch_kev() -> int:
    """Pull KEV catalog. Returns count of vulnerabilities upserted."""
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT,
                                     headers={"User-Agent": config.USER_AGENT},
                                     follow_redirects=True, max_redirects=5) as client:
            # KEV catalog is currently ~600 KiB; allow up to 16 MiB headroom.
            r = await safe_get(client, config.KEV_URL, max_bytes=16 * 1024 * 1024)
            data = r.json()
    except Exception as e:
        record_feed_health("cisa-kev", "CISA KEV Catalog", ok=False, error=str(e))
        return 0

    vulns = data.get("vulnerabilities", [])
    count = 0
    new_kev: list[dict] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    with tx() as conn:
        for v in vulns:
            cve_id = (v.get("cveID") or "").upper()
            if not cve_id:
                continue
            existing = conn.execute(
                "SELECT cve_id, is_kev, cvss_score, epss_score FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            refs = [v.get("notes") or ""] if v.get("notes") else []
            description = v.get("shortDescription") or v.get("vulnerabilityName") or ""
            kev_added = v.get("dateAdded")
            kev_ransomware = v.get("knownRansomwareCampaignUse")
            newly_kev = existing is None or not (existing and existing["is_kev"])
            # Recompute priority so the +30 KEV bonus (+15 ransomware) applies
            # immediately. Was previously stale until next NVD/EPSS sync.
            from ..enrich.scoring import cve_priority
            prio = cve_priority(
                cvss=existing["cvss_score"] if existing else None,
                epss=existing["epss_score"] if existing else None,
                is_kev=True,
                kev_ransomware=kev_ransomware,
            )
            if existing is None:
                conn.execute(
                    """INSERT INTO cves (cve_id, published_at, last_modified, description, is_kev, kev_added,
                                         kev_ransomware, priority, refs_json, raw_json)
                       VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)""",
                    (cve_id, kev_added or now_iso, now_iso, description, kev_added, kev_ransomware,
                     prio, json.dumps(refs), json.dumps(v)),
                )
            else:
                conn.execute(
                    """UPDATE cves SET is_kev = 1, kev_added = ?, kev_ransomware = ?,
                                       priority = ?, last_modified = ?
                       WHERE cve_id = ?""",
                    (kev_added, kev_ransomware, prio, now_iso, cve_id),
                )
            count += 1
            if newly_kev:
                new_kev.append({
                    "cve_id": cve_id, "description": description,
                    "cvss_score": existing["cvss_score"] if existing else None,
                    "is_kev": 1, "kev_added": kev_added, "kev_ransomware": kev_ransomware,
                    "priority": 80,
                })
    record_feed_health("cisa-kev", "CISA KEV Catalog", ok=True, items=count)
    if new_kev:
        push_kev_batch(len(new_kev), new_kev)
    return count
