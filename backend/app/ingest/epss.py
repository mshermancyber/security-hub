"""EPSS standalone sync — populates EPSS for every CVE in the DB.

The NVD pipeline only enriches CVEs in its rolling window, so most KEV entries
historically lack EPSS scores. This module fixes that by paging all CVE IDs
through FIRST.org's batch endpoint (up to 100 IDs per call).

Runs daily by default. Can be triggered immediately via /api/admin/refresh/epss.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from .. import config
from ..db import get_conn, record_feed_health, tx
from ..enrich.scoring import cve_priority

log = logging.getLogger("sechub.ingest.epss")

BATCH = 100


async def fetch_epss_batch(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not cve_ids:
        return out
    try:
        from ..safe_http import safe_get
        r = await safe_get(client, config.EPSS_BASE,
                           params={"cve": ",".join(cve_ids)},
                           max_bytes=8 * 1024 * 1024)
        for row in r.json().get("data", []):
            out[row["cve"].upper()] = {
                "score": float(row.get("epss", 0) or 0),
                "percentile": float(row.get("percentile", 0) or 0),
            }
    except Exception as e:
        log.warning("epss batch failed (%d ids): %s", len(cve_ids), e)
    return out


async def fetch_epss_all(only_missing: bool = False) -> int:
    """Sync EPSS for every CVE in the DB.

    Args:
        only_missing: if True, skip rows that already have an epss_score.
    Returns count of rows updated.
    """
    conn = get_conn()
    if only_missing:
        rows = conn.execute("SELECT cve_id FROM cves WHERE epss_score IS NULL").fetchall()
    else:
        rows = conn.execute("SELECT cve_id FROM cves").fetchall()
    cve_ids = [r["cve_id"] for r in rows]
    if not cve_ids:
        record_feed_health("epss", "FIRST.org EPSS", ok=True, items=0)
        return 0

    log.info("epss sync: %d CVEs to enrich (only_missing=%s)", len(cve_ids), only_missing)

    updated = 0
    headers = {"User-Agent": config.USER_AGENT}
    async with httpx.AsyncClient(timeout=60.0, headers=headers,
                                 follow_redirects=True, max_redirects=3) as client:
        for i in range(0, len(cve_ids), BATCH):
            batch = cve_ids[i:i + BATCH]
            mapping = await fetch_epss_batch(client, batch)
            if not mapping:
                continue
            with tx() as txconn:
                for cve_id, data in mapping.items():
                    row = txconn.execute(
                        "SELECT cvss_score, is_kev, kev_ransomware FROM cves WHERE cve_id = ?",
                        (cve_id,),
                    ).fetchone()
                    if row is None:
                        continue
                    prio = cve_priority(
                        cvss=row["cvss_score"],
                        epss=data["score"],
                        is_kev=bool(row["is_kev"]),
                        kev_ransomware=row["kev_ransomware"],
                    )
                    txconn.execute(
                        "UPDATE cves SET epss_score = ?, epss_percentile = ?, priority = ? WHERE cve_id = ?",
                        (data["score"], data["percentile"], prio, cve_id),
                    )
                    updated += 1
    record_feed_health("epss", "FIRST.org EPSS", ok=True, items=updated)
    log.info("epss sync done: %d updated", updated)
    return updated
