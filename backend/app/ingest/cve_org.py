"""CVE.org direct + ADP enrichments.

The CVE Program's `cveawg.mitre.org` API returns the full CVE record
including `containers.adp[]` enrichments from Authorized Data
Publishers — most notably CISA's "Vulnrichment" project, which adds
human-curated exploitation status, vendor commentary, and additional
CVSS scores that NVD often doesn't surface.

We pick the N most operationally interesting CVEs from our local DB
(prioritizing KEV-listed, then high CVSS, then newest), fetch their
CVE.org record, and emit a news row for each one that has non-trivial
ADP content. The news row links back to CVE.org with the CISA-ADP
metric and any vendor `affected` ranges in the summary.

Run this less aggressively than NVD (CVE.org has its own rate limits).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import httpx

from .. import config
from ..db import fetchall, record_feed_health
from .custom import _persist as persist_news

log = logging.getLogger("sechub.ingest.cve_org")

CVEAWG_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"


def _select_candidates(limit: int = 40) -> list[str]:
    """Return CVE IDs worth fetching from CVE.org. Order:
    1. KEV-listed CVEs (always check for new Vulnrichment)
    2. High-CVSS CVEs published in last 14 days
    3. EPSS-high CVEs that we haven't covered as news yet
    """
    rows = fetchall(
        """
        SELECT cve_id FROM cves
         WHERE is_kev = 1
         ORDER BY published_at DESC
         LIMIT ?
        """,
        (limit // 2,),
    )
    cves = [r["cve_id"] for r in rows]

    remaining = limit - len(cves)
    if remaining > 0:
        rows2 = fetchall(
            """
            SELECT cve_id FROM cves
             WHERE cvss_score >= 8.0
               AND datetime(published_at) >= datetime('now', '-14 days')
               AND cve_id NOT IN ({})
             ORDER BY cvss_score DESC, published_at DESC
             LIMIT ?
            """.format(",".join("?" for _ in cves) or "''"),
            (*cves, remaining),
        )
        cves.extend(r["cve_id"] for r in rows2)
    return cves


def _extract_adp_signal(record: dict) -> tuple[str, list[dict], list[str]]:
    """Parse a CVE.org record. Returns (summary, adp_metrics_list, affected_products)."""
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adp_list = containers.get("adp") or []

    # Get the CNA's description (vendor's own description)
    descriptions = cna.get("descriptions") or []
    cna_desc = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    # Affected products from CNA
    affected = []
    for a in (cna.get("affected") or [])[:5]:
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        if vendor and product:
            affected.append(f"{vendor}/{product}")

    # Collect ADP enrichments with non-trivial content
    adp_signal: list[dict] = []
    for adp in adp_list:
        provider = (adp.get("providerMetadata") or {}).get("shortName") or "ADP"
        # Vulnrichment-style "other" metric (SSVC etc.)
        metrics = []
        for m in (adp.get("metrics") or []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if key in m:
                    score = m[key].get("baseScore")
                    severity = m[key].get("baseSeverity")
                    if score:
                        metrics.append(f"{key}={score} ({severity or '?'})")
            other = m.get("other") or {}
            content = other.get("content") or {}
            if isinstance(content, dict) and other.get("type") == "ssvc":
                # SSVC decision tree from CISA
                opts = content.get("options") or []
                ssvc_parts = []
                for o in opts:
                    for k, v in o.items():
                        ssvc_parts.append(f"{k}:{v}")
                if ssvc_parts:
                    metrics.append("SSVC " + ", ".join(ssvc_parts))
        if metrics or adp.get("title"):
            adp_signal.append({"provider": provider, "metrics": metrics,
                               "title": adp.get("title", "")})

    summary_parts = [cna_desc[:300]] if cna_desc else []
    if affected:
        summary_parts.append("Affected: " + ", ".join(affected))
    return " · ".join(summary_parts), adp_signal, affected


async def fetch_cve_org(limit: int = 40) -> int:
    """Pull CVE.org records + ADP enrichments for top candidate CVEs."""
    cve_ids = _select_candidates(limit=limit)
    if not cve_ids:
        record_feed_health("cve-org-adp", "CVE.org + ADP", ok=True, items=0)
        return 0

    headers = {"Accept": "application/json", "User-Agent": config.USER_AGENT}
    inserted = 0
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=20, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            for cve_id in cve_ids:
                try:
                    r = await safe_get(cx, CVEAWG_URL.format(cve_id=cve_id),
                                       max_bytes=4 * 1024 * 1024)
                except Exception:
                    continue
                try:
                    rec = r.json()
                except Exception:
                    continue
                desc, adp_signal, affected = _extract_adp_signal(rec)
                if not adp_signal:
                    # Skip CVEs with no ADP enrichment — nothing new vs NVD
                    continue
                providers = ", ".join(a["provider"] for a in adp_signal)
                metric_lines = []
                for a in adp_signal:
                    if a["metrics"]:
                        metric_lines.append(f"[{a['provider']}] " + "; ".join(a["metrics"][:4]))
                summary = (desc + "  · ADP enrichments: " + " · ".join(metric_lines)).strip()
                if len(summary) > 800:
                    summary = summary[:800] + "…"
                tags = ["cve", "adp-enriched"]
                if any(a["provider"] == "CISA-ADP" for a in adp_signal):
                    tags.append("cisa-vulnrichment")
                # Bump priority for KEV + ADP combination
                meta = rec.get("cveMetadata") or {}
                published_iso = (
                    meta.get("datePublished") or meta.get("dateUpdated")
                    or datetime.now(timezone.utc).isoformat()
                )
                url = f"https://www.cve.org/CVERecord?id={cve_id}"
                persist_news(
                    source="cve-org", source_name="CVE.org + ADP",
                    reliability=96, feed_bump=2,
                    key=cve_id, title=f"[{cve_id}] ADP enrichment ({providers})",
                    summary=summary, url=url, published=published_iso,
                    extra_tags=tags, cves_hint=[cve_id],
                )
                inserted += 1
                # Be polite to cveawg
                await asyncio.sleep(0.1)
        record_feed_health("cve-org-adp", "CVE.org + ADP", ok=True, items=inserted)
        log.info("cve-org: %d enriched CVEs (from %d candidates)", inserted, len(cve_ids))
        return inserted
    except Exception as e:
        log.exception("cve-org failed")
        record_feed_health("cve-org-adp", "CVE.org + ADP", ok=False, error=str(e))
        return 0
