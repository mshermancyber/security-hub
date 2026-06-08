"""NVD CVE feed — pulls recently-published CVEs and enriches with EPSS."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .. import config
from ..db import record_feed_health, tx
from ..enrich.entities import extract_entities
from ..enrich.scoring import cve_priority


def _iso_z(dt: datetime) -> str:
    # NVD expects 2024-09-01T00:00:00.000
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _pick_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Prefer CVSS v3.1 → v3.0 → v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            m = arr[0].get("cvssData", {})
            return m.get("baseScore"), m.get("baseSeverity"), m.get("vectorString")
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        m = arr[0].get("cvssData", {})
        sev = arr[0].get("baseSeverity")
        return m.get("baseScore"), sev, m.get("vectorString")
    return None, None, None


def _english_desc(descs: list[dict]) -> str:
    for d in descs:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descs[0].get("value", "") if descs else ""


async def fetch_epss(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, dict]:
    """Batch EPSS query (FIRST.org). Returns {cve_id: {score, percentile}}."""
    if not cve_ids:
        return {}
    out: dict[str, dict] = {}
    # FIRST EPSS supports comma-separated cve list in `cve` param, up to ~100 ids per call.
    from ..safe_http import safe_get
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i + 100]
        try:
            r = await safe_get(client, config.EPSS_BASE,
                               params={"cve": ",".join(batch)},
                               max_bytes=8 * 1024 * 1024)
            for row in r.json().get("data", []):
                out[row["cve"].upper()] = {
                    "score": float(row.get("epss", 0) or 0),
                    "percentile": float(row.get("percentile", 0) or 0),
                }
        except Exception:
            continue
    return out


async def fetch_nvd(lookback_days: int | None = None) -> int:
    """Pull CVEs modified in the last N days from NVD. Returns upsert count."""
    lookback_days = lookback_days or config.NVD_LOOKBACK_DAYS
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=lookback_days)

    headers = {"User-Agent": config.USER_AGENT}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    params: dict[str, Any] = {
        "lastModStartDate": _iso_z(start),
        "lastModEndDate": _iso_z(now),
        "resultsPerPage": 200,
        "startIndex": 0,
    }

    total = 0
    all_items: list[dict] = []
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=60.0, headers=headers,
                                     follow_redirects=True, max_redirects=3) as client:
            # paginate
            while True:
                try:
                    # NVD pages are capped at 200 results; 8 MiB is well above
                    # the largest observed page.
                    r = await safe_get(client, config.NVD_BASE, params=params,
                                       max_bytes=8 * 1024 * 1024)
                except httpx.HTTPStatusError as he:
                    if he.response.status_code == 403:
                        raise RuntimeError("NVD rate-limited (403). Consider setting NVD_API_KEY.")
                    raise
                body = r.json()
                vulns = body.get("vulnerabilities", []) or []
                all_items.extend(vulns)
                total_results = body.get("totalResults", 0)
                params["startIndex"] += len(vulns)
                if params["startIndex"] >= total_results or not vulns:
                    break
                if params["startIndex"] >= 1000:  # cap on a single refresh
                    break

            # EPSS enrichment
            cve_ids = [v.get("cve", {}).get("id", "").upper() for v in all_items if v.get("cve", {}).get("id")]
            epss_map = await fetch_epss(client, cve_ids)

        with tx() as conn:
            for v in all_items:
                cve = v.get("cve", {})
                cve_id = (cve.get("id") or "").upper()
                if not cve_id:
                    continue
                description = _english_desc(cve.get("descriptions", []))
                metrics = cve.get("metrics", {}) or {}
                cvss, sev, vector = _pick_cvss(metrics)
                cwes = []
                for w in cve.get("weaknesses", []) or []:
                    for d in w.get("description", []):
                        if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                            cwes.append(d["value"])
                refs = [r.get("url") for r in (cve.get("references", []) or []) if r.get("url")][:20]
                entities = extract_entities(description)
                epss = epss_map.get(cve_id, {})
                epss_score = epss.get("score")
                epss_pct = epss.get("percentile")

                existing = conn.execute(
                    "SELECT is_kev, kev_added, kev_ransomware FROM cves WHERE cve_id = ?", (cve_id,)
                ).fetchone()
                is_kev = bool(existing and existing["is_kev"])
                kev_ransomware = existing["kev_ransomware"] if existing else None

                prio = cve_priority(cvss=cvss, epss=epss_score, is_kev=is_kev, kev_ransomware=kev_ransomware)

                conn.execute(
                    """INSERT INTO cves (cve_id, published_at, last_modified, description, cvss_score, cvss_severity,
                                        cvss_vector, epss_score, epss_percentile, is_kev, kev_added, kev_ransomware,
                                        priority, entities_json, refs_json, cwe_json, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(cve_id) DO UPDATE SET
                         last_modified = excluded.last_modified,
                         description   = excluded.description,
                         cvss_score    = excluded.cvss_score,
                         cvss_severity = excluded.cvss_severity,
                         cvss_vector   = excluded.cvss_vector,
                         epss_score    = excluded.epss_score,
                         epss_percentile = excluded.epss_percentile,
                         priority      = excluded.priority,
                         entities_json = excluded.entities_json,
                         refs_json     = excluded.refs_json,
                         cwe_json      = excluded.cwe_json""",
                    (
                        cve_id,
                        cve.get("published") or now.isoformat(),
                        cve.get("lastModified") or now.isoformat(),
                        description,
                        cvss,
                        sev,
                        vector,
                        epss_score,
                        epss_pct,
                        1 if is_kev else 0,
                        existing["kev_added"] if existing else None,
                        kev_ransomware,
                        prio,
                        json.dumps(entities),
                        json.dumps(refs),
                        json.dumps(cwes),
                        json.dumps(cve)[:80000],
                    ),
                )
                total += 1
    except Exception as e:
        record_feed_health("nvd", "NVD CVE Feed", ok=False, error=str(e))
        return 0

    record_feed_health("nvd", "NVD CVE Feed", ok=True, items=total)
    return total
