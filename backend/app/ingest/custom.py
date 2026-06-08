"""Custom (non-RSS) ingest modules for vendor advisories that don't
publish a clean RSS feed.

Each function pulls from a vendor-specific HTML page or JSON API,
normalizes to the news schema, and emits one logical "feed" worth of
health stats per source.

The shared `_persist` helper runs the standard enrichment pipeline
(entities, tags, industry, simhash, cluster_key, news_refs) so these
items live in the same news table as everything else.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin

import feedparser
import httpx

from .. import config
from ..db import record_feed_health, tx
from ..enrich.cluster import cluster_key, simhash
from ..enrich.entities import extract_entities, extract_tags, severity_from_tags
from ..enrich.industry import INDUSTRY_TAGS, extract_industry
from ..enrich.refs import index_news_refs
from ..enrich.scoring import news_priority

log = logging.getLogger("sechub.ingest.custom")

CURL_UA = "curl/8.5.0"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _hash_id(source_id: str, key: str) -> str:
    return hashlib.sha1(f"{source_id}|{key}".encode()).hexdigest()[:16]


def _parse_dt(s: str | None) -> str:
    if not s:
        return datetime.now(timezone.utc).isoformat()
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc).isoformat()
    except Exception:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()


_MAX_AGE_DAYS = 10


def _persist(
    *, source: str, source_name: str, reliability: int, feed_bump: int,
    key: str, title: str, summary: str, url: str, published: str,
    extra_tags: list[str], cves_hint: list[str] | None = None,
    skip_enrichment_tags: bool = False,
) -> None:
    """Run enrichment + insert one news row."""
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if pub_dt.tzinfo is None:
            pub_dt = pub_dt.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - pub_dt).days > _MAX_AGE_DAYS:
            return
    except Exception:
        return
    blob = f"{title}\n{summary}"
    if skip_enrichment_tags:
        tags = list(extra_tags)
    else:
        tags = extract_tags(blob)
        for t in extra_tags:
            if t not in tags:
                tags.append(t)
    entities = extract_entities(blob)
    for c in (cves_hint or []):
        cu = c.upper()
        if cu not in entities.get("cves", []):
            entities["cves"].append(cu)
    industry = extract_industry(blob, entities)
    for kind in industry:
        tag = INDUSTRY_TAGS.get(kind)
        if tag and tag not in tags:
            tags.append(tag)
    severity = severity_from_tags(tags)
    # recency: 0h since these are just-fetched
    prio = news_priority(
        reliability=reliability, severity=severity,
        recency_hours=0, entity_hits=len(entities.get("cves", [])),
        feed_bump=feed_bump,
    )
    nid = _hash_id(source, key)
    ckey = cluster_key(title, summary, entities)
    shash = simhash(title, summary)
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
            (nid, source, source_name, title, summary, url,
             published, now_iso, reliability, severity, prio,
             json.dumps(tags), json.dumps(entities),
             json.dumps(entities.get("cves", [])),
             json.dumps(industry), ckey, shash),
        )
        index_news_refs(conn, nid, entities, entities.get("cves", []))


# ─────────────────────────── Cisco PSIRT ───────────────────────────

CISCO_URL = "https://tools.cisco.com/security/center/publicationService.x?fields=all"


async def fetch_cisco_psirt() -> int:
    headers = {"Accept": "application/json, text/plain, */*",
               "User-Agent": config.USER_AGENT}
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=30, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            r = None
            for attempt in range(3):
                try:
                    r = await safe_get(cx, CISCO_URL, max_bytes=16 * 1024 * 1024)
                except Exception:
                    r = None
                if r is not None and r.content:
                    break
                await asyncio.sleep(2 + attempt * 2)
            if not r or not r.content:
                raise RuntimeError("empty response after retries")
            try:
                items = r.json()
            except Exception:
                items = json.loads(r.text)
            if not isinstance(items, list):
                items = items.get("items") or items.get("data") or []
            inserted = 0
            for it in items:
                identifier = it.get("identifier") or it.get("advisoryId")
                if not identifier:
                    continue
                title = it.get("title") or identifier
                summary = it.get("summary") or it.get("description") or ""
                url = it.get("url") or f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{identifier}"
                published = _parse_dt(
                    it.get("firstPublished") or it.get("publishedDate") or it.get("lastUpdated")
                )
                cves: list[str] = []
                raw_cve = it.get("cve") or it.get("cves") or []
                # Cisco returns `cve` as a string or list of strings
                if isinstance(raw_cve, str):
                    raw_cve = [s.strip() for s in re.split(r"[,\s]+", raw_cve) if s.strip()]
                for c in raw_cve:
                    if isinstance(c, str) and _CVE_RE.search(c):
                        cves.append(c.upper())
                    elif isinstance(c, dict):
                        v = c.get("id") or c.get("name") or ""
                        if v and _CVE_RE.search(v):
                            cves.append(v.upper())
                tags = ["patch", "vendor-advisory", "cisco"]
                sir = (it.get("sir") or it.get("severityImpactRating") or "").lower()
                if sir in ("critical", "high"):
                    tags.append("critical-patch")
                _persist(
                    source="cisco-psirt", source_name="Cisco PSIRT",
                    reliability=96, feed_bump=3,
                    key=identifier, title=title, summary=summary, url=url,
                    published=published, extra_tags=tags, cves_hint=cves,
                )
                inserted += 1
        record_feed_health("cisco-psirt", "Cisco PSIRT", ok=True, items=inserted)
        log.info("cisco-psirt: %d advisories", inserted)
        return inserted
    except Exception as e:
        log.exception("cisco-psirt failed")
        record_feed_health("cisco-psirt", "Cisco PSIRT", ok=False, error=str(e))
        return 0


# ─────────────────────────── Atlassian Security Advisories ───────────────────────────

ATL_URL = "https://www.atlassian.com/trust/security/advisories"
_ATL_BULLETIN_RE = re.compile(
    r'<a[^>]*href="(https://confluence\.atlassian\.com/spaces/SECURITY/pages/\d+/[^"]+)"[^>]*>([^<]+)</a>'
)
_ATL_ADVISORY_RE = re.compile(
    r'data-label-english="([^"]+CVE-\d{4}-\d{4,7}[^"]*)"\s+href="(https?://[^"]+)"'
)
_ATL_BULLETIN_DATE_RE = re.compile(
    r"Security[+_\- ]+Bulletin[+_\- ]+-?[+_\- ]+([A-Za-z]+)[+_\- ]+(\d{1,2})[+_\- ]+(\d{4})"
)


async def fetch_atlassian(days_back: int = 365) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": config.USER_AGENT},
                                      follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, ATL_URL, max_bytes=8 * 1024 * 1024)
            html = r.text
            inserted = 0
            seen: set[str] = set()

            for url_, label in _ATL_BULLETIN_RE.findall(html):
                if url_ in seen:
                    continue
                seen.add(url_)
                title = label.strip()
                m = _ATL_BULLETIN_DATE_RE.search(url_)
                if m:
                    try:
                        d = datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3)}", "%B %d %Y")
                        d = d.replace(tzinfo=timezone.utc)
                        if d < cutoff:
                            continue
                        published = d.isoformat()
                    except ValueError:
                        published = datetime.now(timezone.utc).isoformat()
                else:
                    published = datetime.now(timezone.utc).isoformat()
                _persist(
                    source="atlassian-psirt", source_name="Atlassian Advisories",
                    reliability=94, feed_bump=2,
                    key=url_, title=title, summary=title, url=url_,
                    published=published, extra_tags=["patch", "vendor-advisory", "atlassian"],
                )
                inserted += 1

            for label, url_ in _ATL_ADVISORY_RE.findall(html):
                if url_ in seen:
                    continue
                seen.add(url_)
                cves = [c.upper() for c in _CVE_RE.findall(label)]
                # Derive published date from CVE year; skip old CVEs
                pub = datetime.now(timezone.utc)
                cve_year_match = re.search(r'CVE-(\d{4})', label)
                if cve_year_match:
                    cve_year = int(cve_year_match.group(1))
                    pub = datetime(cve_year, 7, 1, tzinfo=timezone.utc)
                if pub < cutoff:
                    continue
                _persist(
                    source="atlassian-psirt", source_name="Atlassian Advisories",
                    reliability=94, feed_bump=2,
                    key=url_, title=label.strip(), summary=label.strip(), url=url_,
                    published=pub.isoformat(),
                    extra_tags=["patch", "vendor-advisory", "atlassian"],
                    cves_hint=cves,
                )
                inserted += 1

        record_feed_health("atlassian-psirt", "Atlassian Advisories", ok=True, items=inserted)
        log.info("atlassian: %d advisories", inserted)
        return inserted
    except Exception as e:
        log.exception("atlassian failed")
        record_feed_health("atlassian-psirt", "Atlassian Advisories", ok=False, error=str(e))
        return 0


# ─────────────────────────── Apple Security Releases ───────────────────────────

APPLE_URL = "https://support.apple.com/100100"
_APPLE_ROW_RE = re.compile(
    r'<td[^>]*>\s*<p[^>]*><a[^>]*href="(/en-us/\d+)"[^>]*>([^<]+)</a></p></td>'
    r'\s*<td[^>]*>\s*<p[^>]*>([^<]+)</p></td>'
    r'\s*<td[^>]*>\s*<p[^>]*>([^<]+)</p></td>',
    re.DOTALL,
)


async def fetch_apple_security() -> int:
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": config.USER_AGENT},
                                      follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, APPLE_URL, max_bytes=8 * 1024 * 1024)
            html = r.text
            inserted = 0
            for href, name, available, released in _APPLE_ROW_RE.findall(html):
                name = re.sub(r"\s+", " ", name).strip()
                available = re.sub(r"\s+", " ", available).strip()
                released = re.sub(r"\s+", " ", released).strip()
                published = datetime.now(timezone.utc).isoformat()
                for fmt in ("%d %b %Y", "%d %B %Y", "%B %d, %Y", "%b %d, %Y", "%Y-%m-%d"):
                    try:
                        d = datetime.strptime(released, fmt)
                        published = d.replace(tzinfo=timezone.utc).isoformat()
                        break
                    except ValueError:
                        continue
                url = urljoin("https://support.apple.com", href)
                title = f"Apple Security: {name}"
                summary = f"Available for: {available}. Released: {released}."
                lt = name.lower()
                extra = ["patch", "vendor-advisory", "apple"]
                if "ipados" in lt or "ios " in lt or lt.startswith("ios"):
                    extra.append("apple-ios")
                if "macos" in lt:
                    extra.append("apple-macos")
                if "safari" in lt:
                    extra.append("apple-safari")
                if "watchos" in lt:
                    extra.append("apple-watchos")
                if "tvos" in lt:
                    extra.append("apple-tvos")
                if "xcode" in lt:
                    extra.append("apple-xcode")
                _persist(
                    source="apple-security", source_name="Apple Security Releases",
                    reliability=95, feed_bump=2,
                    key=href, title=title, summary=summary, url=url,
                    published=published, extra_tags=extra,
                )
                inserted += 1
        record_feed_health("apple-security", "Apple Security Releases", ok=True, items=inserted)
        log.info("apple: %d advisories", inserted)
        return inserted
    except Exception as e:
        log.exception("apple failed")
        record_feed_health("apple-security", "Apple Security Releases", ok=False, error=str(e))
        return 0


# ─────────────────────────── CCCS Canada JSON API ───────────────────────────

CCCS_URL = "https://www.cyber.gc.ca/api/cccs/threats/v1/get?lang=en"


async def fetch_cccs() -> int:
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=60, headers={"User-Agent": config.USER_AGENT},
                                      follow_redirects=True, max_redirects=3) as cx:
            # CCCS dumps the full alert corpus on each call. As of 2026 it's
            # ~17 MiB and growing; bump headroom to 64 MiB.
            r = await safe_get(cx, CCCS_URL, max_bytes=64 * 1024 * 1024)
            doc = r.json()
            items = doc.get("response") or doc.get("data") or []
            # CCCS returns historical alerts in arbitrary order; sort newest first
            items.sort(key=lambda x: (x.get("date_modified_ts") or x.get("date_modified") or ""),
                       reverse=True)
            inserted = 0
            for it in items[:500]:
                nid_key = str(it.get("nid") or it.get("serial_number") or "")
                if not nid_key:
                    continue
                title = (it.get("title") or "").strip()
                if not title:
                    continue
                serial = (it.get("serial_number") or "").strip()
                summary = (it.get("summary") or it.get("subject") or "").strip()
                url = it.get("external_url") or it.get("url") or f"https://www.cyber.gc.ca/en/alerts-advisories/{nid_key}"
                published = _parse_dt(
                    it.get("date_modified_ts") or it.get("date_modified")
                    or it.get("date_created") or it.get("changed")
                )
                tags = ["advisory", "cert"]
                # alert_type 397 = "Alert" in CCCS taxonomy
                if it.get("alert_type") in (397, "alert", "Alert"):
                    tags.append("alert")
                full_title = f"[{serial}] {title}" if serial else title
                _persist(
                    source="cccs-canada", source_name="Canadian Centre for Cyber Security",
                    reliability=92, feed_bump=2,
                    key=nid_key, title=full_title, summary=summary, url=url,
                    published=published, extra_tags=tags,
                )
                inserted += 1
        record_feed_health("cccs-canada", "Canadian Centre for Cyber Security", ok=True, items=inserted)
        log.info("cccs: %d alerts", inserted)
        return inserted
    except Exception as e:
        log.exception("cccs failed")
        record_feed_health("cccs-canada", "Canadian Centre for Cyber Security", ok=False, error=str(e))
        return 0


# ─────────────────────────── Sophos (Akamai-gated) ───────────────────────────

SOPHOS_URL = "https://news.sophos.com/feed/"


async def fetch_sophos() -> int:
    """Sophos news.sophos.com sits behind Akamai bot mgmt that blocks
    browser-like UAs but allows curl/wget through. Use the curl UA."""
    headers = {"User-Agent": CURL_UA, "Accept": "application/rss+xml, */*"}
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=30, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, SOPHOS_URL, max_bytes=16 * 1024 * 1024)
            f = feedparser.parse(r.content)
            inserted = 0
            for e in f.entries:
                eid = e.get("id") or e.get("link")
                if not eid:
                    continue
                title = (e.get("title") or "").strip()
                summary_html = e.get("summary") or ""
                summary = re.sub(r"<[^>]+>", " ", summary_html)
                summary = re.sub(r"\s+", " ", summary).strip()[:600]
                url = e.get("link") or ""
                published = _parse_dt(e.get("published") or e.get("updated"))
                _persist(
                    source="sophos-xops", source_name="Sophos X-Ops",
                    reliability=91, feed_bump=0,
                    key=eid, title=title, summary=summary, url=url,
                    published=published, extra_tags=["vendor-research"],
                )
                inserted += 1
        record_feed_health("sophos-xops", "Sophos X-Ops", ok=True, items=inserted)
        log.info("sophos: %d posts", inserted)
        return inserted
    except Exception as e:
        log.exception("sophos failed")
        record_feed_health("sophos-xops", "Sophos X-Ops", ok=False, error=str(e))
        return 0


# ─────────────────────────── Red Hat Security Data ───────────────────────────
#
# The `rhsa-blog` RSS we already pull is Red Hat's commentary blog — not
# vulnerability details. The actual CVE corpus lives at the Hydra security
# data API. Each record carries severity, public_date, CVSS3, CWE, affected
# packages, and a stable resource_url back to the canonical CVE page.

REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"


async def fetch_redhat_cves(days_back: int = 30, per_page: int = 100) -> int:
    """Pull Red Hat-flagged CVEs from the last N days. Each CVE becomes a
    news row tagged with severity + 'redhat' + 'patch'."""
    from ..safe_http import safe_get
    after = (datetime.now(timezone.utc) - timedelta(days=days_back)).date().isoformat()
    headers = {"Accept": "application/json", "User-Agent": config.USER_AGENT}
    inserted = 0
    try:
        async with httpx.AsyncClient(timeout=30, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            page = 1
            while True:
                params = {"per_page": per_page, "page": page, "after": after}
                try:
                    r = await safe_get(cx, REDHAT_CVE_URL, params=params,
                                       max_bytes=8 * 1024 * 1024)
                except Exception:
                    break
                items = r.json() or []
                if not isinstance(items, list) or not items:
                    break
                for it in items:
                    cve = (it.get("CVE") or "").upper()
                    if not cve or not _CVE_RE.match(cve):
                        continue
                    severity = (it.get("severity") or "").lower()  # low|moderate|important|critical
                    pub = it.get("public_date") or datetime.now(timezone.utc).isoformat()
                    desc = (it.get("bugzilla_description") or "").strip()
                    cvss3 = it.get("cvss3_score") or it.get("cvss_score")
                    # Red Hat Hydra returns CWE as either a string ("CWE-79")
                    # or a list (["CWE-79","CWE-94"]) depending on the entry.
                    # Coerce defensively — joining a list into the summary
                    # would TypeError otherwise and the outer try/except would
                    # swallow the whole page.
                    cwe_raw = it.get("CWE") or ""
                    if isinstance(cwe_raw, list):
                        cwe = ", ".join(str(c) for c in cwe_raw if c)
                    else:
                        cwe = str(cwe_raw)
                    pkgs = it.get("affected_packages") or []
                    pkg_str = ", ".join(str(p) for p in pkgs[:4]) if isinstance(pkgs, list) else ""
                    summary_parts = [desc]
                    if cvss3:
                        summary_parts.append(f"CVSS {cvss3}")
                    if cwe:
                        summary_parts.append(cwe)
                    if pkg_str:
                        summary_parts.append(f"affects: {pkg_str}")
                    summary = "  ·  ".join(p for p in summary_parts if p)
                    title = f"Red Hat [{severity.upper() or 'CVE'}] {cve}: {(desc.split('—')[-1] or desc)[:120]}".strip()
                    url = it.get("resource_url") or f"https://access.redhat.com/security/cve/{cve}"
                    extra_tags = ["redhat", "patch", "vuln"]
                    if severity in ("critical", "important"):
                        extra_tags.append(severity)
                    _persist(
                        source="redhat-cve", source_name="Red Hat Security Data",
                        reliability=96, feed_bump=4,
                        key=cve, title=title, summary=summary, url=url,
                        published=pub, extra_tags=extra_tags, cves_hint=[cve],
                    )
                    inserted += 1
                if len(items) < per_page:
                    break
                page += 1
                if page > 5:  # hard cap — 5 pages × 100 = 500 CVEs / run
                    break
        record_feed_health("redhat-cve", "Red Hat Security Data", ok=True, items=inserted)
        log.info("redhat-cve: %d CVEs", inserted)
        return inserted
    except Exception as e:
        log.exception("redhat-cve failed")
        record_feed_health("redhat-cve", "Red Hat Security Data", ok=False, error=str(e))
        return 0


# ─────────────────────────── Aggregator ───────────────────────────

async def fetch_all_custom() -> int:
    results = await asyncio.gather(
        fetch_cisco_psirt(),
        fetch_atlassian(),
        fetch_apple_security(),
        fetch_cccs(),
        fetch_sophos(),
        fetch_redhat_cves(),
        return_exceptions=True,
    )
    return sum(r for r in results if isinstance(r, int))
