"""RSS news ingestion across the configured security feeds."""
from __future__ import annotations

import hashlib
import json
import logging
log = logging.getLogger("sechub.ingest.rss")
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import feedparser
import httpx

from .. import config
from ..db import load_taxonomy, record_feed_health, tx
from ..enrich.cluster import cluster_key, simhash
from ..enrich.entities import extract_entities, extract_tags, severity_from_tags
from ..enrich.industry import INDUSTRY_TAGS, extract_industry
from ..enrich.refs import index_news_refs
from ..enrich.scoring import magnitude_bump as _magnitude_bump, news_priority
from ..enrich.watchlist import check_batch as check_watchlist
from ..ws import push_news_batch, push_org_alerts


def _normalize_dt(raw) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, str):
        try:
            return parsedate_to_datetime(raw).astimezone(timezone.utc)
        except Exception:
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            except Exception:
                return datetime.now(timezone.utc)
    # feedparser sometimes gives a struct_time
    try:
        import time
        return datetime.fromtimestamp(time.mktime(raw), tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _summary_text(entry) -> str:
    raw = entry.get("summary") or entry.get("description") or ""
    # crude HTML strip
    import re
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw[:1200]


def _hash_id(source_id: str, url: str, title: str) -> str:
    h = hashlib.sha1(f"{source_id}|{url or title}".encode()).hexdigest()
    return h[:16]


import re as _re_filter
from urllib.parse import urlparse as _urlparse

# Matches "(YYYY)" at end of title — common HN convention for resurfaced
# historical articles. We also scan the URL path for a year segment
# (e.g. "/2011/09/google-just-got-zagat-rated") since some feeds don't
# annotate the title.
_OLD_TITLE_YEAR_RE = _re_filter.compile(r"\((19|20)\d{2}\)\s*$")
_URL_YEAR_RE       = _re_filter.compile(r"/((?:19|20)\d{2})/")


_SAFE_SCHEME_RE = _re_filter.compile(r"^(?:https?:|mailto:|/[^/])", _re_filter.IGNORECASE)


def _is_safe_url(url: str) -> bool:
    """Reject `javascript:`, `data:`, `vbscript:`, and other dangerous
    schemes that an attacker-controlled feed could land in the news.url
    field. The frontend's safeHref is the primary defense; this is the
    second layer so we don't store unsafe URLs to begin with."""
    if not url:
        return True  # empty URL is fine — frontend falls back to "#"
    u = url.strip()
    if not u:
        return True
    # Strip leading control chars / whitespace bypass tricks.
    u = _re_filter.sub(r"^[\s\x00-\x1f]+", "", u)
    return bool(_SAFE_SCHEME_RE.match(u))


def _is_resurfaced_old_article(title: str, url: str, current_year: int) -> bool:
    """True when the article is clearly from > 2 years ago even though the
    feed's pubDate is recent. HN industry submissions often resurrect old
    Google/Apple/etc announcements; the in-title (YEAR) marker or a
    /YYYY/ slug in the URL is the giveaway."""
    m = _OLD_TITLE_YEAR_RE.search(title or "")
    if m:
        try:
            y = int(m.group(0).strip("() "))
            if y <= current_year - 2:
                return True
        except ValueError:
            pass
    m = _URL_YEAR_RE.search(url or "")
    if m:
        try:
            y = int(m.group(1))
            if y <= current_year - 2:
                return True
        except ValueError:
            pass
    return False


def _link_domain_source(url: str, default: str) -> str:
    """Pull the publication name out of a URL: politico.com → 'politico.com'.
    Used for link-aggregator feeds (HN industry, HN layoffs) where the
    feed's source_name would otherwise hide the real publication."""
    try:
        host = _urlparse(url).netloc
    except Exception:
        return default
    if not host:
        return default
    return host.removeprefix("www.")


async def fetch_feed(feed_cfg: dict) -> int:
    source_id = feed_cfg["id"]
    source_name = feed_cfg["name"]
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT,
                                     headers={"User-Agent": config.USER_AGENT},
                                     follow_redirects=True, max_redirects=5) as client:
            r = await safe_get(client, feed_cfg["url"], max_bytes=20 * 1024 * 1024)
            body = r.content
    except Exception as e:
        record_feed_health(source_id, source_name, ok=False, error=str(e))
        return 0

    # Scan the entire body for DTD/ENTITY declarations (not just the
    # prolog) — a crafted feed can push the payload past the XML
    # declaration.  feedparser 6.x blocks external entities but still
    # expands internal ones (billion-laughs vector).
    body_lower = body.lower()
    if b"<!entity" in body_lower or b"<!doctype" in body_lower:
        record_feed_health(source_id, source_name, ok=False,
                           error="feed contains DTD/ENTITY declarations — refused")
        return 0

    parsed = feedparser.parse(body)
    if parsed.bozo and not parsed.entries:
        record_feed_health(source_id, source_name, ok=False, error=f"feedparser: {parsed.bozo_exception}")
        return 0

    now_iso = datetime.now(timezone.utc).isoformat()
    inserted = 0
    new_items: list[dict] = []
    with tx() as conn:
        link_as_source = bool(feed_cfg.get("link_as_source"))
        for entry in parsed.entries[:60]:
            url = (entry.get("link") or "").strip()
            title = (entry.get("title") or "").strip()
            if not title:
                continue
            # Reject `javascript:` / `data:` / etc. — feed-injected XSS guard.
            if not _is_safe_url(url):
                continue
            # Skip resurfaced historical articles (e.g. HN reposting a
            # 2011 Google blog post). Feeds carry the submission date,
            # not the article date, so a 14-year-old article looks "new".
            if _is_resurfaced_old_article(title, url, datetime.now(timezone.utc).year):
                continue
            # For link-aggregator feeds (HN industry, HN layoffs) the
            # feed's source_name is generic; the link points to the real
            # publication. Use the link's domain as the source name so
            # users see "politico.com" not "Hacker News (industry)".
            row_source_name = source_name
            if link_as_source and url:
                row_source_name = _link_domain_source(url, source_name)
            summary = _summary_text(entry)
            published = _normalize_dt(entry.get("published_parsed") or entry.get("updated_parsed")
                                       or entry.get("published") or entry.get("updated"))
            if (datetime.now(timezone.utc) - published).days > 10:
                continue
            blob = f"{title}\n{summary}"
            tags = extract_tags(blob)
            entities = extract_entities(blob)
            # Pass entities so acquisition extractor can resolve lowercase brands.
            industry = extract_industry(blob, entities)
            for kind in industry:
                tag = INDUSTRY_TAGS.get(kind)
                if tag and tag not in tags:
                    tags.append(tag)
            severity = severity_from_tags(tags)
            entity_hits = (len(entities["vendors"]) + len(entities["ai_companies"]) +
                           len(entities["threat_actors"]) + len(entities["malware"]) +
                           len(entities["sectors"]) + len(entities["cves"]))
            recency_h = max(0.0, (datetime.now(timezone.utc) - published).total_seconds() / 3600)
            mag = _magnitude_bump(blob)["bump"]
            feed_bump = int(feed_cfg.get("priority_bump", 0))
            prio = news_priority(reliability=feed_cfg["reliability"], severity=severity,
                                 recency_hours=recency_h, entity_hits=entity_hits,
                                 feed_bump=feed_bump, magnitude_bump=mag)

            nid = _hash_id(source_id, url, title)
            try:
                existed = conn.execute("SELECT 1 FROM news WHERE id = ?", (nid,)).fetchone() is not None
                ckey = cluster_key(title, summary, entities)
                shash = simhash(title, summary)
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
                    (nid, source_id, row_source_name, title, summary, url, published.isoformat(), now_iso,
                     feed_cfg["reliability"], severity, prio,
                     json.dumps(tags), json.dumps(entities), json.dumps(entities["cves"]),
                     json.dumps(industry), ckey, shash),
                )
                index_news_refs(conn, nid, entities, entities["cves"])
                inserted += 1
                if not existed:
                    new_items.append({
                        "id": nid, "source_name": row_source_name, "title": title, "url": url,
                        "published_at": published.isoformat(), "priority": prio, "severity": severity,
                        "tags": tags, "cves": entities["cves"], "entities": entities,
                    })
            except Exception:
                continue

    record_feed_health(source_id, source_name, ok=True, items=inserted)
    if new_items:
        push_news_batch(new_items)
        push_org_alerts(new_items)
        try:
            check_watchlist(new_items)
        except Exception:
            log.exception("watchlist match failed")
    return inserted


async def fetch_all_feeds() -> int:
    import asyncio
    feeds = load_taxonomy("sources")["feeds"]
    results = await asyncio.gather(*(fetch_feed(f) for f in feeds), return_exceptions=True)
    return sum(r for r in results if isinstance(r, int))
