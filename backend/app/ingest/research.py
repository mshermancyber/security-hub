"""Early-signal research ingest: arXiv cs.CR + USENIX Security proceedings
+ Bugcrowd crowdstream public disclosures.

These add 6+-month leading indicators (academic papers, conference
abstracts) and *real* vulnerability disclosures that frequently land
ahead of vendor advisories.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import feedparser
import httpx

from .. import config
from ..db import record_feed_health
from .custom import _persist as persist_news

log = logging.getLogger("sechub.ingest.research")


# ─────────────────────────── arXiv cs.CR ───────────────────────────

ARXIV_URL = (
    "http://export.arxiv.org/api/query"
    "?search_query=cat:cs.CR"
    "&sortBy=submittedDate&sortOrder=descending&max_results=50"
)


async def fetch_arxiv() -> int:
    """arXiv requires polite UA and rate limiting. We pull once per ingest
    interval (every 12h via scheduler)."""
    headers = {"User-Agent": "SecurityHub-Terminal/1.0 (mailto:research@example.org)"}
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=60, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, ARXIV_URL, max_bytes=16 * 1024 * 1024)
            body = r.content
            # Case-insensitive DTD/ENTITY check on the XML prolog.
            prolog = body[:8192].lower()
            if b"<!entity" in prolog or b"<!doctype" in prolog:
                raise RuntimeError("arxiv response contained DTD/ENTITY — refused")
            f = feedparser.parse(body)
            inserted = 0
            for e in f.entries:
                arxiv_id = e.get("id") or e.get("link") or ""
                if not arxiv_id:
                    continue
                title = re.sub(r"\s+", " ", e.get("title", "")).strip()
                summary = re.sub(r"\s+", " ", e.get("summary", "")).strip()[:600]
                # Parse author list
                authors = ", ".join(a.get("name", "") for a in (e.get("authors") or [])[:5])
                if authors:
                    summary = f"{summary}  · {authors}"
                published = e.get("published") or e.get("updated") or ""
                try:
                    published = datetime.fromisoformat(published.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
                except Exception:
                    published = datetime.now(timezone.utc).isoformat()
                # Primary link is the abstract page
                url = e.get("link") or arxiv_id
                tags = ["research", "arxiv", "academic"]
                # Topic heuristics from title/summary
                blob_lower = (title + " " + summary).lower()
                if any(k in blob_lower for k in ("llm", "language model", "gpt", "prompt injection")):
                    tags.append("ai-security")
                if any(k in blob_lower for k in ("ransom", "encryption malware")):
                    tags.append("ransomware")
                if any(k in blob_lower for k in ("supply chain", "package", "npm", "pypi")):
                    tags.append("supply-chain")
                persist_news(
                    source="arxiv-cscr", source_name="arXiv cs.CR",
                    reliability=85, feed_bump=1,
                    key=arxiv_id, title=f"[arXiv] {title}",
                    summary=summary, url=url,
                    published=published, extra_tags=tags,
                )
                inserted += 1
        record_feed_health("arxiv-cscr", "arXiv cs.CR", ok=True, items=inserted)
        log.info("arxiv: %d papers", inserted)
        return inserted
    except Exception as e:
        log.exception("arxiv failed")
        record_feed_health("arxiv-cscr", "arXiv cs.CR", ok=False, error=str(e))
        return 0


# ─────────────────────────── USENIX Security proceedings ───────────────────────────

USENIX_BASE = "https://www.usenix.org"
USENIX_RECENT_CONFS = [
    "usenixsecurity26",
    "usenixsecurity25",
]

# Match presentation rows: anchor href + linked paper title
_USENIX_PAPER_RE = re.compile(
    r'<a[^>]+href="(/conference/(?:usenixsecurity\d+)/presentation/[^"]+)"[^>]*>'
    r'\s*([^<][^<]{5,200}?)\s*</a>',
    re.DOTALL,
)


async def fetch_usenix() -> int:
    headers = {"User-Agent": config.USER_AGENT}
    inserted = 0
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=30, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            seen: set[str] = set()
            for conf in USENIX_RECENT_CONFS:
                try:
                    r = await safe_get(cx, f"{USENIX_BASE}/conference/{conf}/technical-sessions",
                                       max_bytes=8 * 1024 * 1024)
                except Exception:
                    continue
                html = r.text
                for href, title in _USENIX_PAPER_RE.findall(html):
                    title = re.sub(r"\s+", " ", title).strip()
                    if not title or href in seen:
                        continue
                    seen.add(href)
                    url = USENIX_BASE + href
                    summary = f"USENIX {conf.replace('usenixsecurity', 'Security ')} accepted paper"
                    tags = ["research", "conference", "usenix", "academic"]
                    persist_news(
                        source="usenix-security", source_name="USENIX Security",
                        reliability=92, feed_bump=2,
                        key=href, title=f"[USENIX] {title}",
                        summary=summary, url=url,
                        published=datetime.now(timezone.utc).isoformat(),
                        extra_tags=tags,
                    )
                    inserted += 1
        record_feed_health("usenix-security", "USENIX Security", ok=True, items=inserted)
        log.info("usenix: %d papers", inserted)
        return inserted
    except Exception as e:
        log.exception("usenix failed")
        record_feed_health("usenix-security", "USENIX Security", ok=False, error=str(e))
        return 0


# ─────────────────────────── Bugcrowd crowdstream ───────────────────────────

BUGCROWD_URL = "https://bugcrowd.com/crowdstream.json"

_PRIORITY_LABEL = {1: "P1-Critical", 2: "P2-High", 3: "P3-Medium", 4: "P4-Low", 5: "P5-Info"}


async def fetch_bugcrowd() -> int:
    headers = {"Accept": "application/json", "User-Agent": config.USER_AGENT}
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=30, headers=headers,
                                      follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, BUGCROWD_URL, max_bytes=4 * 1024 * 1024)
            doc = r.json()
            items = doc.get("results") or []
            inserted = 0
            for it in items:
                rid = it.get("id")
                if not rid:
                    continue
                target = it.get("target") or ""
                engagement = it.get("engagement_name") or ""
                priority = it.get("priority") or 5
                substate = it.get("substate") or ""
                state_text = it.get("submission_state_text") or ""
                state_date = it.get("submission_state_date_text") or ""
                disclosed = it.get("disclosed") is not None
                engagement_path = it.get("engagement_path") or ""
                title = f"[{_PRIORITY_LABEL.get(priority, 'P?')}] {engagement}: {target}"
                summary = f"{state_text} · {state_date}"
                url = f"https://bugcrowd.com{engagement_path}" if engagement_path else "https://bugcrowd.com"
                published = it.get("disclosed") or it.get("closed_at") or it.get("created_at") or datetime.now(timezone.utc).isoformat()
                try:
                    published = datetime.fromisoformat(published.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
                except Exception:
                    published = datetime.now(timezone.utc).isoformat()
                tags = ["bounty", "disclosure"]
                if priority <= 2:
                    tags.append("critical-bounty")
                if disclosed:
                    tags.append("publicly-disclosed")
                if "*" in target or "." in target:
                    tags.append("domain-target")
                persist_news(
                    source="bugcrowd", source_name="Bugcrowd Crowdstream",
                    reliability=88, feed_bump=2 if priority <= 2 else 0,
                    key=rid, title=title, summary=summary, url=url,
                    published=published, extra_tags=tags,
                )
                inserted += 1
        record_feed_health("bugcrowd", "Bugcrowd Crowdstream", ok=True, items=inserted)
        log.info("bugcrowd: %d disclosures", inserted)
        return inserted
    except Exception as e:
        log.exception("bugcrowd failed")
        record_feed_health("bugcrowd", "Bugcrowd Crowdstream", ok=False, error=str(e))
        return 0


# ─────────────────────────── Aggregator ───────────────────────────

async def fetch_all_research() -> int:
    results = await asyncio.gather(
        fetch_arxiv(),
        fetch_usenix(),
        fetch_bugcrowd(),
        return_exceptions=True,
    )
    return sum(r for r in results if isinstance(r, int))
