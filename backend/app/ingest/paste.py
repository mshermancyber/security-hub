"""Dark-web / paste-site exposure feed.

Ingests public paste indexes (no auth) and stores entries in iocs/news-style
rows for org mention scanning.

Sources:
  - PsbDmp public RSS (paste leak summaries, free)
  - DarkOwl Vision public sample (skipped if no key)
"""
from __future__ import annotations

import logging

from .. import config
from ..db import record_feed_health
from .rss import fetch_feed

log = logging.getLogger("sechub.ingest.paste")


PASTE_FEEDS = [
    {"id": "psbdmp",     "name": "PsbDmp leaks",         "url": "https://psbdmp.ws/rss",          "tier": 3, "reliability": 50, "category": "paste"},
    {"id": "leakix",     "name": "LeakIX index",         "url": "https://leakix.net/feed",        "tier": 3, "reliability": 55, "category": "paste"},
]


async def fetch_paste_feeds() -> int:
    total = 0
    for cfg in PASTE_FEEDS:
        try:
            total += await fetch_feed(cfg)
        except Exception as e:
            log.warning("%s failed: %s", cfg["id"], e)
            record_feed_health(cfg["id"], cfg["name"], ok=False, error=str(e))
    return total
