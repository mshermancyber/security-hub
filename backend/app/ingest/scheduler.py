"""Background ingestion scheduler — fires on app startup."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from .. import config
from ..db import kv_set
from ..enrich.backfill import backfill_all
from .db_backup import backup_db
from .epss import fetch_epss_all
from .kev import fetch_kev
from .mitre import fetch_mitre
from .custom import fetch_all_custom
from .cve_org import fetch_cve_org
from .msrc import fetch_msrc
from .research import fetch_all_research
from .nvd import fetch_nvd
from .ransomwatch import fetch_ransomwatch
from .rss import fetch_all_feeds
from .staleness import check_staleness
from .stix import fetch_threatfox

log = logging.getLogger("sechub.scheduler")


async def _loop(name: str, interval: int, fn):
    while True:
        try:
            t0 = datetime.now(timezone.utc)
            n = await fn()
            kv_set(f"last_run.{name}", {"at": t0.isoformat(), "count": n})
            log.info("[%s] ok, ingested %d items", name, n)
        except Exception as e:
            log.exception("[%s] failed: %s", name, e)
            kv_set(f"last_run.{name}", {"at": datetime.now(timezone.utc).isoformat(), "error": str(e)})
        await asyncio.sleep(interval)


async def run_startup() -> None:
    """Kick off one-shot warm fetches in parallel, then start loops."""
    # warm fetch — KEV first so NVD ingest can flag KEV entries
    try:
        await fetch_kev()
    except Exception:
        log.exception("initial kev fetch failed")
    await asyncio.gather(fetch_all_feeds(), fetch_nvd(), fetch_msrc(),
                         fetch_all_custom(), return_exceptions=True)
    # Run EPSS sync on startup so KEV/old CVEs get scores immediately.
    try:
        await fetch_epss_all(only_missing=True)
    except Exception:
        log.exception("startup epss sync failed")
    # Re-extract entities so taxonomy changes (e.g. new orgs) apply to historical rows.
    try:
        result = await asyncio.to_thread(backfill_all)
        log.info("startup backfill: %s", result)
        kv_set("last_run.backfill",
               {"at": datetime.now(timezone.utc).isoformat(), **result})
    except Exception:
        log.exception("startup backfill failed")


def start_background(loop_factory=None):
    """Schedule periodic refresh loops on the current event loop."""
    loop = asyncio.get_event_loop()
    loop.create_task(_loop("kev",  config.REFRESH_KEV,  fetch_kev))
    loop.create_task(_loop("nvd",  config.REFRESH_NVD,  fetch_nvd))
    loop.create_task(_loop("news", config.REFRESH_NEWS, fetch_all_feeds))
    # EPSS — daily, covering every CVE in DB
    loop.create_task(_loop("epss", 86400, lambda: fetch_epss_all(only_missing=False)))
    # ThreatFox IOCs — every 30 min
    loop.create_task(_loop("threatfox", 1800, fetch_threatfox))
    # Ransomware.live leak-site postings — every 30 min
    loop.create_task(_loop("ransomware-live", 1800, fetch_ransomwatch))
    # MITRE ATT&CK — weekly refresh of group/malware taxonomy
    loop.create_task(_loop("mitre", 7 * 86400, fetch_mitre))
    # Microsoft MSRC CVRF — every 6h (Patch Tuesday + out-of-band releases)
    loop.create_task(_loop("msrc", 6 * 3600, fetch_msrc))
    # Custom vendor ingests (Cisco PSIRT, Atlassian, Apple, CCCS, Sophos) — every 3h
    loop.create_task(_loop("custom-vendors", 3 * 3600, fetch_all_custom))
    # Research signal (arXiv cs.CR + USENIX + Bugcrowd) — every 12h
    loop.create_task(_loop("research", 12 * 3600, fetch_all_research))
    # CVE.org ADP enrichments — every 4h, ~40 candidates per pass
    loop.create_task(_loop("cve-org", 4 * 3600, fetch_cve_org))
    # SQLite backup — every 24h, rotation = 7
    loop.create_task(_loop("db-backup", 86400, backup_db))
    # Per-feed staleness check — every 15 min
    loop.create_task(_loop("staleness", 900, check_staleness))
