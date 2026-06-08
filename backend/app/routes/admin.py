"""Admin / operator endpoints — trigger refreshes, fire test alerts."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from ..ingest.epss import fetch_epss_all
from ..ingest.kev import fetch_kev
from ..ingest.mitre import fetch_mitre
from ..ingest.nvd import fetch_nvd
from ..ingest.ransomwatch import fetch_ransomwatch
from ..ingest.rss import fetch_all_feeds
from ..ws import bus

router = APIRouter(prefix="/api/admin", tags=["admin"])

_FEED_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,40}$")
_ORG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,40}$")


@router.post("/refresh/{feed}")
async def refresh(feed: str):
    feed = (feed or "").lower()
    if not _FEED_RE.match(feed):
        raise HTTPException(400, "invalid feed id")
    if feed in ("news", "rss"):
        n = await fetch_all_feeds()
    elif feed == "kev":
        n = await fetch_kev()
    elif feed == "nvd":
        n = await fetch_nvd()
    elif feed == "epss":
        n = await fetch_epss_all(only_missing=False)
    elif feed == "epss-missing":
        n = await fetch_epss_all(only_missing=True)
    elif feed == "mitre":
        n = await fetch_mitre()
    elif feed == "msrc":
        from ..ingest.msrc import fetch_msrc
        n = await fetch_msrc()
    elif feed == "cisco-psirt":
        from ..ingest.custom import fetch_cisco_psirt
        n = await fetch_cisco_psirt()
    elif feed == "atlassian":
        from ..ingest.custom import fetch_atlassian
        n = await fetch_atlassian()
    elif feed == "apple":
        from ..ingest.custom import fetch_apple_security
        n = await fetch_apple_security()
    elif feed == "cccs":
        from ..ingest.custom import fetch_cccs
        n = await fetch_cccs()
    elif feed == "sophos":
        from ..ingest.custom import fetch_sophos
        n = await fetch_sophos()
    elif feed in ("redhat", "redhat-cve"):
        from ..ingest.custom import fetch_redhat_cves
        n = await fetch_redhat_cves()
    elif feed == "custom-vendors":
        from ..ingest.custom import fetch_all_custom
        n = await fetch_all_custom()
    elif feed == "arxiv":
        from ..ingest.research import fetch_arxiv
        n = await fetch_arxiv()
    elif feed == "usenix":
        from ..ingest.research import fetch_usenix
        n = await fetch_usenix()
    elif feed == "bugcrowd":
        from ..ingest.research import fetch_bugcrowd
        n = await fetch_bugcrowd()
    elif feed == "research":
        from ..ingest.research import fetch_all_research
        n = await fetch_all_research()
    elif feed == "cve-org":
        from ..ingest.cve_org import fetch_cve_org
        n = await fetch_cve_org()
    elif feed == "ransomwatch" or feed == "ransomware-live":
        n = await fetch_ransomwatch()
    elif feed == "db-backup":
        from ..ingest.db_backup import backup_db
        n = await backup_db()
    elif feed == "staleness":
        from ..ingest.staleness import check_staleness
        n = await check_staleness()
    elif feed == "all":
        results = await asyncio.gather(fetch_kev(), fetch_all_feeds(), fetch_nvd(), return_exceptions=True)
        n = sum(r for r in results if isinstance(r, int))
    else:
        raise HTTPException(404, f"unknown feed: {feed}")
    return {"ok": True, "ingested": n, "at": datetime.now(timezone.utc).isoformat()}


@router.post("/test-alert")
async def test_alert(org: str = "acme-corp"):
    """Fire a synthetic org.alert event for the named org. Useful for verifying
    push pipeline end-to-end and for operator drills."""
    if not _ORG_RE.match(org):
        raise HTTPException(400, "invalid org id")
    await bus.broadcast({
        "type": "org.alert",
        "org": org,
        "org_name": org.upper(),
        "reason": "operator-test",
        "item": {
            "id": "test-" + datetime.now(timezone.utc).strftime("%H%M%S"),
            "title": f"[TEST] Synthetic alert for {org}",
            "url": "about:blank",
            "source_name": "Operator Test",
            "priority": 80, "severity": 70,
            "tags": ["breach", "phishing"],
            "cves": [], "published_at": datetime.now(timezone.utc).isoformat(),
            "entities": {"orgs": [org]},
        },
    })
    return {"ok": True, "delivered_to": len(bus.clients)}
