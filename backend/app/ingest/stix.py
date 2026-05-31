"""Threat-intel IOC ingestion.

Pulls IOCs from abuse.ch ThreatFox (free, no auth). The threat_intel feed
isn't STIX 2.x natively — ThreatFox publishes a JSON dump and a STIX
endpoint. The JSON dump is reliable and lightweight; we normalize it to
our `iocs` schema.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone

import httpx

from .. import config
from ..db import record_feed_health, tx

log = logging.getLogger("sechub.ingest.stix")

THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"


def _hash_id(source: str, value: str) -> str:
    return hashlib.sha1(f"{source}|{value}".encode()).hexdigest()[:16]


async def fetch_threatfox(limit_records: int | None = None) -> int:
    """Ingest recent ThreatFox IOCs. Returns count inserted/updated."""
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT,
                                     headers={"User-Agent": config.USER_AGENT},
                                     follow_redirects=True, max_redirects=3) as cx:
            r = await safe_get(cx, THREATFOX_URL, max_bytes=32 * 1024 * 1024)
            doc = r.json()
    except Exception as e:
        record_feed_health("threatfox", "abuse.ch ThreatFox", ok=False, error=str(e))
        return 0

    rows: list[dict] = []
    for arr in doc.values():
        if isinstance(arr, list):
            rows.extend(arr)
    if limit_records:
        rows = rows[:limit_records]

    inserted = 0
    with tx() as conn:
        for d in rows:
            value = d.get("ioc_value")
            if not value:
                continue
            iid = _hash_id("threatfox", value)
            tags = [t.strip() for t in (d.get("tags") or "").split(",") if t.strip()]
            conn.execute(
                """INSERT INTO iocs (id, source, ioc_value, ioc_type, threat_type, malware,
                                     malware_printable, confidence, first_seen, last_seen,
                                     tags_json, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       confidence = excluded.confidence,
                       tags_json = excluded.tags_json""",
                (iid, "threatfox", value, d.get("ioc_type"), d.get("threat_type"),
                 d.get("malware"), d.get("malware_printable"),
                 int(d.get("confidence_level") or 0) if d.get("confidence_level") else None,
                 d.get("first_seen_utc"), d.get("last_seen_utc"),
                 json.dumps(tags), json.dumps(d)),
            )
            inserted += 1

    record_feed_health("threatfox", "abuse.ch ThreatFox", ok=True, items=inserted)
    log.info("threatfox ingest: %d IOCs", inserted)
    return inserted
