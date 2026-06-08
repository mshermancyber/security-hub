"""Integrations control surface — health, test-fires, enrichment lookups."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from ..db import fetchall, fetchone, row_to_dict
from ..sqlutil import ESCAPE_CLAUSE, like
from ..integrations import router as routing
from ..integrations import shodan as shodan_mod
from ..integrations import virustotal as vt_mod

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


# Strict allowlists for upstream URL path-segments. Reject anything that could
# alter the URL path (`/`, `?`, `#`, `@`, whitespace, control chars) before the
# value is interpolated into a Shodan / VT / HIBP request URL.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
# IOC for VT: file hashes (md5/sha1/sha256), domains, ipv4, urls (we accept hash-only here).
_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")
_SINK_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,40}$")


def _valid_domain(d: str) -> bool:
    return bool(_DOMAIN_RE.match(d or ""))


def _valid_ipv4(ip: str) -> bool:
    if not _IPV4_RE.match(ip or ""):
        return False
    try:
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    except ValueError:
        return False


@router.get("/health")
def health():
    return routing.health_snapshot()


@router.post("/fire-test/{sink_id}")
async def fire_test(sink_id: str):
    """Send a synthetic news.item event to a single sink for verification."""
    if not _SINK_RE.match(sink_id):
        raise HTTPException(400, "invalid sink id")
    snap = routing.health_snapshot()
    sink_ids = {s["id"] for s in snap["sinks"]}
    if sink_id not in sink_ids:
        raise HTTPException(404, f"unknown sink {sink_id}")
    event = {
        "type": "news.item",
        "at": datetime.now(timezone.utc).isoformat(),
        "item": {
            "id": "test", "title": "[TEST] Synthetic high-priority alert from SecurityHub",
            "url": "about:blank", "source_name": "Operator Test",
            "priority": 90, "severity": 80,
            "tags": ["test", "operator-drill"], "cves": [],
            "published_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    fake_rule = {"id": "fire-test", "sink": sink_id, "match": {"event_type": "news.item"}}
    await routing._dispatch_to(sink_id, fake_rule, event)
    return {"ok": True, "sink": sink_id, "after": routing.health_snapshot()["sinks"]}


# ---- IOC routes ---------------------------------------------------------

@router.get("/iocs")
def iocs(limit: int = Query(100, ge=1, le=500), ioc_type: str | None = None, q: str | None = None):
    where = []
    params: list = []
    if ioc_type:
        where.append("ioc_type = ?")
        params.append(ioc_type)
    if q:
        where.append(f"ioc_value LIKE ? {ESCAPE_CLAUSE}")
        params.append(f"%{like(q)}%")
    sql = "SELECT id, source, ioc_value, ioc_type, threat_type, malware, malware_printable, " \
          "confidence, first_seen, last_seen, tags_json FROM iocs"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY first_seen DESC LIMIT ?"
    rows = fetchall(sql, (*params, limit))
    return {"items": [row_to_dict(r) for r in rows]}


@router.get("/iocs/stats")
def ioc_stats():
    by_type = {r["ioc_type"]: r["n"] for r in fetchall("SELECT ioc_type, COUNT(*) as n FROM iocs GROUP BY ioc_type")}
    by_malware = [dict(r) for r in fetchall("SELECT malware_printable, COUNT(*) as n FROM iocs WHERE malware_printable IS NOT NULL GROUP BY malware_printable ORDER BY n DESC LIMIT 12")]
    total = fetchone("SELECT COUNT(*) AS n FROM iocs")["n"]
    return {"total": total, "by_type": by_type, "top_malware": by_malware}


# ---- enrichment proxy routes -------------------------------------------

@router.get("/shodan/domain/{domain}")
async def shodan_domain(domain: str):
    if not _valid_domain(domain):
        raise HTTPException(400, "invalid domain")
    return await shodan_mod.domain_info(domain)


@router.get("/shodan/host/{ip}")
async def shodan_host(ip: str):
    if not _valid_ipv4(ip):
        raise HTTPException(400, "invalid ipv4 address")
    return await shodan_mod.host_info(ip)


@router.get("/virustotal/{ioc}")
async def vt_lookup(ioc: str):
    # VT accepts hash | domain | ipv4. Reject anything that could rewrite the
    # outbound request path.
    if not (_HASH_RE.match(ioc) or _valid_domain(ioc) or _valid_ipv4(ioc)):
        raise HTTPException(400, "invalid ioc (expected sha1/sha256/md5, domain, or ipv4)")
    return await vt_mod.lookup(ioc)
