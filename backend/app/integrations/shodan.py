"""Shodan integration — internet-exposure lookups for org domains.

Gated by SHODAN_API_KEY. When absent, /api/enrich/shodan/* returns a
"not configured" response so the UI can render a clear stub state.
"""
from __future__ import annotations

import os

import httpx

API = "https://api.shodan.io"


def is_configured() -> bool:
    return bool(os.environ.get("SHODAN_API_KEY"))


async def domain_info(domain: str) -> dict:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return {"configured": False, "domain": domain,
                "hint": "set SHODAN_API_KEY to enable"}
    from ..safe_http import safe_get
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as cx:
        r = await safe_get(cx, f"{API}/dns/domain/{domain}",
                           params={"key": key}, max_bytes=8 * 1024 * 1024)
        d = r.json()
    return {
        "configured": True,
        "domain": domain,
        "subdomains": d.get("subdomains", [])[:50],
        "data": [
            {"type": rec.get("type"), "value": rec.get("value"),
             "subdomain": rec.get("subdomain"), "last_seen": rec.get("last_seen")}
            for rec in d.get("data", [])[:30]
        ],
    }


async def host_info(ip: str) -> dict:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return {"configured": False, "ip": ip, "hint": "set SHODAN_API_KEY to enable"}
    from ..safe_http import safe_get
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as cx:
        r = await safe_get(cx, f"{API}/shodan/host/{ip}",
                           params={"key": key}, max_bytes=8 * 1024 * 1024)
        d = r.json()
    return {
        "configured": True,
        "ip": ip,
        "org": d.get("org"),
        "isp": d.get("isp"),
        "country": d.get("country_code"),
        "ports": d.get("ports") or [],
        "vulns": list((d.get("vulns") or []))[:30],
        "tags": d.get("tags") or [],
        "hostnames": d.get("hostnames") or [],
        "last_update": d.get("last_update"),
    }
