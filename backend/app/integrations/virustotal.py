"""VirusTotal v3 IOC enrichment.

Gated by VIRUSTOTAL_API_KEY. Supports IP / domain / URL / file hash.
"""
from __future__ import annotations

import base64
import os

import httpx

API = "https://www.virustotal.com/api/v3"


def is_configured() -> bool:
    return bool(os.environ.get("VIRUSTOTAL_API_KEY"))


def _kind_path(ioc: str) -> tuple[str, str]:
    s = ioc.strip()
    # IP
    if s.count(".") == 3 and all(p.isdigit() for p in s.split(".")):
        return "ip_addresses", s
    # hash
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) in (32, 40, 64):
        return "files", s.lower()
    # URL
    if s.startswith("http://") or s.startswith("https://"):
        b = base64.urlsafe_b64encode(s.encode()).rstrip(b"=").decode()
        return "urls", b
    # domain (fallback)
    return "domains", s


async def lookup(ioc: str) -> dict:
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return {"configured": False, "ioc": ioc,
                "hint": "set VIRUSTOTAL_API_KEY to enable"}
    kind, ident = _kind_path(ioc)
    from ..safe_http import safe_get
    async with httpx.AsyncClient(timeout=15, headers={"x-apikey": key},
                                 follow_redirects=False) as cx:
        try:
            r = await safe_get(cx, f"{API}/{kind}/{ident}", max_bytes=8 * 1024 * 1024)
        except httpx.HTTPStatusError as he:
            if he.response.status_code == 404:
                return {"configured": True, "ioc": ioc, "kind": kind, "found": False}
            raise
        d = r.json().get("data", {}).get("attributes", {})
    stats = d.get("last_analysis_stats", {}) or {}
    return {
        "configured": True,
        "ioc": ioc,
        "kind": kind,
        "found": True,
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": d.get("reputation"),
        "tags":       d.get("tags") or [],
        "last_analysis_date": d.get("last_analysis_date"),
        "total_votes": d.get("total_votes"),
        "categories": d.get("categories") or {},
    }
