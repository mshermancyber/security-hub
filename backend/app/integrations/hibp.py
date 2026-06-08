"""Have I Been Pwned credential-leak lookups.

Gated by HIBP_API_KEY. Two endpoints:
  - breachedaccount/{email}  — paid HIBP API
  - breaches?domain=         — public, no key needed
"""
from __future__ import annotations

import os

import httpx

API = "https://haveibeenpwned.com/api/v3"


def is_configured() -> bool:
    return bool(os.environ.get("HIBP_API_KEY"))


async def breaches_for_domain(domain: str) -> dict:
    """List of breaches for a given domain (no API key required)."""
    from ..safe_http import safe_get
    try:
        async with httpx.AsyncClient(timeout=15,
                                     headers={"User-Agent": "SecurityHub-Terminal/1.0"},
                                     follow_redirects=False) as cx:
            r = await safe_get(cx, f"{API}/breaches",
                               params={"domain": domain}, max_bytes=4 * 1024 * 1024)
            return {"domain": domain, "configured": True, "breaches": r.json()}
    except Exception as e:
        return {"domain": domain, "configured": True, "error": str(e), "breaches": []}


async def breached_account(email: str) -> dict:
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        return {"configured": False, "email": email,
                "hint": "set HIBP_API_KEY to enable account lookup"}
    headers = {"hibp-api-key": key, "User-Agent": "SecurityHub-Terminal/1.0"}
    from ..safe_http import safe_get
    try:
        async with httpx.AsyncClient(timeout=15, headers=headers,
                                     follow_redirects=False) as cx:
            try:
                r = await safe_get(cx, f"{API}/breachedaccount/{email}",
                                   params={"truncateResponse": "false"},
                                   max_bytes=4 * 1024 * 1024)
            except httpx.HTTPStatusError as he:
                if he.response.status_code == 404:
                    return {"configured": True, "email": email, "breaches": []}
                raise
            return {"configured": True, "email": email, "breaches": r.json()}
    except Exception as e:
        return {"configured": True, "email": email, "error": str(e)}
