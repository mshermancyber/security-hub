"""Hardened HTTP helpers for ingesters.

Two protections that every ingest fetch needs:

1. **SSRF redirect guard** — an attacker (or a compromised upstream feed)
   that returns a 30x to `http://169.254.169.254/` (cloud metadata) or a
   loopback / RFC1918 address would otherwise pull internal data into the
   ingester's working set. We resolve the redirect target's host and
   reject anything that isn't a globally-routable public IP.

2. **Response-size cap** — `httpx` loads the full body into memory before
   returning. A hostile feed serving a multi-GB stream OOMs the worker.
   We stream and abort once the cap is reached.

The cap is per-call so the larger feeds (MITRE STIX bundle ~25-30 MB) can
opt into a higher limit explicitly.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterable

import httpx

log = logging.getLogger("sechub.safe_http")

# 20 MiB default — comfortably above every well-behaved feed we ingest.
DEFAULT_MAX_BYTES = 20 * 1024 * 1024


class _ResolveFailed:
    """Sentinel returned by `_resolve_host` when DNS lookup itself fails.
    Distinct from `False` (resolved-to-private) so callers can let httpx
    take a swing at it instead of failing closed on a transient DNS hiccup."""
    pass


_DNS_FAILED = _ResolveFailed()


def _resolve_host(host: str | None):
    """Return True (public), False (resolved-to-private), or _DNS_FAILED.

    Why the three-state result: a hard "False on lookup failure" causes a
    flapping resolver to mark legitimate feeds as SSRF attempts and stick a
    "non-public host" error in `feed_health`. We'd rather let httpx do its
    own DNS and surface a real connection error than blame the operator.
    """
    if not host:
        return False
    h = host.strip().strip("[]")
    if "%" in h:
        h = h.split("%", 1)[0]
    try:
        infos = socket.getaddrinfo(h, None)
    except (socket.gaierror, UnicodeError):
        return _DNS_FAILED
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError):
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False
    return True


def _is_public_host(host: str | None) -> bool:
    """Backwards-compat: True only if explicitly public. Treats DNS-failure
    as not-public for the pre-flight URL check (where it's safe to fail
    closed because we haven't issued a request yet)."""
    return _resolve_host(host) is True


def _enforce_public_url(url: str) -> None:
    parsed = httpx.URL(url)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError(f"refused non-http(s) scheme: {parsed.scheme}")
    if not _is_public_host(parsed.host):
        raise RuntimeError(f"refused non-public host: {parsed.host}")


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    headers: dict | None = None,
    params: dict | None = None,
    allow_internal: bool = False,
) -> httpx.Response:
    """Stream a GET with SSRF + size guards.

    Mirrors httpx.Response — body is loaded into `r.content`/`r.text`, but
    the load happens incrementally so we can abort on cap.

    `allow_internal=True` is for explicit internal calls (none today; flag
    is here so future callers don't reach for `client.get` and lose the
    body cap).
    """
    if not allow_internal:
        _enforce_public_url(url)
    async with client.stream("GET", url, headers=headers, params=params) as r:
        # Reject redirects to internal hosts. httpx follows redirects under
        # the client's `follow_redirects` flag — when it's True we may end
        # up at a different `r.url` than the one we vetted above.
        # Allow DNS-failure (returns _DNS_FAILED) to fall through — httpx
        # already connected, so a transient resolver hiccup shouldn't
        # masquerade as a malicious redirect.
        if not allow_internal:
            verdict = _resolve_host(r.url.host)
            if verdict is False:
                raise RuntimeError(f"redirect target is non-public: {r.url.host}")
        r.raise_for_status()
        buf = bytearray()
        async for chunk in r.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise RuntimeError(
                    f"response from {url} exceeded cap of {max_bytes} bytes"
                )
        # Re-attach the buffered body as `r.content`. httpx's Response
        # exposes `_content`; setting it lets `.text` / `.json()` work.
        r._content = bytes(buf)
        return r


async def safe_post(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    headers: dict | None = None,
    json: dict | None = None,
    data: dict | bytes | str | None = None,
    allow_internal: bool = False,
) -> httpx.Response:
    if not allow_internal:
        _enforce_public_url(url)
    # POST bodies are smaller and we don't need streaming, but we still
    # want the redirect/host guard. Use stream() then dial back.
    async with client.stream(
        "POST", url, headers=headers, json=json, data=data
    ) as r:
        if not allow_internal:
            verdict = _resolve_host(r.url.host)
            if verdict is False:
                raise RuntimeError(f"redirect target is non-public: {r.url.host}")
        r.raise_for_status()
        buf = bytearray()
        async for chunk in r.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise RuntimeError(
                    f"response from {url} exceeded cap of {max_bytes} bytes"
                )
        r._content = bytes(buf)
        return r


def is_public_url(url: str) -> bool:
    """Convenience predicate for callers that want to pre-validate URLs
    (e.g. webhook sinks)."""
    try:
        _enforce_public_url(url)
        return True
    except Exception:
        return False
