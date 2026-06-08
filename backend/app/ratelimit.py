"""Tiny in-process token-bucket rate limiter.

Used to cap workspace POSTs (stars / annotations / saved). Not a substitute
for an edge rate limiter on internet-exposed deployments, but enough to
prevent accidental client loops from saturating the SQLite write queue.

Defaults: 60 requests per minute per (path-prefix, client IP) bucket.
Override per-prefix in `LIMITS`. Disable entirely with SECHUB_RATELIMIT=0.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


# (prefix, requests, per_seconds)
LIMITS = [
    ("/api/workspace/", 60, 60),     # 60 req/min default
    # Admin endpoints kick off heavy ingest jobs (NVD/MITRE downloads,
    # full-RSS sweep). Under SECHUB_INSECURE=1 these are reachable from any
    # LAN client, so cap to a sane operator-drill rate.
    ("/api/admin/",     10, 60),
    # CRUD on orgs.json — defends against accidental client loops corrupting
    # the taxonomy file via repeated POST/PUT/DELETE.
    ("/api/orgs-admin/", 30, 60),
]


_buckets: dict[tuple[str, str], list[float]] = defaultdict(list)
_lock = threading.Lock()


def _check(prefix: str, limit: int, window: float, key: str) -> bool:
    now = time.monotonic()
    cutoff = now - window
    with _lock:
        bucket = _buckets[(prefix, key)]
        # drop expired
        i = 0
        for i, t in enumerate(bucket):
            if t >= cutoff:
                break
        else:
            i = len(bucket)
        del bucket[:i]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if os.environ.get("SECHUB_RATELIMIT", "1") == "0":
            return await call_next(request)
        if request.method not in ("POST", "PUT", "DELETE"):
            return await call_next(request)
        path = request.url.path
        client = request.client.host if request.client else "?"
        for prefix, limit, window in LIMITS:
            if path.startswith(prefix):
                if not _check(prefix, limit, window, client):
                    return JSONResponse(
                        status_code=429,
                        content={"detail": f"rate limit: {limit}/{int(window)}s on {prefix}"},
                        headers={"Retry-After": str(int(window))},
                    )
                break
        return await call_next(request)
