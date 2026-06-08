"""Bearer-token auth.

`SECHUB_AUTH_TOKEN` is REQUIRED unless `SECHUB_INSECURE=1` is set.
Default is fail-closed: if the token is missing, the middleware rejects
every authenticated request with 401. Public paths (health/about/metrics
and the /m mobile landing) are always reachable.

Query-string `?token=...` is supported for HTML routes only — POST/DELETE/
PUT/PATCH must use the `Authorization: Bearer …` header so the token
doesn't leak via Referer headers or access logs of state-changing calls.
"""
from __future__ import annotations

import logging
import os
import re
import secrets

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

log = logging.getLogger("sechub.auth")


# Exact-match public routes (no surprises from future mounts under shared prefixes).
PUBLIC_PATHS = {"/api/health", "/api/about", "/metrics", "/m", "/m/"}

# Restricted public regex: static-asset filenames only. Limits the /assets/
# prefix to files with a sensible extension and no path-traversal sequences;
# anything else under /assets/ falls through to the token check.
_PUBLIC_PATH_RE = re.compile(
    r"^/assets/[A-Za-z0-9_\-./]+\.(?:js|mjs|css|map|woff2?|ttf|otf|svg|png|jpe?g|gif|webp|ico|json|txt)$"
)

# Mutating HTTP methods can't authenticate via `?token=` — the QS shortcut
# would leak the token to access logs, Referer headers, browser history.
_QS_SAFE_METHODS = {"GET", "HEAD"}


def _insecure_mode() -> bool:
    return os.environ.get("SECHUB_INSECURE", "").strip().lower() in ("1", "true", "yes")


class TokenAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # WebSocket upgrade and OPTIONS pre-flight always pass through —
        # the WS handshake runs auth separately, OPTIONS is for CORS.
        if request.method == "OPTIONS" or request.scope.get("type") == "websocket":
            return await call_next(request)

        path = request.url.path
        # Reject obvious path-traversal attempts (..) before any allowlist check.
        if ".." in path:
            return JSONResponse(status_code=400, content={"detail": "invalid path"})
        if path in PUBLIC_PATHS or _PUBLIC_PATH_RE.match(path):
            return await call_next(request)

        token = os.environ.get("SECHUB_AUTH_TOKEN", "").strip()
        if not token:
            if _insecure_mode():
                # Operator has explicitly opted into open-API mode.
                return await call_next(request)
            return JSONResponse(
                status_code=401,
                content={"detail": "auth required: set SECHUB_AUTH_TOKEN or SECHUB_INSECURE=1"},
            )

        # Header-based auth — always accepted.
        auth = request.headers.get("Authorization") or ""
        if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], token):
            return await call_next(request)

        # Query-string token — only for safe (read) methods so it doesn't
        # leak via Referer / access logs / browser history on state changes.
        if request.method in _QS_SAFE_METHODS:
            qs_token = request.query_params.get("token") or ""
            if qs_token and secrets.compare_digest(qs_token, token):
                return await call_next(request)

        return JSONResponse(status_code=401, content={"detail": "auth required"})
