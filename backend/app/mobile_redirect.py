"""Server-side mobile-UA redirect.

Catches the case where the client doesn't run JS (rare today, but happens
on broken phones, scraper bots, link previews, accessibility tooling).
The frontend also performs the same check in `frontend/src/lib/useDeviceType.ts`
before React mounts, so this is a belt-and-suspenders layer.

Rules (matched against the request User-Agent):
  - iPhone / iPod / iPad      → mobile  (kind=ios)
  - macOS UA + a touch context → mobile  (iPadOS-as-Mac edge case is
    only detectable client-side via maxTouchPoints; the server can't tell,
    so iPad reports as desktop here and the client-side check fixes it up)
  - Android (any variant, including tablets per operator choice)
  - webOS / BlackBerry / Opera Mini / IEMobile

Opt-outs (operator-controlled — desktop view stays reachable on phones):
  - Query string  `?desktop=1`
  - Cookie        `sechub_view=desktop`

Only `GET /` (the SPA shell) is redirected. Everything else — static
assets, `/api/*`, `/m/*`, `/metrics`, `/healthz` — passes through.
"""
from __future__ import annotations

import re

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse


# Tablets included intentionally (operator decision: terminal UI is too
# dense for portrait tablet use; iPad/Android tablet route to /m).
_MOBILE_UA_RE = re.compile(
    r"(?:iPhone|iPod|iPad|Android|webOS|BlackBerry|Opera Mini|IEMobile)",
    re.IGNORECASE,
)

# Only the SPA index gets redirected. The exact set is small on purpose —
# anything under /api, /m, /assets, /metrics, /healthz, /favicon.ico, etc.
# must pass through unchanged. Matching the SPA index by an explicit set
# avoids accidentally redirecting an asset that happens to share a prefix.
_REDIRECTABLE_PATHS = frozenset({"/", "/index.html"})


def _wants_desktop(request: Request) -> bool:
    """Return True if the visitor has explicitly opted into the desktop
    view from a mobile device (query-string or cookie)."""
    if request.query_params.get("desktop") == "1":
        return True
    if request.cookies.get("sechub_view") == "desktop":
        return True
    return False


def _looks_mobile(ua: str) -> bool:
    return bool(_MOBILE_UA_RE.search(ua or ""))


class MobileRedirectMiddleware(BaseHTTPMiddleware):
    """302 redirect mobile UAs hitting the SPA index to /m."""

    async def dispatch(self, request: Request, call_next):
        if request.method != "GET":
            return await call_next(request)
        if request.url.path not in _REDIRECTABLE_PATHS:
            return await call_next(request)
        if _wants_desktop(request):
            return await call_next(request)
        ua = request.headers.get("user-agent", "")
        if not _looks_mobile(ua):
            return await call_next(request)
        # Preserve query string + fragment so a deep-link still lands
        # on the mobile equivalent. (Fragments don't reach the server,
        # but the client-side redirect handles them.)
        qs = request.url.query
        target = "/m" + (f"?{qs}" if qs else "")
        resp = RedirectResponse(url=target, status_code=302)
        # Vary on User-Agent so any cache between us and the client doesn't
        # serve the redirect to a desktop user (or vice versa).
        resp.headers["Vary"] = "User-Agent, Cookie"
        # Don't let intermediate caches store the redirect either — the
        # decision depends on per-request UA + cookie state.
        resp.headers["Cache-Control"] = "no-store"
        return resp
