"""FastAPI entrypoint for the Security Hub terminal backend."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .db import get_conn
from .ingest.scheduler import run_startup, start_background
from .routes import news, vulns, watch, narratives, search, status, taxonomy, orgs, admin, industry, integrations, digest, mobile, intel, ai, exposure, orgs_admin, workspace, metrics, patches
from .ws import bus
from .integrations import router as routing_engine
from .auth import TokenAuthMiddleware
from .ratelimit import RateLimitMiddleware
from .mobile_redirect import MobileRedirectMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sechub")


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_conn()  # init schema
    log.info("DB ready, kicking off initial ingestion")
    # Precompile entity matchers so first request isn't paying compile cost.
    try:
        from .enrich.entities import precompile_matchers
        n = precompile_matchers()
        log.info("precompiled %d entity matchers", n)
    except Exception:
        log.exception("matcher precompile failed (non-fatal)")
    import asyncio
    loop = asyncio.get_running_loop()
    bus.bind_loop(loop)
    routing_engine.install(bus)  # hook routing engine into WS bus
    # Run initial fetch in the background — don't block app startup
    asyncio.create_task(run_startup())
    start_background()
    # Heartbeat keeps proxies + clients aware that the WS is alive.
    asyncio.create_task(bus.heartbeat_loop())
    yield


app = FastAPI(title="Security Hub Terminal", version="1.0", lifespan=lifespan)

import os as _os
# CORS allowlist. Default: same-origin frontend on localhost only.
# Operators behind a reverse proxy on a real hostname should set
# SECHUB_CORS_ORIGINS as a comma-separated list (e.g. "https://intel.example.com").
_cors = _os.environ.get("SECHUB_CORS_ORIGINS", "").strip()
_cors_origins = (
    [o.strip() for o in _cors.split(",") if o.strip()] if _cors
    else [
        "http://localhost", "http://127.0.0.1",
        "https://localhost", "https://127.0.0.1",
        "http://localhost:8080", "http://127.0.0.1:8080",
    ]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "DELETE", "PATCH", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    allow_credentials=False,
)
app.add_middleware(TokenAuthMiddleware)
app.add_middleware(RateLimitMiddleware)
# Last add = outermost = runs first. We want the mobile redirect to fire
# before TokenAuth so an unauthenticated phone visitor still gets bounced
# to /m instead of 401'd at the door. /m itself is in PUBLIC_PATHS so the
# redirect target is reachable without a token.
app.add_middleware(MobileRedirectMiddleware)

app.include_router(news.router)
app.include_router(vulns.router)
app.include_router(watch.router)
app.include_router(narratives.router)
app.include_router(search.router)
app.include_router(status.router)
app.include_router(taxonomy.router)
app.include_router(orgs.router)
app.include_router(admin.router)
app.include_router(industry.router)
app.include_router(integrations.router)
app.include_router(digest.router)
app.include_router(mobile.router)
app.include_router(intel.router)
app.include_router(ai.router)
app.include_router(exposure.router)
app.include_router(orgs_admin.router)
app.include_router(workspace.router)
app.include_router(metrics.router)
app.include_router(patches.router)


@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/about")
def about():
    """AGPL §5d Appropriate Legal Notice — license + source link."""
    import os
    return {
        "name": "SecurityHub Terminal",
        "version": "1.0.0",
        "license": "AGPL-3.0-or-later",
        "license_url": "https://www.gnu.org/licenses/agpl-3.0.txt",
        "source_url": os.environ.get("SECHUB_SOURCE_URL", "https://github.com/mshermancyber/security-hub"),
        "warranty": "This program comes with ABSOLUTELY NO WARRANTY.",
    }


@app.websocket("/api/ws")
async def websocket_endpoint(ws: WebSocket):
    # WS bypasses the HTTP TokenAuthMiddleware (it explicitly skips ws scopes),
    # so we must enforce the same bearer-token model here. Without this gate,
    # anyone reachable on the backend port can subscribe to news.item /
    # org.alert / kev.batch events and exfil the entire alert stream.
    import os as _os
    import secrets as _secrets
    from .auth import _insecure_mode
    token = _os.environ.get("SECHUB_AUTH_TOKEN", "").strip()
    if not token:
        if not _insecure_mode():
            await ws.close(code=4401)
            return
    else:
        # Accept either `Authorization: Bearer <token>` or `?token=…`.
        # The Sec-WebSocket-Protocol header is the standard browser-side way
        # to pass a token without query-string leakage; accept that too.
        provided = ""
        hdr = ws.headers.get("authorization", "")
        if hdr.startswith("Bearer "):
            provided = hdr[7:]
        if not provided:
            provided = ws.query_params.get("token") or ""
        if not provided:
            subproto = ws.headers.get("sec-websocket-protocol", "")
            # Accept "bearer, <token>" pattern as a subprotocol list.
            parts = [p.strip() for p in subproto.split(",")]
            if len(parts) == 2 and parts[0].lower() == "bearer":
                provided = parts[1]
        if not provided or not _secrets.compare_digest(provided, token):
            await ws.close(code=4401)
            return

    await bus.connect(ws)
    try:
        while True:
            msg = await ws.receive_text()
            # Minimal protocol: pong on ping, ignore everything else.
            try:
                import json as _json
                data = _json.loads(msg)
            except Exception:
                continue
            if isinstance(data, dict) and data.get("type") == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        await bus.disconnect(ws)
