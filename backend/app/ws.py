"""WebSocket broadcaster — pushes ingestion events + org alerts to connected clients.

Event protocol (JSON over text frames):

    { "type": "hello",       "at": "<iso>", "server": "sechub-terminal/1.0" }
    { "type": "news.batch",  "at": "<iso>", "count": N, "top": [<NewsItem>...] }
    { "type": "news.item",   "at": "<iso>", "item": <NewsItem> }       # high-priority single push
    { "type": "kev.batch",   "at": "<iso>", "count": N, "top": [<CVEItem>...] }
    { "type": "nvd.batch",   "at": "<iso>", "count": N, "top": [<CVEItem>...] }
    { "type": "org.alert",   "at": "<iso>", "org": "<id>", "item": <NewsItem|CVEItem>, "reason": "..." }
    { "type": "status",      "at": "<iso>", "counts": {...}, "feeds_ok": N }
    { "type": "heartbeat",   "at": "<iso>" }                            # every 25s

Clients send { "type": "ping" } and receive { "type": "pong" }.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket

log = logging.getLogger("sechub.ws")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Broadcaster:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self.clients.add(ws)
        log.info("ws connected; total=%d", len(self.clients))
        await self._send(ws, {"type": "hello", "at": _now(), "server": "sechub-terminal/1.0",
                              "clients": len(self.clients)})

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self.clients.discard(ws)
        log.info("ws disconnected; total=%d", len(self.clients))

    async def _send(self, ws: WebSocket, payload: dict) -> bool:
        try:
            await ws.send_text(json.dumps(payload, default=str))
            return True
        except Exception:
            return False

    async def broadcast(self, event: dict) -> int:
        """Send event to all connected clients. Returns delivered count."""
        if not self.clients:
            return 0
        event = {"at": _now(), **event}
        dead: list[WebSocket] = []
        delivered = 0
        for ws in list(self.clients):
            ok = await self._send(ws, event)
            if ok:
                delivered += 1
            else:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self.clients.discard(ws)
        return delivered

    def broadcast_sync(self, event: dict) -> None:
        """Fire-and-forget broadcast from sync code via the bound loop."""
        if self._loop is None or not self.clients:
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(event), self._loop)
        except Exception:
            log.exception("broadcast_sync failed")

    async def heartbeat_loop(self, interval: float = 25.0) -> None:
        while True:
            await asyncio.sleep(interval)
            await self.broadcast({"type": "heartbeat"})


bus = Broadcaster()


# --- helpers used by ingest pipelines -------------------------------------

def push_news_batch(items: list[dict]) -> None:
    """Broadcast a news.batch event from sync ingest code."""
    if not items:
        return
    top = sorted(items, key=lambda i: i.get("priority", 0), reverse=True)[:5]
    bus.broadcast_sync({
        "type": "news.batch",
        "count": len(items),
        "top": [_slim_news(i) for i in top],
    })
    # also push individual high-priority items as discrete alerts
    for i in items:
        if (i.get("priority") or 0) >= 70:
            bus.broadcast_sync({"type": "news.item", "item": _slim_news(i)})


def push_kev_batch(count: int, top: list[dict]) -> None:
    if count <= 0:
        return
    bus.broadcast_sync({
        "type": "kev.batch",
        "count": count,
        "top": [_slim_cve(i) for i in top[:5]],
    })


def push_nvd_batch(count: int, top: list[dict]) -> None:
    if count <= 0:
        return
    bus.broadcast_sync({
        "type": "nvd.batch",
        "count": count,
        "top": [_slim_cve(i) for i in top[:5]],
    })


def push_org_alerts(items: list[dict]) -> None:
    """For each news item with org matches, fire an org.alert event.

    Also fires `eol.alert` when an item tagged 'eol' mentions a vendor
    that's in any org's tech_stack — early warning of forced upgrades.
    """
    from .db import load_taxonomy
    try:
        orgs_doc = load_taxonomy("orgs").get("orgs", [])
    except FileNotFoundError:
        orgs_doc = []
    # Build vendor → orgs index once
    vendor_to_orgs: dict[str, list[dict]] = {}
    for o in orgs_doc:
        for v in (o.get("tech_stack") or []):
            vendor_to_orgs.setdefault(v, []).append({"id": o["id"], "name": o["name"]})

    for n in items:
        orgs = (n.get("entities") or {}).get("orgs") or []
        for o in orgs:
            bus.broadcast_sync({
                "type": "org.alert",
                "org": o["id"],
                "org_name": o["name"],
                "reason": "direct-mention",
                "item": _slim_news(n),
            })
        # EOL alert: tag 'eol' + vendor in any org tech_stack
        tags = n.get("tags") or []
        if "eol" in tags:
            for v in ((n.get("entities") or {}).get("vendors") or []):
                impacted = vendor_to_orgs.get(v["id"]) or []
                for org in impacted:
                    bus.broadcast_sync({
                        "type": "eol.alert",
                        "org": org["id"],
                        "org_name": org["name"],
                        "vendor": v["id"], "vendor_name": v["name"],
                        "reason": "eol-in-tech-stack",
                        "item": _slim_news(n),
                    })


def _slim_news(n: dict) -> dict:
    return {
        "id": n.get("id"),
        "title": n.get("title"),
        "url": n.get("url"),
        "source_name": n.get("source_name"),
        "priority": n.get("priority"),
        "severity": n.get("severity"),
        "tags": n.get("tags") or [],
        "cves": n.get("cves") or [],
        "published_at": n.get("published_at"),
        "entities": {
            "vendors": [v["id"] for v in (n.get("entities", {}).get("vendors") or [])][:5],
            "orgs":    [o["id"] for o in (n.get("entities", {}).get("orgs")    or [])],
            "threat_actors": [a["id"] for a in (n.get("entities", {}).get("threat_actors") or [])][:3],
        },
    }


def _slim_cve(c: dict) -> dict:
    return {
        "cve_id": c.get("cve_id"),
        "description": (c.get("description") or "")[:200],
        "cvss_score": c.get("cvss_score"),
        "is_kev": c.get("is_kev"),
        "kev_added": c.get("kev_added"),
        "kev_ransomware": c.get("kev_ransomware"),
        "priority": c.get("priority"),
    }
