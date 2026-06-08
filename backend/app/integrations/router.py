"""Alert routing engine.

Subscribes to the WS broadcaster bus and fans matching events out to
configured sinks (Slack, Teams, email, CEF/syslog) according to rules
in `taxonomy/routing.json`.

Routing is fire-and-forget: each sink runs in its own task so a slow
or down sink doesn't block others. Per-sink delivery counters + last
error are exposed via /api/integrations/health.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ..db import kv_get, kv_set, load_taxonomy

log = logging.getLogger("sechub.integrations.router")

_HEALTH_KV_KEY = "integrations.health"

import threading as _threading

# In-memory mirror of the persisted dict. We hydrate on first record/snapshot.
_health: dict[str, dict] = defaultdict(lambda: {"delivered": 0, "errors": 0, "last_error": None, "last_at": None})
_health_loaded = False
# Async dispatch can call record() concurrently from multiple awaiting sinks.
# CPython's GIL makes individual dict ops atomic, but the read-modify-write
# of h["delivered"] += 1 is not — under load we'd undercount. Lock it.
_health_lock = _threading.Lock()


def _ensure_loaded() -> None:
    global _health_loaded
    with _health_lock:
        if _health_loaded:
            return
        try:
            persisted = kv_get(_HEALTH_KV_KEY, {}) or {}
            for sink_id, h in persisted.items():
                _health[sink_id] = {
                    "delivered": int(h.get("delivered", 0)),
                    "errors":    int(h.get("errors", 0)),
                    "last_error": h.get("last_error"),
                    "last_at":    h.get("last_at"),
                }
        except Exception:
            log.exception("failed to load routing health from kv")
        _health_loaded = True


def _persist() -> None:
    try:
        # Snapshot under the lock so we don't serialize a dict mid-mutation.
        with _health_lock:
            snap = {k: dict(v) for k, v in _health.items()}
        kv_set(_HEALTH_KV_KEY, snap)
    except Exception:
        log.exception("failed to persist routing health")


def record(sink_id: str, *, ok: bool, error: str | None = None) -> None:
    _ensure_loaded()
    with _health_lock:
        h = _health[sink_id]
        if ok:
            h["delivered"] += 1
        else:
            h["errors"] += 1
            h["last_error"] = error
        h["last_at"] = datetime.now(timezone.utc).isoformat()
    # Persist on every write — cheap (single JSON blob in kv) and avoids
    # losing counters on crash. Batching would be premature.
    _persist()


def health_snapshot() -> dict:
    _ensure_loaded()
    cfg = load_taxonomy("routing")
    sinks_cfg = cfg.get("sinks", {})
    out = []
    for sink_id, sink_cfg in sinks_cfg.items():
        env_key = sink_cfg.get("webhook_env") or sink_cfg.get("smtp_env") or sink_cfg.get("syslog_env")
        configured = bool(env_key and os.environ.get(env_key))
        with _health_lock:
            h = dict(_health.get(sink_id, {"delivered": 0, "errors": 0, "last_error": None, "last_at": None}))
        out.append({
            "id": sink_id,
            "kind": sink_cfg.get("kind"),
            "configured": configured,
            "env_key": env_key,
            **h,
        })
    return {"sinks": out, "rules": cfg.get("rules", [])}


def _match_rule(rule: dict, event: dict) -> bool:
    m = rule.get("match", {})
    et = m.get("event_type")
    if et and et != "*" and et != event.get("type"):
        return False
    if (mp := m.get("min_priority")) is not None:
        item = event.get("item", {})
        if (item.get("priority") or 0) < mp:
            return False
    if (mc := m.get("min_count")) is not None:
        if (event.get("count") or 0) < mc:
            return False
    if (org := m.get("org")):
        if event.get("org") != org:
            return False
    if (tag := m.get("tag")):
        tags = (event.get("item", {}) or {}).get("tags") or []
        if tag not in tags:
            return False
    return True


def _rule_sinks(rule: dict) -> list[str]:
    if rule.get("sinks"):
        return rule["sinks"]
    if rule.get("sink"):
        return [rule["sink"]]
    return []


async def _dispatch_to(sink_id: str, rule: dict, event: dict) -> None:
    from . import slack as slack_sink
    from . import teams as teams_sink
    from . import email as email_sink
    from . import cef as cef_sink
    cfg = load_taxonomy("routing")
    sink_cfg = cfg.get("sinks", {}).get(sink_id)
    if not sink_cfg:
        record(sink_id, ok=False, error="sink not defined")
        return
    kind = sink_cfg.get("kind")
    target = rule.get("target")
    try:
        if kind == "slack":
            await slack_sink.send(event, webhook=target or os.environ.get(sink_cfg.get("webhook_env", "")))
        elif kind == "teams":
            await teams_sink.send(event, webhook=target or os.environ.get(sink_cfg.get("webhook_env", "")))
        elif kind == "email":
            await email_sink.send(event, to=target, smtp_url=os.environ.get(sink_cfg.get("smtp_env", "")),
                                  from_addr=os.environ.get(sink_cfg.get("from_env", "")))
        elif kind == "cef":
            await cef_sink.send(event, syslog_url=os.environ.get(sink_cfg.get("syslog_env", "")))
        else:
            record(sink_id, ok=False, error=f"unknown kind {kind}")
            return
        record(sink_id, ok=True)
    except Exception as e:
        log.warning("sink %s failed: %s", sink_id, e)
        record(sink_id, ok=False, error=str(e))


def handle_event(event: dict) -> None:
    """Called from the WS bus (sync). Dispatches matching rules asynchronously."""
    try:
        cfg = load_taxonomy("routing")
    except FileNotFoundError:
        return
    rules = [r for r in cfg.get("rules", []) if r.get("enabled", False)]
    # `get_event_loop()` is deprecated and raises in Python 3.14+ when called
    # outside a running loop. `get_running_loop()` is correct here because the
    # routing engine is invoked from within the WS bus's running event loop.
    loop = asyncio.get_running_loop()
    for rule in rules:
        if not _match_rule(rule, event):
            continue
        for sink_id in _rule_sinks(rule):
            loop.create_task(_dispatch_to(sink_id, rule, event))


# Bus integration -----------------------------------------------------------

def install(bus) -> None:
    """Attach to the WS broadcaster bus. Every broadcast also fires routing."""
    original_broadcast = bus.broadcast

    async def wrapped(event: dict) -> int:
        # Don't route heartbeats / hellos
        if event.get("type") not in ("heartbeat", "hello", "pong"):
            try:
                handle_event(event)
            except Exception:
                log.exception("routing handler failed")
        return await original_broadcast(event)

    bus.broadcast = wrapped  # type: ignore[assignment]
