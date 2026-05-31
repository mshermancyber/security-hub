"""Per-feed staleness monitor.

Periodically checks `feed_health.last_success`. If a feed hasn't ingested
in > threshold hours, emits a `feed.stale` WebSocket event so the UI can
flag it. Tracks already-warned feeds in memory so we don't spam.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..db import fetchall, kv_get, kv_set
from ..ws import bus

log = logging.getLogger("sechub.staleness")

STALE_HOURS = 6
_STATE_KEY = "staleness.warned"


def _load_warned() -> set[str]:
    return set(kv_get(_STATE_KEY, []) or [])


def _save_warned(s: set[str]) -> None:
    kv_set(_STATE_KEY, sorted(s))


def _age_hours(iso: str | None) -> float:
    if not iso:
        return float("inf")
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except Exception:
        return float("inf")


async def check_staleness() -> int:
    """Emit feed.stale events for any feed whose last_success is older than
    STALE_HOURS. Warned-state persists in kv so a process restart doesn't
    re-fire alerts."""
    warned = _load_warned()
    rows = fetchall(
        "SELECT source_id, source_name, last_success, last_error FROM feed_health"
    )
    stale_now: set[str] = set()
    for r in rows:
        age = _age_hours(r["last_success"])
        if age > STALE_HOURS:
            stale_now.add(r["source_id"])
            if r["source_id"] not in warned:
                warned.add(r["source_id"])
                await bus.broadcast({
                    "type": "feed.stale",
                    "feed": r["source_id"],
                    "name": r["source_name"],
                    "hours_stale": round(age, 1),
                    "last_success": r["last_success"],
                    "last_error": r["last_error"],
                })
    # Resolve any feeds that came back
    for fid in (warned - stale_now):
        warned.discard(fid)
        await bus.broadcast({"type": "feed.recovered", "feed": fid})
    _save_warned(warned)
    return len(stale_now)
