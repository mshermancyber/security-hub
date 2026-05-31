"""OpenMetrics endpoint for Prometheus scraping."""
from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response

from ..db import fetchall, fetchone
from ..integrations import router as routing
from ..ws import bus

router = APIRouter(tags=["metrics"])


def _metrics_auth_check(request: Request) -> None:
    """Optional bearer-token gate. If SECHUB_METRICS_TOKEN is set, require it.
    Off by default to preserve the Prometheus scrape pattern."""
    expected = os.environ.get("SECHUB_METRICS_TOKEN")
    if not expected:
        return
    auth = request.headers.get("Authorization") or ""
    if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], expected):
        return
    qs = request.query_params.get("token") or ""
    if qs and secrets.compare_digest(qs, expected):
        return
    raise HTTPException(status_code=401, detail="metrics auth required")


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except Exception:
        return None


@router.get("/metrics")
def metrics(request: Request):
    _metrics_auth_check(request)
    lines: list[str] = []

    def help(name: str, helpline: str, mtype: str):
        lines.append(f"# HELP {name} {helpline}")
        lines.append(f"# TYPE {name} {mtype}")

    def _esc_label(v) -> str:
        # OpenMetrics requires `\`, `"`, LF, and CR be escaped in label values.
        return (str(v)
                .replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace('"', '\\"'))

    def emit(name: str, value, labels: dict | None = None):
        if value is None:
            return
        if labels:
            ls = ",".join(f'{k}="{_esc_label(v)}"' for k, v in labels.items())
            lines.append(f"{name}{{{ls}}} {value}")
        else:
            lines.append(f"{name} {value}")

    # --- counts ---
    help("sechub_news_total", "Total news items in DB", "gauge")
    emit("sechub_news_total", fetchone("SELECT COUNT(*) AS n FROM news")["n"])

    help("sechub_cves_total", "Total CVEs in DB", "gauge")
    emit("sechub_cves_total", fetchone("SELECT COUNT(*) AS n FROM cves")["n"])

    help("sechub_kev_total", "KEV-flagged CVEs in DB", "gauge")
    emit("sechub_kev_total", fetchone("SELECT COUNT(*) AS n FROM cves WHERE is_kev = 1")["n"])

    help("sechub_iocs_total", "IOCs in DB", "gauge")
    emit("sechub_iocs_total", fetchone("SELECT COUNT(*) AS n FROM iocs")["n"])

    help("sechub_ransom_postings_total", "Ransom leak-site postings in DB", "gauge")
    emit("sechub_ransom_postings_total",
         fetchone("SELECT COUNT(*) AS n FROM ransom_postings")["n"])

    # --- per-feed health ---
    help("sechub_feed_last_success_age_seconds",
         "Seconds since feed's last successful ingestion", "gauge")
    help("sechub_feed_error_total", "Cumulative error count per feed", "counter")
    for r in fetchall("SELECT source_id, last_success, last_error FROM feed_health"):
        age = _age_seconds(r["last_success"])
        emit("sechub_feed_last_success_age_seconds", age, {"feed": r["source_id"]})
        emit("sechub_feed_error_total", 1 if r["last_error"] else 0, {"feed": r["source_id"]})

    # --- ws / sinks ---
    help("sechub_ws_clients", "Currently connected WebSocket clients", "gauge")
    emit("sechub_ws_clients", len(bus.clients))

    snap = routing.health_snapshot()
    help("sechub_sink_delivered_total", "Cumulative events delivered per sink", "counter")
    help("sechub_sink_errors_total", "Cumulative sink errors", "counter")
    help("sechub_sink_configured", "1 if sink is configured (env var set)", "gauge")
    for s in snap.get("sinks", []):
        emit("sechub_sink_delivered_total", s.get("delivered", 0), {"sink": s["id"]})
        emit("sechub_sink_errors_total", s.get("errors", 0), {"sink": s["id"]})
        emit("sechub_sink_configured", 1 if s.get("configured") else 0, {"sink": s["id"]})

    # --- workspace ---
    help("sechub_starred_total", "Total starred items", "gauge")
    emit("sechub_starred_total", fetchone("SELECT COUNT(*) AS n FROM starred_items")["n"])

    help("sechub_annotations_total", "Total annotations", "gauge")
    emit("sechub_annotations_total", fetchone("SELECT COUNT(*) AS n FROM annotations")["n"])

    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4")
