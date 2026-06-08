"""Status / health endpoints for the status bar."""
from __future__ import annotations

from fastapi import APIRouter

from ..db import fetchall, fetchone, kv_get, row_to_dict

router = APIRouter(prefix="/api/status", tags=["status"])


@router.get("")
def status():
    feeds = [dict(r) for r in fetchall("SELECT * FROM feed_health ORDER BY source_name")]
    n_news = fetchone("SELECT COUNT(*) AS n FROM news")["n"]
    n_cves = fetchone("SELECT COUNT(*) AS n FROM cves")["n"]
    n_kev = fetchone("SELECT COUNT(*) AS n FROM cves WHERE is_kev = 1")["n"]
    crit = fetchone("SELECT COUNT(*) AS n FROM news WHERE priority >= 70")["n"]
    return {
        "counts": {"news": n_news, "cves": n_cves, "kev": n_kev, "critical_news": crit},
        "feeds": feeds,
        "last_runs": {
            "kev":  kv_get("last_run.kev"),
            "nvd":  kv_get("last_run.nvd"),
            "news": kv_get("last_run.news"),
        },
    }
