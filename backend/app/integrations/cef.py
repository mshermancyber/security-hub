"""CEF (Common Event Format) → syslog sink for SIEM forwarding.

Configure SECHUB_SYSLOG_URL as:
    udp://siem.example.com:514
    tcp://siem.example.com:1514

Produces ArcSight-style CEF:0|SecurityHub|Terminal|1.0|<sig>|<name>|<sev>|<ext>
"""
from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

# Note: syslog/CEF targets are almost always internal SIEMs (LAN-side
# Splunk / QRadar / Sentinel forwarders), so we DO NOT apply the
# public-host check that we use on Slack/Teams webhooks. The operator
# explicitly opts in by setting SECHUB_SYSLOG_URL.


def _escape(v) -> str:
    if v is None:
        return ""
    s = str(v).replace("\\", "\\\\").replace("=", "\\=").replace("|", "\\|").replace("\n", " ")
    return s


def _ext(d: dict) -> str:
    return " ".join(f"{k}={_escape(v)}" for k, v in d.items() if v not in (None, ""))


def format_cef(event: dict) -> str:
    et = event.get("type", "unknown")
    sev = 5
    name = et
    ext: dict = {"rt": event.get("at")}
    if et in ("news.item",):
        it = event.get("item", {})
        prio = it.get("priority", 0)
        sev = 10 if prio >= 85 else 8 if prio >= 70 else 5
        name = "news_item"
        ext.update({
            "msg": it.get("title"),
            "request": it.get("url"),
            "act": "ingested",
            "cs1Label": "source", "cs1": it.get("source_name"),
            "cs2Label": "tags",   "cs2": ",".join(it.get("tags") or []),
            "cn1Label": "priority", "cn1": prio,
        })
    elif et == "org.alert":
        it = event.get("item", {})
        sev = 9
        name = "org_alert"
        ext.update({
            "msg": it.get("title"),
            "request": it.get("url"),
            "cs1Label": "org",     "cs1": event.get("org"),
            "cs2Label": "reason",  "cs2": event.get("reason"),
            "cs3Label": "source",  "cs3": it.get("source_name"),
        })
    elif et == "kev.batch":
        sev = 8
        name = "kev_addition"
        ext.update({
            "cn1Label": "count", "cn1": event.get("count"),
            "msg": "; ".join(c.get("cve_id", "") for c in (event.get("top") or [])[:5]),
        })
    return (f"CEF:0|SecurityHub|Terminal|1.0|{_escape(et)}|{_escape(name)}|{sev}|" + _ext(ext))


def _send_sync(*, syslog_url: str, payload: str) -> None:
    u = urlparse(syslog_url)
    host = u.hostname or "localhost"
    port = u.port or 514
    line = f"<{14}>{payload}".encode("utf-8")  # facility=1 (user), severity=6 (info)
    if (u.scheme or "udp") == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(line, (host, port))
        finally:
            s.close()
    else:
        s = socket.create_connection((host, port), timeout=5)
        try:
            s.sendall(line + b"\n")
        finally:
            s.close()


async def send(event: dict, *, syslog_url: str | None) -> None:
    if not syslog_url:
        raise RuntimeError("SECHUB_SYSLOG_URL not configured")
    payload = format_cef(event)
    await asyncio.to_thread(_send_sync, syslog_url=syslog_url, payload=payload)
