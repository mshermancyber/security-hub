"""Microsoft Teams webhook sink (MessageCard format)."""
from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx

from ..safe_http import is_public_url, safe_post


def _validate_webhook(url: str) -> None:
    u = urlparse(url)
    if u.scheme != "https":
        raise RuntimeError("Teams webhook must be https://")
    if os.environ.get("SECHUB_ALLOW_INTERNAL_SINKS", "").strip().lower() in ("1", "true", "yes"):
        return
    if not is_public_url(url):
        raise RuntimeError(f"refused internal teams webhook host: {u.hostname}")


def _format(event: dict) -> dict:
    et = event.get("type")
    if et == "news.item":
        it = event.get("item", {})
        prio = it.get("priority", 0)
        color = "FF4D6D" if prio >= 85 else "FF9F1C" if prio >= 70 else "FFD166"
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": it.get("title") or "high-priority alert",
            "title": f"[P{prio}] {it.get('title')}",
            "sections": [{
                "activityTitle": it.get("source_name") or "",
                "activitySubtitle": " · ".join(it.get("tags") or []),
                "facts": [{"name": k, "value": str(v)}
                          for k, v in (("Priority", prio),
                                       ("Source", it.get("source_name")),
                                       ("CVEs", ", ".join(it.get("cves") or []) or "—"))],
                "text": it.get("url") and f"[Open article]({it.get('url')})" or "",
            }],
        }
    if et == "org.alert":
        it = event.get("item", {})
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "FF4D6D",
            "summary": f"Org alert {event.get('org')}",
            "title": f"🚨 Org alert: {event.get('org_name', event.get('org'))}",
            "sections": [{
                "activityTitle": it.get("title") or "",
                "activitySubtitle": it.get("source_name") or "",
                "facts": [{"name": "Reason", "value": event.get("reason") or ""}],
                "text": it.get("url") and f"[Open article]({it.get('url')})" or "",
            }],
        }
    if et == "kev.batch":
        top = event.get("top") or []
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "FF4D6D",
            "summary": f"KEV: {event.get('count')} new",
            "title": f"🔥 CISA KEV — {event.get('count')} newly exploited",
            "sections": [{
                "facts": [{"name": c.get("cve_id"), "value": (c.get("description") or "")[:120]} for c in top[:5]],
            }],
        }
    return {"text": f"[{et}] {event}"}


async def send(event: dict, *, webhook: str | None) -> None:
    if not webhook:
        raise RuntimeError("Teams webhook URL not configured")
    _validate_webhook(webhook)
    payload = _format(event)
    allow_internal = (os.environ.get("SECHUB_ALLOW_INTERNAL_SINKS", "").strip().lower()
                      in ("1", "true", "yes"))
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as cx:
        await safe_post(cx, webhook, json=payload,
                        max_bytes=64 * 1024, allow_internal=allow_internal)
