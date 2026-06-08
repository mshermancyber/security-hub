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


def _esc(s: str) -> str:
    """Escape markdown link metacharacters in untrusted text."""
    return (s or "").replace("[", "\\[").replace("]", "\\]").replace("(", "\\(").replace(")", "\\)")


def _format(event: dict) -> dict:
    et = event.get("type")
    if et == "news.item":
        it = event.get("item", {})
        prio = it.get("priority", 0)
        title = _esc(it.get("title") or "high-priority alert")
        source = _esc(it.get("source_name") or "")
        url = it.get("url") or ""
        color = "FF4D6D" if prio >= 85 else "FF9F1C" if prio >= 70 else "FFD166"
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": title,
            "title": f"[P{prio}] {title}",
            "sections": [{
                "activityTitle": source,
                "activitySubtitle": " · ".join(_esc(t) for t in (it.get("tags") or [])),
                "facts": [{"name": k, "value": str(v)}
                          for k, v in (("Priority", prio),
                                       ("Source", source),
                                       ("CVEs", ", ".join(_esc(c) for c in (it.get("cves") or [])) or "—"))],
                "text": url and f"[Open article]({_esc(url)})" or "",
            }],
        }
    if et == "org.alert":
        it = event.get("item", {})
        org_name = _esc(event.get("org_name") or event.get("org") or "")
        title = _esc(it.get("title") or "")
        source = _esc(it.get("source_name") or "")
        url = it.get("url") or ""
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "FF4D6D",
            "summary": f"Org alert {org_name}",
            "title": f"🚨 Org alert: {org_name}",
            "sections": [{
                "activityTitle": title,
                "activitySubtitle": source,
                "facts": [{"name": "Reason", "value": _esc(event.get("reason") or "")}],
                "text": url and f"[Open article]({_esc(url)})" or "",
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
                "facts": [{"name": _esc(c.get("cve_id") or ""), "value": _esc((c.get("description") or "")[:120])} for c in top[:5]],
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
