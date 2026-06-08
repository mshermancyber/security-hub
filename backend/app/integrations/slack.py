"""Slack webhook sink."""
from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx

from ..safe_http import is_public_url, safe_post


def _validate_webhook(url: str) -> None:
    """Refuse webhooks pointing at non-public hosts unless the operator
    explicitly opts in (e.g. for a self-hosted Mattermost on the LAN)."""
    u = urlparse(url)
    if u.scheme != "https":
        raise RuntimeError("Slack webhook must be https://")
    if os.environ.get("SECHUB_ALLOW_INTERNAL_SINKS", "").strip().lower() in ("1", "true", "yes"):
        return
    if not is_public_url(url):
        raise RuntimeError(f"refused internal slack webhook host: {u.hostname}")


def _esc(s: str) -> str:
    """Escape Slack mrkdwn metacharacters in untrusted text."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format(event: dict) -> dict:
    et = event.get("type")
    if et == "news.item":
        it = event.get("item", {})
        prio = it.get("priority", 0)
        title = _esc(it.get("title") or "(no title)")
        source = _esc(it.get("source_name") or "")
        url = _esc(it.get("url") or "")
        tags = ", ".join(_esc(t) for t in (it.get("tags") or []))
        return {
            "text": f"[P{prio}] {title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"*[P{prio}] {title}*\n_{source}_"}},
                {"type": "context", "elements": [{"type": "mrkdwn",
                 "text": f"tags: `{tags}`  ·  <{url}|open>"}]},
            ],
        }
    if et == "org.alert":
        it = event.get("item", {})
        org_name = _esc(event.get("org_name") or event.get("org") or "")
        title = _esc(it.get("title") or "")
        source = _esc(it.get("source_name") or "")
        url = _esc(it.get("url") or "")
        reason = _esc(event.get("reason") or "")
        return {
            "text": f"[ORG:{_esc(event.get('org',''))}] {title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"*🚨 Org alert: {org_name}*\n{title}"}},
                {"type": "context", "elements": [{"type": "mrkdwn",
                 "text": f"reason: `{reason}`  ·  {source}  ·  <{url}|open>"}]},
            ],
        }
    if et == "kev.batch":
        top = event.get("top") or []
        lines = [f"• `{_esc(c.get('cve_id',''))}` — {_esc((c.get('description') or '')[:80])}" for c in top]
        return {
            "text": f"CISA KEV: {event.get('count')} new",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"*🔥 CISA KEV: {event.get('count')} newly exploited*\n" + "\n".join(lines)}},
            ],
        }
    return {"text": f"[{et}] {event}"}


async def send(event: dict, *, webhook: str | None) -> None:
    if not webhook:
        raise RuntimeError("Slack webhook URL not configured")
    _validate_webhook(webhook)
    payload = _format(event)
    allow_internal = (os.environ.get("SECHUB_ALLOW_INTERNAL_SINKS", "").strip().lower()
                      in ("1", "true", "yes"))
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as cx:
        # safe_post re-validates the host post-resolution, defending against
        # DNS-rebinding attacks where the second resolution returns 127.0.0.1
        # or a metadata-service IP.
        await safe_post(cx, webhook, json=payload,
                        max_bytes=64 * 1024, allow_internal=allow_internal)
