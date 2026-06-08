"""Email sink via SMTP.

Configure with SECHUB_SMTP_URL like:
    smtp://user:pass@smtp.example.com:587
    smtps://user:pass@smtp.example.com:465
    smtp+starttls://user:pass@smtp.example.com:587
"""
from __future__ import annotations

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import unquote, urlparse


def _strip_crlf(s: str) -> str:
    return (s or "").replace("\r", "").replace("\n", " ")


def _format_subject(event: dict) -> str:
    et = event.get("type")
    if et == "news.item":
        it = event.get("item", {})
        return _strip_crlf(f"[SecHub P{it.get('priority',0)}] {it.get('title','(no title)')}")
    if et == "org.alert":
        it = event.get("item", {})
        return _strip_crlf(f"[SecHub ORG:{event.get('org')}] {it.get('title','')}")
    if et == "kev.batch":
        return f"[SecHub KEV] {event.get('count')} newly exploited"
    return _strip_crlf(f"[SecHub] {et}")


def _format_body(event: dict) -> str:
    et = event.get("type")
    body = [f"Event type: {et}", f"At: {event.get('at')}", ""]
    if et in ("news.item", "org.alert"):
        it = event.get("item", {})
        body += [
            f"Title:    {it.get('title')}",
            f"Source:   {it.get('source_name')}",
            f"URL:      {it.get('url')}",
            f"Priority: {it.get('priority')}",
            f"Tags:     {', '.join(it.get('tags') or [])}",
            f"CVEs:     {', '.join(it.get('cves') or [])}",
        ]
    elif et == "kev.batch":
        body += [f"Count: {event.get('count')}", "Top:"]
        for c in event.get("top", []):
            body += [f"  {c.get('cve_id')}: {(c.get('description') or '')[:120]}"]
    return "\n".join(body)


def _send_sync(*, smtp_url: str, from_addr: str, to_addr: str, subject: str, body: str) -> None:
    u = urlparse(smtp_url)
    user = unquote(u.username or "")
    pwd = unquote(u.password or "")
    host = u.hostname or "localhost"
    port = u.port or (465 if u.scheme.startswith("smtps") else 587)
    msg = EmailMessage()
    msg["From"] = from_addr or user or "sechub@localhost"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    # Wrap the network calls in try/except that scrubs credentials from any
    # exception message before re-raising. The router persists these errors
    # to /api/integrations/health, where any leaked credential becomes
    # visible to every authenticated operator.
    import re as _re
    def _scrub(e: Exception) -> str:
        s = str(e)
        if user:
            s = _re.sub(_re.escape(user), "<user>", s, flags=_re.IGNORECASE)
        if pwd:
            # No IGNORECASE on the password — passwords are case-sensitive
            # and we don't want to accidentally redact a substring match.
            s = s.replace(pwd, "<redacted>")
        return s
    try:
        if u.scheme in ("smtps",):
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                if user: s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                try:
                    s.starttls(context=ctx)
                except smtplib.SMTPNotSupportedError:
                    pass
                if user: s.login(user, pwd)
                s.send_message(msg)
    except Exception as e:
        raise RuntimeError(f"smtp send failed: {_scrub(e)}") from None


async def send(event: dict, *, to: str | None, smtp_url: str | None, from_addr: str | None) -> None:
    if not smtp_url:
        raise RuntimeError("SECHUB_SMTP_URL not configured")
    if not to:
        raise RuntimeError("email rule has no `target` recipient")
    subject = _format_subject(event)
    body = _format_body(event)
    await asyncio.to_thread(_send_sync, smtp_url=smtp_url, from_addr=from_addr or "",
                            to_addr=to, subject=subject, body=body)
