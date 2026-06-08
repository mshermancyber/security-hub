"""OpenAI-compatible chat-completions client.

Works against any server that speaks `POST /v1/chat/completions` with the
OpenAI request/response shape:

    - OpenAI:    https://api.openai.com/v1
    - Anthropic: https://api.anthropic.com/v1   (OpenAI-compat endpoint)
    - Ollama:    http://localhost:11434/v1
    - vLLM:      http://your-host:8000/v1
    - LM Studio: http://localhost:1234/v1
    - Together:  https://api.together.xyz/v1

Config via env:
    SECHUB_LLM_BASE_URL   — e.g. http://localhost:11434/v1
    SECHUB_LLM_API_KEY    — bearer token (empty for keyless Ollama)
    SECHUB_LLM_MODEL      — model name (gpt-4o-mini, claude-sonnet-4-6, llama3.1, ...)
    SECHUB_LLM_TIMEOUT    — request timeout seconds (default 60)
"""
from __future__ import annotations

import os
from typing import Any

import httpx


def is_configured() -> bool:
    return bool(os.environ.get("SECHUB_LLM_BASE_URL"))


def provider_hint() -> str:
    base = (os.environ.get("SECHUB_LLM_BASE_URL") or "").lower()
    if "openai.com" in base:        return "openai"
    if "anthropic.com" in base:     return "anthropic"
    if "11434" in base or "ollama" in base: return "ollama"
    if "together" in base:          return "together"
    if "groq" in base:              return "groq"
    if "lmstudio" in base or "1234" in base: return "lmstudio"
    if "vllm" in base:              return "vllm"
    return "openai-compat"


def config_snapshot() -> dict:
    base = os.environ.get("SECHUB_LLM_BASE_URL")
    return {
        "configured": bool(base),
        "provider": provider_hint() if base else None,
        "model": os.environ.get("SECHUB_LLM_MODEL"),
        "has_api_key": bool(os.environ.get("SECHUB_LLM_API_KEY")),
    }


async def chat(messages: list[dict[str, str]], *,
               model: str | None = None,
               max_tokens: int = 512,
               temperature: float = 0.2,
               timeout: float | None = None,
               extra: dict | None = None) -> str:
    """Send a chat-completions request and return the assistant's text."""
    base = os.environ.get("SECHUB_LLM_BASE_URL")
    if not base:
        raise RuntimeError("SECHUB_LLM_BASE_URL not set")
    key = os.environ.get("SECHUB_LLM_API_KEY", "")
    mdl = model or os.environ.get("SECHUB_LLM_MODEL")
    if not mdl:
        raise RuntimeError("SECHUB_LLM_MODEL not set")
    to = timeout or float(os.environ.get("SECHUB_LLM_TIMEOUT", "60"))

    url = base.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"

    payload: dict[str, Any] = {
        "model": mdl,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }
    if extra:
        payload.update(extra)

    # Disable redirect-following + cap response body. The LLM URL is
    # operator-configured; without these guards a compromised LLM gateway
    # could 30x us to a private host (SSRF) or stream a multi-GB reply.
    # Default httpx redirect-follow is already False, but we make it explicit.
    LLM_MAX_BYTES = 16 * 1024 * 1024
    async with httpx.AsyncClient(timeout=to, follow_redirects=False) as cx:
        async with cx.stream("POST", url, headers=headers, json=payload) as r:
            r.raise_for_status()
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > LLM_MAX_BYTES:
                    raise RuntimeError(f"LLM response exceeded {LLM_MAX_BYTES} bytes")
            import json as _json
            body = _json.loads(bytes(buf))

    # OpenAI shape:
    #   { choices: [ { message: { role, content } } ], usage: {...} }
    choices = body.get("choices") or []
    if not choices:
        raise RuntimeError(f"empty response from LLM: {body}")
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    if content is None:
        # some Anthropic-compat responses use a list of parts
        parts = msg.get("content_parts") or []
        content = "".join(p.get("text", "") for p in parts)
    return (content or "").strip()
