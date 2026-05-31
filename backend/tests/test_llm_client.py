"""LLM client tests against a local mock OpenAI-compat server."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _MockHandler(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        type(self).received.append(body)
        resp = {
            "id": "test",
            "object": "chat.completion",
            "model": body.get("model"),
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "MOCK SUMMARY [1] [2]"},
                "finish_reason": "stop",
            }],
        }
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a, **k):
        pass


@pytest.fixture
def mock_llm(monkeypatch):
    _MockHandler.received = []
    srv = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("SECHUB_LLM_BASE_URL", f"http://127.0.0.1:{port}/v1")
    monkeypatch.setenv("SECHUB_LLM_API_KEY", "test-key")
    monkeypatch.setenv("SECHUB_LLM_MODEL", "claude-sonnet-4-6")
    yield _MockHandler
    srv.shutdown()


@pytest.mark.asyncio
async def test_llm_chat_returns_content(mock_llm):
    from app.integrations import llm
    out = await llm.chat([{"role": "user", "content": "hi"}])
    assert "MOCK SUMMARY" in out
    assert len(mock_llm.received) == 1
    assert mock_llm.received[0]["model"] == "claude-sonnet-4-6"
    assert mock_llm.received[0]["messages"][0]["content"] == "hi"


@pytest.mark.asyncio
async def test_llm_provider_detection(mock_llm, monkeypatch):
    from app.integrations import llm
    # ollama hint
    monkeypatch.setenv("SECHUB_LLM_BASE_URL", "http://localhost:11434/v1")
    assert llm.provider_hint() == "ollama"
    monkeypatch.setenv("SECHUB_LLM_BASE_URL", "https://api.anthropic.com/v1")
    assert llm.provider_hint() == "anthropic"
    monkeypatch.setenv("SECHUB_LLM_BASE_URL", "https://api.openai.com/v1")
    assert llm.provider_hint() == "openai"


def test_llm_unconfigured(monkeypatch):
    from app.integrations import llm
    monkeypatch.delenv("SECHUB_LLM_BASE_URL", raising=False)
    assert llm.is_configured() is False
