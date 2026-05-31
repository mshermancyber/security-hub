"""End-to-end route smoke tests using FastAPI TestClient."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    # Import here so the isolated-DB fixture has applied SECHUB_DB
    from app.main import app
    return TestClient(app)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_news_empty(client):
    r = client.get("/api/news?limit=5")
    assert r.status_code == 200
    assert "items" in r.json()


def test_vulns_empty(client):
    r = client.get("/api/vulns?limit=5")
    assert r.status_code == 200


def test_taxonomy_orgs(client):
    r = client.get("/api/taxonomy/orgs")
    assert r.status_code == 200
    orgs = r.json()["orgs"]
    assert any(o["id"] == "acme-corp" for o in orgs)
    assert any(o["id"] == "globex-bank" for o in orgs)


def test_orgs_list(client):
    r = client.get("/api/orgs?days=30")
    assert r.status_code == 200
    assert "orgs" in r.json()


def test_orgs_health(client):
    r = client.get("/api/orgs/health?days=30")
    assert r.status_code == 200
    orgs = r.json()["orgs"]
    assert len(orgs) >= 2  # Acme Corp + Globex Bank
    for o in orgs:
        assert "score" in o and "state" in o


def test_industry_signals(client):
    r = client.get("/api/industry/signals?days=30")
    assert r.status_code == 200
    body = r.json()
    for k in ("layoffs", "funding", "acquisitions", "execs"):
        assert k in body


def test_intel_velocity_kev(client):
    r = client.get("/api/intel/velocity/kev?days=7")
    assert r.status_code == 200
    s = r.json()["series"]
    assert len(s) == 8  # inclusive of today


def test_ai_config(client):
    r = client.get("/api/ai/config")
    assert r.status_code == 200
    assert "configured" in r.json()


def test_integrations_health(client):
    r = client.get("/api/integrations/health")
    assert r.status_code == 200
    assert "sinks" in r.json()


def test_exposure_spoofing(client):
    r = client.get("/api/exposure/spoofing")
    assert r.status_code == 200
    assert "orgs" in r.json()


def test_orgs_admin_create_update_delete(client):
    payload = {
        "id": "testco", "name": "Test Co", "sector": "saas", "country": "US",
        "brands": ["TestCo"], "subsidiaries": [], "domains": ["testco.com"],
        "aliases": ["testco"], "tech_stack": ["microsoft"], "watch_keywords": []
    }
    r = client.post("/api/orgs-admin", json=payload)
    assert r.status_code == 200
    r = client.put("/api/orgs-admin/testco", json={**payload, "name": "Test Co Inc"})
    assert r.status_code == 200
    r = client.delete("/api/orgs-admin/testco")
    assert r.status_code == 200
    r = client.delete("/api/orgs-admin/testco")
    assert r.status_code == 404


def test_auth_enforced_when_env_set(monkeypatch):
    monkeypatch.setenv("SECHUB_AUTH_TOKEN", "secret-xyz")
    from app.main import app
    c = TestClient(app)
    r = c.get("/api/news")
    assert r.status_code == 401
    r = c.get("/api/news", headers={"Authorization": "Bearer secret-xyz"})
    assert r.status_code == 200
    r = c.get("/api/health")  # always public
    assert r.status_code == 200
