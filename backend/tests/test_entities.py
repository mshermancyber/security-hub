"""Entity-extraction tests against the live taxonomy."""
from app.enrich.entities import extract_entities, extract_tags, severity_from_tags


def test_cve_pattern():
    out = extract_entities("Fortinet patches CVE-2024-21762 actively exploited in the wild.")
    assert "CVE-2024-21762" in out["cves"]
    assert any(v["id"] == "fortinet" for v in out["vendors"])


def test_ai_company_detection():
    out = extract_entities("OpenAI announced GPT-5 today")
    assert any(c["id"] == "openai" for c in out["ai_companies"])


def test_threat_actor_alias():
    out = extract_entities("LockBit ransomware affiliates breached two healthcare systems")
    assert any(a["id"] == "lockbit" for a in out["threat_actors"])
    assert any(s["id"] == "healthcare" for s in out["sectors"])


def test_org_alias():
    out = extract_entities("Acme Corp reports a phishing campaign targeting Acme customers")
    assert any(o["id"] == "acme-corp" for o in out["orgs"])


def test_tags_and_severity():
    tags = extract_tags("Zero-day actively exploited in Fortinet appliances; ransomware groups adopt the exploit")
    assert "zero-day" in tags
    assert "active-exploitation" in tags
    assert "ransomware" in tags
    sev = severity_from_tags(tags)
    assert sev >= 80
