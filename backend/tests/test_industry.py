"""Industry-event extractor tests."""
from app.enrich.industry import extract_industry


def test_layoff_headcount():
    e = extract_industry("Microsoft lays off 6,000 employees in latest restructuring")["layoff"]
    assert e["headcount"] == 6000


def test_layoff_percent():
    e = extract_industry("Wix laying off about 20% of its workforce")["layoff"]
    assert e["percent"] == 20.0


def test_layoff_ai_driven():
    e = extract_industry("AI-driven workforce reduction at Salesforce")["layoff"]
    assert e["ai_driven"] is True


def test_funding_amount_and_round():
    e = extract_industry("Anthropic raises $65B in Series H funding")["funding"]
    assert e["amount_usd"] == 65_000_000_000
    assert e["round"] == "Series H"


def test_funding_seed_round():
    e = extract_industry("Stealth startup raised $5M seed round")["funding"]
    assert e["amount_usd"] == 5_000_000


def test_acquisition_parties():
    e = extract_industry("Cisco completes acquisition of Splunk for $28B in cash deal")["acquisition"]
    assert e["acquirer"] == "Cisco"
    assert e["target"] == "Splunk"
    assert e["amount_usd"] == 28_000_000_000


def test_exec_change_out():
    e = extract_industry("Dropbox CEO Drew Houston steps down")["exec_change"]
    assert e["role"] == "CEO"
    assert e["direction"] == "out"


def test_exec_change_political_noise_filtered():
    out = extract_industry("Trump appoints new chair to AI policy panel")
    assert "exec_change" not in out


def test_ipo_detection():
    assert "ipo" in extract_industry("Stripe files S-1 ahead of IPO")


def test_outage_detection():
    assert "outage" in extract_industry("AWS suffers major outage in us-east-1")
