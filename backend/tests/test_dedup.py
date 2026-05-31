"""Tests for cluster_key + SimHash near-duplicate detection."""
from app.enrich.cluster import (
    NEAR_DUP_THRESHOLD,
    cluster_key,
    hamming,
    simhash,
)


def test_cluster_key_cve_first():
    assert cluster_key("Drupal patched CVE-2026-9082", "") == "cve:CVE-2026-9082"


def test_cluster_key_token_fingerprint_order_independent():
    a = cluster_key("Drupal Core SQL injection actively exploited", "")
    b = cluster_key("SQL injection in Drupal Core actively exploited", "")
    assert a == b


def test_cluster_key_short_title_uses_entity_anchor():
    ents = {"vendors": [{"id": "microsoft", "name": "Microsoft"}]}
    assert cluster_key("Microsoft patches", "", ents) == "e:vendor:microsoft"


def test_cluster_key_fallback_sha1_when_no_signal():
    k = cluster_key("hi", "", None)
    assert k.startswith("h:")


def test_simhash_identical_titles_have_zero_distance():
    a = simhash("Microsoft patches actively exploited Defender vulnerability")
    b = simhash("Microsoft patches actively exploited Defender vulnerability")
    assert a == b
    assert hamming(a, b) == 0


def test_simhash_minor_rephrase_close_distance():
    # Small wording change; SimHash should be close.
    a = simhash("Microsoft patches actively exploited Defender vulnerability")
    b = simhash("Microsoft patches Defender vulnerability that is being actively exploited")
    d = hamming(a, b)
    # Should be within the near-dup threshold or close to it.
    assert d <= NEAR_DUP_THRESHOLD + 4, f"distance {d} unexpectedly large"


def test_simhash_unrelated_titles_far_apart():
    a = simhash("Anthropic raises $65B at $1T valuation")
    b = simhash("Volt Typhoon targets US energy infrastructure")
    d = hamming(a, b)
    assert d > NEAR_DUP_THRESHOLD * 3, f"distance {d} too small for unrelated"


def test_simhash_handles_empty():
    assert isinstance(simhash(""), int)
    assert isinstance(simhash("", ""), int)
