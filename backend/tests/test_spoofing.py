"""Domain spoofing detector tests."""
from app.enrich.spoofing import damerau_levenshtein, candidate_lookalikes_for, normalize


def test_levenshtein_basic():
    assert damerau_levenshtein("chase", "chase") == 0
    assert damerau_levenshtein("chase", "chaze") == 1
    assert damerau_levenshtein("chase", "chse") == 1
    # Transposition is a single edit in Damerau
    assert damerau_levenshtein("chase", "chsae") == 1


def test_homoglyph_normalize():
    # Cyrillic 'а' should normalize to 'a'
    assert normalize("сhase.com") == "chase.com"
    # digit-letter swaps: 0 → o, 1 → l
    assert normalize("g00gle") == "google"
    assert normalize("acmec0rp") == "acmecorp"


def test_lookalike_finds_typo():
    hits = candidate_lookalikes_for("chase.com",
                                    ["chasse.com", "amazon.com", "ch4se.com", "totally-other.io"])
    found = {h["candidate"] for h in hits}
    assert "chasse.com" in found
    assert "ch4se.com" in found
    assert "amazon.com" not in found
    assert "totally-other.io" not in found


def test_lookalike_different_tld():
    hits = candidate_lookalikes_for("acme-corp.example", ["acme-corp.xyz"])
    found = {h["candidate"] for h in hits}
    assert "acme-corp.xyz" in found
