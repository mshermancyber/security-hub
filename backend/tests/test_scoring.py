"""Priority-scoring sanity tests."""
from app.enrich.scoring import cve_priority, news_priority, severity_label


def test_kev_with_high_epss_dominates():
    p = cve_priority(cvss=9.8, epss=0.95, is_kev=True, kev_ransomware="Known")
    assert p >= 90


def test_low_cvss_no_kev_low_priority():
    p = cve_priority(cvss=3.0, epss=0.01, is_kev=False, kev_ransomware=None)
    assert p < 30


def test_news_priority_recency():
    fresh = news_priority(reliability=90, severity=80, recency_hours=0.5, entity_hits=3)
    stale = news_priority(reliability=90, severity=80, recency_hours=120, entity_hits=3)
    assert fresh > stale


def test_severity_label_thresholds():
    assert severity_label(95) == "CRITICAL"
    assert severity_label(75) == "HIGH"
    assert severity_label(50) == "ELEVATED"
    assert severity_label(25) == "GUARDED"
    assert severity_label(5) == "LOW"
