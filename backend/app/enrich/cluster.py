"""Cross-source news clustering.

Two layers:

  1. **cluster_key** — exact-match clustering. Stored on each row at
     ingest. Items sharing a CVE, a token fingerprint, an entity, or a
     SHA1 of the normalized title share the same key. Fast and indexed.

  2. **simhash** — a 64-bit fingerprint of title shingles. Stored as a
     SIGNED INTEGER on the news row. The /api/news cluster pass uses
     it as a post-merge: items whose Hamming distance is ≤
     NEAR_DUP_THRESHOLD collapse together even if their cluster_keys
     differ. Catches reworded headlines that token clustering misses.
"""
from __future__ import annotations

import hashlib
import re

# Hamming-distance threshold for SimHash near-duplicate merging.
# 64-bit hash. Empirically:
#   ≤ 3 → almost-certain reword of the same story
#   ≤ 6 → likely related but possibly distinct
NEAR_DUP_THRESHOLD = 3


_STOPWORDS = {
    "a", "an", "the", "of", "in", "on", "at", "for", "to", "with", "and",
    "or", "but", "is", "are", "was", "were", "be", "been", "being", "as",
    "by", "from", "this", "that", "these", "those", "it", "its", "into",
    "over", "under", "after", "before", "amid", "via", "per", "vs",
    "new", "more", "than", "out", "off", "now",
}

_NOISE = {
    "vulnerability", "vulnerabilities", "attack", "attacks", "breach",
    "breaches", "hack", "hacks", "hackers", "cyber", "cybersecurity",
    "security", "threat", "threats", "alert", "warning", "report",
    "reports", "news", "exploit", "exploits", "researcher", "researchers",
    "advisory", "patch", "patches", "patched", "update", "updates",
    "fix", "fixes", "flaw", "flaws", "bug", "bugs", "risk", "risks",
    "victim", "victims", "case", "cases", "year", "years", "week", "weeks",
    "day", "days", "today", "yesterday",
}

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ----- cluster_key (exact) -------------------------------------------------


def cluster_key(title: str, summary: str = "", entities: dict | None = None) -> str:
    """Return the exact-match cluster key for a news item."""
    blob = f"{title or ''} {summary or ''}"
    cves = sorted({m.upper() for m in _CVE_RE.findall(blob)})
    if cves:
        return f"cve:{cves[0]}"

    t = (title or "").lower()
    t = re.sub(r"[^a-z0-9 ]+", " ", t)
    raw = [w for w in t.split() if len(w) > 3]
    sig = [w for w in raw if w not in _STOPWORDS and w not in _NOISE]
    if len(sig) >= 2:
        return "t:" + ":".join(sorted(sig[:5]))

    if entities:
        for kind in ("threat_actors", "malware", "orgs", "vendors", "ai_companies", "sectors"):
            arr = entities.get(kind) or []
            if arr:
                return f"e:{kind[:-1] if kind.endswith('s') else kind}:{arr[0]['id']}"
    return f"h:{hashlib.sha1(t.encode()).hexdigest()[:12]}"


# ----- SimHash (near-match) ------------------------------------------------


def _tokens(text: str) -> list[str]:
    """Normalized tokens, filtered by stopwords + noise."""
    t = (text or "").lower()
    t = re.sub(r"[^a-z0-9 ]+", " ", t)
    return [
        w for w in t.split()
        if len(w) > 2 and w not in _STOPWORDS and w not in _NOISE
    ]


def simhash(title: str, summary: str = "") -> int:
    """Compute a 64-bit SimHash of the title (+ first ~80 chars of summary).

    Bag-of-significant-tokens approach: each token contributes a sign
    vote to each of the 64 bit positions, weighted by SHA-1 of the
    token. This is the classic SimHash configuration for short text
    and gives bag-of-words similarity — two articles sharing 70%+ of
    their meaningful tokens land within ~6 bits of each other;
    unrelated articles typically end up 25+ bits apart.

    Returned as a signed 64-bit int safe for SQLite INTEGER storage.
    """
    text = (title or "")
    if summary:
        text = text + " " + (summary[:80])
    tokens = _tokens(text)
    if not tokens:
        return 0
    # Frequency = weight (caps over-weighting of repeated tokens).
    freq: dict[str, int] = {}
    for tok in tokens:
        freq[tok] = freq.get(tok, 0) + 1
    vec = [0] * 64
    for tok, w in freq.items():
        h = hashlib.sha1(tok.encode("utf-8")).digest()
        h64 = int.from_bytes(h[:8], "big", signed=False)
        for i in range(64):
            if h64 & (1 << i):
                vec[i] += w
            else:
                vec[i] -= w
    out = 0
    for i in range(64):
        if vec[i] > 0:
            out |= (1 << i)
    if out >= (1 << 63):
        out -= (1 << 64)
    return out


def hamming(a: int, b: int) -> int:
    """Hamming distance between two 64-bit SimHashes (signed int safe)."""
    x = ((a & 0xFFFFFFFFFFFFFFFF) ^ (b & 0xFFFFFFFFFFFFFFFF))
    return bin(x).count("1")
