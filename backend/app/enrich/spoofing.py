"""Domain spoofing / lookalike detection.

For each monitored org domain, scan known IOC values + news article URLs +
threat-feed indicators for lookalikes using:
  - Edit distance (Damerau-Levenshtein) — typo / character swap
  - Homoglyph normalization — Cyrillic/Greek look-alikes mapped to ASCII
  - Subdomain abuse — legitimate-looking subdomain on a different TLD
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..db import fetchall, load_taxonomy

# Common visual confusables (limited but high-signal set)
HOMOGLYPHS = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "У": "y", "Х": "x",
    "В": "b", "Н": "h", "К": "k", "М": "m", "Т": "t",
    # Greek
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "τ": "t",
    # Math/typography
    "ⅰ": "i", "Ⅰ": "i", "ⅼ": "l",
    # Digit/letter swaps the heuristic should normalize before comparing
    "0": "o", "1": "l", "3": "e", "5": "s",
}


def normalize(s: str) -> str:
    s = s.lower().strip()
    return "".join(HOMOGLYPHS.get(c, c) for c in s)


def damerau_levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    da: dict[str, int] = {}
    maxd = len(a) + len(b)
    H = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    H[0][0] = maxd
    for i in range(0, len(a) + 1):
        H[i + 1][0] = maxd
        H[i + 1][1] = i
    for j in range(0, len(b) + 1):
        H[0][j + 1] = maxd
        H[1][j + 1] = j
    for i in range(1, len(a) + 1):
        db = 0
        for j in range(1, len(b) + 1):
            i1 = da.get(b[j - 1], 0)
            j1 = db
            cost = 0
            if a[i - 1] == b[j - 1]:
                db = j
            else:
                cost = 1
            H[i + 1][j + 1] = min(
                H[i][j] + cost,
                H[i + 1][j] + 1,
                H[i][j + 1] + 1,
                H[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        da[a[i - 1]] = i
    return H[len(a) + 1][len(b) + 1]


_KNOWN_2LD_TLDS = {
    "co.uk", "co.jp", "co.in", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.mx", "com.sg", "com.tw", "com.cn", "com.tr",
    "ne.jp", "or.jp", "ac.uk", "gov.uk", "org.uk",
}


def _root(domain: str) -> str:
    """Reduce host to its registrable root — best effort without PSL."""
    d = domain.lower().strip().rstrip(".")
    # strip scheme/path if a URL was passed
    if "/" in d:
        d = urlparse("http://" + d if "://" not in d else d).hostname or d
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    # Handle known 2-label TLDs like .co.uk by keeping 3 labels
    last_two = ".".join(parts[-2:])
    if last_two in _KNOWN_2LD_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _strip_tld(domain: str) -> str:
    parts = _root(domain).split(".")
    return parts[0] if parts else domain


def candidate_lookalikes_for(domain: str, candidates: list[str], *, threshold: int = 2) -> list[dict]:
    """Find candidates within edit-distance `threshold` of the org root,
    after homoglyph normalization. Returns sorted by distance."""
    norm_org_root = normalize(_strip_tld(domain))
    org_tld = _root(domain).split(".")[-1]
    hits: list[dict] = []
    seen: set[str] = set()
    for cand in candidates:
        if not cand:
            continue
        host = _root(cand)
        if not host or host in seen:
            continue
        seen.add(host)
        norm_root = normalize(_strip_tld(host))
        if norm_root == norm_org_root and host.split(".")[-1] != org_tld:
            hits.append({"candidate": host, "distance": 0, "kind": "different_tld"})
            continue
        if not norm_root:
            continue
        d = damerau_levenshtein(norm_root, norm_org_root)
        if 1 <= d <= threshold and len(norm_root) >= max(4, len(norm_org_root) - 2):
            hits.append({"candidate": host, "distance": d, "kind": "lookalike"})
    hits.sort(key=lambda x: x["distance"])
    return hits


def scan_org(org_id: str) -> dict:
    """Scan IOC index + news URLs for lookalikes of the org's domains."""
    orgs = load_taxonomy("orgs").get("orgs", [])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if org is None:
        return {"error": "unknown_org"}
    org_domains = list({_root(d) for d in (org.get("domains") or []) if d})
    if not org_domains:
        return {"org_id": org_id, "candidates_scanned": 0, "matches": []}

    # Candidate pool: IOC values that look like domains/URLs, plus news URLs
    ioc_rows = fetchall(
        "SELECT DISTINCT ioc_value FROM iocs WHERE ioc_type IN ('domain','url','ip:port')"
    )
    news_rows = fetchall("SELECT DISTINCT url FROM news WHERE url != ''")
    candidates = [r["ioc_value"] for r in ioc_rows] + [r["url"] for r in news_rows]

    matches: list[dict] = []
    for d in org_domains:
        hits = candidate_lookalikes_for(d, candidates)
        for h in hits:
            matches.append({"org_domain": d, **h})

    return {
        "org_id": org_id,
        "org_name": org["name"],
        "org_domains": org_domains,
        "candidates_scanned": len(candidates),
        "matches": matches,
    }


def scan_all() -> dict:
    out = []
    for o in load_taxonomy("orgs").get("orgs", []):
        s = scan_org(o["id"])
        out.append({
            "org_id": s["org_id"],
            "org_name": s.get("org_name"),
            "match_count": len(s.get("matches", [])),
            "matches": s.get("matches", [])[:25],
        })
    return {"orgs": out}
