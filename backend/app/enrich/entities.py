"""Entity extraction — finds vendors / AI cos / threat actors / malware /
sectors / orgs / CVEs in free text.

Performance: aliases for every entity in every loaded taxonomy are
compiled into a per-kind union regex (`\\b(alias1|alias2|...)\\b`).
re.compile uses an internal DFA-style matcher, so a single pass over
the text classifies every alias hit at C speed. Cached by taxonomy
file mtime so analyst edits hot-reload.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..db import load_taxonomy

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ----- alias-set → union regex matcher ------------------------------------


# Common English words that appear as MITRE/STIX malware/actor aliases and
# cause runaway false positives ("94-page ruling" → Elise malware via "page").
# We drop these UNLESS they match the entity's canonical name exactly — that
# way Snake (the actor named Snake) still matches "snake" while Turla's
# "snake" alias is filtered.
_ALIAS_STOPWORDS = frozenset({
    "page", "agenda", "beacon", "carbon", "cannon", "panel", "anchor",
    "aurora", "snake", "shark", "spark", "pony", "rover", "royal", "maze",
    "viper", "soldier", "photo", "wiper", "epic", "vault", "bank", "axiom",
    "elise", "rover", "spike", "ember", "rocket", "storm", "rain", "fire",
    "ice", "snow", "stone", "metal", "gold", "silver", "iron", "salt",
    "sugar", "honey", "milk", "apple", "orange", "peach", "lemon", "lime",
    "olive", "onion", "pepper", "mint", "basil", "sage", "thyme",
    "horse", "wolf", "bear", "tiger", "lion", "eagle", "hawk", "dove",
    "owl", "crow", "fox", "cat", "rat", "dog", "fish", "frog", "elk",
    "deer", "spider", "panda", "dragon", "crab", "rabbit", "mouse",
    "sheep", "goat", "pig", "cow", "demon", "ghost", "angel", "knight",
    "priest", "wizard", "witch", "elf", "dwarf", "giant", "rocket", "star",
    "moon", "sun", "sky", "cloud", "tree", "leaf", "rose", "flower",
    "grass", "wood", "rock",
})


def _normalize(aliases: Iterable[str], entity_name: str | None = None) -> list[str]:
    """Lowercased, deduped, non-empty, sorted by length-desc so longest
    aliases are matched first (avoids 'apt2' shadowing 'apt29').

    Drops aliases in `_ALIAS_STOPWORDS` UNLESS the alias equals the entity's
    canonical name (so Snake-the-actor still matches; Turla's 'snake' alias
    does not)."""
    canonical = (entity_name or "").lower().strip()
    out: list[str] = []
    seen: set[str] = set()
    for a in aliases:
        if not a:
            continue
        a = a.lower().strip()
        if len(a) < 2 or a in seen:
            continue
        if a in _ALIAS_STOPWORDS and a != canonical:
            continue
        seen.add(a)
        out.append(a)
    out.sort(key=len, reverse=True)
    return out


def _word_re(aliases: list[str]) -> re.Pattern | None:
    """Build a single `\\b(?:alias|...)\\b` regex from the alias list."""
    if not aliases:
        return None
    # re.escape protects any regex metachars in the alias strings.
    pattern = r"\b(?:" + "|".join(re.escape(a) for a in aliases) + r")\b"
    return re.compile(pattern, re.IGNORECASE)


class _AliasMatcher:
    """Compiles per-entity-id alias union regexes from a list of entries
    and gives O(text-len) hits-extraction per call.

    `entries` is a list of dicts each with `id`, `name`, and `aliases`
    (any iterable of strings).
    """

    def __init__(self, entries: list[dict], extra_keys: tuple[str, ...] = ()):
        # Single combined regex + an index from alias string back to entry id
        all_aliases: list[str] = []
        alias_to_id: dict[str, str] = {}
        meta: dict[str, dict] = {}
        for e in entries:
            eid = e.get("id")
            if not eid:
                continue
            aliases = _normalize(e.get("aliases") or [], entity_name=e.get("name"))
            for a in aliases:
                # First-write wins so longer aliases (sorted earlier) own ties
                if a not in alias_to_id:
                    alias_to_id[a] = eid
                    all_aliases.append(a)
            meta[eid] = {"id": eid, "name": e.get("name") or eid}
            for k in extra_keys:
                meta[eid][k] = e.get(k)
        self._re = _word_re(all_aliases)
        self._alias_to_id = alias_to_id
        self._meta = meta

    def hits(self, text_lc: str) -> list[dict]:
        if not self._re:
            return []
        seen: set[str] = set()
        out: list[dict] = []
        for m in self._re.finditer(text_lc):
            alias = m.group(0)
            eid = self._alias_to_id.get(alias)
            if not eid or eid in seen:
                continue
            seen.add(eid)
            out.append(self._meta[eid])
        return out


# ----- per-taxonomy matcher cache (rebuilt on taxonomy mtime change) ------

import threading as _threading_for_cache
_matcher_cache: dict[str, tuple[float, _AliasMatcher]] = {}
_matcher_cache_lock = _threading_for_cache.Lock()


def precompile_matchers() -> int:
    """Force-compile all matchers at startup so the first ingest / query
    after boot doesn't pay the regex-union compile cost. Returns count
    compiled."""
    n = 0
    for taxon, key, extra in (
        ("vendors", "vendors", ("category",)),
        ("ai_companies", "ai_companies", ("category",)),
        ("threat_actors", "threat_actors", ("type", "origin")),
        ("threat_actors_mitre", "threat_actors", ("type", "origin")),
        ("sectors", "sectors", ()),
        ("orgs", "orgs", ("sector", "country")),
    ):
        if _get_matcher(taxon, key, extra):
            n += 1
    # Malware matchers — distinct cache key per taxonomy via `_get_matcher`,
    # which now keys on (taxon, list_key).
    for taxon_name in ("threat_actors", "threat_actors_mitre"):
        if _get_matcher(taxon_name, "malware_families", ("type",)):
            n += 1
    return n


def _get_matcher(taxon_name: str, list_key: str, extra_keys: tuple[str, ...]) -> _AliasMatcher | None:
    """Build (or reuse) the compiled matcher for a taxonomy file.

    Cache access is locked so two threads racing on a cold cache don't
    both compile + race-stomp each other's writes. The cache key includes
    `list_key` so the same file used for two different lists (threat
    actors + malware families) produces two distinct matchers.
    """
    from ..config import TAXONOMY_DIR
    path = TAXONOMY_DIR / f"{taxon_name}.json"
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        return None
    cache_key = f"{taxon_name}::{list_key}"
    with _matcher_cache_lock:
        cached = _matcher_cache.get(cache_key)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            doc = load_taxonomy(taxon_name)
        except FileNotFoundError:
            return None
        matcher = _AliasMatcher(doc.get(list_key, []), extra_keys=extra_keys)
        _matcher_cache[cache_key] = (mtime, matcher)
        return matcher


# ----- public entry point -------------------------------------------------


def extract_entities(text: str) -> dict:
    """Return matched entities grouped by category."""
    if not text:
        return {"vendors": [], "ai_companies": [], "threat_actors": [], "malware": [],
                "sectors": [], "orgs": [], "cves": []}
    tlc = text.lower()
    out: dict = {
        "vendors": [],
        "ai_companies": [],
        "threat_actors": [],
        "malware": [],
        "sectors": [],
        "orgs": [],
        "cves": sorted({m.upper() for m in CVE_RE.findall(text)}),
    }

    # Vendors
    m = _get_matcher("vendors", "vendors", ("category",))
    if m:
        out["vendors"] = m.hits(tlc)

    # AI companies
    m = _get_matcher("ai_companies", "ai_companies", ("category",))
    if m:
        out["ai_companies"] = m.hits(tlc)

    # Threat actors — hand-curated first, MITRE fills the rest (no duplicate ids).
    seen_actor_ids: set[str] = set()
    for taxon_name in ("threat_actors", "threat_actors_mitre"):
        m = _get_matcher(taxon_name, "threat_actors", ("type", "origin"))
        if not m:
            continue
        for entry in m.hits(tlc):
            if entry["id"] in seen_actor_ids:
                continue
            seen_actor_ids.add(entry["id"])
            out["threat_actors"].append(entry)

    # Malware (same dual-taxonomy union). Routed through `_get_matcher` so
    # the cache write is locked and two threads racing on a cold cache can't
    # partially-update the entry.
    seen_malware_ids: set[str] = set()
    for taxon_name in ("threat_actors", "threat_actors_mitre"):
        mm = _get_matcher(taxon_name, "malware_families", ("type",))
        if not mm:
            continue
        for entry in mm.hits(tlc):
            if entry["id"] in seen_malware_ids:
                continue
            seen_malware_ids.add(entry["id"])
            out["malware"].append(entry)

    # Sectors
    m = _get_matcher("sectors", "sectors", ())
    if m:
        out["sectors"] = m.hits(tlc)

    # Orgs (curated aliases only — see docstring of the older impl for why)
    m = _get_matcher("orgs", "orgs", ("sector", "country"))
    if m:
        out["orgs"] = m.hits(tlc)

    return out


# ----- heuristic tags + severity (unchanged) ------------------------------

_TAG_RULES: list[tuple[str, list[str]]] = [
    ("zero-day", ["zero-day", "0day", "0-day", "zero day"]),
    ("active-exploitation", ["actively exploited", "active exploitation", "exploited in the wild", "in-the-wild", "in the wild"]),
    ("ransomware", ["ransomware", "ransom note", "encrypted files"]),
    ("breach", ["data breach", "breached", "leaked data", "data leak"]),
    ("supply-chain", ["supply chain", "supply-chain"]),
    ("nation-state", ["nation-state", "nation state", "state-sponsored", "state sponsored"]),
    ("phishing", ["phishing", "spear-phish", "spear phishing"]),
    ("malware", ["malware", "trojan", "backdoor"]),
    ("vulnerability", ["vulnerability", "cve-", "rce", "remote code execution", "privilege escalation", "lpe"]),
    ("patch", ["patch tuesday", "security update", "fixes vulnerability"]),
    ("ddos", ["ddos", "denial-of-service", "denial of service"]),
    ("ai-incident", ["prompt injection", "jailbreak", "model abuse", "deepfake"]),
    ("layoff", ["layoffs", "laid off", "workforce reduction", "job cuts"]),
    ("funding", ["series a", "series b", "series c", "series d", "raised $", "funding round"]),
    ("acquisition", ["acquired", "acquisition", "merger"]),
    ("darknet", [
        "dark web", "darknet", "deep web",
        "tor network", "tor browser", ".onion",
        "leak site", "data leak site", "leak forum",
        "underground forum", "underground market", "criminal forum", "criminal marketplace",
        "telegram channel", "telegram group",
        "russianmarket", "alphabay", "empire market", "genesis market", "industrial spy",
        "breachforums", "exploit.in", "raidforums", "xss.is", "exposed.vc",
        "dread forum", "dread.onion",
        "shinyhunters", "lapsus$",
    ]),
]


_TAG_REGEXES = [
    (tag, re.compile(
        r"\b(?:" + "|".join(re.escape(k) for k in keys) + r")\b",
        re.IGNORECASE,
    ))
    for tag, keys in _TAG_RULES
]


def extract_tags(text: str) -> list[str]:
    """Word-boundary tag matching. Plain `in` substring matching caused
    'zero-day' to fire on '60-day ceasefire', 'ddos' on 'addons', etc."""
    if not text:
        return []
    return [tag for tag, pat in _TAG_REGEXES if pat.search(text)]


def severity_from_tags(tags: Iterable[str]) -> int:
    """0-100 heuristic severity for news items."""
    tags = set(tags)
    score = 10
    if "active-exploitation" in tags: score += 40
    if "zero-day" in tags:            score += 30
    if "ransomware" in tags:          score += 25
    if "breach" in tags:              score += 25
    if "supply-chain" in tags:        score += 20
    if "nation-state" in tags:        score += 20
    if "vulnerability" in tags:       score += 10
    if "ddos" in tags:                score += 10
    if "patch" in tags:               score += 5
    return min(100, score)
