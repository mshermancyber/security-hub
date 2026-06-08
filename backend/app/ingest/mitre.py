"""MITRE ATT&CK ingestion.

Pulls intrusion-set + malware objects from the official STIX bundle on
GitHub and normalizes them into the threat_actors taxonomy shape so the
existing entity-extraction + actor_watch pipelines pick them up.

This goes from our hand-curated ~20 actors to ~190 groups + ~700 malware
families with every vendor's naming convention (CrowdStrike's "Cozy Bear",
Microsoft's "Midnight Blizzard", Mandiant's "APT29", Recorded Future's
"NOBELIUM") unified by ATT&CK group ID.

Cadence: weekly is plenty (MITRE updates the bundle every release).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import httpx

from .. import config
from ..db import record_feed_health

log = logging.getLogger("sechub.ingest.mitre")

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

# Heuristic origin classification — MITRE doesn't tag attribution directly.
# We count *strong* attribution phrases in the first ~600 chars of the
# description (where the lead attribution sentence usually sits). Higher
# weight = more specific.
_ORIGIN_PATTERNS = [
    ("KP", re.compile(r"\bnorth\s+korea(?:n)?\b|\bDPRK\b|reconnaissance\s+general\s+bureau", re.I), 3),
    ("CN", re.compile(r"\bchina(?:-based| government| state)?\b|\bChinese\s+(?:state|cyber|hacking|intelligence|APT)\b|\bMSS\b|People'?s?\s+Liberation\s+Army|\bPLA\b", re.I), 3),
    ("IR", re.compile(r"\bIran(?:ian)?\b|\bIRGC\b|Islamic\s+Revolutionary\s+Guard", re.I), 3),
    ("RU", re.compile(r"\bRussia(?:n)?\s+(?:government|state|cyber|military|intelligence|federation|APT)\b|\bGRU\b|\bSVR\b|\bFSB\b|\bRussian\s+threat\s+actor\b", re.I), 3),
    ("VN", re.compile(r"\bVietnam(?:ese)?\s+(?:state|government|APT|cyber)\b", re.I), 3),
    ("US", re.compile(r"\bequation\s+group\b|\bNSA\b\s+linked|Tailored\s+Access\s+Operations", re.I), 3),
    # Weaker / general country mentions count for less
    ("KP", re.compile(r"\bnorth\s+korea\b", re.I), 1),
    ("CN", re.compile(r"\bchina\b|\bchinese\b", re.I), 1),
    ("RU", re.compile(r"\brussia\b|\brussian\b", re.I), 1),
    ("IR", re.compile(r"\biran\b|\biranian\b", re.I), 1),
]

# Well-known actor → origin map. Used to override the heuristic when the
# description contains comparative language (e.g. "similar to Russian APT28")
# that confuses the regex. Names match the MITRE intrusion-set name field.
_KNOWN_ORIGINS = {
    # DPRK
    "lazarus group": "KP", "apt37": "KP", "apt38": "KP", "kimsuky": "KP",
    "andariel": "KP", "bluenoroff": "KP", "reaper": "KP",
    # CN
    "apt1": "CN", "apt3": "CN", "apt10": "CN", "apt12": "CN", "apt16": "CN",
    "apt17": "CN", "apt19": "CN", "apt30": "CN", "apt40": "CN", "apt41": "CN",
    "volt typhoon": "CN", "salt typhoon": "CN", "deep panda": "CN",
    "leviathan": "CN", "naikon": "CN", "axiom": "CN", "ke3chang": "CN",
    "mustang panda": "CN", "winnti group": "CN", "stone panda": "CN",
    "elderwood": "CN", "barium": "CN",
    # RU
    "apt28": "RU", "apt29": "RU", "sandworm team": "RU", "turla": "RU",
    "fancy bear": "RU", "cozy bear": "RU", "berserk bear": "RU",
    "energetic bear": "RU", "gamaredon group": "RU", "indrik spider": "RU",
    "wizard spider": "RU", "fin7": "RU", "ta505": "RU", "evil corp": "RU",
    # IR
    "apt33": "IR", "apt34": "IR", "apt35": "IR", "apt39": "IR", "apt42": "IR",
    "muddywater": "IR", "oilrig": "IR", "charming kitten": "IR",
    "leafminer": "IR", "magic hound": "IR", "domestic kitten": "IR",
}

_RANSOMWARE_PATTERN = re.compile(
    r"\b(ransom|extortion|leak site|encrypt(?:s|or|ed) (?:files|data)|raas)\b",
    re.IGNORECASE,
)


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s.lower()).strip("-")
    return s or "unknown"


def _origin(name: str, text: str) -> str:
    # 1. Explicit override for well-known groups
    n = name.lower().strip()
    if n in _KNOWN_ORIGINS:
        return _KNOWN_ORIGINS[n]
    # 2. Heuristic scoring on description lead
    lead = (text or "")[:600]
    scores: dict[str, int] = {}
    for code, rx, weight in _ORIGIN_PATTERNS:
        if rx.search(lead):
            scores[code] = scores.get(code, 0) + weight
    if not scores:
        return "UNK"
    # Pick highest. Require a meaningful score (>=2) to avoid weak single-word matches.
    code, score = max(scores.items(), key=lambda kv: kv[1])
    return code if score >= 2 else "UNK"


def _actor_type(name: str, description: str) -> str:
    blob = f"{name} {description}".lower()
    if _RANSOMWARE_PATTERN.search(blob):
        return "ecrime"
    if re.search(r"\b(apt|state-sponsored|nation-state|cyber-?espionage|espionage)\b", blob):
        return "nation-state"
    return "intrusion-set"


def _malware_type(stix_obj: dict) -> str:
    types = stix_obj.get("malware_types") or []
    if types:
        return types[0].lower()
    name = (stix_obj.get("name") or "").lower()
    if "ransom" in name: return "ransomware"
    if "rat" in name or "trojan" in name: return "rat"
    return "malware"


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


async def fetch_mitre() -> int:
    """Fetch the STIX bundle, write `taxonomy/threat_actors_mitre.json`.
    Returns count of entries written."""
    out_path: Path = config.TAXONOMY_DIR / "threat_actors_mitre.json"
    try:
        from ..safe_http import safe_get
        async with httpx.AsyncClient(timeout=120.0,
                                     headers={"User-Agent": config.USER_AGENT},
                                     follow_redirects=True, max_redirects=5) as cx:
            # STIX bundle is ~25-30 MiB; allow 80 MiB headroom.
            r = await safe_get(cx, MITRE_URL, max_bytes=80 * 1024 * 1024)
            doc = r.json()
    except Exception as e:
        record_feed_health("mitre-attack", "MITRE ATT&CK", ok=False, error=str(e))
        return 0

    objs = doc.get("objects", [])
    # First, build technique lookups: technique stix id → ATT&CK ID + name
    # so we can resolve relationships from `relationship` objects.
    tech_lookup: dict[str, dict] = {}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        ext = _attack_id(o)
        if ext:
            tech_lookup[o.get("id")] = {"attack_id": ext, "name": o.get("name") or ext}
    # Build a map: intrusion-set stix id → list of (attack_id, name)
    group_to_techs: dict[str, list[dict]] = {}
    for o in objs:
        if o.get("type") != "relationship":
            continue
        if o.get("relationship_type") != "uses":
            continue
        src = o.get("source_ref") or ""
        dst = o.get("target_ref") or ""
        if not src.startswith("intrusion-set--"):
            continue
        tech = tech_lookup.get(dst)
        if not tech:
            continue
        group_to_techs.setdefault(src, []).append(tech)

    groups: list[dict] = []
    seen_ids: set[str] = set()
    for o in objs:
        if o.get("type") != "intrusion-set":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        name = o.get("name") or ""
        if not name:
            continue
        aliases = list(o.get("aliases") or [])
        if name not in aliases:
            aliases.insert(0, name)
        # Lowercase + deduped; each goes through the existing word-boundary matcher.
        norm_aliases = sorted({a.lower().strip() for a in aliases if a and len(a) >= 3})
        if not norm_aliases:
            continue
        gid = _slugify(name)
        if gid in seen_ids:
            continue
        seen_ids.add(gid)
        techs = group_to_techs.get(o.get("id")) or []
        # Dedupe + cap to top 20 most-cited TTPs per group
        seen_t: set[str] = set()
        unique_techs: list[dict] = []
        for t in techs:
            if t["attack_id"] in seen_t:
                continue
            seen_t.add(t["attack_id"])
            unique_techs.append(t)
        groups.append({
            "id": gid,
            "name": name,
            "type": _actor_type(name, o.get("description", "")),
            "origin": _origin(name, o.get("description", "")),
            "attack_id": _attack_id(o),
            "techniques": unique_techs[:20],
            "aliases": norm_aliases,
        })

    malware: list[dict] = []
    mseen: set[str] = set()
    for o in objs:
        if o.get("type") != "malware":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        name = o.get("name") or ""
        if not name or len(name) < 3:
            continue
        aliases = list(o.get("x_mitre_aliases") or o.get("aliases") or [])
        if name not in aliases:
            aliases.insert(0, name)
        norm_aliases = sorted({a.lower().strip() for a in aliases if a and len(a) >= 3})
        # Reject extremely common-word names that would over-match
        bad = {"shell", "tool", "client", "loader", "agent", "service", "command"}
        norm_aliases = [a for a in norm_aliases if a not in bad and not a.isnumeric()]
        if not norm_aliases:
            continue
        mid = _slugify(name)
        if mid in mseen:
            continue
        mseen.add(mid)
        malware.append({
            "id": mid,
            "name": name,
            "type": _malware_type(o),
            "attack_id": _attack_id(o),
            "aliases": norm_aliases,
        })

    payload = {
        "_meta": {
            "source": "MITRE ATT&CK Enterprise (intrusion-set + malware)",
            "url": MITRE_URL,
            "description": "Auto-generated by ingest/mitre.py. Do not hand-edit; will be overwritten.",
        },
        "threat_actors": groups,
        "malware_families": malware,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n")
    record_feed_health("mitre-attack", "MITRE ATT&CK",
                       ok=True, items=len(groups) + len(malware))
    log.info("mitre ingest: %d groups, %d malware → %s", len(groups), len(malware), out_path)
    return len(groups) + len(malware)
