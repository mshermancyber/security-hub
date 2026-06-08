"""Tech industry event extraction.

Parses news titles + summaries for:
  - layoffs: headcount + percent + driver (ai, restructuring, ...)
  - funding: round (seed / pre-seed / Series A-F / strategic) + amount USD
  - acquisitions: acquirer + target (best effort)
  - IPOs: filing / pricing / direct listing
  - executive changes: role (CEO / CTO / CISO / CFO / COO / president / chair) + direction (in / out)
  - product events: launch, EOL, outage, GA

Output is shaped for downstream API consumption and stored on the news row as
`industry_json` so we can query without re-parsing.
"""
from __future__ import annotations

import re
from typing import Any

# --- helpers --------------------------------------------------------------

_NUM_RE = re.compile(
    r"""(\$|USD\s*)?               # optional currency
        (\d{1,3}(?:[,\.]\d{3})*    # 1,000 or 1.000 etc
         (?:\.\d+)?                # decimals
         |\d+\.?\d*)               # plain number
        \s*
        (k|m|mn|million|bn|billion|b|thousand)?\b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _to_int(num: str) -> int | None:
    try:
        return int(num.replace(",", "").replace(".", "")) if num else None
    except Exception:
        return None


def _money_to_usd(match: re.Match) -> float | None:
    raw = match.group(2)
    unit = (match.group(3) or "").lower()
    try:
        val = float(raw.replace(",", "")) if "." not in raw or raw.count(".") == 1 and not unit else float(raw.replace(",", ""))
        # treat comma as thousands sep, dot as decimal — best-effort
        val = float(raw.replace(",", ""))
    except Exception:
        return None
    mult = {
        "k": 1_000, "thousand": 1_000,
        "m": 1_000_000, "mn": 1_000_000, "million": 1_000_000,
        "b": 1_000_000_000, "bn": 1_000_000_000, "billion": 1_000_000_000,
    }.get(unit, 1)
    return val * mult


# --- layoffs --------------------------------------------------------------

# A bare "<number> <unit-word>" pattern. We require the unit word so we
# don't accidentally capture percentages ("8% of workforce") or unrelated
# numbers ("Q3 2024"). Used in combination with _LAYOFF_TRIGGER_RE to
# ensure we're in a layoff context.
_LAYOFF_HEADCOUNT_RE = re.compile(
    r"(?:about\s+|nearly\s+|over\s+|more\s+than\s+|up\s+to\s+|around\s+|approximately\s+|some\s+)?"
    r"(\d{1,3}(?:,\d{3})*|\d+(?:\.\d+)?)\s*(k|thousand|m|million)?\s+"
    r"(?:more\s+)?(?:employees|workers|jobs|staff|positions|roles|people)\b",
    re.IGNORECASE,
)
# Compact "<verb> <N><k>" without a unit word — catches "Meta cuts 12k",
# "Google lays off 5k". Only fires when explicitly attached to a verb.
_LAYOFF_COMPACT_RE = re.compile(
    r"\b(?:lays?\s+off|cut(?:s|ting)?|axes?|sheds?|fires?|eliminat(?:e|es|ing))\s+"
    r"(?:about\s+|nearly\s+|over\s+|more\s+than\s+|up\s+to\s+|around\s+|approximately\s+|some\s+)?"
    r"(\d+(?:\.\d+)?)\s*(k|thousand|m|million)\b",
    re.IGNORECASE,
)
# Aggregation/tracker articles cite cumulative numbers we shouldn't credit
# to a single event.
_AGGREGATION_RE = re.compile(
    r"\b(tracker|tally|aggregat|cumulative|year[\s\-]to[\s\-]date|round[\s\-_]?up"
    r"|all\s+(?:the\s+)?(?:tech\s+)?layoffs|so\s+far\s+(?:this\s+year|in\s+\d{4})"
    r"|since\s+(?:january\s+)?20\d{2})\b",
    re.IGNORECASE,
)
_LAYOFF_PERCENT_RE = re.compile(
    r"\b(\d{1,2}(?:\.\d+)?)\s*(?:%|percent)\s+of\s+(?:its\s+|the\s+)?(?:global\s+|total\s+)?(?:workforce|staff|employees|headcount)\b",
    re.IGNORECASE,
)
_LAYOFF_TRIGGER_RE = re.compile(
    r"\b(layoffs?|laid\s+off|lay(?:s|ing)?\s+off|workforce\s+reduction|job\s+cuts|"
    r"cutting\s+(?:its\s+)?staff|hiring\s+freeze|riffed|riff\b|restructuring|"
    r"workforce\s+cuts?|cuts?\s+\d|cut\s+\d|eliminat(?:e|es|ing)|"
    r"shed(?:s|ding)?\s+\d|fires?\s+\d|let(?:s|ting)?\s+go)\b",
    re.IGNORECASE,
)
_HIRING_FREEZE_RE = re.compile(r"\bhiring\s+freeze\b", re.IGNORECASE)
_AI_DRIVEN_RE = re.compile(r"\b(ai[-\s]?driven|due\s+to\s+ai|replaced\s+by\s+ai|ai\s+automation)\b", re.IGNORECASE)


def extract_layoff(text: str) -> dict | None:
    if not text or not _LAYOFF_TRIGGER_RE.search(text):
        return None
    is_aggregation = bool(_AGGREGATION_RE.search(text))
    headcount = None
    if not is_aggregation:
        # Try compact verb-attached first ("Meta cuts 12k"), then
        # explicit unit-word form ("lays off 1,200 employees").
        m = _LAYOFF_COMPACT_RE.search(text) or _LAYOFF_HEADCOUNT_RE.search(text)
        if m:
            try:
                n = float(m.group(1).replace(",", ""))
                unit = (m.group(2) or "").lower()
                if unit in ("k", "thousand"):
                    n *= 1_000
                elif unit in ("m", "million"):
                    n *= 1_000_000
                headcount = int(n)
            except Exception:
                headcount = None
    percent = None
    m = _LAYOFF_PERCENT_RE.search(text)
    if m:
        try:
            percent = float(m.group(1))
        except Exception:
            percent = None
    if headcount is None and percent is None and not _HIRING_FREEZE_RE.search(text):
        # only a trigger word, not enough signal
        return {"detected": True, "headcount": None, "percent": None, "ai_driven": bool(_AI_DRIVEN_RE.search(text)),
                "hiring_freeze": False}
    return {
        "detected": True,
        "headcount": headcount,
        "percent": percent,
        "ai_driven": bool(_AI_DRIVEN_RE.search(text)),
        "hiring_freeze": bool(_HIRING_FREEZE_RE.search(text)),
    }


# --- funding --------------------------------------------------------------

_FUNDING_AMOUNT_RE = re.compile(
    r"(?:raises?|raised|raising|secure[sd]?|securing|net(?:s|ted)?|"
    r"clos(?:e[ds]?|ing)|announce[sd]?|land(?:s|ed|ing)?|"
    r"banks?|bagging|bagged|wraps?\s+up)\s+"
    r"(?:a\s+|an\s+|its\s+)?"
    r"\$?\s*(\d{1,3}(?:[,\.]\d{3})*(?:\.\d+)?|\d+\.?\d*)\s*"
    r"(k|m|mn|million|bn|billion|b|thousand)\b",
    re.IGNORECASE,
)
_VALUATION_RE = re.compile(
    r"(?:(?:valuation|valued|valuing)\s+(?:of|at)\s+\$?\s*"
    r"|at\s+(?:a\s+)?\$?\s*)"
    r"(\d{1,3}(?:[,\.]\d{3})*(?:\.\d+)?|\d+\.?\d*)\s*"
    r"(k|m|mn|million|bn|billion|b)\s*(?:valuation\b)?",
    re.IGNORECASE,
)
_ROUND_RE = re.compile(
    r"\b(pre[-\s]?seed|seed\s+(?:round|funding|extension)?|"
    r"series\s+([a-h])\b|"
    r"strategic\s+(?:round|investment)|"
    r"bridge\s+round|"
    r"growth\s+round)\b",
    re.IGNORECASE,
)
_FUNDING_TRIGGER_RE = re.compile(
    r"\b(raised|raises|raising|funding\s+round|series\s+[a-h]\b|"
    r"secured?|securing|nets?|netted|closes?\s+(?:its\s+)?\$|"
    r"closing\s+(?:its\s+)?\$|venture\s+round|seed\s+round|pre-?seed|"
    r"announce[sd]?\s+\$|landed?\s+\$|landing\s+\$|bagged?\s+\$)\b",
    re.IGNORECASE,
)


def _amount_to_usd(num_str: str, unit: str) -> float | None:
    try:
        val = float(num_str.replace(",", ""))
    except Exception:
        return None
    mult = {
        "k": 1_000, "thousand": 1_000,
        "m": 1_000_000, "mn": 1_000_000, "million": 1_000_000,
        "b": 1_000_000_000, "bn": 1_000_000_000, "billion": 1_000_000_000,
    }.get(unit.lower(), 1)
    return val * mult


def extract_funding(text: str) -> dict | None:
    if not text or not _FUNDING_TRIGGER_RE.search(text):
        return None
    amount = None
    m = _FUNDING_AMOUNT_RE.search(text)
    if m:
        amount = _amount_to_usd(m.group(1), m.group(2))
    valuation = None
    m = _VALUATION_RE.search(text)
    if m:
        valuation = _amount_to_usd(m.group(1), m.group(2))
    round_label = None
    m = _ROUND_RE.search(text)
    if m:
        if m.group(2):  # Series X
            round_label = f"Series {m.group(2).upper()}"
        else:
            round_label = m.group(1).strip().title()
    if amount is None and round_label is None and valuation is None:
        return None
    return {
        "detected": True,
        "amount_usd": amount,
        "valuation_usd": valuation,
        "round": round_label,
    }


# --- acquisitions / M&A ---------------------------------------------------

_ACQUIRES_RE = re.compile(
    r"\b([A-Z][\w\.\-&]*(?:\s+[A-Z][\w\.\-&]*){0,3})\s+"
    r"(?:acquires?|to\s+acquire|has\s+acquired|completes?\s+acquisition\s+of|buys?|to\s+buy)\s+"
    r"([A-Z][\w\.\-&]*(?:\s+[A-Z][\w\.\-&]*){0,3})\b",
)
# Passive form: "<TARGET> acquired by <ACQUIRER>" — note the role swap.
# Capitalization is required on the entity captures (case-sensitive) while
# the linking verbs use case-insensitive inline flag — so "WhatsApp has been
# acquired by Meta" captures "WhatsApp" / "Meta", not "WhatsApp has been".
_ACQUIRED_BY_RE = re.compile(
    r"\b([A-Z][\w\.\-&]*(?:\s+[A-Z][\w\.\-&]*){0,3})\s+"
    r"(?i:(?:was\s+|is\s+|has\s+been\s+)?acquired\s+by)\s+"
    r"([A-Z][\w\.\-&]*(?:\s+[A-Z][\w\.\-&]*){0,3}?)"
    r"(?=\s+(?i:for|in|at|on|with|after|via|amid|by)\s+|[.,;:!?]|\s+\$|\s*$)",
)
# Common short words that should never appear at the end of a company-name
# capture — strip them post-match so "Apple for" → "Apple", "Twitch was" → "Twitch".
_TRAILING_NOISE_RE = re.compile(
    r"\s+(?:was|is|for|in|at|on|with|after|via|amid|by|the|a|an|of|to|from|its|their)$",
    re.IGNORECASE,
)


def _strip_noise(name: str) -> str:
    prev = None
    while name != prev:
        prev = name
        name = _TRAILING_NOISE_RE.sub("", name).strip()
    return name
# Strict trigger: require a verb form, "acquisition OF X", "acquired BY X",
# or a merger pattern. Plain "acquisition" alone is incidental context
# (e.g. "layoffs after $200M acquisition") and shouldn't classify the
# article as an acquisition event.
_ACQUISITION_TRIGGER_RE = re.compile(
    r"\b(acquires?|to\s+acquire|has\s+acquired|acquired\s+by|"
    r"acquisition\s+of|completes?\s+(?:the\s+)?acquisition\s+of|"
    r"merger\s+(?:with|of)|merge\s+with|"
    r"in\s+\$[\d\.]+[mb]?\s+deal)\b",
    re.IGNORECASE,
)
_ACQ_AMOUNT_RE = re.compile(
    r"(?:for|in\s+a)\s+\$?\s*(\d{1,3}(?:[,\.]\d{3})*(?:\.\d+)?|\d+\.?\d*)\s*"
    r"(k|m|mn|million|bn|billion|b)\b",
    re.IGNORECASE,
)


def extract_acquisition(text: str, entities: dict | None = None) -> dict | None:
    if not text or not _ACQUISITION_TRIGGER_RE.search(text):
        return None
    acquirer = target = None
    # Passive "X acquired by Y" — must run before active so the active
    # capture doesn't shadow when "acquired" appears in both contexts.
    m = _ACQUIRED_BY_RE.search(text)
    if m:
        target = _strip_noise(m.group(1).strip())
        acquirer = _strip_noise(m.group(2).strip())
    else:
        m = _ACQUIRES_RE.search(text)
        if m:
            acquirer = _strip_noise(m.group(1).strip())
            target = _strip_noise(m.group(2).strip())
    # Drop empties after noise strip
    acquirer = acquirer or None
    target = target or None
    # Fallback / supplement: use the extracted entities to catch lowercase
    # brand names ("stripe acquires X") that the Title-Case regex misses.
    if entities and (not acquirer or not target):
        candidates: list[str] = []
        for kind in ("vendors", "ai_companies", "orgs"):
            for ent in entities.get(kind) or []:
                if ent.get("name") and ent["name"] not in candidates:
                    candidates.append(ent["name"])
        # Find the first two distinct candidates that appear in order in
        # the text — that ordering matches the "X acquires Y" pattern.
        tlc = text.lower()
        positions = [(tlc.find(n.lower()), n) for n in candidates]
        positions = [(p, n) for p, n in positions if p >= 0]
        positions.sort()
        if len(positions) >= 2:
            if not acquirer:
                acquirer = positions[0][1]
            if not target and positions[1][1] != acquirer:
                target = positions[1][1]
    amount = None
    m = _ACQ_AMOUNT_RE.search(text)
    if m:
        amount = _amount_to_usd(m.group(1), m.group(2))
    # Require at least one of (acquirer, target, amount) to call this an
    # acquisition. Otherwise the trigger word alone is too noisy.
    if not (acquirer or target or amount):
        return None
    return {
        "detected": True,
        "acquirer": acquirer,
        "target": target,
        "amount_usd": amount,
    }


# --- executive changes ----------------------------------------------------

_EXEC_ROLE_RE = re.compile(
    r"\b(CEO|CTO|CISO|CFO|COO|CRO|CMO|CDO|"
    r"chief\s+(?:executive|technology|information\s+security|financial|operating|revenue|marketing|data)\s+officer|"
    r"chair(?:man|woman|person)|"
    r"board\s+chair)\b",
    re.IGNORECASE,
)
# Political-news guard — skip when these names dominate the text
_POLITICAL_NOISE_RE = re.compile(
    r"\b(Trump|Biden|Obama|Harris|Pence|Putin|Xi\s+Jinping|congress|senate|"
    r"white\s+house|republican|democrat|election|MAGA|capitol|GOP)\b",
    re.IGNORECASE,
)
_EXEC_OUT_RE = re.compile(
    r"\b(step(?:s|ping|ped)?\s+down|resign(?:s|ed)?|depart(?:s|ed)?|exit(?:s|ed)?|out\s+as|to\s+leave|fired|ousted)\b",
    re.IGNORECASE,
)
_EXEC_IN_RE = re.compile(
    r"\b(appoint(?:s|ed)?|named\s+(?:as\s+)?(?:new\s+)?|hire[sd]?\s+as|hired\s+as|joins\s+as|new\s+(?:CEO|CTO|CISO|CFO|COO))\b",
    re.IGNORECASE,
)


def extract_exec_change(text: str) -> dict | None:
    if not text:
        return None
    if _POLITICAL_NOISE_RE.search(text):
        return None  # drop political news that mentions "president" etc.
    role_match = _EXEC_ROLE_RE.search(text)
    if not role_match:
        return None
    direction = None
    if _EXEC_OUT_RE.search(text):
        direction = "out"
    if _EXEC_IN_RE.search(text):
        direction = "in" if direction is None else "transition"
    if direction is None:
        return None
    role = role_match.group(1).upper()
    if "OFFICER" in role:
        role = role.title()
    return {
        "detected": True,
        "role": role,
        "direction": direction,
    }


# --- IPO / product / outage triggers --------------------------------------

_IPO_RE = re.compile(
    r"\b(IPO|files\s+to\s+go\s+public|direct\s+listing|S-1\s+filing|prices\s+(?:its\s+)?IPO|SPAC\s+merger)\b",
    re.IGNORECASE,
)
_PRODUCT_LAUNCH_RE = re.compile(
    r"\b(launches?|unveils?|debuts?|introduces?|announces\s+general\s+availability|GA\s+release|now\s+(?:available|GA)|releases?\s+(?:a\s+new|its\s+new))\b",
    re.IGNORECASE,
)
_EOL_RE = re.compile(
    r"\b(end[-\s]of[-\s]life|sunset(?:s|ting|ted)?|discontinues?|deprecat(?:es|ed|ing)|retire(?:s|d)\s+(?:its\s+)?product|EOL\b)\b",
    re.IGNORECASE,
)
_OUTAGE_RE = re.compile(
    r"\b(outage|downtime|service\s+disruption|major\s+incident|down\s+for|widespread\s+disruption|degraded\s+performance)\b",
    re.IGNORECASE,
)
_STEALTH_RE = re.compile(r"\b(stealth\s+(?:startup|mode)|emerging\s+from\s+stealth)\b", re.IGNORECASE)
_YC_RE = re.compile(r"\b(Y\s+Combinator|YC\s+[WSF]\d{2}|YC-backed)\b", re.IGNORECASE)


# --- bankruptcy ---------------------------------------------------------

_BANKRUPTCY_TRIGGER_RE = re.compile(
    r"\b(?:files?\s+(?:for\s+)?(?:chapter\s+(?:7|11|15)|bankruptcy|insolvency|administration)"
    r"|chapter\s+(?:7|11|15)\s+(?:filing|protection|bankruptcy)"
    r"|files?\s+for\s+chapter\s+(?:7|11|15)"
    r"|declared?\s+bankrupt(?:cy)?"
    r"|goes?\s+bankrupt"
    r"|enters?\s+(?:administration|receivership|liquidation)"
    r"|wound\s+(?:up|down)\s+(?:operations|business)"
    r"|ceases?\s+operations"
    r"|shutting\s+down\s+(?:after|amid|due\s+to)"
    r"|collapse[sd]?\s+(?:into\s+bankruptcy|amid)"
    r"|insolvent"
    r")\b",
    re.IGNORECASE,
)
_BANKRUPTCY_CHAPTER_RE = re.compile(r"\bchapter\s+(7|11|15)\b", re.IGNORECASE)
_BANKRUPTCY_DEBT_RE = re.compile(
    r"(?:debt|liabilities|owes?)\s+of\s+\$?(\d+(?:\.\d+)?)\s*(k|thousand|m|million|b|bn|billion)\b",
    re.IGNORECASE,
)


def extract_bankruptcy(text: str) -> dict | None:
    if not text or not _BANKRUPTCY_TRIGGER_RE.search(text):
        return None
    chapter = None
    m = _BANKRUPTCY_CHAPTER_RE.search(text)
    if m:
        chapter = int(m.group(1))
    debt_usd = None
    m = _BANKRUPTCY_DEBT_RE.search(text)
    if m:
        try:
            n = float(m.group(1).replace(",", ""))
            unit = (m.group(2) or "").lower()
            if unit in ("k", "thousand"): n *= 1_000
            elif unit in ("m", "million"): n *= 1_000_000
            elif unit in ("b", "bn", "billion"): n *= 1_000_000_000
            debt_usd = n
        except Exception:
            debt_usd = None
    return {
        "detected": True,
        "chapter": chapter,
        "debt_usd": debt_usd,
        "ceased_operations": bool(re.search(r"\b(ceases?\s+operations|wound\s+up|shutting\s+down)\b", text, re.IGNORECASE)),
    }


# --- crypto scams / DeFi exploits ---------------------------------------

_CRYPTO_TRIGGER_RE = re.compile(
    r"\b(?:rug[\s\-]?pull(?:ed|s)?"
    r"|wallet\s+drainer"
    r"|drainer\s+(?:campaign|attack|script)"
    r"|crypto\s+(?:heist|theft|exploit|scam|hack)"
    r"|defi\s+(?:exploit|hack|attack|drain)"
    r"|cross[\s\-]?chain\s+bridge\s+(?:hack|exploit)"
    r"|nft\s+(?:scam|rug)"
    r"|honey[\s\-]?pot\s+(?:token|contract)"
    r"|pig\s+butchering"
    r"|exit\s+scam"
    r"|stolen\s+(?:eth|btc|sol|usdt|usdc|crypto|tokens?)"
    r"|exchange\s+(?:collapse|insolvency|halts?\s+withdrawals)"
    r"|smart\s+contract\s+(?:exploit|drain|hack)"
    r"|flash\s+loan\s+(?:attack|exploit)"
    r"|reentrancy\s+(?:attack|exploit)"
    r"|pump\s+and\s+dump"
    r"|fake\s+(?:airdrop|token|ico)"
    # Generic W3IGG-style "<protocol/bridge/DAO/wallet/etc> hacked|exploited|drained for $X"
    # Catches "THORchain exploited for $10.8 million", "Verus bridge hacked for $11.6M"
    r"|(?:bridge|protocol|dex|dao|wallet|exchange|smart\s+contract|finance|vault|pool)\s+"
        r"(?:was\s+|got\s+|just\s+)?(?:hacked|exploited|drained|breached|compromised)\s+for\s+\$?\d"
    # Bare "<TokenName> exploited|hacked|drained for $X" — most W3IGG titles fit this.
    # Bound the leading \w+ to 1-40 chars to prevent catastrophic backtracking
    # on adversarial input like "a"*5000 followed by "exploited for $".
    r"|\w{1,40}\s+(?:hacked|exploited|drained|breached)\s+for\s+(?:about\s+|over\s+|nearly\s+|more\s+than\s+|around\s+|approximately\s+)?\$\d"
    r"|stole(?:n)?\s+(?:more\s+than\s+|over\s+|nearly\s+|approximately\s+|about\s+|around\s+)?\$\d.*?\b(?:bitcoin|ethereum|crypto|tokens?|coins?|wallet|defi)\b"
    r")",
    re.IGNORECASE,
)
_CRYPTO_AMOUNT_RE = re.compile(
    r"(?:stole|drained|lost|hacked\s+for|exploit(?:ed)?\s+for|breached\s+for|theft\s+of|worth)\s+"
    r"(?:about\s+|nearly\s+|over\s+|more\s+than\s+|around\s+|approximately\s+)?"
    r"\$?(\d+(?:\.\d+)?)\s*(k|thousand|m|million|b|bn|billion)\b",
    re.IGNORECASE,
)
_CRYPTO_ASSET_RE = re.compile(r"\b(BTC|ETH|SOL|USDT|USDC|BNB|XRP|ADA|DOGE|MATIC|AVAX|LINK)\b", re.IGNORECASE)
_CRYPTO_SCAM_KIND_RE = re.compile(
    r"\b(rug[\s\-]?pull|wallet\s+drainer|defi\s+exploit|bridge\s+hack|nft\s+scam"
    r"|honeypot|pig\s+butchering|exit\s+scam|exchange\s+collapse|flash\s+loan|smart\s+contract\s+exploit|pump\s+and\s+dump|fake\s+airdrop)\b",
    re.IGNORECASE,
)


def extract_crypto_scam(text: str) -> dict | None:
    if not text or not _CRYPTO_TRIGGER_RE.search(text):
        return None
    amount_usd = None
    m = _CRYPTO_AMOUNT_RE.search(text)
    if m:
        try:
            n = float(m.group(1).replace(",", ""))
            unit = (m.group(2) or "").lower()
            if unit in ("k", "thousand"): n *= 1_000
            elif unit in ("m", "million"): n *= 1_000_000
            elif unit in ("b", "bn", "billion"): n *= 1_000_000_000
            amount_usd = n
        except Exception:
            amount_usd = None
    kind = None
    m = _CRYPTO_SCAM_KIND_RE.search(text)
    if m:
        kind = re.sub(r"[\s\-]+", "-", m.group(1).lower())
    assets = sorted({m.group(0).upper() for m in _CRYPTO_ASSET_RE.finditer(text)})
    return {
        "detected": True,
        "kind": kind,
        "amount_usd": amount_usd,
        "assets": assets[:6],
    }


# --- aggregator -----------------------------------------------------------

def extract_industry(text: str, entities: dict | None = None) -> dict[str, Any]:
    """Return a dict of detected industry-event kinds → details.

    `entities` is the result of `extract_entities(text)`. When passed, the
    acquisition extractor uses it to resolve lowercase brand names that
    its capitalized-word regex misses ("stripe acquires X").
    """
    out: dict[str, Any] = {}
    if not text:
        return out
    # Cap input length to put a hard ceiling on regex worst-case work even
    # if a future pattern slips back into nested-quantifier territory.
    # News titles + summaries are well under 4 KiB in practice.
    if len(text) > 4000:
        text = text[:4000]
    if (e := extract_layoff(text)) is not None:           out["layoff"] = e
    if (e := extract_funding(text)) is not None:          out["funding"] = e
    if (e := extract_acquisition(text, entities)) is not None:
        out["acquisition"] = e
    if (e := extract_exec_change(text)) is not None:      out["exec_change"] = e
    if _IPO_RE.search(text):              out["ipo"] = {"detected": True}
    if _PRODUCT_LAUNCH_RE.search(text):   out["product_launch"] = {"detected": True}
    if _EOL_RE.search(text):              out["eol"] = {"detected": True}
    if _OUTAGE_RE.search(text):           out["outage"] = {"detected": True}
    if _STEALTH_RE.search(text):          out["stealth"] = {"detected": True}
    if _YC_RE.search(text):               out["yc"] = {"detected": True}
    if (e := extract_bankruptcy(text)) is not None:       out["bankruptcy"] = e
    if (e := extract_crypto_scam(text)) is not None:      out["crypto_scam"] = e
    return out


# Map industry event kinds to canonical tag strings (additive to existing
# tag rules in entities.py).
INDUSTRY_TAGS = {
    "layoff": "layoff",
    "funding": "funding",
    "acquisition": "acquisition",
    "exec_change": "exec-change",
    "ipo": "ipo",
    "product_launch": "product-launch",
    "eol": "eol",
    "outage": "outage",
    "stealth": "stealth",
    "yc": "yc",
    "bankruptcy": "bankruptcy",
    "crypto_scam": "crypto-scam",
}
