# Code Review — SecurityHub Terminal

Reviewer pass over the full codebase. Findings are grouped by severity. Items
prefixed `FIXED` were patched during the review; `OPEN` are tracked items
documented for future hardening.

---

## Severity: high

(none open)

---

## Severity: medium

### M-1 FIXED — Auth middleware raised `HTTPException` instead of returning a response

`app/auth.py` originally raised `HTTPException(401, ...)` from inside a
Starlette middleware. Starlette doesn't run FastAPI's exception handlers on
middleware-raised exceptions, so the request would surface as a 500 in some
deployments. Now returns a `JSONResponse(status_code=401, ...)`. Verified by
`tests/test_routes.py::test_auth_enforced_when_env_set`.

### M-2 OPEN — News-title injection into LLM context

`app/enrich/ai.py` builds an LLM prompt by concatenating
attacker-controlled news titles and summaries. A malicious RSS source could
embed instructions like *"Ignore previous instructions and..."*. Mitigations
currently in place:

- The system prompt forbids invention of facts.
- Sources are presented as a numbered list and the model is told to cite by
  number; injected instructions don't have a citation slot, so cited claims
  are traceable.

Future hardening:

- Wrap each source body in fenced delimiters (e.g. `<<<SOURCE [n]>>> … <<<END>>>`).
- Strip role-control keywords from titles before passing to the LLM.
- Add an output-side validator that rejects responses whose claims have no
  citation index.

### M-3 OPEN — SQLite `LIKE '%entity%'` queries are O(rows) scans

Entity look-ups for org / vendor / actor join via `LIKE '%"id": "<id>"%'`.
Fine at the current scale (~2.6 k CVEs, ~400 news), but linear scan will
hurt past ~50 k rows. Future fix: extract a normalized
`(news_id, entity_kind, entity_id)` index table at ingest time.

### M-4 OPEN — Postgres adapter is documented, not implemented

`app/db_pg.py` describes the migration path but does not actually serve as
a runtime adapter. SQLite handles the current single-node workload
comfortably; cut over when a deployment needs concurrent writes.

---

## Severity: low

### L-1 FIXED — Layoff trigger regex missed "lays off" / "laying off"

`extract_industry` failed to extract a layoff event from titles like
*"Microsoft lays off 6,000 employees"* unless another trigger keyword was
present in the summary. Trigger pattern broadened to include
`lay(?:s|ing)\s+off` and `workforce\s+cuts?`.

### L-2 FIXED — Lookalike detector ignored `.co.uk`-style ccTLDs

`_root()` in `app/enrich/spoofing.py` reduced `acme-corp.co.uk` to `co.uk`
and lost the registrable label. Added a curated list of common second-level
TLDs (`co.uk`, `co.jp`, `com.au`, etc.) so multi-label ccTLDs reduce
correctly.

### L-3 FIXED — Org routes path collision

`/api/orgs/_health` was matched by `/api/orgs/{org_id}/...` and returned
`"Unknown org _health"`. Moved the aggregate endpoint to `/api/orgs/health`
(declared before the parameterized routes).

### L-4 OPEN — Several SQL queries build LIKE patterns from user input

All such queries use parameter binding (`?`) for the value, so this is
not SQL injection. The LIKE *pattern* still allows `%` and `_` wildcards
from query strings. The risk is over-broad matches, not data exposure.
If exposed to untrusted query input, sanitize wildcards before binding.

### L-5 OPEN — In-memory routing health counters reset on process restart

`integrations/router.py::_health` is a process-local `defaultdict`.
Acceptable for a single-process deployment; a multi-worker uvicorn would
show per-worker counters. If needed, persist to the `kv` table.

### L-6 OPEN — `extract_acquisition` parses on capitalized words

`_ACQUIRES_RE` extracts acquirer/target by capitalized-word heuristics.
Misses lowercase brands (`stripe acquires …`) and over-matches Title-Case
headlines that don't actually describe acquisitions. Tagging is reliable;
parties extraction is best-effort.

### L-7 OPEN — Frontend bundle holds whole panel set

Code-splitting per-panel (`React.lazy`) would shrink first paint from
~75 KB gzipped to ~25 KB and lazy-load the rest. Not a problem at current
size; revisit if more panels land.

### L-8 OPEN — Mobile route uses inline JavaScript

`/m` ships a self-contained HTML page with inline JS. Acceptable for an
analyst tool; if exposed publicly, add a strict `Content-Security-Policy`
header and move the script to a CSP-allowlisted asset.

---

## Architecture observations (informational)

- **Modular ingestion** (`app/ingest/*.py`): each source is one file with a
  `fetch_*` coroutine and a `record_feed_health` call. Adding a new feed is
  ~50 LOC. Good.
- **Hot-reload taxonomy**: every taxonomy load mtime-checks the JSON file
  so analysts can edit `orgs.json` / `vendors.json` etc. without a
  restart. Tested.
- **Single broadcaster**: WS bus is the spine — ingestion → broadcaster →
  routing engine → external sinks. Clean.
- **Provider-neutral LLM**: same `/v1/chat/completions` shape works against
  OpenAI, Claude (Anthropic compat), Ollama, vLLM, LM Studio, Together,
  Groq. Three env vars switch providers.
- **Graceful degradation everywhere**: every external integration
  (Shodan / VT / HIBP / LLM / Slack / Teams / Email / Syslog) returns a
  shaped "not configured" response when its key/URL is missing, never a
  500.

---

## Validation summary

- `backend/tests/`: **39 unit + route tests pass** under pytest.
- Frontend: **TypeScript clean**, production build succeeds (~258 KB /
  75 KB gzipped).
- Live data: 2,651 CVEs (1,606 KEV with **100% EPSS** coverage), 400+
  news items across 18 feeds, 3,400+ IOCs from abuse.ch ThreatFox.
- WebSocket: hello / heartbeat / pong / news.batch / org.alert all
  verified through Vite proxy and direct.
- Sinks: Slack webhook + CEF syslog verified end-to-end against local
  mock listeners.
- LLM client: verified against a mock OpenAI-shaped server with a
  `claude-sonnet-4-6` model name; auth header + request shape + response
  parsing + cache hit all correct.

---

## Recommended next hardening pass

1. M-2: prompt-injection mitigation for the LLM enrichment layer.
2. M-3: entity index table to keep query latency flat as the corpus grows.
3. L-7: per-panel code-splitting for the frontend bundle.
4. L-5: persist routing health to the `kv` table.

---

# Code Review — Round 2

Reviewer pass after the second wave of features (MITRE ingest, ransomware.live,
news clustering, predicted-KEV, workspace tables, OpenMetrics, DB backup,
staleness alerts, keyboard nav).

## Severity: high

(none open)

## Severity: medium

### M-5 FIXED — Overview hid actors with ransom-only signal

`ActorPanel.tsx` filtered `active = actors.filter(a => a.mentions > 0)`.
After the actor-watch endpoint started fusing news + ransomware.live + IOC
signals, groups like DragonForce (24 victims, 0 news mentions) and Qilin
(17 victims) were dropped from the active list and not shown anywhere.
Switched the filter to `mentions > 0 || ransom_postings > 0 || ioc_count > 0`.

### M-6 FIXED — Overview grid gave Sector panel only 1 of 6 rows

The right column was `KEV(3) + AIWatch(2) + Sector(1)`. Sector at 1/6 of
panel height couldn't fit even its own header. Rebalanced to `2+2+2`.

### M-7 OPEN — News dedup is token-based; can't catch reworded headlines

`enrich/cluster.py` keys on sorted significant tokens. "Anthropic raises
$65B" and "Anthropic overtakes OpenAI as most valuable AI startup" share
`anthropic` but their token sets diverge enough that they cluster apart.
Acceptable for now — false-merge is worse than false-split — but a
MinHash/LSH approach would help if the corpus grows.

### M-8 OPEN — Predicted-KEV joins news on `LIKE '%' || c.cve_id || '%'`

Same pattern as the existing narrative join. Linear scan of news per CVE.
At 2,759 CVEs × 639 news it's single-digit ms; plan is O(N×M). When
news passes ~50k rows, denormalize `(news_id, cve_id)` into a side table.

## Severity: low

### L-9 FIXED — Auth middleware blocked /metrics

`/metrics` is meant for Prometheus scrapers (no Authorization header).
Added it to `PUBLIC_PATHS`.

### L-10 OPEN — Staleness `_warned` set lives in process memory

`ingest/staleness.py::_warned` is module-level. Process restart loses the
"already warned" state, so a still-stale feed fires a fresh `feed.stale`
right after restart. Single-process: fine. Multi-worker: persist to `kv`.

### L-11 OPEN — Workspace endpoints have no rate limiting

`POST /api/workspace/stars` / `annotations` / `saved` are unbounded.
Behind the optional auth token this isn't exposed; if you ever drop the
token, add a per-IP rate limit.

### L-12 OPEN — DB backup doesn't fsync the destination

`sqlite3.backup()` writes a fresh file but doesn't force a flush before
return. Loss of the most recent backup on hard power-loss is the worst
case. Acceptable for daily snapshots.

### L-13 OPEN — MITRE matching is O(taxonomy × text len) per article

After MITRE expansion (~900 entries) entity extraction runs every alias
check on every news title+summary. Still ~10 ms per article at ingest.
Aho-Corasick trie would make it constant per article if/when needed.

### L-14 OPEN — `cluster_key` collisions on very short titles

Titles with <2 significant tokens fall through to `h:<sha1>`. Different
sources writing the same short headline still cluster correctly. Verified
that "Patch Tuesday April 2026" and "Patch Tuesday March 2026" cluster
apart correctly in current data.

### L-15 OPEN — `/metrics` exposes counts without auth

Intentional (Prometheus scrape pattern). For internet-exposed deployments
restrict by source IP at the nginx layer.

---

## Validation summary — Round 2

- **39 pytest** still passing, no regression.
- **TypeScript clean**, production build ~268 KB / 77 KB gzipped.
- New endpoints verified end-to-end:
  - `/api/intel/kev-watch` → 9 predicted KEV candidates, confidence-scored
  - `/api/news?cluster=true` → Tenable + Cisco Talos merging confirmed live
  - `/api/workspace/stars` POST/GET roundtrip works
  - `/metrics` → OpenMetrics format with per-feed `last_success_age_seconds`
- Live state after Round-2 ingest:
  - 174 MITRE intrusion-sets + 726 malware families
  - 102 ransomware victim postings (DragonForce 24, Qilin 17, Akira 9)
  - 20 actively-signaled actors (was 3 pre-MITRE)
  - 196 total tracked actors (was ~20)
  - 100% KEV EPSS coverage retained

## Deferred — Round 3 closeout

All previously-deferred items shipped:

| ID | Status | What landed |
|----|--------|------------|
| **L-4**  | ✅ | SQL LIKE wildcards (`%`, `_`) escaped from user `q` params; `ESCAPE '\\'` appended on news/vulns/search/integrations |
| **L-6**  | ✅ | Acquisition extractor now consumes entity extraction; resolves lowercase brand names ("stripe acquires X") the Title-Case regex missed |
| **L-7**  | ✅ | React.lazy code-splitting (already shipped) |
| **L-8**  | ✅ | Mobile `/m` ships `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy` |
| **L-13** | ✅ | Per-kind precompiled regex-union matcher cached by taxonomy mtime; single `re.finditer` pass for ~900 aliases |
| **M-7**  | ✅ | 64-bit SimHash on every news row; cluster pass merges by Hamming ≤ 3 on top of `cluster_key` |

**Validation — Round 3**

- **47 pytest** (39 prior + 8 new in `tests/test_dedup.py`)
- TypeScript clean, bundle 232 KB main / 71 KB gz + lazy chunks
- Live data verified:
  - `?q=%%%%%%%` → 0 items (escape clause active)
  - `/m` ships full CSP + nosniff + no-referrer
  - SimHash merge collapsed Cisco Talos + Tenable on Cisco SD-WAN exploitation
  - Bag-of-tokens distances: identical = 0, related rephrase ≤ 6, unrelated ≥ 21

## What's actually open

Nothing flagged in the review. CSP allows inline script/style for the
mobile bundle because it's single-file HTML; if internet-exposed, swap
to a nonced/hashed script and tighten.
