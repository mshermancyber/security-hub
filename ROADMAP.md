# SecurityHub Terminal — Roadmap

Status as of v1.0.0.

Legend: ✅ shipped · 🟡 partial · 🟠 not yet shipped

---

## Core platform

| # | Milestone | Status | Notes |
|---|-----------|:------:|-------|
| 1 | News terminal (multi-feed RSS aggregation) | ✅ | ~110 feeds, dedupe (3-pass cluster_key + SimHash + entity+magnitude), tagging, severity scoring, search/filter |
| 2 | Vulnerability intelligence engine — CVE + KEV | ✅ | Steady-state ~2,600 CVEs, 1,607 KEV-flagged |
| 3 | EPSS enrichment | ✅ | Standalone sync covers every CVE in DB. KEV EPSS coverage 100%. Daily refresh + admin trigger |
| 4 | AI company watch | ✅ | Editable taxonomy + activity scoring |
| 5 | Threat actor intelligence | ✅ | Nation-state, ransomware, malware families, news correlation |
| 6 | Sector heatmap | ✅ | 19 sectors, 30-day targeting signal, clickable BREACH/RANSOM chips → filtered news |
| 7 | Threat narrative engine | ✅ | CVE → KEV → news event timeline + radial entity graph |
| 8 | Editable JSON taxonomy (hot-reload) | ✅ | vendors, ai_companies, threat_actors, sectors, sources, orgs |
| 9 | Ingestion pipeline (async, scheduled, dedup, score) | ✅ | KEV hourly · NVD 30m · news 15m · MITRE / Red Hat / custom 3h · backfill on taxonomy change |
| 10 | Terminal UX (dark, dense, keyboard, command palette) | ✅ | Bloomberg-amber + JetBrains Mono, ⌘K, 1–9 + 0 + `-` panel hotkeys |
| 11 | Organization monitoring | ✅ | Per-org brands / subs / domains / tech stack with CVE intersection |
| 12 | WebSocket push | ✅ | Live event bus (news.batch / news.item / kev.batch / org.alert), reconnect + heartbeat, **token-gated** |
| 13 | Tech industry intelligence (layoffs / funding / execs / products / startups / IPOs / bankruptcy / crypto-scams) | ✅ | 8 industry kinds + extractors + `/api/industry/*` |

## Intelligence depth

| # | Milestone | Status | Notes |
|---|-----------|:------:|-------|
| 14 | EPSS standalone daily sync | ✅ | 100% KEV coverage |
| 15 | AI enrichment layer (LLM summaries + executive briefing) | ✅ | OpenAI-compat client (OpenAI / Anthropic / Ollama / vLLM / LM Studio / Together / Groq). Summaries cited + cached by content hash |
| 16 | Company health scoring | ✅ | Composite STATE per org (Stable / Growing / Distressed / Under Attack / High Risk) |
| 17 | Threat narrative — graph view | ✅ | Radial entity graph (CVE↔vendor↔actor↔malware↔org↔sector↔news), SVG, kind-coded |
| 18 | Exploit velocity charts | ✅ | KEV adds/day, ransomware-use rate, news volume, EPSS percentile distribution, industry-event velocity, status-bar sparklines |
| 19 | Conflict detection | ✅ | Detects layoff headcount disagreement, funding amount mismatches, and exploitation-claim divergence across independent tier-1 sources |
| 20 | Red Hat Security Data ingest | ✅ | Hydra JSON API — severity, CVSS3, CWE, affected packages. Per CVE id, 30-day window, 500 entries/run cap |

## Tech industry intelligence

| # | Milestone | Status | Notes |
|---|-----------|:------:|-------|
| 21 | Layoff tracker | ✅ | Headcount + percent + AI-driven flag + hiring-freeze. Per-company top-10 |
| 22 | Funding / IPOs / M&A | ✅ | Round, amount (USD), valuation, acquirer/target, total raised |
| 23 | Executive departure tracker | ✅ | CEO/CTO/CISO/CFO/COO/CRO/CMO/Chair detection with in/out/transition direction. Political-news guard |
| 24 | Cybersec product intelligence | ✅ | Launches / GA / EOL / outages parsed from news |
| 25 | Startup discovery engine | ✅ | Stealth emergence, YC batches, seed-round funding |
| 26 | Bankruptcy + crypto-scam tracking | ✅ | Kind-aware dedup so multiple stories per event collapse |

## Org-monitoring extensions

| # | Milestone | Status | Notes |
|---|-----------|:------:|-------|
| 27 | Per-org configurable watch (CRUD API) | ✅ | `/api/orgs-admin/*` POST/PUT/DELETE with atomic write + lock |
| 28 | Domain spoofing / lookalike detection | ✅ | `enrich/spoofing.py` + `/api/exposure/spoofing/{org_id}` (Levenshtein + char-substitution) |
| 29 | HIBP credential-leak monitoring | ✅ | `/api/exposure/account/{email}` + `/api/exposure/breaches/{domain}` |
| 30 | databreaches.net feed | ✅ | RSS ingest, tagged `breach`, sector-routed |
| 31 | Per-org admin UI (web form) | 🟠 | API exists; web form is BACKLOG #1 |
| 32 | Dark-web / paste-site exposure feed | 🟡 | ThreatFox IOCs + ransomware.live live; paste-site coverage still partial |

## Distribution & integrations

| # | Milestone | Status | Notes |
|---|-----------|:------:|-------|
| 33 | Alert routing (Slack / Teams / email) | ✅ | Routing engine taps WS bus; rules in `routing.json`. SSRF host-allowlist on Slack/Teams |
| 34 | Shodan integration | ✅ | `/api/integrations/shodan/{domain|host}` gated by `SHODAN_API_KEY` |
| 35 | VirusTotal integration | ✅ | v3 IOC lookup (IP / domain / URL / hash) |
| 36 | Threat-intel IOC ingestion | ✅ | abuse.ch ThreatFox JSON feed, 30-min cadence, indexed by value / type / malware |
| 37 | SIEM forwarding (CEF / syslog) | ✅ | ArcSight-style CEF over UDP/TCP syslog |
| 38 | Executive briefing | ✅ | `/api/digest/daily?hours=24` self-contained HTML + Markdown variant |
| 39 | Mobile / lite view | ✅ | `/m` self-contained mobile HTML, 6 tabs (Critical / KEV / Sectors / Orgs / Industry / Search). Auto-served to phones+tablets via server middleware + client pre-mount check. iOS safe-area + 48 px targets |

## Quality / hardening

| # | Milestone | Status | Notes |
|---|-----------|:------:|-------|
| 40 | Source reliability scoring | ✅ | Per-feed reliability + priority_bump in sources.json |
| 41 | Test coverage (pytest) | 🟡 | 47 backend tests; frontend Playwright e2e still 🟠 |
| 42 | Container hardening | ✅ | `cap_drop: ALL`, `read_only: true`, `no-new-privileges:true`, non-root uid 10001 on backend |
| 43 | Outbound HTTP safety (SSRF + body cap + redirect guard + DTD pre-screen) | ✅ | `app/safe_http.py:safe_get()` / `safe_post()` used by every ingest + integration call |
| 44 | Token-gated WebSocket | ✅ | `/api/ws` enforces same Bearer / query / Sec-WebSocket-Protocol token rules as `/api/*` |
| 45 | Rate-limited admin endpoints | ✅ | `/api/admin/*` 10/min, `/api/orgs-admin/*` 30/min, `/api/workspace/*` 60/min |
| 46 | Docker / Compose deployment | ✅ | Two-container compose, bind-mount data + certs, auto-TLS on first boot |
| 47 | Multi-user auth + saved workspaces | 🟠 | Single-operator tool today. Token-or-insecure modes only |
| 48 | Postgres migration path | 🟠 | Schema is vanilla SQL; `db_pg.py` stub exists; flip when scale demands |

---

## Suggested next sprint

Core + intel + integrations are done. What's left is mostly UX polish
and the multi-user story:

1. **#31 Per-org admin web UI** — small React form on top of the
   existing `/api/orgs-admin/*` REST surface. Removes the JSON-editing
   friction.
2. **#47 Multi-user auth + login UI** — lets us drop `SECHUB_INSECURE=1`
   on LAN deployments. Lightweight session model + token vault.
3. **#41 Frontend e2e tests** — Playwright run via `docker compose run`
   on a built image. Catches regressions in the dense panel layout.
4. **Detection rules library (Sigma / YARA)** — see BACKLOG. Differentiator
   vs every other threat-intel aggregator.
