# SecurityHub Terminal — User Guide

A keyboard-driven, Bloomberg-style operator console for cybersecurity,
vulnerability, AI, threat, and tech-industry intelligence.

This guide walks an analyst through day-to-day use after the platform
is up and running. For setup, see [INSTALL.md](INSTALL.md). For things
that broke, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

**Access URLs** (defaults — change in `.env`):

- `https://<host>/` — desktop terminal (HTTP redirects to HTTPS)
- `https://<host>/m` — mobile lite view (auto-served to phones / tablets)
- `https://<host>/api/health` — readiness check

---

## Table of contents

1. [Layout & navigation](#layout--navigation)
2. [Keyboard shortcuts](#keyboard-shortcuts)
3. [The command palette](#the-command-palette)
4. [Panels](#panels)
   - [1 — News](#1--news)
   - [2 — Vulnerability intelligence](#2--vulnerability-intelligence)
   - [3 — KEV](#3--kev)
   - [4 — AI Watch](#4--ai-watch)
   - [5 — Actors](#5--actors)
   - [6 — Sectors](#6--sectors)
   - [7 — Threat narrative](#7--threat-narrative)
   - [8 — Orgs](#8--orgs)
   - [9 — Industry](#9--industry)
   - [0 — Pipe (integrations / IOCs / digest / mobile)](#0--pipe-integrations--iocs--digest--mobile)
5. [AI summaries](#ai-summaries)
6. [Alerting](#alerting)
7. [Executive briefing](#executive-briefing)
8. [Mobile lite view](#mobile-lite-view)
9. [Editing taxonomies](#editing-taxonomies)
10. [Operator drills](#operator-drills)

---

## Layout & navigation

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ●  SECURITY//HUB  TERMINAL   [1 NEWS] [2 VULN] [3 KEV] [4 AI WATCH] ...  │  ← header
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   <active panel — single full-pane view, or overview grid>               │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│ FEEDS 12/18 · NEWS 487 · CVES 2,651 · KEV 1,606 · ··· ●WS LIVE 3 pushes  │  ← status bar
└──────────────────────────────────────────────────────────────────────────┘
```

- **Overview** (the backtick `` ` ``): multi-pane dashboard.
- **Single panel** (`1`–`9`, `0`): full-pane focus.
- **Command palette** (`⌘K` / `Ctrl+K`): jump anywhere, search anything.

---

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| `⌘K` / `Ctrl+K` | Open command palette |
| `` ` ``         | Return to multi-pane overview |
| `1`             | News terminal |
| `2`             | Vulnerability intelligence |
| `3`             | KEV catalog |
| `4`             | AI company watch |
| `5`             | Threat actors |
| `6`             | Sector heatmap |
| `7`             | Threat narrative engine |
| `8`             | Organization monitoring |
| `9`             | Tech industry intelligence |
| `0`             | Integrations / IOCs / digest / mobile |
| `Esc`           | Close command palette / modal |
| `↑` `↓`         | Navigate palette results |
| `↵`             | Open selected item |

Input fields swallow digit keys, so number-key navigation only triggers
when the focus is outside an input.

---

## The command palette

`⌘K` opens a fuzzy entry point. It supports:

- **Free-text search** across news titles, summaries, CVE IDs, vendors,
  AI companies, threat actors, sectors, orgs.
- **Quick commands** (parsed prefixes):
  - `CVE <keyword>` → vulnerability panel filtered to that term
  - `AI <company>` → AI watch focused on that company
  - `RANSOMWARE` → news filtered to `tag:ransomware`
  - `EXPLOITS TODAY` → news filtered to `tag:active-exploitation`

Hit `↵` on a result to open it. CVE entries jump straight into the
Narrative panel.

---

## Panels

### 1 — News

Live cybersecurity feed across 18 RSS sources (Krebs, TheHackerNews,
BleepingComputer, Talos, Unit 42, Google TAG, MSRC, TechCrunch,
The Verge, Ars Technica, VentureBeat, Axios, HN search, …).

Per row you see:

- **Priority chip** (CRIT / HIGH / ELEV / GRD / LOW)
- Relative timestamp
- Source name
- Tag chips (zero-day, active-exploitation, ransomware, breach,
  nation-state, layoff, funding, exec-change, product-launch, outage …)
- CVE chips (click to jump to that CVE's narrative)
- Threat actor chips (LockBit, Cl0p, Volt Typhoon …)

The top filter bar lets you pin one tag (e.g. `active-exploitation`).

When the WebSocket bus pushes a new batch, a pulsing **`N new ↻`** chip
appears. Click to refresh.

### 2 — Vulnerability intelligence

Sortable CVE table with CVSS, EPSS (%), KEV flag, ransomware-use flag,
affected vendors (cross-referenced from your taxonomy), and a priority
score that combines all of them. Filter by free text in the header
input.

### 3 — KEV

CISA's Known Exploited Vulnerabilities, sorted by `kev_added` date.
This is the "patch now" feed. Each entry includes EPSS — after the
standalone EPSS sync, **100% of KEV entries have an EPSS score**.

### 4 — AI Watch

Watchlist of AI-industry entities (OpenAI, Anthropic, Mistral, Google
DeepMind, Meta AI, Cohere, xAI, Perplexity, Stability, Groq, Cerebras,
Hugging Face, …). Window selector (7 / 14 / 30 days).

Each row: mention count, max priority, signal tags (funding /
ai-incident / breach / phishing), latest headlines.

A "silent" footer shows tracked AI entities with zero mentions in the
window — useful for noting *absence* of expected activity.

### 5 — Actors

Threat actors with activity in the window: ransomware groups (LockBit,
Cl0p, ALPHV, Akira, BlackSuit, Play …), nation-state APTs (Volt
Typhoon, Salt Typhoon, APT28/29/40/41, Lazarus, MuddyWater …),
ecrime crews (Scattered Spider, LAPSUS$).

### 6 — Sectors

30-day targeting heatmap. 19 sectors — Healthcare / Finance / Energy /
Defense / Critical Infrastructure / Government / Education / Retail /
Manufacturing / Telecom / Transportation / Media / SaaS / Legal /
Hospitality / Real Estate / Gaming / Agriculture / Non-Profit — scaled
by mention volume with ransomware and breach counters.

Each row is clickable:

- **Click the sector name** → News panel filtered to articles tagged
  with that sector.
- **Click `BREACH N`** chip → News panel filtered to breach articles
  in that sector (jumps directly to the source articles).
- **Click `RANSOM N`** chip → Same, for ransomware-tagged articles.

The "show all" toggle reveals tracked sectors with zero mentions in the
window — useful for noting *absence* of expected activity.

### 7 — Threat narrative

Left rail: top CVE narratives (KEV-flagged or high-coverage).
Right pane: per-CVE briefing with toggle between **TIMELINE** and **GRAPH**.

The header shows priority, CVSS, EPSS, KEV/ransomware flags, and
affected vendors.

Below the header is the **AI Brief** block. If the LLM is configured,
this auto-generates a CISO-shaped 3-section brief (WHAT HAPPENED / WHY
IT MATTERS / WHAT TO WATCH) with inline `[1]` `[2]` citations matched
to a sources strip. Click `REGEN` to force a re-render.

**TIMELINE** view: chronological events (CVE published → CISA KEV
added → news mentions).
**GRAPH** view: radial SVG of CVE ↔ vendor ↔ org ↔ threat actor ↔
malware ↔ sector ↔ news.

### 8 — Orgs

Watched organizations (ships with **Acme Corp** and **Globex Bank**,
their brands, subsidiaries, domains, and tech stacks).

Left rail per org:

- Name, ticker
- Composite **HEALTH** state badge (STABLE / GROWING / DISTRESSED /
  UNDER ATTACK / HIGH RISK) with score 0–100
- KEV, mention, keyword counters

Right pane:

- Signal tag breakdown (breaches / phishing / ransomware / outages)
- **Industry events** (layoffs, funding, M&A, exec changes that
  matched this org)
- **Direct mentions / keyword hits**
- **Tech-stack vulnerability intersection** — CVEs affecting any
  vendor in the org's tech stack, with KEV / ransom flags

Add or edit orgs via [`backend/app/taxonomy/orgs.json`](#editing-taxonomies)
or `POST /api/orgs-admin`.

### 9 — Industry

Six tabs sharing one signal strip:

- **LAYOFFS** — headcount + percent + AI-driven flag + freeze flag
- **FUNDING** — amount, round (Seed / Series A-H), valuation
- **M&A / IPOs** — acquirer/target/value plus IPO/S-1/listings
- **EXECS** — role (CEO/CTO/CISO/CFO/COO/Chair) + direction
  (in/out/transition) with political-news guard
- **PRODUCTS** — launches / outages / EOL
- **STARTUPS** — stealth emergence / YC batches / seed rounds

Top of every tab: 30-day totals + top companies.

### 0 — Pipe (integrations / IOCs / digest / mobile)

Left rail:

- **Sinks**: Slack / Teams / Email / CEF syslog with configured-status
  dot, delivered/error counters, last error, and a `TEST` button to
  fire a synthetic event.
- **Routing rules** from `routing.json`, with enabled-state chips.

Right pane:

- **3,400+ live IOCs** from abuse.ch ThreatFox, filterable by type
  (domain / IP / hash / URL) and grouped by malware family
  (Cobalt Strike, Remcos, AsyncRAT, RansomHub, …).

Header actions:

- `DIGEST 24h` / `7D` — open the executive briefing HTML
- `MOBILE` — open the lite phone-friendly view

---

## AI summaries

The Narrative panel's AI Brief block calls the configured LLM via the
**OpenAI-compatible chat-completions** protocol. The same code path
works against:

| Provider | Set `SECHUB_LLM_BASE_URL` to |
|----------|------------------------------|
| OpenAI | `https://api.openai.com/v1` |
| Anthropic (Claude) | `https://api.anthropic.com/v1` |
| Ollama (local) | `http://localhost:11434/v1` |
| vLLM | `http://your-host:8000/v1` (whatever your vLLM binds to) |
| LM Studio | `http://localhost:1234/v1` |
| Together | `https://api.together.xyz/v1` |
| Groq | `https://api.groq.com/openai/v1` |

Plus `SECHUB_LLM_API_KEY` (empty for Ollama) and `SECHUB_LLM_MODEL`
(e.g. `gpt-4o-mini`, `claude-sonnet-4-6`, `llama3.1`).

Summaries are cached by content hash. Re-rendering the same narrative
doesn't re-spend tokens. Append `?force=true` to the API route to
bypass the cache.

If the LLM is unconfigured, the panel shows a `needs_llm` hint with
example provider lines.

---

## Alerting

Edit `backend/app/taxonomy/routing.json` to control which events go to
which sinks. Hot-reloaded — no restart needed.

Sample rule:

```json
{
  "id": "high-prio-news → slack",
  "enabled": true,
  "match": { "event_type": "news.item", "min_priority": 70 },
  "sink": "slack"
}
```

Supported matchers:

- `event_type` — `news.batch`, `news.item`, `kev.batch`, `org.alert`, `*`
- `min_priority` — for `news.item`
- `min_count` — for batch events
- `org` — match a single org id
- `tag` — match an item tag (e.g. `ransomware`)

Set the corresponding env vars (`SLACK_WEBHOOK_URL`, `TEAMS_WEBHOOK_URL`,
`SECHUB_SMTP_URL`, `SECHUB_SYSLOG_URL`) and the routing engine fans
matching events out automatically.

---

## Executive briefing

`GET /api/digest/daily?hours=24[&org=...]` renders a self-contained
HTML page with:

- 30-day industry signal grid
- Top narratives
- Newly exploited CVEs (CISA KEV)
- High-priority news
- Per-org breakdown (or filtered to one org with `?org=globex-bank`)

Wire this to email by configuring the email sink and adding a routing
rule that fires daily — or generate the HTML and pipe it via your own
cron.

---

## Mobile lite view

`GET /m` returns a self-contained dark-themed HTML page that fits a
phone screen. **Phones and tablets visiting `/` auto-redirect to `/m`**
— both via a server middleware (302) and a pre-React client check.
Detection rules:

- iPhone / iPod / iPad → mobile
- iPadOS-as-Mac (Safari reports "Macintosh" since iOS 13) → mobile
  (detected client-side via `navigator.maxTouchPoints > 1`)
- Android (phones AND tablets) → mobile
- Everything else → desktop SPA

**Tabs** (six, all read-only):

- **CRITICAL** — news at priority ≥ 70
- **KEV** — recent CISA KEV additions
- **SECTORS** — 30-day targeting heatmap with breach/ransom chips
- **ORGS** — per-org KEV / mention / priority chips
- **INDUSTRY** — 30-day signal cells (layoffs / funding / acquisitions /
  execs / IPOs / outages / bankruptcy / crypto-scams)
- **SEARCH** — full-text across news, CVEs, entities

**Opt out**: tap "Open desktop view →" at the bottom of any `/m` page
to set a 30-day `sechub_view=desktop` cookie. Or append `?desktop=1`
to any URL for a one-shot bypass. Cookie clears on browser reset.

**Touch hygiene**: 48 px minimum touch targets (WCAG 2.5.5), no `:hover`
dependencies, iOS safe-area padding, pinch-zoom allowed (WCAG 1.4.4).

Refreshes the active tab every 30 seconds. No JS framework — just
`fetch` + DOM. No service worker, no caching beyond what your browser
does on its own.

---

## Editing taxonomies

Files in `backend/app/taxonomy/`:

| File | What's inside |
|------|---------------|
| `vendors.json` | Enterprise tech & security vendors |
| `ai_companies.json` | Model providers, GPU vendors, AI infra |
| `threat_actors.json` | Nation-state, ransomware, malware families |
| `sectors.json` | Industry verticals |
| `sources.json` | RSS feeds + per-source reliability scores |
| `orgs.json` | Monitored orgs (brands / subs / domains / stack) |
| `routing.json` | Alert routing rules + sink definitions |

Hot-reloaded by mtime check. You can also use the org admin API
(`POST /api/orgs-admin`) to add / update / delete orgs without
editing JSON directly.

---

## Operator drills

All `/api/admin/*` endpoints are rate-limited to 10 calls per 60 s per
client IP. URL examples below use the **frontend HTTPS port** (443 by
default) — `/api/*` proxies through to the backend internally on the
docker network.

Force ingestion now:

```bash
H=https://localhost/api/admin/refresh
curl -ksX POST $H/news        # full RSS sweep (~110 feeds)
curl -ksX POST $H/kev         # CISA KEV catalog
curl -ksX POST $H/nvd         # NVD CVE corpus
curl -ksX POST $H/epss        # FIRST.org EPSS scores
curl -ksX POST $H/mitre       # MITRE ATT&CK STIX bundle
curl -ksX POST $H/redhat-cve  # Red Hat Security Data API
curl -ksX POST $H/cve-org     # CVE.org ADP enrichments
curl -ksX POST $H/ransomwatch # ransomware.live victims
curl -ksX POST $H/all         # kev + news + nvd in parallel
```

Trigger a single custom-vendor feed:

```bash
curl -ksX POST $H/cisco-psirt
curl -ksX POST $H/apple
curl -ksX POST $H/atlassian
curl -ksX POST $H/cccs
curl -ksX POST $H/sophos
curl -ksX POST $H/msrc
```

Fire a synthetic org alert (verifies the routing pipeline end-to-end):

```bash
curl -ksX POST 'https://localhost/api/admin/test-alert?org=globex-bank'
```

Fire a synthetic event at a single sink:

```bash
curl -ksX POST https://localhost/api/integrations/fire-test/slack
```

Check sink health and per-sink delivery counters:

```bash
curl -ks https://localhost/api/integrations/health | jq
```

Verify LLM config:

```bash
curl -ks https://localhost/api/ai/config | jq
```

Check per-feed health (which RSS feeds are erroring, when each last succeeded):

```bash
curl -ks https://localhost/api/status | jq '.feeds[] | select(.last_error) | {id: .source_id, err: .last_error}'
```

Run the backend test suite inside the container:

```bash
docker compose exec backend pytest -q
```
