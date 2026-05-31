# Backlog

Recommendations the team chose to defer. Sorted by likely impact /
operational value, not effort.

Status: 🟠 not started · 🟡 partial · ✅ shipped

---

## Security follow-ups (deferred from the audit-fix batch)

### 🟠 Lightweight login UI — so we can drop `SECHUB_INSECURE=1` on the LAN
- Current LAN-accessible setup requires `SECHUB_INSECURE=1` because there's
  no in-app way to enter a bearer token. A small login page (single input,
  stores token in `sessionStorage`, attaches `Authorization` header to
  fetch + WS) would let the operator set `SECHUB_AUTH_TOKEN=$(openssl rand)`
  and bind `0.0.0.0` with real auth.
- ~150 LOC across `auth.py`, `api/client.ts`, `api/ws.ts`, plus a tiny
  `Login.tsx`.
- After shipping: also tighten `auth.py` query-string token path to a
  one-time exchange (issue session cookie, drop `?token=` from the URL bar).

### 🟠 httpx URL redaction in backend logs
- Audit finding L7: backend log captures every outbound httpx URL incl.
  query strings. Currently no secrets land there because keys travel as
  headers, but any future integration that puts a key in the query string
  would leak. Add an httpx event hook that scrubs known sensitive params
  before logging.
- ~30 LOC in `config.py` + global httpx client factory.

### 🟠 Dependency lockfile + upper-bound pinning
- Audit finding L8: `backend/requirements.txt` pins only floors; no
  `requirements.lock` or `uv.lock`. Reproducible builds + dependabot-style
  alerts both need a real lockfile.
- Switch to `uv` or `pip-tools` and commit `requirements.lock`.

### 🟠 Per-route admin auth tier
- Audit finding H6: `/api/admin/*` shares the same bearer-token gate as
  read endpoints. A second token (or IP allowlist) would mean even a
  leaked analyst token can't trigger arbitrary feed refreshes.
- Small: extend `auth.py` with an `ADMIN_PATHS` set and a separate
  `SECHUB_ADMIN_TOKEN` env var.

### 🟠 Google News opaque URL resolution
- `gnews-*` feeds wrap real article URLs in `news.google.com/rss/articles/CBMi…`
  opaque redirectors, so our `link_as_source` flag shows "news.google.com"
  instead of the real publication. Either:
  (a) HEAD the redirect once at ingest and store the final URL, or
  (b) extract the encoded URL via base64-decode of the path segment
      (Google News uses a stable encoding).
- ~60 LOC + a HEAD cache to avoid hammering Google News.

---

## High-leverage (next sprint candidates)

### 🟠 Detection rules library — Sigma / YARA / Elastic / Splunk
- Ingest SigmaHQ (~3500 rules), Elastic Detection Rules repo,
  splunk-security-content, YARAHQ — cross-link to actors/CVEs/tags
- "Volt Typhoon" page shows the 12 Sigma rules that hit it; CVE page
  shows the YARA/Snort signature if one exists
- Differentiator vs every other threat-intel feed
- ~250 LOC + a Rules panel

### 🟠 GitHub Advisory DB + OSV.dev for OSS vulns
- Fills the NVD coverage gap on npm/PyPI/Go/Gem/Cargo dependencies
- Free JSON dumps, daily refresh; OSV.dev aggregates GH + PyPI
  Security + RustSec + Go vulns into one schema
- New ingest module + an "OSS Vulns" filter on the Vuln panel
- ~150 LOC

### 🟠 Save-search-to-alert
- Turn any News/Vuln filter combination into a watchlist that fires
  `query.match` events on new matching rows
- Power-user multiplier — everyone who's used stars wants this
- Backend: extend `workspace.saved`; new event type on WS bus
- ~120 LOC

### 🟠 CVE → Patches auto-link
- When KEV/NVD entry lands, automatically join against `patches` rows
  in DB; fire `patch.match` event when our patches table has the fix
- Tightens "is this in our stack and have we patched" loop
- ~80 LOC — both sides already exist, just need the join


### 🟠 IOC matching against your own footprint
- Config `monitored_assets.json`: list of CIDRs, ASNs, domains
- ThreatFox IOC ingest cross-references; emits `asset.match` event (highest priority)
- Today we know what's bad globally — this would surface what's bad **for you**
- ~150 LOC

### 🟠 Public PoC monitoring
- Watch Exploit-DB RSS + known GitHub PoC repos (`nomi-sec/PoC-in-GitHub`,
  `trickest/cve`, etc.) for CVE references
- When a PoC drops, +30 priority bump on the matching CVE
- Catches the "going viral on Twitter" window before KEV picks it up
- ~80 LOC

### 🟠 Scheduled morning email brief
- We already have SMTP sink + Markdown digest at `/api/digest/daily.md`
- Wire a cron-style scheduler entry (7am local) that POSTs the markdown to
  configured subscribers
- Add `digest_subscribers` array to `routing.json`
- ~80 LOC

### 🟠 CVSS v4 support
- We use v3 only. v4 adds "vulnerable system criticality" — directly addresses
  the prioritization gap that magnitude_bump partially covers
- New columns on `cves`, parse v4 vectors from NVD when present
- ~120 LOC

### 🟠 CWE clustering as a query dimension
- We store CWE IDs but don't surface them. "Show me all auth-bypass CVEs in
  last 30d" is a real analyst query
- Add `/api/vulns?cwe=CWE-287&days=30` filter; small CWE dimension in VulnPanel
- ~60 LOC

---

## Medium

### 🟠 Auto-narrative generation
- Instead of per-CVE narratives, LLM clusters news + IOCs + actor activity
  over 7d into 3–5 named story arcs (e.g. "Volt Typhoon's May campaign
  targets US energy")
- New endpoint `/api/intel/storylines?days=7`
- ~200 LOC + prompting

### 🟠 Trend / spike alerts
- When a tag count (ransomware in healthcare, phishing targeting AWS) is
  >3× its 7d rolling average, fire `trend.spike` event
- Daily window comparison from velocity data we already aggregate
- ~100 LOC

### 🟠 CSAF / VEX advisory ingestion
- Cisco, Red Hat, SAP, Oracle publish CSAF (Common Security Advisory
  Framework) — modern structured advisory format that includes
  per-product exploitation status
- More precise than parsing prose blog posts
- New `ingest/csaf.py`; Red Hat advisory CSV index already 200

### 🟠 GeoIP / sector geographic overlay
- Country-level victim map using ransomware.live `country` field +
  breach data
- D3 or just an SVG world map; sector heatmap is good as-is
- ~150 LOC

---

### 🟠 Phishing kit / typosquat monitor for OrgWatch
- For each OrgWatch-configured org, hit PhishTank + OpenPhish + urlscan.io
  to detect spoofed domains in real time
- Pairs with existing OrgWatch — same event surface, different signal class
- ~180 LOC

### 🟠 Product stack pre-filter
- "I run Confluence + NetScaler + Okta + Office 365" → pre-filter feeds
  to surface only relevant alerts. Lighter weight than SBOM matching
- Config in `stack.json`; query enrichment in news/vulns routes
- ~120 LOC

---

## Bigger / next horizon

### 🟠 STIX 2.x / TAXII server
- Expose our enriched intel for downstream consumption by Splunk / Sentinel /
  MISP via the standard TAXII protocol
- `python-stix2` lib + small TAXII 2.1 server
- Real ~300 LOC + STIX object mapping

### 🟠 SBOM CVE matching
- Paste a CycloneDX 1.x or SPDX 2.x SBOM
- Match against CVE corpus + KEV; return vulnerability intersection
- Differentiator vs "just another vuln tracker"
- ~250 LOC

### 🟠 SOAR webhook outputs
- Tines / Cortex XSOAR / Torq playbook triggers — alongside existing
  CEF/Slack/Teams sinks
- Format: JSON with `type`, `severity`, full event payload
- ~80 LOC; mostly a new sink in `integrations/`

### 🟠 Jira / Linear / ServiceNow ticket creation
- On `org.alert` or `kev-watch` confidence > 70, auto-create ticket on
  configured queue
- Per-org `ticketing` config in `orgs.json`
- ~150 LOC

### 🟠 LLM-driven threat hunt
- "Show me ransomware affecting healthcare orgs > $1B revenue in last 30d"
- LLM-to-SQL against our schema, with a strict allow-list of read-only
  tables and a query validator
- Real risk if not gated; ship behind an explicit `ENABLE_LLM_QUERY` env flag
- ~250 LOC + prompts + safety

### 🟠 Multi-user auth + attribution
- Light user model: name + optional OIDC
- Stars/annotations/saved-views become per-user, watchlist hits show owner
- Audit log of admin actions
- Real ~400 LOC

### 🟠 Mobile push notifications (FCM / APNs)
- WS only works when the app is open. Push = "asleep but a critical
  alert about my org just landed"
- Needs device-token registration (lightweight user model OK) + sink
- ~200 LOC + push provider setup

### 🟠 5-minute voice digest as podcast feed
- TTS the morning brief, serve as RSS-with-MP3 enclosures so it shows
  up in any podcast app
- "Listen on commute" use case nobody in this space has
- ~150 LOC + TTS API key (ElevenLabs / Azure / Cartesia)

### 🟠 Telegram / Discord / Mattermost sinks
- Extends existing Slack/Teams/CEF/Email. Telegram is especially common
  for analyst-OPSEC reasons (encrypted, ephemeral)
- ~80 LOC; mostly new `integrations/` modules

### 🟠 Slack / Teams interactive bot
- `/sechub watch acmecorp`, `/sechub brief 7d`, button-driven star/ack
  from chat. Much bigger than the existing one-way webhook
- ~400 LOC; needs OAuth installation flow

### 🟠 Browser extension (Chrome MV3)
- Highlight CVE IDs / threat actor names on any web page; popup with
  our enrichment + KEV/EPSS context. Reuses the API
- Ships separately; ~300 LOC

### 🟠 Counter-intel: detection adoption tracker
- When SigmaHQ ships a new rule, watch dark-web chatter / paste sites
  for actor adaptation. "Your detection went public; here's when
  actors started referencing it"
- Hard to source cleanly, high differentiation
- ~250 LOC + curated chatter sources

### 🟠 Sankey diagram of attack chain
- Threat actor → vendor → org impact in one image
- Useful for executive presentations
- Pull from existing narrative graph data
- ~150 LOC frontend (D3-sankey)

---

## Vendor advisory sources still without ingest

Five of the original seven landed via `ingest/custom.py` (Cisco JSON,
Atlassian HTML scrape, Apple HTML scrape, CCCS JSON API, Sophos via
`curl/8.5.0` UA bypass of Akamai). Two remain unsalvageable:

| Source | Issue | Path forward |
|---|---|---|
| **Citrix Security Bulletins** | Angular SPA at `support.citrix.com`; backend is Salesforce Lightning, requires auth | Scrape rendered listing via headless browser, OR mirror via a third-party tracker |
| **Lumen Black Lotus Labs** | CMS has no `/feed`, sitemap, or JSON API — all paths return blog index HTML | Custom HTML scrape of `lumen.com/en-us/security/black-lotus-labs.html` (server-rendered) |

Also worth a follow-up: **Apple per-release CVE extraction** — the index page
gives us release names + dates but not CVEs. Currently ingested 224 releases
with 0 CVE links. Per-release pages (e.g. `support.apple.com/127121`) list
CVEs and we could crawl them on demand.

✅ **Red Hat advisory regression** — RESOLVED in v1.0.0. The `rhsa-blog`
feed remains (commentary blog), but actual CVE detail now ingests via
the Hydra JSON API in `ingest/custom.py:fetch_redhat_cves()` →
`access.redhat.com/hydra/rest/securitydata/cve.json`. ~500 CVEs/run,
30-day window, severity + CVSS3 + CWE + affected packages captured.

---

## Smaller, intentionally on the back burner

- 🟠 **Time-window scrubber** — slider to fast-forward through the past month
- 🟠 **MISP federation** — push enriched events to MISP, pull from others
- 🟠 **HaveIBeenPwned breach feed sub** — ingest new breaches from HIBP API
- 🟠 **GitHub disclosed-vulnerability RSS** — security advisories per repo
- 🟠 **Vendor product lifecycle EOL UI** — backend already wired (eol.alert),
  needs a frontend list view
- 🟠 **Cyber insurance impact scoring** — for org watch, estimate liability
  delta from breach signals
- 🟠 **Time-bucket comparison** ("this week vs last week" overlay charts)
- 🟠 **Vendor research blog deep-link parsing** — LLM-extract structured TTPs/
  industries/IOCs from prose
- 🟠 **Apple per-release CVE crawling** — index page has 224 releases; each
  per-release page (`support.apple.com/127121` etc.) has CVE detail
- ✅ **Red Hat advisory replacement** — shipped in v1.0.0 via Hydra JSON
  API (see resolved item under "Vendor advisory sources" above)
- 🟠 **HackerOne hacktivity ingest** — GraphQL endpoint requires auth;
  worth it for ~50 public reports/day with severity + CVE refs
- 🟠 **OpenBugBounty + Bugcrowd full disclosures** — currently we have
  Bugcrowd crowdstream (20 latest); both have RSS but Cloudflare-gated
- 🟠 **Black Hat / DEF CON briefings** — both Cloudflare-blocked at the
  feed level; would need headless browser or community mirror
- 🟠 **CVE.org discovery (not just enrichment)** — current `cve_org` ingest
  enriches existing CVEs with ADP; add discovery via cvelistV5 GitHub
  release deltas for CVEs published before NVD picks them up

---

## Already shipped (mentioned in passing in earlier sessions but worth noting)

- ✅ AI watch · Org monitor · Sector heatmap · Industry intel · Threat
  narrative timeline + graph · MITRE ATT&CK 174 groups + 726 malware
  + 170 actor TTPs · ransomware.live ingestion · WS push · Slack/Teams/
  Email/CEF sinks · SMTP + Markdown digest · "What changed since" LLM
  brief · Mobile lite view · Per-feed priority bumps · Magnitude-aware
  scoring · Domain spoofing · HIBP · Predicted-KEV · SimHash near-dup
  · Entity index table · Code-split frontend · Workspace (stars/
  annotations/saved searches/watchlist) · Patches panel (Microsoft +
  RHEL + Amazon Linux) · News acknowledged state · Darknet tag + 4
  darknet vendor feeds + darknetlive

Detailed status in `ROADMAP.md` and `CODE_REVIEW.md`.
