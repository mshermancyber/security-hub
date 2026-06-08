# Changelog

## v1.1.0

### Security hardening
- **DTD/entity scan covers entire feed body**, not just the first 8 KB
  prolog — prevents crafted feeds from hiding billion-laughs payloads
  past the XML declaration.
- **Slack sink escapes mrkdwn metacharacters** (`&`, `<`, `>`) in all
  untrusted fields (title, source, tags, URL) before posting.
- **Teams sink escapes markdown link metacharacters** (`[`, `]`, `(`,
  `)`) in untrusted fields.
- **Email subject strips CRLF** to prevent header-injection attacks via
  crafted news titles.
- **WebSocket connection cap** (50 concurrent clients) prevents resource
  exhaustion from leaked or abusive connections.
- **LLM config endpoint no longer exposes `base_url`** — only the model
  name is returned.

### Data quality
- **10-day age gate on ingest** — news items older than 10 days are
  silently dropped during RSS and custom feed ingestion, keeping the
  corpus current.
- **Tighter retention windows** — durable hard cap reduced from 30 to
  10 days; KEV-linked article cap reduced from 90 to 14 days.
- **Research/conference feeds tuned** — USENIX and arXiv reliability
  lowered (92→70), feed bump zeroed, enrichment tags skipped to avoid
  false-positive entity matches on academic paper titles. Conference
  papers now carry proper publication-year dates instead of ingest time.

### Features
- **Weighted sector threat scoring** — the sector heatmap now uses a
  composite score (breach 25×, ransomware 20×, active-exploitation 15×,
  zero-day 15×, vulnerability 3×, patch 2×, general 1×) instead of raw
  mention count. Sorts by threat signal, not volume.
- **Weather widget** — header bar shows local weather (city, temp,
  condition icon) via a lightweight NWS-backed endpoint. Auto-refreshes
  every 30 minutes.

### Ports (defaults)
- 80 → frontend HTTP (auto-redirects to HTTPS)
- 443 → frontend HTTPS
- 8080 → backend (container-internal only, NOT host-exposed)

Override `SECHUB_HTTP_PORT` / `SECHUB_HTTPS_PORT` in `.env` to remap.

---

## v1.0.0 — Initial public release

First GitHub-distributable release of SecurityHub Terminal.

### What's in
- **Backend**: FastAPI + SQLite, ~110 RSS / JSON ingesters spanning NVD,
  CISA KEV, MITRE ATT&CK, Red Hat Security Data, Microsoft MSRC, abuse.ch
  ThreatFox, ransomware.live, databreaches.net, arXiv cs.CR, USENIX,
  Bugcrowd, plus per-vendor advisory scrapers (Cisco, Atlassian, Apple,
  CCCS, Sophos).
- **Frontend**: React 19 + Vite + Tailwind v3. Bloomberg-terminal-style
  dense panels (NEWS / VULN / KEV / AI WATCH / ACTORS / SECTORS /
  NARRATIVE / ORGS / INDUSTRY / PIPE / PATCHES). Keyboard-driven, command
  palette (Ctrl+K).
- **Mobile**: Server + client UA detection redirects phones / tablets to
  `/m` — self-contained dark HTML page with 6 read-only tabs (critical /
  KEV / sectors / orgs / industry / search). Pinch-zoom allowed, 48 px
  touch targets, iOS safe-area padding, opt-out cookie.
- **Enrichment**: word-boundary entity matching across vendors / threat
  actors / AI companies / orgs / sectors; SimHash 3-pass news clustering
  preserving SQL sort; magnitude-aware industry-event dedup; LLM
  narrative briefs (OpenAI / Anthropic / Ollama compatible).
- **Alerting**: routing engine → Slack / Teams / SMTP / CEF syslog sinks
  with per-rule severity + entity matching.
- **Security posture**: token-gated API + WebSocket; URL-allowlist auth
  exempts; rate-limited admin / orgs-admin endpoints; per-feed body cap
  + SSRF redirect guard on every outbound HTTP; DTD/XXE pre-screen on
  feedparser; LIKE escape on all user-input SQL; bound regex extractors
  to prevent ReDoS; opaque error messages on workspace inserts;
  webhook-URL public-host check with DNS-rebinding protection.
- **Containerized**: 2-service docker-compose, `cap_drop: ALL` +
  `read_only: true` + `no-new-privileges:true` on backend; bind-mounted
  data + certs for operator visibility; self-signed TLS auto-generated
  on first boot; healthchecks on both services.

### Ports (defaults)
- 80 → frontend HTTP (auto-redirects to HTTPS)
- 443 → frontend HTTPS
- 8080 → backend (container-internal only, NOT host-exposed)

### Known limitations
- Single-operator design — no multi-user auth UI (BACKLOG).
- 6 RSS feeds upstream-broken at release time (Cloudflare 403 on direct
  Python httpx fingerprint; documented in BACKLOG).
- Per-feed body caps may need tuning on slow upstreams (defaults work
  for ~99% of observed feeds).
