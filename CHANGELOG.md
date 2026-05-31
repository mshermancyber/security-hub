# Changelog

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
  palette (⌘K).
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

Override `SECHUB_HTTP_PORT` / `SECHUB_HTTPS_PORT` in `.env` to remap.

### Known limitations
- Single-operator design — no multi-user auth UI (BACKLOG).
- 6 RSS feeds upstream-broken at release time (Cloudflare 403 on direct
  Python httpx fingerprint; documented in BACKLOG).
- Per-feed body caps may need tuning on slow upstreams (defaults work
  for ~99% of observed feeds).
