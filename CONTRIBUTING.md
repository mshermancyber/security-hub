# Contributing to SecurityHub Terminal

Thanks for considering a contribution. This is a young project and small,
focused PRs are the easiest to merge.

## Quick start

```bash
git clone https://github.com/mshermancyber/security-hub.git
cd security-hub
cp .env.example .env
docker compose up -d --build
# → https://localhost   (accept the self-signed cert)
```

After a code change:

```bash
docker compose up -d --build           # rebuild the affected image(s)
docker compose logs -f                  # watch the boot
docker compose exec backend pytest -q   # run the backend test suite
```

## Project layout

```
backend/
  app/
    config.py              env-driven config + paths
    db.py                  SQLite schema + helpers (vanilla SQL, per-thread conn)
    sqlutil.py             like() + ESCAPE_CLAUSE helpers — USE for LIKE
    safe_http.py           hardened httpx wrappers (SSRF + body cap)
    main.py                FastAPI app, lifespan, WebSocket
    auth.py                bearer-token middleware
    mobile_redirect.py     302 mobile UAs from / to /m
    ratelimit.py           per-prefix in-process rate limiter
    ingest/                live feeds (RSS, KEV, NVD, EPSS, MITRE, MSRC,
                           Red Hat, ransomware.live, ThreatFox, custom)
    enrich/                entity matching, scoring, AI, health, graph,
                           velocity, conflict, spoofing, clustering
    integrations/          OpenAI-compat LLM + sinks (Slack/Teams/Email/CEF)
                           + Shodan + VirusTotal + HIBP + routing engine
    routes/                FastAPI routers (one per surface)
    taxonomy/              editable JSON (hot-reloaded by mtime):
                           vendors, ai_companies, threat_actors, sectors,
                           sources, orgs, routing
  tests/                   pytest suite (47+ tests)
  Dockerfile               python:3.12-slim, non-root uid 10001 (sechub)

frontend/
  src/
    api/                   typed fetch wrappers + WS bus
    components/            panels, header, status bar, sparkline,
                           graph, command palette
    lib/
      safeUrl.ts           safeHref() + openExternal() — USE these
      useDeviceType.ts     UA detection + pre-mount mobile redirect
      debug.ts             namespaced console logger
    main.tsx               pre-mount redirect, then React mount
  index.html               viewport + CSP + favicon link
  Dockerfile               node:20-alpine build → nginx:1.27-alpine
  nginx.conf               reverse proxy + CSP + HSTS + ciphers
  vite.config.ts           dev proxy

docker-compose.yml         backend + frontend (bind mounts, cap_drop hardening)
.env.example               every env var the platform reads
```

## Conventions that have bitten us — read before editing

These are summarized; see the in-source comments for the long form.

### Backend

- **SQLite is per-thread.** Never share a `Connection` across threads.
  Use `db.get_conn()` inside the worker — it returns a thread-local
  connection.
- **LIKE patterns must use `sqlutil.like()` + `ESCAPE_CLAUSE`.** Raw
  `f'%{user_input}%'` is a soft bug: `%` and `_` in the input silently
  widens the match.
- **All outbound HTTP must go through `app/safe_http.py:safe_get()` /
  `safe_post()`.** They cap response size and reject redirects to
  private / loopback / link-local hosts. Direct `httpx.AsyncClient().get(...)`
  in `ingest/*` or `integrations/*` is a security regression.
- **Entity matching is word-boundary**, not substring. See
  `enrich/entities.py:_word_re`. `if k in text` once matched "0-day"
  inside "60-day ceasefire" and mis-tagged an Iran politics article.
- **News UPSERTs must refresh `source_name`, `published_at`, `title`,
  `url`, and `reliability`** — not just enrichment fields. We've shipped
  bugs where retitled stories silently kept the old title.
- **External integrations must degrade gracefully** when their env var
  is missing. Return `{"configured": false, "hint": "..."}` instead of
  500.

### Frontend

- **Always use `safeHref()` / `openExternal()`** from `lib/safeUrl.ts`
  for any `<a href>` or programmatic open. Never `window.open(url,
  '_blank', 'noreferrer')` — the third arg is *windowFeatures*, the
  string "noreferrer" is silently ignored.
- **All dynamic URL path segments go through `encodeURIComponent()`**
  when building API URLs in `api/client.ts` or panels.
- **No state libraries** — components own their state, hooks share
  what's shared.
- **Dark Bloomberg palette is in `tailwind.config.js`** — use the
  `chip-*` classes instead of inline color.

### Taxonomies

- **Hot-reloaded by mtime** — no restart needed after JSON edits.
- **Keep the existing shape** and add new entries by appending to the
  array.
- **Don't use overly-broad single-word aliases** in `sectors.json` /
  `vendors.json` (e.g. "navy", "solar"). The matcher is word-boundary,
  not context-aware — "navy blue" tags as `defense`.

### Mobile

- **Mobile redirect runs in two layers** — `mobile_redirect.py`
  middleware (server) and `useDeviceType.ts:maybeRedirectToMobile()`
  (client, pre-React-mount). Don't break either independently.
- **`/m` HTML uses `esc()` on every interpolation**, including numeric
  fields, as defense-in-depth XSS.
- **No write actions on `/m`** — read-only by design. Reduces UA-spoof
  attack surface.

## Adding a new ingestion source

1. Create `backend/app/ingest/<source>.py` with an async `fetch_*()`
   function that:
   - Uses `safe_http.safe_get(client, url, max_bytes=N)` (NOT raw `client.get`).
   - Returns a count.
   - Calls `record_feed_health(source_id, source_name, ok=True, items=N)`
     on success and `(ok=False, error=...)` on failure.
2. If it produces news items, persist them via the `_persist(...)` helper
   pattern in `ingest/custom.py` so they get the standard enrichment.
3. Schedule it in `ingest/scheduler.py`:
   ```python
   loop.create_task(_loop("source-id", INTERVAL_SECS, fetch_source))
   ```
4. Add an admin trigger branch in `routes/admin.py` so operators can
   fire it on demand. Use the standard `_FEED_RE` validation.

If it's a pure RSS feed, you may not need any new code at all — just
add an entry to `backend/app/taxonomy/sources.json` and the existing
`ingest/rss.py` picks it up.

## Adding a new alert sink

1. Create `backend/app/integrations/<sink>.py` exporting an async
   `send(event, *, ...config) -> None`.
2. If the sink reaches an external URL, validate it through
   `safe_http.is_public_url()` first (Slack/Teams already do this).
3. Add a sink config entry to `backend/app/taxonomy/routing.json`.
4. Add a dispatch branch in `integrations/router.py::_dispatch_to`.

The routing engine subscribes to `bus.broadcast`, so once your sink is
wired, matching events fan out automatically.

## Adding a new panel

1. New component at `frontend/src/components/panels/<Name>Panel.tsx`.
   For non-overview-grid panels, lazy-load via `React.lazy()` in
   `App.tsx` to keep the initial bundle small.
2. Add the nav slot in `Header.tsx` and the route branch in `App.tsx`.
3. Add a hotkey (digit / character) in `App.tsx`'s key-map.
4. Wrap any user-data interpolation safely — text via JSX (auto-escaped),
   URLs via `safeHref()`.

## Running tests

```bash
# Backend (in the running container)
docker compose exec backend pytest -q

# Frontend type-check + production build
# (the Dockerfile runs `vite build` so a successful image build = clean tsc)
docker compose build frontend
```

The full release pipeline (build images + run pytest) is in the
`.github/workflows/` directory.

## Commit style

Conventional-ish, short, imperative. Examples:

```
ingest: add Recorded Future free feed
ui: show health badge inline on org row
enrich/industry: extend layoff trigger to include "lays off"
mobile: bump touch targets to 48px per WCAG 2.5.5
security: route ingest calls through safe_http.safe_get
```

## PR checklist

- [ ] `docker compose exec backend pytest -q` passes
- [ ] `docker compose build` succeeds (frontend tsc + vite build)
- [ ] Added taxonomy entries if you added a new vendor / actor / org
- [ ] No new env var without an `.env.example` entry
- [ ] No new external integration without a `configured: false` fallback
- [ ] No new outbound `httpx` call that skips `safe_get` / `safe_post`
- [ ] No new LIKE pattern that skips `sqlutil.like()` + `ESCAPE_CLAUSE`
- [ ] Updated `README.md` / `USER_GUIDE.md` if you added a user-facing feature
- [ ] Updated `CHANGELOG.md` for non-trivial changes
