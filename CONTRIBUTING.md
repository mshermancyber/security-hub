# Contributing to SecurityHub Terminal

Thanks for considering a contribution. This is a young project and small,
focused PRs are the easiest to merge.

## Quick start

```bash
git clone https://github.com/your-org/security-hub.git
cd security-hub
./scripts/install.sh
./scripts/start.sh
# → http://localhost
```

## Project layout

```
backend/
  app/
    config.py              env-driven config
    db.py                  SQLite schema + helpers (vanilla SQL)
    main.py                FastAPI app, lifespan, WebSocket
    auth.py                optional bearer-token middleware
    ingest/                live feeds (KEV, NVD, RSS, EPSS, ThreatFox, paste)
    enrich/                entity extraction, scoring, AI, health, graph,
                           velocity, conflict, spoofing
    integrations/          OpenAI-compat LLM + sinks (Slack/Teams/Email/CEF)
                           + Shodan + VirusTotal + HIBP + routing engine
    routes/                FastAPI routers (one per surface area)
    taxonomy/              editable JSON: vendors, AI cos, threat actors,
                           sectors, sources, orgs, routing rules
  tests/                   pytest suite
  Dockerfile

frontend/
  src/
    api/                   client + types + WS bus
    components/            panels, header, status bar, sparkline,
                           graph, command palette
    lib/                   formatting + WS hooks
  Dockerfile + nginx.conf
  vite.config.ts           dev proxy → backend:8080

scripts/                   install / start / stop / test
docker-compose.yml         backend + frontend nginx
.env.example               every env var the platform reads
```

## Conventions

- **Backend**: Python 3.10+, FastAPI, SQLite (Postgres adapter documented
  in `app/db_pg.py`). No ORM — plain SQL kept readable. All async I/O
  uses `httpx`. Type hints are encouraged but not required.
- **Frontend**: React 19 + TypeScript + Tailwind. No state libraries —
  components own their state, hooks share what's shared. Dark Bloomberg
  palette is in `tailwind.config.js`; use the `chip-*` classes instead
  of inline color.
- **JSON taxonomies**: hot-reloaded on mtime change. Keep the existing
  shape and add new entries by appending to the array.
- **External integrations**: must degrade gracefully when their env var
  is missing. Return `{configured: false, hint: ...}` rather than 500.
- **No mocks**: every panel should be driven by real data flowing
  through the ingestion pipeline.

## Adding a new ingestion source

1. Create `backend/app/ingest/<your_source>.py` with an async
   `fetch_*()` function that returns a count and calls
   `record_feed_health(...)`.
2. If it produces news, hook into the broadcaster:
   ```python
   from ..ws import push_news_batch, push_org_alerts
   ```
3. Schedule it in `app/ingest/scheduler.py`:
   ```python
   loop.create_task(_loop("your_source", INTERVAL, fetch_your_source))
   ```
4. Add an admin trigger in `routes/admin.py` so operators can fire it
   on demand.

## Adding a new alert sink

1. Create `backend/app/integrations/<sink>.py` exporting an async
   `send(event, *, ...config) -> None`.
2. Add a sink config entry to `backend/app/taxonomy/routing.json`.
3. Add a dispatch branch in `integrations/router.py::_dispatch_to`.

The routing engine taps `bus.broadcast`, so once your sink is wired,
matching events will fan out automatically.

## Adding a new panel

1. New component at `frontend/src/components/panels/<Name>Panel.tsx`.
2. Add the nav slot in `Header.tsx` and the route in `App.tsx`.
3. Add a hotkey (digit) in `App.tsx`'s key-map.

## Running tests

```bash
./scripts/test.sh
```

Or individually:

```bash
cd backend && .venv/bin/pytest -q
cd frontend && npx tsc -b --noEmit
cd frontend && npm run build
```

## Commit style

Conventional-ish, short, imperative. Examples:

```
ingest: add Recorded Future free feed
ui: show health badge inline on org row
enrich/industry: extend layoff trigger to include "lays off"
```

## PR checklist

- [ ] `./scripts/test.sh` passes
- [ ] Added taxonomy entries if you added a new vendor / actor / org
- [ ] No new env var without an `.env.example` entry
- [ ] No new external integration without a `configured: false` fallback
- [ ] Updated `README.md` / `USER_GUIDE.md` if you added a user-facing feature
