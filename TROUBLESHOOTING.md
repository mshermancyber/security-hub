# Troubleshooting

Common bring-up + runtime failures, in roughly the order you'll hit them.
Each section: **symptom → root cause → fix → how to verify.**

---

## Quick diagnosis

```bash
# 1. What's running?
docker compose ps

# 2. Health of each service
docker compose logs --tail=50 backend
docker compose logs --tail=50 frontend

# 3. End-to-end reachability
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost/api/health    # → 200
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost/healthz       # → 200

# 4. Per-feed health
curl -ks https://localhost/api/status | jq '.feeds[] | select(.last_error)'
```

---

## Bring-up failures

### Backend exits with `sqlite3.OperationalError: unable to open database file`

**Symptom**

```
sechub-backend  | sqlite3.OperationalError: unable to open database file
sechub-backend  | ERROR:    Application startup failed. Exiting.
```

Backend container restart-loops; never reaches "Application startup
complete."

**Root cause**

`./data/` (bind-mounted into `/app/data/` inside the container) is
owned by a UID the container can't write to. The backend image runs as
the UID set by `SECHUB_UID` in `.env` (default 1000); your host
directory is owned by whoever ran `git clone`.

**Fix**

Pick one:

```bash
# Option A — set SECHUB_UID/GID to match your shell user
echo "SECHUB_UID=$(id -u)" >> .env
echo "SECHUB_GID=$(id -g)" >> .env
docker compose restart backend

# Option B — chown the bind-mount to match the container default (1000:1000)
sudo chown -R 1000:1000 ./data
docker compose restart backend

# Option C — relaxed perms (single-operator boxes only)
chmod 777 ./data
docker compose restart backend
```

**Verify**

```bash
docker compose ps         # backend should be "Up X seconds (healthy)"
ls -la ./data/            # sechub.sqlite owned by SECHUB_UID, mode 600
```

---

### Frontend stuck in restart loop on first boot

**Symptom**

```
sechub-frontend  | [sechub-tls] No cert found — generating self-signed
sechub-frontend  | (entrypoint exits, container restarts, same line again)
```

**Root cause**

`./certs/` is empty (first boot) but the container user lacks write
permission to create `cert.pem` / `key.pem` there. Same UID issue as
the data dir.

**Fix**

```bash
# Make ./certs writable, then restart
chmod 777 ./certs
docker compose restart frontend

# (After first boot, certs exist; you can tighten back to 700.)
```

**Verify**

```bash
ls -la ./certs/           # cert.pem + key.pem exist
docker compose logs frontend | grep tls-ready
```

If you have a real cert, drop `cert.pem` + `key.pem` into `./certs/`
**before** first boot to skip the self-sign step entirely.

---

### Port already in use

**Symptom**

```
Error response from daemon: driver failed programming external
connectivity on endpoint sechub-frontend: failed to bind host port
0.0.0.0:80: address already in use
```

**Root cause**

Another service on the host (nginx, Apache, another container) is
already bound to port 80 / 443.

**Fix**

```bash
# Find the offender
sudo ss -tlnp | grep -E ':80|:443'

# Either stop it, or pick different ports for SecurityHub
cat > .env.ports <<'EOF'
SECHUB_HTTP_PORT=8000
SECHUB_HTTPS_PORT=8443
EOF
cat .env.ports >> .env
docker compose down && docker compose up -d
```

**Verify**

```bash
docker compose ps
# PORTS column: 0.0.0.0:8000->80/tcp, 0.0.0.0:8443->443/tcp
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost:8443/api/health
```

---

### Healthcheck failing — backend says "unhealthy"

**Symptom**

```
sechub-backend  | Up 30 seconds (unhealthy)
```

Frontend never starts because it depends on `backend: condition: service_healthy`.

**Root cause**

The backend `HEALTHCHECK` runs `curl -fsS http://127.0.0.1:8080/api/health`.
It fails if:

- The app crashed during startup (check `docker compose logs backend`).
- The app is alive but slow to finish first-boot ingest enrichment
  (MITRE STIX bundle download can take 30+ seconds).
- `curl` isn't installed in the image (it is by default — only an
  issue if you've customized the Dockerfile).

**Fix**

```bash
docker compose logs backend | tail -100
# Look for the actual exception. Common causes:
#   - `unable to open database file` → see UID section above
#   - `Address already in use` → port collision on 8080 inside the container (rare)
#   - `ImportError` → you've modified source and broke an import
```

If the app is just slow on first boot, give it more time — the
healthcheck has `start_period=20s, retries=3, interval=30s`, so it has
~110 s before marking unhealthy.

---

## Runtime issues

### "Empty data" / panels show skeleton state forever

**Symptom**

UI loads, but every panel reads "loading..." or "no items in window."

**Root cause**

You're looking at the UI before first-boot ingest finished. The
scheduler kicks off immediately but RSS / NVD / MITRE all take a few
minutes.

**Fix**

```bash
# Watch the ingestion progress
docker compose logs -f backend | grep -E 'ingest|scheduler'

# Force-trigger to skip the cadence
H=https://localhost/api/admin/refresh
curl -ksX POST $H/news
curl -ksX POST $H/kev
curl -ksX POST $H/nvd
# Wait ~30 s
curl -ks https://localhost/api/status | jq '.counts'
# → {"news":4000,"cves":2500,"kev":1607,"critical_news":13}
```

If counts stay at zero, the backend isn't reaching the internet:

```bash
docker compose exec backend curl -sI https://services.nvd.nist.gov/
# Should return HTTP/2 200. If timeout or DNS fail, your docker host
# has no outbound or its DNS is broken.
```

---

### Mobile redirect not firing

**Symptom**

Loading `https://<host>/` on a phone shows the dense desktop UI instead
of `/m`.

**Root cause** (in order of likelihood)

1. **You're on a tablet** and overriding via the cookie. Check for
   `sechub_view=desktop` in browser dev tools → Application → Cookies.
2. **You followed an `?desktop=1` link** at some point — same cookie.
3. **Your phone's UA is non-standard** (custom browser, scraper) and
   the detection regex doesn't match.

**Fix**

```javascript
// In phone browser address bar:
javascript:document.cookie='sechub_view=; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/';location.href='/'
```

Or clear all cookies for the site. Then visit `https://<host>/` again
— you should be 302'd to `/m`.

**Verify**

```bash
# From any machine — simulate an iPhone UA
curl -sk -o /dev/null -w "%{http_code} → %{redirect_url}\n" \
    -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)" \
    https://localhost/
# → 302 → /m   (the server middleware fired)
```

---

### Many feeds show as red in the dashboard

**Symptom**

The STATUS bar reads `FEEDS 70/108` instead of close to full.

**Root cause**

Some upstream RSS sources actively block Python-httpx's TLS fingerprint
(Cloudflare bot detection). Some have moved or been retired. This is a
fact of life for a 100+ feed aggregator.

**Fix**

```bash
# List the broken feeds + the actual error
curl -ks https://localhost/api/status | \
    jq '.feeds[] | select(.last_error) | {id:.source_id, err:.last_error[0:120]}'
```

For each:

- **"Server disconnected without sending a response"** → transient TLS/TCP issue,
  often self-recovers on next refresh. Re-trigger: `curl -ksX POST
  https://localhost/api/admin/refresh/news`.
- **"403 Forbidden"** → upstream Cloudflare gating. No client-side fix;
  remove the feed from `backend/app/taxonomy/sources.json` or proxy
  through Google News as some entries already do.
- **"feedparser: ... mismatched tag"** → upstream serves malformed XML.
  Same — either wait for them to fix it or remove.
- **"response from X exceeded cap"** → bump the per-feed `max_bytes` cap
  in the ingester (`backend/app/ingest/*.py`).
- **"redirect target is non-public"** → SSRF guard blocked a redirect to a
  private IP. Almost always upstream misconfiguration; remove the feed.

---

### Browser shows "Your connection is not private"

**Symptom**

Chrome / Firefox refuses to load the page on first visit.

**Root cause**

You're hitting the self-signed cert generated on first boot. Expected.

**Fix**

- Chrome: type `thisisunsafe` while the warning page is focused (no
  input box, just type the letters).
- Firefox: "Advanced" → "Accept the Risk and Continue".
- Safari: "Show Details" → "visit this website" → "Visit Website".

For a permanent fix, replace the self-signed cert with a real one — see
[INSTALL.md §6](INSTALL.md#6-tls--using-your-own-cert).

---

### "401 Unauthorized" on every API call

**Symptom**

The UI loads but every panel shows an error; `curl -ks
https://localhost/api/news` returns `{"detail":"auth required"}`.

**Root cause**

You've set `SECHUB_AUTH_TOKEN` but the browser isn't sending the
header, OR you've removed `SECHUB_INSECURE=1` without setting a token.

**Fix**

Either configure a token AND a way to send it (reverse proxy or
query-string), or revert to open mode for local dev:

```bash
# Open mode (LAN demo / local dev only)
sed -i '/^SECHUB_AUTH_TOKEN=/d' .env
echo "SECHUB_INSECURE=1" >> .env
docker compose restart backend
```

The browser UI doesn't have a login form yet (BACKLOG); for now the
practical path on a private deployment is `SECHUB_INSECURE=1` behind a
trusted network boundary.

---

### `Cannot connect to the Docker daemon`

**Symptom**

```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock.
Is the docker daemon running?
```

**Fix**

```bash
sudo systemctl start docker
# Or on macOS / Windows: open Docker Desktop
```

If you're a non-root user, add yourself to the `docker` group:

```bash
sudo usermod -aG docker $USER
newgrp docker     # or log out + back in
```

---

### Mobile page works but desktop UI shows blank screen

**Symptom**

`/m` renders, but `https://<host>/` is white.

**Root cause** (in order)

1. **Build error in the SPA bundle**. Check the browser console — most
   common is a stale cached `index.html` pointing at a no-longer-built
   asset.
2. **CSP blocked the bundle**. Look in the console for a CSP violation
   on `script-src`.
3. **You modified `frontend/src/` but didn't rebuild** — `docker compose
   up -d --build` doesn't auto-detect source changes unless you pass it.

**Fix**

```bash
# Hard refresh in the browser (Ctrl-Shift-R / Cmd-Shift-R)
# AND force-rebuild:
docker compose up -d --build --force-recreate frontend
```

If you've edited `frontend/index.html`'s CSP meta tag, double-check
you haven't accidentally dropped `'unsafe-inline'` from `style-src`
(Tailwind injects inline styles).

---

### Backend can't reach an outbound API (e.g. OpenAI)

**Symptom**

LLM narrative shows `{"needs_llm": true}` even though you set
`SECHUB_LLM_BASE_URL`. Or NVD ingest fails with timeouts.

**Root cause**

The backend container has its own DNS + network. If your host uses
internal DNS or sits behind a proxy, the container may not inherit
the same network access.

**Fix**

```bash
# Test from inside the container
docker compose exec backend curl -sI https://api.openai.com/v1/models
# Should return HTTP/2 401 (no key) — proves DNS + TLS work.

# If timeout / DNS error, point docker at your DNS resolver:
# /etc/docker/daemon.json
{
  "dns": ["1.1.1.1", "8.8.8.8"]
}
# sudo systemctl restart docker
# docker compose down && docker compose up -d
```

---

### Need to start fresh

```bash
# Stop everything, wipe images, wipe state — fully clean slate
docker compose down --rmi local --volumes
rm -rf ./data ./certs ./backups
# Then rebuild
cp .env.example .env
docker compose up -d --build
```

⚠️ This destroys the SQLite DB. First-boot ingest will take ~10 min to
rebuild the corpus.

---

## Still stuck

Open an issue at the repo with:

1. `docker compose ps` output
2. `docker compose logs --tail=100 backend` output (scrub secrets)
3. `docker compose logs --tail=100 frontend` output
4. `docker version` + `docker compose version`
5. The exact `.env` (with secrets redacted)
6. What you expected vs. what happened
