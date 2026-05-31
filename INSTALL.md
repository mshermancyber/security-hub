# Installation

SecurityHub Terminal ships as a 2-container docker-compose stack. There
is no host Python venv, no `npm install` on the host, no system-wide
deps beyond Docker itself. Install is one `git clone` + one `docker
compose up`.

---

## 1. Prerequisites

You need **Docker Engine 25+** and **Docker Compose v2** on a 64-bit
Linux / macOS / Windows host.

```bash
docker --version          # → Docker version 25.x.x or newer
docker compose version    # → Docker Compose version v2.x.x or newer
```

If `docker compose` (with a space) isn't recognized, you're on the old
`docker-compose` (with a hyphen) plugin. Either upgrade to v2 or
substitute `docker-compose` everywhere `docker compose` appears below.

**Resources**: ~512 MB RAM, ~2 GB disk for images + steady-state SQLite.
First-boot ingest peaks around 1 GB RAM briefly during NVD pagination
and the MITRE STIX bundle download.

**Network**: outbound HTTPS to ~110 RSS / JSON feeds. No inbound ports
opened beyond the two you choose (default 80/443).

---

## 2. Clone + configure

```bash
git clone https://github.com/mshermancyber/security-hub.git sechub
cd sechub
cp .env.example .env
```

Open `.env` in your editor. The interesting lines:

```ini
# Ports the host will expose. 80/443 default — change if they conflict.
SECHUB_HTTP_PORT=80
SECHUB_HTTPS_PORT=443

# Container user — set to your host UID/GID so files in ./data are
# readable from the host. Defaults to 1000:1000; on macOS use 0:0.
SECHUB_UID=1000
SECHUB_GID=1000

# Auth posture. Pick ONE:
#   (a) leave SECHUB_INSECURE=1 for an open LAN demo / private dev box
#   (b) set SECHUB_AUTH_TOKEN=<random> and remove SECHUB_INSECURE
# SECHUB_AUTH_TOKEN=
SECHUB_INSECURE=1
```

Everything else (API keys, LLM endpoint, alert sinks) is optional —
features degrade gracefully when their keys aren't set.

### UID/GID — why it matters

The backend container writes the SQLite DB into the bind-mounted
`./data/` directory. Container writes land owned by `SECHUB_UID`. If
you want to `sqlite3 ./data/sechub.sqlite` from your host, that UID
needs to match your shell user — get it with `id -u` and `id -g`.

If you don't care about host-side DB poking, leave the defaults; the
container will write as UID 1000.

---

## 3. First boot

```bash
docker compose up -d --build
```

Output (truncated):

```
[+] Building 132.4s (24/24) FINISHED
 ✔ Network sechub_default        Created
 ✔ Container sechub-backend      Started
 ✔ Container sechub-frontend     Started
```

**Initial image build takes 2–4 min** (pip install + npm ci + vite
build). Subsequent runs use the layer cache and finish in seconds.

Watch the boot complete:

```bash
docker compose logs -f
```

When you see `Application startup complete` from the backend and
`[sechub-tls] Self-signed cert ready` from the frontend, you're up.

---

## 4. Verify

```bash
# Health checks
curl -sk https://localhost/api/health         # → {"ok":true}
curl -sk -o /dev/null -w "%{http_code}\n" http://localhost/    # → 301 (HTTPS redirect)
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost/   # → 200

# Container status
docker compose ps
# Both services should be "Up X seconds (healthy)" within 30 seconds.
```

Open `https://localhost/` in a browser. **Accept the self-signed cert**
(`thisisunsafe` in Chrome, "Advanced → Proceed" in Firefox). The
terminal UI loads.

---

## 5. First-ingest expectations

The scheduler kicks off immediately. Realistic timeline:

| Time | What's populated |
|---|---|
| **+30 s** | CISA KEV catalog (≈1,600 entries) |
| **+2 min** | RSS sweep complete (~110 feeds, ~5,000 news items) |
| **+5 min** | NVD recent CVEs (~2,500 entries) |
| **+10 min** | MITRE ATT&CK STIX bundle (~900 actor/malware records) |
| **+15 min** | EPSS scores synced for every CVE |

The UI shows skeleton states for empty panels — that's normal during
first boot. The STATUS bar at the bottom shows per-feed health.

---

## 6. TLS — using your own cert

On first boot, `frontend/docker-entrypoint.sh` writes a self-signed
cert into `./certs/`:

```
./certs/
├── cert.pem    (CN=sechub.local, 365-day validity)
└── key.pem
```

To use a real cert (Let's Encrypt, internal CA, etc.):

```bash
cp /path/to/your/cert.pem ./certs/cert.pem
cp /path/to/your/key.pem  ./certs/key.pem
chmod 600 ./certs/key.pem
docker compose restart frontend
```

The frontend will pick up the new cert on restart.

---

## 7. Switching to token-auth

For anything reachable beyond your local network:

```bash
# Generate a random 32-byte token
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
# → 4Tc6...long-base64-string

# In .env:
SECHUB_AUTH_TOKEN=4Tc6...long-base64-string
# DELETE or comment out:
# SECHUB_INSECURE=1

docker compose restart backend
```

Now every `/api/*` request needs `Authorization: Bearer 4Tc6...`. GET
also accepts `?token=...`; POST/DELETE/PATCH do not (would leak via
Referer + access logs).

The browser UI doesn't yet have a login form (BACKLOG item), so you'll
need to either keep the SPA accessible via `?token=` query or front
the deployment with a reverse proxy that injects the header.

---

## 8. Optional integrations

Each of these is opt-in via `.env`. Restart `docker compose restart
backend` after editing.

| Variable | Effect when set |
|---|---|
| `NVD_API_KEY` | Raises NVD rate limit (50→200 req per 30 s) |
| `SHODAN_API_KEY` | Enables `/api/integrations/shodan/*` enrichment |
| `VIRUSTOTAL_API_KEY` | Enables `/api/integrations/virustotal/*` |
| `HIBP_API_KEY` | Enables `/api/exposure/account/*` breach lookups |
| `SLACK_WEBHOOK_URL` | Slack alert sink (rules in `taxonomy/routing.json`) |
| `TEAMS_WEBHOOK_URL` | MS Teams alert sink |
| `SECHUB_SMTP_URL` + `SECHUB_FROM_EMAIL` | Email alert sink (`smtp+starttls://user:pass@host:587`) |
| `SECHUB_SYSLOG_URL` | CEF/syslog sink for SIEM forwarding |
| `SECHUB_LLM_BASE_URL` + `SECHUB_LLM_API_KEY` + `SECHUB_LLM_MODEL` | LLM narrative briefs + "since" summaries (OpenAI / Anthropic / Ollama compatible) |

---

## 9. Stop / uninstall

```bash
# Stop, keep images + ./data
docker compose down

# Stop + remove images
docker compose down --rmi local

# Nuclear option — also drops the DB
docker compose down --rmi local
rm -rf ./data ./certs ./backups
```

---

Next: [USER_GUIDE.md](USER_GUIDE.md) for day-to-day operator usage, or
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) if something didn't work.
