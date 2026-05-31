# SecurityHub Terminal

Bloomberg-Terminal-style analyst workstation for security, vulnerability,
threat-intel, and tech-industry news. Single-operator, docker-only,
keyboard-driven.

```
https://<host>/      desktop terminal      (HTTP auto-redirects to HTTPS)
https://<host>/m     mobile lite view      (phones / tablets auto-served)
https://<host>/api   REST + WebSocket bus  (read & control)
```

## 60-second install

```bash
git clone https://github.com/mshermancyber/security-hub.git sechub
cd sechub
cp .env.example .env                # edit if you need non-default ports
docker compose up -d --build
```

First boot builds the images (~3 min) and starts ingesting (~10 min to
steady state). Watch with `docker compose logs -f`. Then open
`https://localhost/` and accept the self-signed cert.

## Documentation

| | |
|---|---|
| **[INSTALL.md](INSTALL.md)** | Prerequisites, configuration, first-boot, TLS, auth modes, optional integrations |
| **[USER_GUIDE.md](USER_GUIDE.md)** | Panel descriptions, keyboard shortcuts, command palette, AI summaries, alerting, mobile view, operator drills |
| **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** | Common bring-up + runtime failures, diagnosis recipes, "start fresh" |
| **[CHANGELOG.md](CHANGELOG.md)** | Release history |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Codebase conventions, security gotchas, PR guidelines |
| **[ROADMAP.md](ROADMAP.md)** / **[BACKLOG.md](BACKLOG.md)** | What's shipped, what's next |
| **[CODE_REVIEW.md](CODE_REVIEW.md)** | Reviewer notes (security-audit findings + fixes) |

## What's in the box

- **~110 ingest sources** — RSS (cybersecurity, vendor advisories, tech
  industry), JSON APIs (NVD, CISA KEV, FIRST EPSS, MITRE ATT&CK,
  Red Hat Security Data, MSRC, abuse.ch ThreatFox, ransomware.live,
  databreaches.net, arXiv, USENIX, Bugcrowd).
- **11 panels** — News, Vulnerabilities, KEV, AI Watch, Threat Actors,
  Sectors, Threat Narrative, Orgs, Industry, Integrations/Pipe, Patches.
- **Mobile view** — auto-served to phones / tablets via UA detection,
  6 read-only tabs, iOS-native touch hygiene.
- **Alerting** — Slack / Teams / Email / CEF syslog sinks with rule-based
  routing.
- **LLM briefs** — narrative summaries via any OpenAI-compatible endpoint
  (OpenAI / Anthropic / Ollama / vLLM / LM Studio / Groq / Together).
- **Containerized + hardened** — `cap_drop: ALL`, `read_only: true`,
  `no-new-privileges:true`, non-root user, auto-generated TLS, bind-mounted
  state for backup visibility.

## License

AGPL-3.0. See [`LICENSE`](./LICENSE).
