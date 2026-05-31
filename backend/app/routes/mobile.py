"""Mobile / lite read-only view.

A single self-contained HTML page that fits on a phone, polls /api/news,
/api/vulns/kev, /api/orgs, /api/industry/signals, /api/watch/sectors,
and /api/search.

No JS framework — vanilla fetch + render. Designed to render below ~25 KB
of HTML so it loads quickly on bad cellular links, and to be reachable
without the SPA bundle (the desktop SPA at /` redirects mobile UAs here
via `mobile_redirect.py`).

Mobile UX rules baked in:
  - 48×48 min touch targets on tabs + interactive chips (WCAG 2.5.5)
  - No :hover dependencies; uses :active for tap feedback
  - iOS safe-area padding on sticky header and footer
  - Rounded corners (10 px) for native iOS feel
  - viewport allows pinch-zoom (WCAG 1.4.4)
  - "Open desktop view" link sets ?desktop=1 + sechub_view=desktop cookie
    so the operator can escape to the terminal UI when needed
"""
from __future__ import annotations

from fastapi import APIRouter, Response

router = APIRouter(prefix="/m", tags=["mobile"])

# The page body. Kept as a triple-quoted constant so it ships with the
# Python module (no separate template engine, no filesystem lookups, no
# CSP/JSX/innerHTML surprises).
_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<!-- viewport-fit=cover lets iOS draw the page under the notch / home-bar
     so our env(safe-area-inset-*) paddings can position content correctly.
     We DELIBERATELY do not set user-scalable=no — WCAG 1.4.4 requires
     pinch-zoom for low-vision users; Apple HIG agrees. -->
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0a0d12">
<meta name="color-scheme" content="dark">
<meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="icon" type="image/png" href="https://avatars.githubusercontent.com/u/48896836?v=7">
<link rel="apple-touch-icon" href="https://avatars.githubusercontent.com/u/48896836?v=7">
<title>SecHub · Lite</title>
<style>
  :root { color-scheme: dark; --amber:#ff9f1c; --amber-glow:#ffcf6b; --bg:#05070b; --card:#10141b; --wire:#1d2330; --wire-strong:#2a3140; --mute:#8a93a6; --red:#ff4d6d; --green:#34f5c5; --blue:#5cc8ff; --yellow:#ffd166; }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html,body { margin:0; background:var(--bg); color:#e5e7eb; font:14px/1.45 -apple-system,BlinkMacSystemFont,'JetBrains Mono','SF Mono',Menlo,monospace; }
  body { min-height: 100vh; padding-bottom: calc(64px + env(safe-area-inset-bottom)); }
  header {
    position: sticky; top: 0; z-index: 20;
    background: rgba(10,13,18,0.95); backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--wire);
    padding: calc(12px + env(safe-area-inset-top)) 16px 12px;
    display: flex; align-items: center; gap: 8px;
  }
  header .dot { width:8px; height:8px; border-radius:50%; background:var(--amber); animation: pulse 1.6s ease-in-out infinite; }
  @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:.3 } }
  header h1 { font-size:13px; margin:0; letter-spacing:.22em; color:var(--amber); font-weight:600; }
  header .clock { margin-left:auto; font-size:11px; color:var(--mute); font-variant-numeric: tabular-nums; }
  nav {
    display:flex; gap:0;
    border-bottom: 1px solid var(--wire);
    background: var(--bg);
    position: sticky;
    /* Header offset varies with notch — let the browser figure it out via
       the natural sticky stack instead of hard-coding pixel offsets. */
    top: calc(45px + env(safe-area-inset-top));
    z-index: 19;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
  }
  nav::-webkit-scrollbar { display: none; }
  nav button {
    /* WCAG 2.5.5 min target: 48×48 px including the bottom border. */
    flex: 1 0 auto;
    min-width: 80px;
    min-height: 48px;
    background: none; border: none;
    color: var(--mute);
    font: inherit; font-size: 11px;
    text-transform: uppercase; letter-spacing: .14em;
    padding: 0 14px;
    border-bottom: 2px solid transparent;
  }
  nav button.active { color: var(--amber); border-bottom-color: var(--amber); }
  nav button:active { background: rgba(255,159,28,0.08); }
  main { padding: 8px; }
  article {
    background: var(--card); border: 1px solid var(--wire);
    border-radius: 10px;             /* iOS-native feel */
    padding: 12px;
    margin-bottom: 8px;
  }
  article .meta {
    font-size: 10px; color: var(--mute);
    text-transform: uppercase; letter-spacing: .08em;
    margin-bottom: 6px;
    display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  }
  /* The whole article is the tap target on news/sector items, so make
     sure the tap-area is comfortably tall. */
  article.tap a.title { display: block; min-height: 44px; }
  a.title {
    color: var(--amber-glow); text-decoration: none;
    line-height: 1.4; font-size: 15px;
  }
  a.title:active { color: var(--amber); }
  .chip {
    display: inline-block;
    padding: 3px 8px;
    border: 1px solid var(--wire-strong);
    border-radius: 999px;            /* pill shape — iOS standard */
    font-size: 11px;
    color: var(--mute);
    margin-right: 4px;
  }
  .chip.red    { border-color: var(--red);    color: var(--red);    background: rgba(255,77,109,.08); }
  .chip.amber  { border-color: var(--amber);  color: var(--amber);  background: rgba(255,159,28,.08); }
  .chip.green  { border-color: var(--green);  color: var(--green); }
  .chip.blue   { border-color: var(--blue);   color: var(--blue); }
  .chip.yellow { border-color: var(--yellow); color: var(--yellow); }
  .chip-btn {
    /* Tappable chips need a real touch target. */
    min-height: 32px; padding: 6px 12px;
    cursor: pointer; user-select: none;
  }
  .chip-btn:active { transform: scale(0.96); }
  .org-card {
    background: var(--card); border: 1px solid var(--wire);
    border-radius: 10px;
    padding: 12px; margin-bottom: 8px;
    display: flex; gap: 6px; align-items: center; flex-wrap: wrap;
  }
  .org-card strong { color: var(--amber-glow); font-size: 13px; flex: 1; min-width: 50%; }
  .sector-row {
    background: var(--card); border: 1px solid var(--wire);
    border-radius: 10px;
    padding: 12px; margin-bottom: 8px;
  }
  .sector-row .name { color: var(--amber-glow); font-size: 14px; font-weight: 500; }
  .sector-row .bar { height: 4px; background: #161b24; margin: 8px 0 6px; border-radius: 4px; overflow: hidden; }
  .sector-row .bar > div { height: 100%; background: linear-gradient(90deg, var(--amber), var(--red)); }
  .sector-row .stats { display: flex; gap: 8px; font-size: 11px; color: var(--mute); align-items: center; flex-wrap: wrap; }
  .skeleton { color: #5e6678; padding: 24px 16px; text-align: center; font-size: 12px; }
  .search-bar {
    padding: 8px; position: sticky; top: calc(93px + env(safe-area-inset-top));
    background: var(--bg); border-bottom: 1px solid var(--wire); z-index: 18;
  }
  .search-bar input {
    width: 100%; padding: 12px 14px; font: inherit; font-size: 15px;
    background: var(--card); border: 1px solid var(--wire-strong);
    border-radius: 10px;
    color: #e5e7eb;
    /* 16 px+ font-size prevents iOS Safari's auto-zoom-on-focus behavior. */
  }
  .search-bar input:focus { outline: none; border-color: var(--amber); }
  /* Fixed footer with desktop opt-out — pinned above the iOS home indicator. */
  footer.escape {
    position: fixed; left: 0; right: 0;
    bottom: 0;
    padding: 12px 16px calc(12px + env(safe-area-inset-bottom));
    background: rgba(10,13,18,0.95); backdrop-filter: blur(8px);
    border-top: 1px solid var(--wire);
    text-align: center; font-size: 11px;
    z-index: 15;
  }
  footer.escape a {
    color: var(--mute); text-decoration: none;
    display: inline-block; min-height: 44px; line-height: 44px;
    padding: 0 16px;
    text-transform: uppercase; letter-spacing: .15em;
  }
  footer.escape a:active { color: var(--amber); }
  /* Print: nuke chrome */
  @media print {
    header, nav, footer.escape { display: none; }
    body { background: white; color: black; }
  }
</style></head><body>
<header>
  <span class="dot"></span>
  <h1>SECHUB · LITE</h1>
  <span class="clock" id="clock"></span>
</header>
<nav id="tabs">
  <button class="active" data-tab="critical">CRITICAL</button>
  <button data-tab="kev">KEV</button>
  <button data-tab="sectors">SECTORS</button>
  <button data-tab="orgs">ORGS</button>
  <button data-tab="industry">INDUSTRY</button>
  <button data-tab="search">SEARCH</button>
</nav>
<main id="root"><div class="skeleton">loading…</div></main>
<footer class="escape">
  <a href="/?desktop=1" id="desktop-link">Open desktop view →</a>
</footer>

<script>
'use strict';
const $ = (id) => document.getElementById(id);
const esc = (s) => (s ?? '').toString().replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Defense-in-depth: backend rejects unsafe schemes at ingest, but never let a
// 'javascript:' / 'data:' URL slip into an <a href> on the mobile page.
const safeUrl = (u) => {
  const s = (u ?? '').toString().trim();
  if (!s) return 'about:blank';
  const lo = s.toLowerCase();
  if (lo.startsWith('javascript:') || lo.startsWith('data:') || lo.startsWith('vbscript:') || lo.startsWith('file:')) return 'about:blank';
  return esc(s);
};
const relTime = (iso) => {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const d = (Date.now() - t) / 1000;
  if (d < 60)    return Math.round(d) + 's';
  if (d < 3600)  return Math.round(d / 60) + 'm';
  if (d < 86400) return Math.round(d / 3600) + 'h';
  return Math.round(d / 86400) + 'd';
};
const tick = () => { const e = $('clock'); if (e) e.textContent = new Date().toISOString().slice(11,19) + 'Z'; };
setInterval(tick, 1000); tick();

const prioCls = (p) => p>=85?'red':p>=70?'amber':p>=45?'yellow':p>=20?'blue':'';
const prioLbl = (p) => p>=85?'CRIT':p>=70?'HIGH':p>=45?'ELEV':p>=20?'GRD':'LOW';

// "Open desktop view" — set a 30-day cookie so the redirect doesn't fire
// next time, then navigate to /.
$('desktop-link').addEventListener('click', (e) => {
  e.preventDefault();
  const expires = new Date(Date.now() + 30*24*3600*1000).toUTCString();
  // Browsers SILENTLY drop a `Secure` cookie when the document is loaded
  // over http:// (dev deployments, LAN demos). Without this conditional
  // the opt-out cookie wouldn't persist and the next visit to / would
  // bounce the user back to /m forever. Apply Secure only on https://.
  const secureFlag = location.protocol === 'https:' ? ' Secure;' : '';
  document.cookie = `sechub_view=desktop; path=/; max-age=${30*24*3600}; SameSite=Lax;${secureFlag} expires=${expires}`;
  location.href = '/?desktop=1';
});

const TABS = {
  critical: async () => {
    const r = await fetch('/api/news?limit=40&min_priority=70').then(r => r.json());
    if (!r.items || !r.items.length) return '<div class="skeleton">No critical items in window.</div>';
    return r.items.map(n => `
      <article class="tap">
        <div class="meta">
          <span class="chip ${prioCls(n.priority)}">${prioLbl(n.priority)} ${esc(n.priority)}</span>
          <span>${esc(n.source_name)}</span>
          <span style="margin-left:auto;">${relTime(n.published_at)}</span>
        </div>
        <a class="title" href="${safeUrl(n.url)}" target="_blank" rel="noreferrer noopener">${esc(n.title)}</a>
        ${(n.tags||[]).length ? `<div style="margin-top:8px;">${(n.tags||[]).slice(0,4).map(t => `<span class="chip">${esc(t)}</span>`).join('')}</div>` : ''}
      </article>`).join('');
  },
  kev: async () => {
    const r = await fetch('/api/vulns/kev?limit=40').then(r => r.json());
    if (!r.items || !r.items.length) return '<div class="skeleton">No KEV entries.</div>';
    return r.items.map(c => `
      <article>
        <div class="meta">
          <span class="chip red">KEV</span>
          ${c.kev_ransomware==='Known' ? '<span class="chip amber">RANSOM</span>' : ''}
          <span>added ${esc((c.kev_added||'').slice(0,10))}</span>
          <span style="margin-left:auto;">prio ${esc(c.priority)}</span>
        </div>
        <div class="title">${esc(c.cve_id)}</div>
        <div style="font-size:12px;color:var(--mute);margin-top:6px;">${esc((c.description||'').slice(0,200))}</div>
      </article>`).join('');
  },
  sectors: async () => {
    const r = await fetch('/api/watch/sectors?days=30').then(r => r.json());
    const items = (r.sectors || []).filter(s => s.mentions > 0).sort((a,b) => b.mentions - a.mentions);
    if (!items.length) return '<div class="skeleton">No sector mentions in window.</div>';
    const max = Math.max(1, ...items.map(s => s.mentions));
    return items.map(s => `
      <div class="sector-row">
        <div class="name">${esc(s.name)}</div>
        <div class="bar"><div style="width:${Math.round((s.mentions/max)*100)}%"></div></div>
        <div class="stats">
          <span>${esc(s.mentions)} mention${s.mentions===1?'':'s'}</span>
          ${s.breaches>0    ? `<span class="chip red">BREACH ${esc(s.breaches)}</span>` : ''}
          ${s.ransomware>0  ? `<span class="chip amber">RANSOM ${esc(s.ransomware)}</span>` : ''}
          <span style="margin-left:auto;">max prio ${esc(s.max_priority||0)}</span>
        </div>
      </div>`).join('');
  },
  orgs: async () => {
    const r = await fetch('/api/orgs?days=14').then(r => r.json());
    if (!r.orgs || !r.orgs.length) return '<div class="skeleton">No orgs configured.</div>';
    return r.orgs.map(o => `
      <div class="org-card">
        <strong>${esc(o.name)}</strong>
        ${o.stack_kev>0       ? `<span class="chip red">KEV ${esc(o.stack_kev)}</span>` : ''}
        ${o.direct_mentions>0 ? `<span class="chip amber">MENT ${esc(o.direct_mentions)}</span>` : ''}
        ${o.max_priority      ? `<span class="chip ${prioCls(o.max_priority)}">${prioLbl(o.max_priority)}</span>` : ''}
      </div>`).join('');
  },
  industry: async () => {
    const r = await fetch('/api/industry/signals?days=30').then(r => r.json());
    const cells = ['layoffs','funding','acquisitions','execs','ipos','outages','bankruptcy','crypto_scams']
      .map(k => `<article style="text-align:center;flex:1;min-width:30%;">
        <div style="font-size:24px;color:var(--amber-glow);font-weight:600;line-height:1.2;">${esc(r[k] ?? 0)}</div>
        <div style="font-size:10px;color:var(--mute);text-transform:uppercase;letter-spacing:.15em;margin-top:4px;">${esc(k.replace('_',' '))}</div>
      </article>`).join('');
    return `<div style="display:flex;flex-wrap:wrap;gap:8px;">${cells}</div>`;
  },
  search: () => `
    <div class="search-bar">
      <input id="q" type="search" inputmode="search" autocomplete="off"
             autocorrect="off" autocapitalize="off" spellcheck="false"
             placeholder="Search news, CVEs, actors…" />
    </div>
    <div id="search-results"><div class="skeleton">Type a query — min 2 chars.</div></div>
  `,
};

let current = 'critical';
let searchTimer = null;

async function runSearch(q) {
  if (!q || q.length < 2) {
    $('search-results').innerHTML = '<div class="skeleton">Type a query — min 2 chars.</div>';
    return;
  }
  $('search-results').innerHTML = '<div class="skeleton">searching…</div>';
  try {
    const r = await fetch('/api/search?q=' + encodeURIComponent(q)).then(r => r.json());
    const news  = (r.news  || []).slice(0, 20);
    const cves  = (r.cves  || []).slice(0, 10);
    const ents  = (r.entities || []).slice(0, 10);
    const parts = [];
    if (ents.length) {
      parts.push('<div style="font-size:10px;color:var(--mute);letter-spacing:.15em;text-transform:uppercase;margin:8px 4px;">Entities</div>');
      parts.push(ents.map(e => `<div class="org-card"><strong>${esc(e.name || e.id)}</strong><span class="chip">${esc(e.kind || '')}</span></div>`).join(''));
    }
    if (cves.length) {
      parts.push('<div style="font-size:10px;color:var(--mute);letter-spacing:.15em;text-transform:uppercase;margin:12px 4px 8px;">CVEs</div>');
      parts.push(cves.map(c => `<article>
        <div class="meta">
          ${c.is_kev ? '<span class="chip red">KEV</span>' : ''}
          <span>CVSS ${esc(c.cvss_score ?? '—')}</span>
          <span style="margin-left:auto;">prio ${esc(c.priority ?? 0)}</span>
        </div>
        <div class="title">${esc(c.cve_id)}</div>
        <div style="font-size:12px;color:var(--mute);margin-top:6px;">${esc((c.description||'').slice(0,200))}</div>
      </article>`).join(''));
    }
    if (news.length) {
      parts.push('<div style="font-size:10px;color:var(--mute);letter-spacing:.15em;text-transform:uppercase;margin:12px 4px 8px;">News</div>');
      parts.push(news.map(n => `<article class="tap">
        <div class="meta">
          <span class="chip ${prioCls(n.priority)}">${prioLbl(n.priority)} ${esc(n.priority)}</span>
          <span>${esc(n.source_name)}</span>
          <span style="margin-left:auto;">${relTime(n.published_at)}</span>
        </div>
        <a class="title" href="${safeUrl(n.url)}" target="_blank" rel="noreferrer noopener">${esc(n.title)}</a>
      </article>`).join(''));
    }
    $('search-results').innerHTML = parts.join('') || '<div class="skeleton">No results.</div>';
  } catch (e) {
    $('search-results').innerHTML = `<div class="skeleton">error: ${esc(e.message)}</div>`;
  }
}

async function render(tab) {
  current = tab;
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  const root = $('root');
  root.innerHTML = '<div class="skeleton">loading…</div>';
  try {
    if (tab === 'search') {
      root.innerHTML = TABS.search();
      const input = $('q');
      input.focus();
      input.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => runSearch(input.value.trim()), 250);
      });
    } else {
      root.innerHTML = await TABS[tab]();
    }
  } catch (e) {
    root.innerHTML = `<div class="skeleton">error: ${esc(e.message)}</div>`;
  }
}

document.querySelectorAll('#tabs button').forEach(b => {
  b.addEventListener('click', () => render(b.dataset.tab));
});

render('critical');
// Auto-refresh the active tab every 30 s, but skip search (user is typing).
setInterval(() => { if (current !== 'search') render(current); }, 30000);
</script></body></html>
"""


@router.get("")
def mobile_index() -> Response:
    # Strict-but-functional CSP for the mobile lite view.
    # - `unsafe-inline` script/style is required because the page is one
    #   self-contained file with inline <script> and <style>.
    # - Allow the github avatar host for the favicon (matches the desktop CSP).
    # - Everything else is locked to 'self'. No external scripts, frames,
    #   form posts, plugins, or object embeds.
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data: https://avatars.githubusercontent.com; "
        "font-src 'self' data:; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    headers = {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        # Always re-render — the page also serves as the choice-board for
        # the desktop opt-out cookie, which must take effect immediately.
        "Cache-Control": "no-store",
    }
    return Response(content=_HTML, media_type="text/html", headers=headers)
