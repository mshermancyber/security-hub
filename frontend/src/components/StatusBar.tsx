import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { relTime } from '../lib/format'
import type { StatusResponse } from '../api/types'
import { useWSConnected, useWSEvent } from '../lib/useWebSocket'
import { Sparkline } from './Sparkline'
import { safeHref } from '../lib/safeUrl'

export function StatusBar() {
  const [s, setS] = useState<StatusResponse | null>(null)
  const wsConnected = useWSConnected()
  const [pushCount, setPushCount] = useState(0)
  const [kevSpark, setKevSpark] = useState<number[]>([])
  const [newsSpark, setNewsSpark] = useState<number[]>([])

  useEffect(() => {
    let alive = true
    fetch('/api/intel/velocity/kev?days=21').then(r => r.json()).then(d => {
      if (alive) setKevSpark((d.series || []).map((p: any) => p.kev_adds))
    }).catch(() => {})
    fetch('/api/intel/velocity/news?days=14').then(r => r.json()).then(d => {
      if (alive) setNewsSpark((d.series || []).map((p: any) => p.items))
    }).catch(() => {})
    const t = setInterval(() => {
      fetch('/api/intel/velocity/kev?days=21').then(r => r.json()).then(d => alive && setKevSpark((d.series || []).map((p: any) => p.kev_adds))).catch(() => {})
      fetch('/api/intel/velocity/news?days=14').then(r => r.json()).then(d => alive && setNewsSpark((d.series || []).map((p: any) => p.items))).catch(() => {})
    }, 60000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  useEffect(() => {
    let alive = true
    const load = () => api.status().then(r => alive && setS(r)).catch(() => {})
    load()
    const t = setInterval(load, 15000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  // any payload-bearing event bumps the push counter
  useWSEvent('news.batch', () => setPushCount(n => n + 1))
  useWSEvent('news.item',  () => setPushCount(n => n + 1))
  useWSEvent('kev.batch',  () => setPushCount(n => n + 1))
  useWSEvent('nvd.batch',  () => setPushCount(n => n + 1))
  useWSEvent('org.alert',  () => setPushCount(n => n + 1))

  const [staleFeeds, setStaleFeeds] = useState<Set<string>>(new Set())
  useWSEvent('feed.stale',     (e) => setStaleFeeds(s => new Set([...s, e.feed])))
  useWSEvent('feed.recovered', (e) => setStaleFeeds(s => { const c = new Set(s); c.delete(e.feed); return c }))

  if (!s) {
    return (
      <footer className="h-8 shrink-0 border-t border-wire bg-ink-900 text-mute text-[11px] flex items-center px-3">
        Connecting to terminal services...
      </footer>
    )
  }

  const ok = s.feeds.filter(f => f.last_success && !f.last_error).length
  const total = s.feeds.length
  const lastNews = s.last_runs?.news?.at
  const lastNvd  = s.last_runs?.nvd?.at
  const lastKev  = s.last_runs?.kev?.at

  return (
    <footer className="h-8 shrink-0 border-t border-wire bg-ink-900 text-[11px] flex items-stretch overflow-hidden">
      <Cell label="FEEDS"     value={`${ok}/${total}`} accent={ok === total ? 'green' : ok > total / 2 ? 'amber' : 'red'} />
      {staleFeeds.size > 0 && <Cell label="STALE" value={String(staleFeeds.size)} accent="red" />}
      <Cell label="NEWS"      value={s.counts.news.toLocaleString()} />
      <Cell label="CVES"      value={s.counts.cves.toLocaleString()} />
      <Cell label="KEV"       value={s.counts.kev.toLocaleString()}  accent="red" />
      <Cell label="CRITICAL"  value={String(s.counts.critical_news)} accent="amber" />
      <Cell label="NEWS REFRESH" value={relTime(lastNews)} />
      <Cell label="NVD"          value={relTime(lastNvd)} />
      <Cell label="KEV REFRESH"  value={relTime(lastKev)} />
      <div className="flex items-center gap-2 px-3 border-r border-wire" title="KEV adds, last 21 days">
        <span className="text-mute uppercase tracking-[0.18em]">KEV 21D</span>
        <Sparkline values={kevSpark} width={70} height={18} color="#ff4d6d" fill="rgba(255,77,109,0.18)" />
      </div>
      <div className="flex items-center gap-2 px-3 border-r border-wire" title="News volume, last 14 days">
        <span className="text-mute uppercase tracking-[0.18em]">NEWS 14D</span>
        <Sparkline values={newsSpark} width={70} height={18} color="#ff9f1c" />
      </div>
      <div className="ml-auto px-3 flex items-center gap-3 border-l border-wire">
        <span className="text-mute">{s.feeds.slice(0, 8).map(f => (
          <span key={f.source_id} title={f.source_name + (f.last_error ? ` — ${f.last_error}` : '')}
                className={`inline-block w-1.5 h-1.5 rounded-full mr-1
                  ${f.last_success && !f.last_error ? 'bg-cyber-green' : f.last_error ? 'bg-cyber-red' : 'bg-mute-deep'}`} />
        ))}</span>
        <span className={`inline-flex items-center gap-1.5 uppercase tracking-wider
            ${wsConnected ? 'text-cyber-green' : 'text-cyber-red'}`}>
          <span className={`inline-block w-1.5 h-1.5 rounded-full
              ${wsConnected ? 'bg-cyber-green animate-pulseDot' : 'bg-cyber-red'}`} />
          {wsConnected ? 'WS LIVE' : 'WS OFFLINE'}
          {pushCount > 0 && <span className="text-mute">· {pushCount} pushes</span>}
        </span>
        {/* AGPL §5d Appropriate Legal Notice — license + source link required for interactive UIs */}
        <a href={safeHref(import.meta.env.VITE_SOURCE_URL || 'https://github.com/mshermancyber/security-hub')}
           target="_blank" rel="noreferrer noopener"
           className="text-mute hover:text-amber uppercase tracking-wider text-[10px] px-2 border-l border-wire"
           title="View source under AGPL-3.0">
          AGPL · SRC
        </a>
      </div>
    </footer>
  )
}

function Cell({ label, value, accent }: { label: string; value: string; accent?: 'green'|'amber'|'red' }) {
  const cls = accent === 'green' ? 'text-cyber-green'
            : accent === 'amber' ? 'text-amber'
            : accent === 'red'   ? 'text-cyber-red'
            : 'text-amber/90'
  return (
    <div className="flex items-center gap-2 px-3 border-r border-wire">
      <span className="text-mute uppercase tracking-[0.18em]">{label}</span>
      <span className={`font-semibold ${cls}`}>{value}</span>
    </div>
  )
}
