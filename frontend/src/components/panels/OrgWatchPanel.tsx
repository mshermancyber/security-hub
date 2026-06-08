import { useEffect, useState } from 'react'
import { safeHref } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type { OrgAlerts, OrgSummary } from '../../api/types'
import { Panel } from '../Panel'
import { fmtDate, priorityClass, relTime, severityLabel, tagClass } from '../../lib/format'
import { useWSEvent } from '../../lib/useWebSocket'

type Props = { onSelectCVE: (cve: string) => void }

type HealthMap = Record<string, { score: number; state: string; counts: any; factors: any[] }>

export function OrgWatchPanel({ onSelectCVE }: Props) {
  useEffect(() => trackPanelLifecycle('OrgWatchPanel'), [])
  const [orgs, setOrgs] = useState<OrgSummary[]>([])
  const [health, setHealth] = useState<HealthMap>({})
  const [selected, setSelected] = useState<string | null>(null)
  const [alerts, setAlerts] = useState<OrgAlerts | null>(null)
  const [industry, setIndustry] = useState<{ events: any[]; buckets: Record<string, number> } | null>(null)
  const [spoof, setSpoof] = useState<{ matches: any[]; candidates_scanned: number; org_domains: string[] } | null>(null)
  const [execs, setExecs] = useState<{ executives: string[]; mentions: any[] } | null>(null)
  const [days, setDays] = useState(14)
  const [loading, setLoading] = useState(true)
  const [flash, setFlash] = useState<string | null>(null)

  // initial load + reload when days changes
  useEffect(() => {
    let alive = true
    setLoading(true)
    api.orgs(days).then(r => {
      if (!alive) return
      setOrgs(r.orgs)
      if (!selected && r.orgs.length) setSelected(r.orgs[0].id)
    }).finally(() => alive && setLoading(false))
    // composite health (always 90d so it's stable across day-window changes)
    fetch('/api/orgs/health?days=90').then(r => r.json()).then(d => {
      if (!alive) return
      const map: HealthMap = {}
      for (const h of d.orgs || []) map[h.org_id] = { score: h.score, state: h.state, counts: h.counts, factors: h.factors }
      setHealth(map)
    }).catch(() => {})
    return () => { alive = false }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days])

  // detail load
  useEffect(() => {
    if (!selected) { setAlerts(null); setIndustry(null); setSpoof(null); setExecs(null); return }
    let alive = true
    api.orgAlerts(selected, days, 80).then(r => alive && setAlerts(r))
    api.orgIndustry(selected, Math.max(days, 90)).then(r => alive && setIndustry(r))
    api.spoofingForOrg(selected).then(r => alive && setSpoof(r)).catch(() => {})
    api.orgExecs(selected, 30).then(r => alive && setExecs(r)).catch(() => {})
    return () => { alive = false }
  }, [selected, days])

  // live: when an org.alert event fires, flash the row + refresh the affected org's summary
  useWSEvent('org.alert', (e) => {
    setFlash(e.org)
    setTimeout(() => setFlash(f => (f === e.org ? null : f)), 2500)
    api.orgs(days).then(r => setOrgs(r.orgs)).catch(() => {})
    if (selected === e.org) {
      api.orgAlerts(e.org, days, 80).then(r => setAlerts(r)).catch(() => {})
    }
  })

  return (
    <Panel
      code="ORGWATCH"
      title="Organization monitoring"
      hotkey="8"
      right={
        <div className="flex items-center gap-1">
          {[7, 14, 30, 90].map(d => (
            <button key={d} onClick={() => setDays(d)}
              className={`chip cursor-pointer ${d === days ? 'chip-amber' : ''}`}>{d}D</button>
          ))}
        </div>
      }
    >
      <div className="flex h-full">
        {/* left rail */}
        <aside className="w-64 shrink-0 border-r border-wire/60 overflow-y-auto">
          {loading && orgs.length === 0 ? (
            <div className="p-3 text-mute text-xs">loading...</div>
          ) : (
            <ul>
              {orgs.map(o => {
                const active = o.id === selected
                const flashing = flash === o.id
                const h = health[o.id]
                const stateCls = h?.state === 'UNDER ATTACK' || h?.state === 'HIGH RISK' ? 'chip-red'
                              : h?.state === 'DISTRESSED' ? 'chip-amber'
                              : h?.state === 'GROWING' ? 'chip-green'
                              : 'chip-blue'
                return (
                  <li key={o.id}
                      onClick={() => setSelected(o.id)}
                      className={`row-link ${active ? 'active' : ''} ${flashing ? 'bg-cyber-red/15' : ''}`}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-amber/95 font-medium">{o.name}</span>
                      {o.ticker && <span className="text-mute text-[10px]">{o.ticker}</span>}
                      {h && <span className={`chip ${stateCls} ml-auto`}>{h.state} {h.score}</span>}
                    </div>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {o.stack_kev > 0  && <span className="chip chip-red">KEV {o.stack_kev}</span>}
                      {o.direct_mentions > 0 && <span className="chip chip-amber">MENT {o.direct_mentions}</span>}
                      {o.keyword_hits > 0    && <span className="chip chip-yellow">KW {o.keyword_hits}</span>}
                      <span className={`chip ${priorityClass(o.max_priority)}`}>
                        {severityLabel(o.max_priority)} {o.max_priority}
                      </span>
                    </div>
                    <div className="mt-0.5 text-mute text-[10px] uppercase tracking-wider">
                      {o.sector}{o.country ? ' · ' + o.country : ''} · {o.brand_count} brands · {o.subsidiary_count} subs
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </aside>

        {/* right: alerts */}
        <div className="flex-1 overflow-y-auto">
          {!alerts ? (
            <div className="p-4 text-mute text-xs">Select an organization on the left.</div>
          ) : (
            <div>
              <header className="px-4 py-3 border-b border-wire/60 bg-ink-800/40">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-amber font-semibold tracking-wider text-[14px]">{alerts.org.name}</span>
                  {alerts.org.ticker && <span className="chip chip-blue">{alerts.org.ticker}</span>}
                  {alerts.org.sector && <span className="chip">{alerts.org.sector}</span>}
                  {alerts.org.country && <span className="chip">{alerts.org.country}</span>}
                  <span className="ml-auto text-mute text-[10px] uppercase tracking-wider">
                    {alerts.window_days}d window
                  </span>
                </div>
                {Object.keys(alerts.signals).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {Object.entries(alerts.signals).map(([t, n]) => (
                      <span key={t} className={`chip ${tagClass(t)}`}>{t} {n}</span>
                    ))}
                  </div>
                )}
              </header>

              {/* Domain spoofing matches */}
              {spoof && (
                <section>
                  <div className="px-4 pt-3 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80 flex items-center gap-2">
                    Domain spoofing
                    {spoof.matches.length > 0
                      ? <span className="text-cyber-red">{spoof.matches.length}</span>
                      : <span className="text-cyber-green">clean</span>}
                    <span className="text-mute normal-case tracking-normal">
                      {spoof.candidates_scanned.toLocaleString()} candidates scanned · {spoof.org_domains.length} domains
                    </span>
                  </div>
                  {spoof.matches.length > 0 && (
                    <ul className="text-[12px]">
                      {spoof.matches.slice(0, 10).map((m: any, i: number) => (
                        <li key={i} className="px-3 py-1.5 border-b border-wire/40 flex items-center gap-2">
                          <span className="chip chip-red shrink-0">d={m.distance}</span>
                          <code className="text-amber/95">{m.candidate}</code>
                          <span className="text-mute text-[10px] uppercase tracking-wider">~ {m.org_domain}</span>
                          <span className="ml-auto chip">{m.kind}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              )}

              {/* Key executives mentions */}
              {execs && execs.mentions.length > 0 && (
                <section>
                  <div className="px-4 pt-3 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80 flex items-center gap-2">
                    Key-executive mentions
                    <span className="text-mute">{execs.mentions.length}</span>
                  </div>
                  <ul className="text-[12px]">
                    {execs.mentions.slice(0, 8).map((m: any) => (
                      <li key={m.id} className="px-3 py-1.5 border-b border-wire/40">
                        <div className="flex items-start gap-2">
                          <span className="chip chip-purple shrink-0">{m.matched_exec}</span>
                          <a href={safeHref(m.url)} target="_blank" rel="noreferrer noopener" className="text-amber/95 hover:text-amber leading-snug">
                            {m.title}
                          </a>
                          <span className="ml-auto text-mute text-[10px] uppercase tracking-wider">{m.source_name}</span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {/* industry events for this org */}
              {industry && industry.events.length > 0 && (
                <section>
                  <div className="px-4 pt-3 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80 flex items-center gap-2">
                    Industry events
                    <span className="text-mute">{industry.events.length}</span>
                    <span className="flex flex-wrap gap-1 ml-2">
                      {Object.entries(industry.buckets).map(([k, n]) => (
                        <span key={k} className="chip">{k.replace('_', '-')} {n}</span>
                      ))}
                    </span>
                  </div>
                  <ul className="text-[12px]">
                    {industry.events.slice(0, 12).map((it: any) => {
                      const kinds = Object.keys(it.industry || {})
                      const ev = it.industry || {}
                      return (
                        <li key={it.id} className="row-link">
                          <div className="flex items-start gap-2">
                            <span className="shrink-0 w-9 text-right text-mute tabular-nums">{relTime(it.published_at)}</span>
                            <span className="shrink-0 text-cyber-blue/80 w-28 truncate uppercase tracking-wider text-[10px]">
                              {it.source_name}
                            </span>
                            <div className="shrink-0 w-44 flex flex-wrap items-center gap-1">
                              {kinds.map(k => {
                                const cls = k === 'layoff' ? 'chip-red'
                                          : k === 'funding' ? 'chip-green'
                                          : k === 'acquisition' ? 'chip-amber'
                                          : k === 'exec_change' ? 'chip-purple'
                                          : k === 'ipo' ? 'chip-blue'
                                          : k === 'outage' ? 'chip-red'
                                          : 'chip'
                                let detail = ''
                                if (k === 'layoff' && ev.layoff?.headcount) detail = ` ${ev.layoff.headcount.toLocaleString()}`
                                if (k === 'layoff' && ev.layoff?.percent)   detail += ` ${ev.layoff.percent}%`
                                if (k === 'funding' && ev.funding?.amount_usd) {
                                  const a = ev.funding.amount_usd
                                  detail = a >= 1e9 ? ` $${(a/1e9).toFixed(1)}B` : ` $${(a/1e6).toFixed(0)}M`
                                }
                                if (k === 'exec_change' && ev.exec_change?.role) {
                                  detail = ` ${ev.exec_change.role} ${ev.exec_change.direction}`
                                }
                                return <span key={k} className={`chip ${cls}`}>{k.replace('_','-')}{detail}</span>
                              })}
                            </div>
                            <a href={safeHref(it.url)} target="_blank" rel="noreferrer noopener"
                               className="text-amber/95 hover:text-amber leading-snug flex-1">
                              {it.title}
                            </a>
                          </div>
                        </li>
                      )
                    })}
                  </ul>
                </section>
              )}

              {/* direct news alerts */}
              <section>
                <div className="px-4 pt-3 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80 flex items-center gap-2">
                  Direct mentions / keyword hits
                  <span className="text-mute">{alerts.news_alerts.length}</span>
                </div>
                {alerts.news_alerts.length === 0 ? (
                  <div className="px-4 py-2 text-mute text-xs">No news mentions in window.</div>
                ) : (
                  <ul className="text-[12px]">
                    {alerts.news_alerts.map(n => (
                      <li key={n.id} className="row-link">
                        <div className="flex items-start gap-2">
                          <span className={`chip ${priorityClass(n.priority)} shrink-0 w-12 justify-center`}>
                            {severityLabel(n.priority)}
                          </span>
                          <span className="shrink-0 text-mute w-9 text-right tabular-nums">{relTime(n.published_at)}</span>
                          <span className="shrink-0 text-cyber-blue/80 w-28 truncate uppercase tracking-wider text-[10px]">
                            {n.source_name}
                          </span>
                          <a href={safeHref(n.url)} target="_blank" rel="noreferrer noopener" className="text-amber/95 hover:text-amber leading-snug">
                            {n.title}
                          </a>
                        </div>
                        {(n.tags.length > 0 || n.cves.length > 0) && (
                          <div className="mt-1 ml-[88px] flex flex-wrap gap-1">
                            {n.tags.slice(0, 4).map(t => <span key={t} className={`chip ${tagClass(t)}`}>{t}</span>)}
                            {n.cves.slice(0, 3).map(c => (
                              <button key={c} onClick={() => onSelectCVE(c)} className="chip chip-red cursor-pointer">{c}</button>
                            ))}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {/* tech-stack CVE intersection */}
              <section>
                <div className="px-4 pt-3 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80 flex items-center gap-2">
                  Tech-stack vulnerability intersection
                  <span className="text-mute">{alerts.stack_alerts.length}</span>
                </div>
                <table className="w-full text-[12px]">
                  <thead className="sticky top-0 bg-ink-800/95 text-mute uppercase tracking-[0.15em] text-[10px]">
                    <tr>
                      <th className="text-left  px-3 py-1.5 font-normal">CVE</th>
                      <th className="text-left  px-2 py-1.5 font-normal">Flags</th>
                      <th className="text-left  px-2 py-1.5 font-normal">CVSS</th>
                      <th className="text-left  px-2 py-1.5 font-normal">Hits Stack</th>
                      <th className="text-left  px-2 py-1.5 font-normal">Description</th>
                      <th className="text-right px-3 py-1.5 font-normal">KEV Added</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.stack_alerts.map(c => (
                      <tr key={c.cve_id}
                          onClick={() => onSelectCVE(c.cve_id)}
                          className="border-b border-wire/40 cursor-pointer hover:bg-ink-800/70">
                        <td className="px-3 py-1.5 font-medium text-amber/95 whitespace-nowrap">{c.cve_id}</td>
                        <td className="px-2 py-1.5">
                          <div className="flex flex-wrap gap-1">
                            {c.is_kev ? <span className="chip chip-red">KEV</span> : null}
                            {c.kev_ransomware === 'Known' ? <span className="chip chip-amber">RANSOM</span> : null}
                          </div>
                        </td>
                        <td className="px-2 py-1.5 text-cyber-yellow tabular-nums">
                          {c.cvss_score != null ? c.cvss_score.toFixed(1) : '—'}
                        </td>
                        <td className="px-2 py-1.5 text-cyber-blue/90 max-w-[180px] truncate">
                          {c.vendors.join(', ') || '—'}
                        </td>
                        <td className="px-2 py-1.5 text-mute max-w-[420px] truncate">{c.description}</td>
                        <td className="px-3 py-1.5 text-right text-mute tabular-nums whitespace-nowrap">{fmtDate(c.kev_added)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}
