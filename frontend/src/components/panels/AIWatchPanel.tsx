import { useEffect, useState } from 'react'
import { safeHref } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type { AICompanyWatch } from '../../api/types'
import { Panel } from '../Panel'
import { priorityClass, relTime, severityLabel, tagClass } from '../../lib/format'

export function AIWatchPanel() {
  useEffect(() => trackPanelLifecycle('AIWatchPanel'), [])
  const [companies, setCompanies] = useState<AICompanyWatch[]>([])
  const [days, setDays] = useState(14)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    let alive = true
    // Only show the full loading state on the FIRST fetch (when we have
    // nothing yet). Subsequent refreshes (e.g. clicking 7D/14D/30D) keep
    // the existing list visible to avoid a blank flicker.
    if (companies.length === 0) setLoading(true); else setRefreshing(true)
    api.aiWatch(days)
      .then(r => { if (alive) setCompanies(r.companies) })
      .finally(() => { if (alive) { setLoading(false); setRefreshing(false) } })
    return () => { alive = false }
  // companies.length intentionally NOT in deps — we only want the
  // "first-load" branch on initial mount.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days])

  const tracked = companies.filter(c => c.mentions > 0)
  const silent = companies.filter(c => c.mentions === 0)

  return (
    <Panel
      code="AIWATCH"
      title="AI company intelligence"
      hotkey="4"
      right={
        <div className="flex items-center gap-1">
          {refreshing && <span className="chip text-mute">refreshing…</span>}
          {[7, 14, 30].map(d => (
            <button key={d} onClick={() => setDays(d)}
              className={`chip cursor-pointer ${d === days ? 'chip-amber' : ''}`}>{d}D</button>
          ))}
        </div>
      }
    >
      {loading && companies.length === 0 ? <div className="p-3 text-mute text-xs">loading...</div> : (
        <div className="text-[12px]">
          <table className="w-full">
            <thead className="sticky top-0 bg-ink-800/95 text-mute uppercase tracking-[0.15em] text-[10px]">
              <tr>
                <th className="text-left  px-3 py-1.5 font-normal">Company</th>
                <th className="text-left  px-2 py-1.5 font-normal">Mentions</th>
                <th className="text-left  px-2 py-1.5 font-normal">Max Severity</th>
                <th className="text-left  px-2 py-1.5 font-normal">Signals</th>
                <th className="text-left  px-2 py-1.5 font-normal">Latest Headlines</th>
              </tr>
            </thead>
            <tbody>
              {tracked.map(c => (
                <tr key={c.id} className="border-b border-wire/40 align-top">
                  <td className="px-3 py-2 whitespace-nowrap">
                    <div className="text-amber/95 font-medium">{c.name}</div>
                    <div className="text-mute text-[10px] uppercase tracking-wider">{c.category}</div>
                  </td>
                  <td className="px-2 py-2 text-cyber-blue tabular-nums">{c.mentions}</td>
                  <td className="px-2 py-2">
                    <span className={`chip ${priorityClass(c.max_priority)}`}>
                      {severityLabel(c.max_priority)} {c.max_priority}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex flex-wrap gap-1 max-w-[140px]">
                      {Object.entries(c.tags).slice(0, 5).map(([t, n]) => (
                        <span key={t} className={`chip ${tagClass(t)}`}>{t} {n}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-2 py-2">
                    <ul className="space-y-1">
                      {c.latest.slice(0, 3).map(n => (
                        <li key={n.id} className="flex gap-2 items-baseline">
                          <span className="text-mute text-[10px] w-9 tabular-nums">{relTime(n.published_at)}</span>
                          <a href={safeHref(n.url)} target="_blank" rel="noreferrer noopener" className="text-amber/85 hover:text-amber leading-snug">
                            {n.title}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-3 py-2 text-mute uppercase tracking-[0.15em] text-[10px] border-b border-wire/40">
            silent — {silent.length} tracked, 0 mentions in window
          </div>
          <div className="px-3 py-2 flex flex-wrap gap-1">
            {silent.map(c => (
              <span key={c.id} className="chip">{c.name}</span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  )
}
