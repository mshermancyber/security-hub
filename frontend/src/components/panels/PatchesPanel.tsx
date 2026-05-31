import { useEffect, useState } from 'react'
import { safeHref } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import { Panel } from '../Panel'
import { fmtDate, priorityClass, relTime, severityLabel } from '../../lib/format'

type Vendor = string


export function PatchesPanel() {
  useEffect(() => trackPanelLifecycle('PatchesPanel'), [])
  const [vendor, setVendor] = useState<Vendor>('microsoft')
  const [days, setDays] = useState(60)
  const [data, setData] = useState<any>(null)
  const [summary, setSummary] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    api.patchSummary(90).then(r => alive && setSummary(r)).catch(() => {})
    return () => { alive = false }
  }, [])

  useEffect(() => {
    let alive = true
    setLoading(true)
    api.patches(vendor, days)
      .then(r => alive && setData(r))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [vendor, days])

  const groups = data?.groups || []

  return (
    <Panel code="PATCHES" title="Vendor advisory feed" hotkey="-"
      right={
        <div className="flex items-center gap-1">
          {summary?.vendors?.map((v: any) => (
            <button key={v.vendor} onClick={() => setVendor(v.vendor)}
              className={`chip cursor-pointer ${vendor === v.vendor ? 'chip-amber' : ''}`}
              title={v.latest ? `latest ${relTime(v.latest)}` : 'no recent advisories'}>
              {v.label.toUpperCase()} {v.count}
            </button>
          ))}
          <span className="kbd ml-2">|</span>
          {[30, 60, 90, 180].map(d => (
            <button key={d} onClick={() => setDays(d)}
              className={`chip cursor-pointer ${d === days ? 'chip-amber' : ''}`}>{d}D</button>
          ))}
        </div>
      }>
      {loading && !data ? (
        <div className="p-3 text-mute text-xs">loading…</div>
      ) : groups.length === 0 ? (
        <div className="p-3 text-mute text-xs">No advisories in window. Force refresh: <code>/api/admin/refresh/msrc</code></div>
      ) : (
        <div className="text-[12px]">
          {groups.map((g: any) => (
            <section key={g.month}>
              <div className="px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-amber/80 border-b border-wire/40 bg-ink-800/30 sticky top-0 flex items-center gap-2">
                {g.month}
                <span className="text-mute">{g.count} advisories</span>
              </div>
              <ul>
                {g.items.map((it: any) => {
                  const cves: string[] = it.cves || []
                  return (
                    <li key={it.id} className="row-link">
                      <div className="flex items-start gap-2">
                        <span className={`chip ${priorityClass(it.priority)} shrink-0 w-12 justify-center`}>
                          {severityLabel(it.priority)}
                        </span>
                        <span className="shrink-0 text-mute w-9 text-right tabular-nums">{relTime(it.published_at)}</span>
                        <a href={safeHref(it.url)} target="_blank" rel="noreferrer noopener" className="text-amber/95 hover:text-amber leading-snug flex-1">
                          {it.title}
                        </a>
                        <span className="text-mute text-[10px] tabular-nums whitespace-nowrap">{fmtDate(it.published_at).slice(0,10)}</span>
                      </div>
                      {cves.length > 0 && (
                        <div className="mt-1 ml-[88px] flex flex-wrap gap-1">
                          {cves.slice(0, 6).map(c => (
                            <span key={c} className="chip chip-red">{c}</span>
                          ))}
                          {cves.length > 6 && <span className="chip">+{cves.length - 6} more</span>}
                        </div>
                      )}
                    </li>
                  )
                })}
              </ul>
            </section>
          ))}
        </div>
      )}
    </Panel>
  )
}
