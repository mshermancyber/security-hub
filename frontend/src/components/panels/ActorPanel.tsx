import { useEffect, useState } from 'react'
import { safeHref } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type { ActorWatch, SectorEntry } from '../../api/types'
import { Panel } from '../Panel'
import { priorityClass, relTime, severityLabel, tagClass } from '../../lib/format'

export function ActorPanel() {
  useEffect(() => trackPanelLifecycle('ActorPanel'), [])
  const [actors, setActors] = useState<ActorWatch[]>([])
  const [counts, setCounts] = useState<{ active: number; silent: number }>({ active: 0, silent: 0 })
  const [days, setDays] = useState(30)
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let alive = true
    setLoading(true)
    api.actorWatch(days).then(r => {
      if (!alive) return
      setActors(r.actors)
      setCounts({ active: (r as any).active_count ?? 0, silent: (r as any).silent_count ?? 0 })
    }).finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [days])

  // Active = any signal source (news mentions, ransom postings, or IOC volume).
  const hasSignal = (a: ActorWatch) =>
    (a.mentions ?? 0) > 0 || (a.ransom_postings ?? 0) > 0 || (a.ioc_count ?? 0) > 0
  const active = actors.filter(hasSignal)
  const silent = actors.filter(a => !hasSignal(a))

  return (
    <Panel
      code="ACTORS"
      title="Threat actor activity"
      hotkey="5"
      right={
        <div className="flex items-center gap-1">
          {[14, 30, 90].map(d => (
            <button key={d} onClick={() => setDays(d)}
              className={`chip cursor-pointer ${d === days ? 'chip-amber' : ''}`}>{d}D</button>
          ))}
        </div>
      }
    >
      {loading ? <div className="p-3 text-mute text-xs">loading...</div> : (
        <div className="text-[12px]">
          <div className="px-3 py-1.5 text-[10px] uppercase tracking-[0.2em] text-amber/80 border-b border-wire/40 bg-ink-800/30 flex items-center gap-2">
            Active <span className="text-mute">{counts.active}</span>
            {counts.silent > 0 && (
              <span className="ml-auto text-mute">silent {counts.silent}</span>
            )}
          </div>
          {active.length === 0 ? (
            <div className="p-3 text-mute text-xs">No tracked actor mentions in window.</div>
          ) : (
        <ul>
          {active.map(a => (
            <li key={a.id} className="px-3 py-2 border-b border-wire/40">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-amber/95 font-medium">{a.name}</span>
                {a.attack_id && (
                  <a href={safeHref(`https://attack.mitre.org/groups/${encodeURIComponent(a.attack_id)}/`)} target="_blank" rel="noreferrer noopener"
                     className="chip chip-blue hover:bg-cyber-blue/20" title="MITRE ATT&CK">
                    {a.attack_id}
                  </a>
                )}
                {a.type && <span className="chip chip-purple">{a.type}</span>}
                {a.origin && a.origin !== 'UNK' && <span className="chip">{a.origin}</span>}
                {(a.max_priority ?? 0) > 0 && (
                  <span className={`chip ${priorityClass(a.max_priority)}`}>{severityLabel(a.max_priority)}</span>
                )}
                <span className="ml-auto flex items-center gap-2 text-[11px]">
                  {(a.mentions ?? 0) > 0 && <span className="text-mute">{a.mentions} news</span>}
                  {(a.ransom_postings ?? 0) > 0 && (
                    <span className="text-cyber-red">{a.ransom_postings} ransom victims</span>
                  )}
                  {(a.ioc_count ?? 0) > 0 && (
                    <span className="text-cyber-purple">{a.ioc_count} IOCs</span>
                  )}
                </span>
              </div>
              {Object.keys(a.tags).length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {Object.entries(a.tags).slice(0, 5).map(([t, n]) => (
                    <span key={t} className={`chip ${tagClass(t)}`}>{t} {n}</span>
                  ))}
                </div>
              )}
              {(a.ransom_victims ?? []).length > 0 && (
                <div className="mt-1 ml-2 text-[11px]">
                  <span className="text-mute uppercase tracking-wider text-[9px]">recent victims · </span>
                  <span className="text-cyber-red/90">{(a.ransom_victims ?? []).slice(0, 5).join(' · ')}</span>
                </div>
              )}
              {a.latest.length > 0 && (
                <ul className="mt-1 space-y-0.5">
                  {a.latest.slice(0, 3).map(n => (
                    <li key={n.id} className="flex gap-2 items-baseline">
                      <span className="text-mute text-[10px] w-9 tabular-nums">{relTime(n.published_at)}</span>
                      <a href={safeHref(n.url)} target="_blank" rel="noreferrer noopener" className="text-amber/85 hover:text-amber leading-snug">
                        {n.title}
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
          )}
          {silent.length > 0 && (
            <>
              <div className="px-3 py-1.5 mt-2 text-[10px] uppercase tracking-[0.2em] text-mute border-y border-wire/40 bg-ink-800/20">
                Silent — {silent.length} tracked actors with 0 mentions in window
              </div>
              <div className="px-3 py-2 flex flex-wrap gap-1">
                {silent.map(a => (
                  <span key={a.id} className="chip" title={`${a.type || ''} ${a.origin || ''}`}>{a.name}</span>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </Panel>
  )
}


type SectorPanelProps = {
  onSelectSector?: (id: string, name: string, tag?: string) => void
}

export function SectorPanel({ onSelectSector }: SectorPanelProps = {}) {
  useEffect(() => trackPanelLifecycle('SectorPanel'), [])
  const [sectors, setSectors] = useState<SectorEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [showEmpty, setShowEmpty] = useState(false)
  useEffect(() => {
    let alive = true
    api.sectorWatch(30).then(r => alive && setSectors(r.sectors)).finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [])

  // Don't show sectors with 0 mentions by default — they're noise.
  const visible = showEmpty ? sectors : sectors.filter(s => s.mentions > 0)
  const max = Math.max(1, ...sectors.map(s => s.mentions))

  return (
    <Panel code="SECTOR" title="Sector heatmap (30d targeting signal)" hotkey="6"
      right={
        <button onClick={() => setShowEmpty(v => !v)}
                className={`chip cursor-pointer ${showEmpty ? 'chip-amber' : ''}`}>
          {showEmpty ? 'hide silent' : 'show all'}
        </button>
      }>
      {loading ? <div className="p-3 text-mute text-xs">loading...</div> : visible.length === 0 ? (
        <div className="p-3 text-mute text-xs">No sector mentions in window. Click "show all" to see tracked sectors.</div>
      ) : (
        <ul className="text-[12px]">
          {visible.map(s => {
            const w = Math.round((s.mentions / max) * 100)
            const clickable = onSelectSector && s.mentions > 0
            return (
              <li key={s.id}
                  onClick={clickable ? () => onSelectSector!(s.id, s.name) : undefined}
                  className={`px-3 py-2 border-b border-wire/40 ${clickable ? 'cursor-pointer hover:bg-ink-800/70' : ''}`}
                  title={clickable ? `Click → news in ${s.name}` : undefined}>
                <div className="flex items-center gap-3">
                  <span className="w-32 text-amber/95">{s.name}</span>
                  <div className="flex-1 h-2 bg-ink-800 relative overflow-hidden">
                    <div className="absolute inset-y-0 left-0 bg-gradient-to-r from-amber/80 to-cyber-red/80"
                         style={{ width: `${w}%` }} />
                  </div>
                  <span className="text-mute tabular-nums w-10 text-right">{s.mentions}</span>
                </div>
                {(s.ransomware > 0 || s.breaches > 0) && (
                  <div className="mt-1 ml-32 flex gap-1">
                    {s.ransomware > 0 && (
                      <button
                        type="button"
                        onClick={(e) => {
                          // Don't bubble up to the row click (which navigates
                          // to the sector with no tag filter).
                          e.stopPropagation()
                          onSelectSector?.(s.id, s.name, 'ransomware')
                        }}
                        title={`Open ${s.ransomware} ransomware article${s.ransomware === 1 ? '' : 's'} for ${s.name}`}
                        className="chip chip-amber cursor-pointer hover:bg-cyber-amber/30">
                        RANSOM {s.ransomware}
                      </button>
                    )}
                    {s.breaches > 0 && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          onSelectSector?.(s.id, s.name, 'breach')
                        }}
                        title={`Open ${s.breaches} breach article${s.breaches === 1 ? '' : 's'} for ${s.name}`}
                        className="chip chip-red cursor-pointer hover:bg-cyber-red/30">
                        BREACH {s.breaches}
                      </button>
                    )}
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}
