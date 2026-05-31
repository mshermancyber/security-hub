import { useEffect, useState } from 'react'
import { safeHref } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type { CVEItem, Narrative } from '../../api/types'
import { Panel } from '../Panel'
import { fmtDate, priorityClass, severityLabel, tagClass } from '../../lib/format'
import { NarrativeGraph } from '../NarrativeGraph'

type AISummary = {
  body?: string
  sources?: { n: number; kind: string; label: string; url?: string }[]
  cached?: boolean
  provider?: string
  model?: string
  needs_llm?: boolean
  hint?: string
  error?: string
  detail?: string
}

type Props = {
  selected?: string
  onSelect: (cve: string) => void
  onGraphEntity?: (kind: 'sector'|'org'|'vendor'|'actor', id: string, name: string) => void
}

export function NarrativePanel({ selected, onSelect, onGraphEntity }: Props) {
  useEffect(() => trackPanelLifecycle('NarrativePanel'), [])
  const [items, setItems] = useState<CVEItem[]>([])
  const [active, setActive] = useState<Narrative | null>(null)
  const [ai, setAi] = useState<AISummary | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [view, setView] = useState<'timeline' | 'graph'>('timeline')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    api.narratives(15).then(r => {
      if (!alive) return
      setItems(r.items)
      const initial = selected || r.items[0]?.cve_id
      if (initial) {
        onSelect(initial)
      }
    }).finally(() => alive && setLoading(false))
    return () => { alive = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!selected) { setActive(null); setAi(null); return }
    let alive = true
    api.narrative(selected).then(r => alive && setActive(r))
    setAi(null)
    setAiLoading(true)
    fetch(`/api/ai/narrative/${encodeURIComponent(selected)}`).then(r => r.json())
      .then(d => alive && setAi(d))
      .finally(() => alive && setAiLoading(false))
    return () => { alive = false }
  }, [selected])

  const regenAI = async () => {
    if (!selected) return
    setAiLoading(true)
    try {
      const r = await fetch(`/api/ai/narrative/${encodeURIComponent(selected)}?force=true`).then(r => r.json())
      setAi(r)
    } finally {
      setAiLoading(false)
    }
  }

  return (
    <Panel code="NARRATIVE" title={selected ? `Threat narrative · ${selected}` : 'Threat narrative engine'} hotkey="7">
      <div className="flex h-full">
        {/* left rail: top narratives */}
        <div className="w-64 shrink-0 border-r border-wire/60 overflow-y-auto">
          {loading && items.length === 0 ? (
            <div className="p-3 text-mute text-xs">loading...</div>
          ) : (
            <ul className="text-[12px]">
              {items.map(c => {
                const isActive = c.cve_id === selected
                return (
                  <li key={c.cve_id}
                      onClick={() => onSelect(c.cve_id)}
                      className={`row-link ${isActive ? 'active' : ''}`}>
                    <div className="flex items-center gap-2">
                      <span className="text-amber/95 font-medium">{c.cve_id}</span>
                      <span className={`chip ${priorityClass(c.priority)}`}>{severityLabel(c.priority)}</span>
                      {c.is_kev ? <span className="chip chip-red">KEV</span> : null}
                    </div>
                    <div className="mt-0.5 text-mute text-[11px] line-clamp-2">{c.description}</div>
                    <div className="mt-0.5 text-mute text-[10px]">
                      {c.news_count || 0} mentions
                      {c.cvss_score ? ` · CVSS ${c.cvss_score.toFixed(1)}` : ''}
                      {c.epss_score != null ? ` · EPSS ${(c.epss_score * 100).toFixed(0)}%` : ''}
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </div>

        {/* right: timeline */}
        <div className="flex-1 overflow-y-auto">
          {!active || !active.cve ? (
            <div className="p-4 text-mute text-xs">Select a CVE on the left to view the timeline.</div>
          ) : (
            <div>
              <div className="p-4 pb-3 border-b border-wire/40">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-amber font-semibold tracking-wider">{active.cve.cve_id}</span>
                  <span className={`chip ${priorityClass(active.cve.priority)}`}>
                    PRIO {active.cve.priority}
                  </span>
                  {active.cve.cvss_score != null && <span className="chip chip-yellow">CVSS {active.cve.cvss_score.toFixed(1)}</span>}
                  {active.cve.epss_score != null && <span className="chip chip-green">EPSS {(active.cve.epss_score * 100).toFixed(1)}%</span>}
                  {active.cve.is_kev ? <span className="chip chip-red">KEV</span> : null}
                  {active.cve.kev_ransomware === 'Known' ? <span className="chip chip-amber">RANSOMWARE USE</span> : null}
                  <div className="ml-auto flex items-center gap-1">
                    <button onClick={() => setView('timeline')}
                      className={`chip cursor-pointer ${view === 'timeline' ? 'chip-amber' : ''}`}>TIMELINE</button>
                    <button onClick={() => setView('graph')}
                      className={`chip cursor-pointer ${view === 'graph' ? 'chip-amber' : ''}`}>GRAPH</button>
                  </div>
                </div>
                <p className="mt-2 text-[12px] text-mute leading-relaxed">{active.cve.description}</p>
                {active.cve.entities && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {active.cve.entities.vendors?.map(v => <span key={v.id} className="chip chip-blue">{v.name}</span>)}
                  </div>
                )}
              </div>

              {/* AI summary */}
              <div className="px-4 py-3 border-b border-wire/40 bg-ink-800/30">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[10px] uppercase tracking-[0.2em] text-amber/80">AI Brief</span>
                  {ai?.provider && <span className="chip">{ai.provider}{ai.model ? ` · ${ai.model}` : ''}</span>}
                  {ai?.cached && <span className="chip chip-blue">CACHED</span>}
                  <button onClick={regenAI} disabled={aiLoading}
                    className="chip chip-amber cursor-pointer ml-auto">
                    {aiLoading ? '…' : 'REGEN'}
                  </button>
                </div>
                {ai?.needs_llm ? (
                  <div className="text-mute text-[11px] leading-relaxed">
                    {ai.hint}<br />
                    Examples: <code className="text-amber/80">SECHUB_LLM_BASE_URL=https://api.openai.com/v1</code> ·
                    <code className="text-amber/80"> SECHUB_LLM_BASE_URL=https://api.anthropic.com/v1</code> ·
                    <code className="text-amber/80"> SECHUB_LLM_BASE_URL=http://localhost:11434/v1</code>
                  </div>
                ) : ai?.error ? (
                  <div className="text-cyber-red text-[11px]">LLM error: {ai.detail || ai.error}</div>
                ) : ai?.body ? (
                  <div className="text-amber/90 text-[12px] leading-relaxed whitespace-pre-wrap">{ai.body}</div>
                ) : aiLoading ? (
                  <div className="text-mute text-[11px]">generating…</div>
                ) : (
                  <div className="text-mute text-[11px]">no summary yet</div>
                )}
                {ai?.sources && ai.sources.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1 text-[10px]">
                    {ai.sources.slice(0, 8).map(s => (
                      <a key={s.n} href={safeHref(s.url)} target="_blank" rel="noreferrer noopener"
                         className="chip chip-blue hover:bg-cyber-blue/20">
                        [{s.n}] {s.kind} · {s.label.length > 32 ? s.label.slice(0, 32) + '…' : s.label}
                      </a>
                    ))}
                  </div>
                )}
              </div>

              {view === 'graph' ? (
                <NarrativeGraph cveId={active.cve.cve_id} onSelectEntity={onGraphEntity} />
              ) : (
                <div className="p-4">
              <div className="text-[10px] uppercase tracking-[0.2em] text-mute mb-2">timeline</div>
              <ol className="relative border-l border-wire-strong ml-1 pl-4 space-y-3 text-[12px]">
                {active.timeline.map((ev, i) => (
                  <li key={i} className="relative">
                    <span className={`absolute -left-[19px] top-1 w-2 h-2 rounded-full
                      ${ev.kind === 'kev_added' ? 'bg-cyber-red' :
                        ev.kind === 'cve_published' ? 'bg-amber' :
                        'bg-cyber-blue'}`} />
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span className="text-mute text-[10px] tabular-nums w-32">{fmtDate(ev.at)}</span>
                      <span className="chip uppercase tracking-wider">{ev.kind.replace('_', ' ')}</span>
                      {ev.source && <span className="text-cyber-blue/80 text-[10px] uppercase tracking-wider">{ev.source}</span>}
                    </div>
                    <div className="mt-0.5">
                      {ev.url ? (
                        <a href={safeHref(ev.url)} target="_blank" rel="noreferrer noopener" className="text-amber/95 hover:text-amber">
                          {ev.title}
                        </a>
                      ) : (
                        <span className="text-amber/95">{ev.title}</span>
                      )}
                    </div>
                    {ev.detail && <div className="text-mute text-[11px] mt-0.5">{ev.detail}</div>}
                    {ev.tags && ev.tags.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {ev.tags.slice(0, 5).map(t => <span key={t} className={`chip ${tagClass(t)}`}>{t}</span>)}
                      </div>
                    )}
                  </li>
                ))}
              </ol>
            </div>
              )}
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}
