import { useEffect, useState } from 'react'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type { CVEItem } from '../../api/types'
import { Panel } from '../Panel'
import { fmtDate, priorityClass, severityLabel } from '../../lib/format'

type Props = { onSelectCVE: (cve: string) => void; selected?: string; mode?: 'all' | 'kev' }

export function VulnPanel({ onSelectCVE, selected, mode = 'all' }: Props) {
  useEffect(() => trackPanelLifecycle('VulnPanel'), [])
  const [items, setItems] = useState<CVEItem[]>([])
  const [loading, setLoading] = useState(true)
  const [q, setQ] = useState('')
  const [predicted, setPredicted] = useState<any[]>([])

  useEffect(() => {
    let alive = true
    setLoading(true)
    const p = mode === 'kev'
      ? api.kev(200)
      : api.vulns({ limit: 150, q: q || undefined })
    p.then(r => alive && setItems(r.items)).finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [q, mode])

  useEffect(() => {
    if (mode !== 'kev') { setPredicted([]); return }
    api.kevWatch(10).then(r => setPredicted(r.items || [])).catch(() => {})
  }, [mode])

  const filtered = mode === 'kev' && q
    ? items.filter(i => i.cve_id.includes(q.toUpperCase()) || (i.description || '').toLowerCase().includes(q.toLowerCase()))
    : items

  return (
    <Panel
      code={mode === 'kev' ? 'KEV' : 'VULN'}
      title={mode === 'kev' ? 'CISA Known Exploited Vulnerabilities' : 'Vulnerability intelligence'}
      hotkey={mode === 'kev' ? '3' : '2'}
      right={
        <input
          value={q}
          onChange={e => setQ(e.target.value)}
          placeholder="filter CVE / vendor..."
          className="bg-ink-800 border border-wire-strong rounded-sm px-2 py-0.5 text-[11px] text-amber/90 placeholder-mute w-44 focus:outline-none focus:border-amber/50"
        />
      }
    >
      {mode === 'kev' && predicted.length > 0 && (
        <div className="border-b border-amber/20 bg-amber/5 px-3 py-2">
          <div className="text-[10px] uppercase tracking-[0.2em] text-amber/90 mb-1 flex items-center gap-2">
            🔥 Predicted KEV — high EPSS + CVSS, not yet in KEV
            <span className="text-mute">{predicted.length}</span>
          </div>
          <div className="flex flex-wrap gap-1 text-[11px]">
            {predicted.slice(0, 12).map((p: any) => (
              <button key={p.cve_id} onClick={() => onSelectCVE(p.cve_id)}
                className="chip chip-amber cursor-pointer"
                title={`EPSS ${p.epss_score ? (p.epss_score*100).toFixed(1)+'%':'—'} · CVSS ${p.cvss_score} · ${p.news_count} news · conf ${p.predicted_kev_confidence}`}>
                {p.cve_id} · {p.predicted_kev_confidence}
              </button>
            ))}
          </div>
        </div>
      )}
      {loading && filtered.length === 0 ? (
        <div className="p-3 text-mute text-xs">loading...</div>
      ) : (
        <table className="w-full text-[12px]">
          <thead className="sticky top-0 bg-ink-800/95 text-mute uppercase tracking-[0.15em] text-[10px]">
            <tr>
              <th className="text-left  px-3 py-1.5 font-normal">CVE</th>
              <th className="text-left  px-2 py-1.5 font-normal">Prio</th>
              <th className="text-left  px-2 py-1.5 font-normal">CVSS</th>
              <th className="text-left  px-2 py-1.5 font-normal">EPSS</th>
              <th className="text-left  px-2 py-1.5 font-normal">Flags</th>
              <th className="text-left  px-2 py-1.5 font-normal">Vendors</th>
              <th className="text-left  px-2 py-1.5 font-normal">Description</th>
              <th className="text-right px-3 py-1.5 font-normal">Added</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(c => {
              const active = selected && c.cve_id === selected
              return (
                <tr key={c.cve_id}
                    onClick={() => onSelectCVE(c.cve_id)}
                    className={`border-b border-wire/40 cursor-pointer hover:bg-ink-800/70 transition-colors ${active ? 'bg-amber/10' : ''}`}>
                  <td className="px-3 py-1.5 font-medium text-amber/95 whitespace-nowrap">{c.cve_id}</td>
                  <td className="px-2 py-1.5"><span className={`chip ${priorityClass(c.priority)}`}>{severityLabel(c.priority)} {c.priority}</span></td>
                  <td className="px-2 py-1.5 text-cyber-yellow tabular-nums">{c.cvss_score?.toFixed(1) ?? '—'}</td>
                  <td className="px-2 py-1.5 text-cyber-green tabular-nums">{c.epss_score != null ? (c.epss_score * 100).toFixed(1) + '%' : '—'}</td>
                  <td className="px-2 py-1.5">
                    <div className="flex flex-wrap gap-1">
                      {c.is_kev ? <span className="chip chip-red">KEV</span> : null}
                      {c.kev_ransomware === 'Known' ? <span className="chip chip-amber">RANSOM</span> : null}
                      {c.epss_score != null && c.epss_score > 0.5 ? <span className="chip chip-yellow">EPSS&gt;.5</span> : null}
                    </div>
                  </td>
                  <td className="px-2 py-1.5 text-cyber-blue/90 max-w-[160px] truncate">
                    {c.entities?.vendors?.slice(0, 3).map(v => v.name).join(', ') || '—'}
                  </td>
                  <td className="px-2 py-1.5 text-mute max-w-[420px] truncate">{c.description || '—'}</td>
                  <td className="px-3 py-1.5 text-right text-mute whitespace-nowrap tabular-nums">{fmtDate(c.kev_added || c.published_at)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </Panel>
  )
}
