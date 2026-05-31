import { useEffect, useState } from 'react'
import { trackPanelLifecycle } from '../../lib/debug'
import { Panel } from '../Panel'
import { relTime } from '../../lib/format'

type Sink = {
  id: string
  kind: string
  configured: boolean
  env_key: string
  delivered: number
  errors: number
  last_error: string | null
  last_at: string | null
}
type Rule = { id: string; enabled?: boolean; match: any; sink?: string; sinks?: string[]; target?: string }
type Health = { sinks: Sink[]; rules: Rule[] }

type IocStats = { total: number; by_type: Record<string, number>; top_malware: { malware_printable: string; n: number }[] }

export function IntegrationsPanel() {
  useEffect(() => trackPanelLifecycle('IntegrationsPanel'), [])
  const [health, setHealth] = useState<Health | null>(null)
  const [iocs, setIocs] = useState<IocStats | null>(null)
  const [iocList, setIocList] = useState<any[]>([])
  const [iocType, setIocType] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const refresh = () => {
    fetch('/api/integrations/health').then(r => r.json()).then(setHealth).catch(() => {})
    fetch('/api/integrations/iocs/stats').then(r => r.json()).then(setIocs).catch(() => {})
  }
  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 8000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const p = new URLSearchParams({ limit: '60' })
    if (iocType) p.set('ioc_type', iocType)
    fetch(`/api/integrations/iocs?${p}`).then(r => r.json()).then(d => setIocList(d.items || [])).catch(() => {})
  }, [iocType])

  const fireTest = async (sinkId: string) => {
    setBusy(sinkId)
    try { await fetch(`/api/integrations/fire-test/${encodeURIComponent(sinkId)}`, { method: 'POST' }) } catch {}
    setBusy(null)
    refresh()
  }

  return (
    <Panel code="INTEGRATIONS" title="Distribution & enrichment" hotkey="0"
      right={
        <div className="flex items-center gap-1">
          <a href="/api/digest/daily?hours=24" target="_blank" rel="noreferrer noopener" className="chip chip-amber cursor-pointer">DIGEST 24h</a>
          <a href="/api/digest/daily?hours=168" target="_blank" rel="noreferrer noopener" className="chip cursor-pointer">7D</a>
          <a href="/m" target="_blank" rel="noreferrer noopener" className="chip chip-blue cursor-pointer">MOBILE</a>
        </div>
      }>
      <div className="flex h-full">
        {/* Sinks + rules */}
        <aside className="w-[420px] shrink-0 border-r border-wire/60 overflow-y-auto">
          <section>
            <div className="px-3 py-2 text-[10px] uppercase tracking-[0.2em] text-amber/80 border-b border-wire/40">Sinks</div>
            <ul className="text-[12px]">
              {health?.sinks.map(s => (
                <li key={s.id} className="px-3 py-2 border-b border-wire/40">
                  <div className="flex items-center gap-2">
                    <span className={`inline-block w-2 h-2 rounded-full ${s.configured ? 'bg-cyber-green' : 'bg-mute-deep'}`} />
                    <span className="text-amber/95 font-medium">{s.id}</span>
                    <span className="text-mute text-[10px] uppercase">{s.kind}</span>
                    <button
                      disabled={!s.configured || busy === s.id}
                      onClick={() => fireTest(s.id)}
                      className={`ml-auto chip ${s.configured ? 'chip-amber cursor-pointer' : 'opacity-50 cursor-not-allowed'}`}>
                      {busy === s.id ? '…' : 'TEST'}
                    </button>
                  </div>
                  <div className="mt-1 text-[10px] text-mute">
                    env: <code className="text-mute">{s.env_key || '—'}</code>
                  </div>
                  <div className="mt-1 flex gap-2 text-[10px]">
                    <span className="text-cyber-green">✓ {s.delivered}</span>
                    <span className="text-cyber-red">✗ {s.errors}</span>
                    <span className="text-mute ml-auto">{relTime(s.last_at)}</span>
                  </div>
                  {s.last_error && (
                    <div className="mt-1 text-[10px] text-cyber-red/80 break-all">{s.last_error}</div>
                  )}
                </li>
              ))}
            </ul>
          </section>
          <section>
            <div className="px-3 py-2 text-[10px] uppercase tracking-[0.2em] text-amber/80 border-b border-wire/40">Routing rules</div>
            <ul className="text-[12px]">
              {health?.rules.map(r => (
                <li key={r.id} className="px-3 py-2 border-b border-wire/40">
                  <div className="flex items-center gap-2">
                    <span className={`chip ${r.enabled ? 'chip-green' : 'chip'}`}>{r.enabled ? 'ON' : 'OFF'}</span>
                    <span className="text-amber/95">{r.id}</span>
                  </div>
                  <div className="mt-1 text-[10px] text-mute">
                    match: <code className="text-mute">{JSON.stringify(r.match)}</code><br />
                    sink: <code className="text-mute">{r.sinks?.join(', ') || r.sink || '—'}</code>
                    {r.target ? <> · target: <code className="text-mute">{r.target}</code></> : null}
                  </div>
                </li>
              ))}
            </ul>
            <div className="px-3 py-2 text-[10px] text-mute border-b border-wire/40">
              Edit <code>backend/app/taxonomy/routing.json</code> to add rules. Hot-reloaded.
            </div>
          </section>
        </aside>

        {/* IOCs */}
        <div className="flex-1 overflow-y-auto">
          <header className="px-4 py-2 border-b border-wire/60 bg-ink-800/40 flex items-center gap-2 flex-wrap">
            <span className="text-amber font-semibold text-[13px]">Threat-intel IOCs</span>
            <span className="text-mute text-[10px] uppercase tracking-wider">abuse.ch ThreatFox</span>
            {iocs && <span className="chip chip-amber ml-auto">TOTAL {iocs.total.toLocaleString()}</span>}
          </header>
          {iocs && (
            <div className="px-4 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
              <button onClick={() => setIocType(null)}
                className={`chip cursor-pointer ${!iocType ? 'chip-amber' : ''}`}>ALL</button>
              {Object.entries(iocs.by_type).map(([t, n]) => (
                <button key={t} onClick={() => setIocType(t === iocType ? null : t)}
                  className={`chip cursor-pointer ${iocType === t ? 'chip-blue' : ''}`}>
                  {t} {n.toLocaleString()}
                </button>
              ))}
              <span className="text-mute ml-2">top malware:</span>
              {iocs.top_malware.slice(0, 6).map(m => (
                <span key={m.malware_printable} className="chip chip-purple">
                  {m.malware_printable} {m.n}
                </span>
              ))}
            </div>
          )}
          <table className="w-full text-[12px]">
            <thead className="sticky top-0 bg-ink-800/95 text-mute uppercase tracking-[0.15em] text-[10px]">
              <tr>
                <th className="text-left px-3 py-1.5 font-normal">IOC</th>
                <th className="text-left px-2 py-1.5 font-normal">Type</th>
                <th className="text-left px-2 py-1.5 font-normal">Malware</th>
                <th className="text-left px-2 py-1.5 font-normal">Threat</th>
                <th className="text-left px-2 py-1.5 font-normal">Confidence</th>
                <th className="text-right px-3 py-1.5 font-normal">First seen</th>
              </tr>
            </thead>
            <tbody>
              {iocList.map(i => (
                <tr key={i.id} className="border-b border-wire/40 hover:bg-ink-800/70">
                  <td className="px-3 py-1.5 text-amber/95 font-medium max-w-[280px] truncate" title={i.ioc_value}>
                    <code>{i.ioc_value}</code>
                  </td>
                  <td className="px-2 py-1.5"><span className="chip chip-blue">{i.ioc_type}</span></td>
                  <td className="px-2 py-1.5 text-cyber-purple">{i.malware_printable || '—'}</td>
                  <td className="px-2 py-1.5 text-mute">{i.threat_type || '—'}</td>
                  <td className="px-2 py-1.5 text-cyber-green tabular-nums">{i.confidence ?? '—'}</td>
                  <td className="px-3 py-1.5 text-right text-mute tabular-nums whitespace-nowrap">{relTime(i.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  )
}
