import { useEffect, useState } from 'react'
import { api } from '../api/client'

type Props = {
  onOpenPalette: () => void
  active: string
  onJump: (panel: string) => void
}

type Weather = { city: string; temp_f: number | null; condition: string | null; icon: string | null }

const NAV = [
  { id: 'news',       label: 'NEWS',      key: '1' },
  { id: 'vulns',      label: 'VULN',      key: '2' },
  { id: 'kev',        label: 'KEV',       key: '3' },
  { id: 'aiwatch',    label: 'AI WATCH',  key: '4' },
  { id: 'actors',     label: 'ACTORS',    key: '5' },
  { id: 'sectors',    label: 'SECTORS',   key: '6' },
  { id: 'narrative',  label: 'NARRATIVE', key: '7' },
  { id: 'orgs',       label: 'ORGS',      key: '8' },
  { id: 'industry',   label: 'INDUSTRY',  key: '9' },
  { id: 'integrations', label: 'PIPE',    key: '0' },
  { id: 'patches',    label: 'PATCHES', key: '-' },
]

const _tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
const _timeFmt = new Intl.DateTimeFormat(undefined, {
  hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true,
  timeZone: _tz,
})
const _dateFmt = new Intl.DateTimeFormat(undefined, {
  year: 'numeric', month: '2-digit', day: '2-digit',
  timeZone: _tz,
})

export function Header({ onOpenPalette, active, onJump }: Props) {
  const [clock, setClock] = useState(() => new Date())
  const [wx, setWx] = useState<Weather | null>(null)
  useEffect(() => {
    const t = setInterval(() => setClock(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    api.weather(_tz).then(setWx).catch(() => {})
    const t = setInterval(() => api.weather(_tz).then(setWx).catch(() => {}), 30 * 60_000)
    return () => clearInterval(t)
  }, [])
  return (
    <header className="h-10 shrink-0 flex items-stretch bg-ink-900 border-b border-wire">
      <div className="flex items-center gap-2 px-3 border-r border-wire">
        <div className="w-2 h-2 rounded-full bg-amber animate-pulseDot" />
        <span className="text-amber font-bold tracking-[0.22em] text-[12px]">SECURITY//HUB</span>
        <span className="chip chip-amber">TERMINAL</span>
      </div>
      <nav className="flex items-stretch text-[11px]">
        {NAV.map(n => (
          <button
            key={n.id}
            onClick={() => onJump(n.id)}
            className={`px-3 flex items-center gap-2 border-r border-wire hover:bg-ink-800 transition-colors
              ${active === n.id ? 'text-amber bg-amber/5' : 'text-mute'}`}
          >
            <span className="kbd">{n.key}</span>
            <span className="tracking-[0.18em]">{n.label}</span>
          </button>
        ))}
      </nav>
      <button
        onClick={onOpenPalette}
        className="ml-auto px-3 flex items-center gap-2 text-[11px] text-mute border-l border-wire hover:bg-ink-800"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="7" />
          <path d="m21 21-4.3-4.3" />
        </svg>
        <span className="tracking-wider">SEARCH / COMMAND</span>
        <span className="kbd">⌘K</span>
      </button>
      {wx && wx.temp_f != null && (
        <div className="px-3 border-l border-wire flex items-center text-[11px] gap-2">
          <span className="text-mute">{wx.city}</span>
          <span className="text-amber/80">{wx.icon} {Math.round(wx.temp_f)}°F</span>
        </div>
      )}
      <div className="px-3 border-l border-wire flex items-center text-mute text-[11px] gap-3">
        <span className="text-cyber-green animate-pulseDot">●</span>
        <span className="font-medium text-amber/90">
          {_dateFmt.format(clock)} {_timeFmt.format(clock)}
        </span>
      </div>
    </header>
  )
}
