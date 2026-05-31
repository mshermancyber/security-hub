import { useEffect, useRef, useState } from 'react'
import { openExternal } from '../lib/safeUrl'
import { api } from '../api/client'
import type { CVEItem, NewsItem } from '../api/types'

type Cmd = { id: string; label: string; hint: string; action: () => void; kind: 'cmd' | 'entity' | 'news' | 'cve' }

type Props = {
  open: boolean
  onClose: () => void
  onJump: (panel: string, filter?: string) => void
  onSelectCVE: (cve: string) => void
}

const QUICK_COMMANDS: { match: RegExp; build: (m: RegExpMatchArray) => Cmd }[] = [
  {
    match: /^cve\s+(.+)/i,
    build: (m) => ({
      id: 'cmd:cve',
      kind: 'cmd',
      label: `Filter vulnerabilities → "${m[1]}"`,
      hint: 'panel: VULN',
      action: () => {},
    }),
  },
  {
    match: /^ransomware(?:\s+(.+))?$/i,
    build: () => ({
      id: 'cmd:ransom',
      kind: 'cmd',
      label: 'News → tag:ransomware',
      hint: 'panel: NEWS',
      action: () => {},
    }),
  },
  {
    match: /^ai\s+(.+)/i,
    build: (m) => ({
      id: 'cmd:ai',
      kind: 'cmd',
      label: `AI watch → ${m[1]}`,
      hint: 'panel: AIWATCH',
      action: () => {},
    }),
  },
  {
    match: /^exploit(s)?(\s+today)?$/i,
    build: () => ({
      id: 'cmd:exploit',
      kind: 'cmd',
      label: 'Active exploitation today',
      hint: 'panel: NEWS',
      action: () => {},
    }),
  },
]

export function CommandPalette({ open, onClose, onJump, onSelectCVE }: Props) {
  const [q, setQ] = useState('')
  const [news, setNews] = useState<NewsItem[]>([])
  const [cves, setCves] = useState<CVEItem[]>([])
  const [entities, setEntities] = useState<any[]>([])
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setQ('')
      setActive(0)
      setTimeout(() => inputRef.current?.focus(), 10)
    }
  }, [open])

  useEffect(() => {
    if (!q) { setNews([]); setCves([]); setEntities([]); return }
    let alive = true
    const handle = setTimeout(() => {
      api.search(q).then(r => {
        if (!alive) return
        setEntities(r.entities)
        setNews(r.news.slice(0, 8))
        setCves(r.cves.slice(0, 8))
      }).catch(() => {})
    }, 120)
    return () => { alive = false; clearTimeout(handle) }
  }, [q])

  const cmds: Cmd[] = []
  for (const c of QUICK_COMMANDS) {
    const m = q.match(c.match)
    if (m) {
      const built = c.build(m)
      if (built.id === 'cmd:cve')      built.action = () => { onJump('vulns', m[1]); onClose() }
      if (built.id === 'cmd:ransom')   built.action = () => { onJump('news', 'ransomware'); onClose() }
      if (built.id === 'cmd:ai')       built.action = () => { onJump('aiwatch'); onClose() }
      if (built.id === 'cmd:exploit')  built.action = () => { onJump('news', 'active-exploitation'); onClose() }
      cmds.push(built)
    }
  }

  const items: Cmd[] = [
    ...cmds,
    ...entities.slice(0, 6).map(e => ({
      id: `ent:${e.kind}:${e.id}`,
      kind: 'entity' as const,
      label: `${e.name}`,
      hint: `${e.kind.replace('_', ' ')}${e.category ? ' · ' + e.category : ''}`,
      action: () => {
        if (e.kind === 'ai_companies') onJump('aiwatch')
        else onJump('news')
        onClose()
      },
    })),
    ...cves.map(c => ({
      id: `cve:${c.cve_id}`,
      kind: 'cve' as const,
      label: c.cve_id,
      hint: `${c.cvss_score ? 'CVSS ' + c.cvss_score.toFixed(1) + ' · ' : ''}${(c.description || '').slice(0, 70)}`,
      action: () => { onSelectCVE(c.cve_id); onJump('narrative'); onClose() },
    })),
    ...news.map(n => ({
      id: `news:${n.id}`,
      kind: 'news' as const,
      label: n.title,
      hint: `${n.source_name} · prio ${n.priority}`,
      action: () => { openExternal(n.url); onClose() },
    })),
  ]

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === 'Escape') { onClose(); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(a => Math.min(a + 1, items.length - 1)); return }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setActive(a => Math.max(a - 1, 0)); return }
    if (e.key === 'Enter') {
      e.preventDefault()
      const it = items[active]
      if (it) it.action()
    }
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 bg-ink-950/80 backdrop-blur-sm"
         onClick={onClose}>
      <div onClick={e => e.stopPropagation()}
           onKeyDown={handleKey}
           className="w-[680px] max-w-[90vw] bg-ink-900 border border-amber/40 rounded-sm shadow-glow overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 border-b border-wire">
          <span className="text-amber/80 text-[11px] tracking-[0.2em]">CMD</span>
          <input
            ref={inputRef}
            value={q}
            onChange={e => { setQ(e.target.value); setActive(0) }}
            placeholder="search news, CVEs, vendors, AI cos · try: CVE FORTINET / AI OPENAI / RANSOMWARE"
            className="flex-1 bg-transparent outline-none text-amber/95 placeholder-mute text-[13px]"
          />
          <span className="kbd">Esc</span>
        </div>
        <ul className="max-h-[60vh] overflow-y-auto text-[12px]">
          {items.length === 0 && q && (
            <li className="px-3 py-3 text-mute text-xs">No results.</li>
          )}
          {items.length === 0 && !q && (
            <li className="px-3 py-3 text-mute text-xs">
              Type to search across news, vulnerabilities, vendors, AI companies.<br />
              Shortcuts: <span className="kbd">CVE &lt;keyword&gt;</span> · <span className="kbd">AI &lt;company&gt;</span> · <span className="kbd">RANSOMWARE</span> · <span className="kbd">EXPLOITS TODAY</span>
            </li>
          )}
          {items.map((it, i) => (
            <li key={it.id}
                onMouseEnter={() => setActive(i)}
                onClick={() => it.action()}
                className={`px-3 py-2 flex items-center gap-3 cursor-pointer border-b border-wire/40
                  ${i === active ? 'bg-amber/10' : 'hover:bg-ink-800'}`}>
              <span className="chip">{it.kind.toUpperCase()}</span>
              <span className="text-amber/95 truncate">{it.label}</span>
              <span className="ml-auto text-mute text-[10px] truncate max-w-[40%]">{it.hint}</span>
            </li>
          ))}
        </ul>
        <div className="px-3 py-1.5 border-t border-wire text-[10px] text-mute flex items-center gap-3 tracking-wider">
          <span><span className="kbd">↑↓</span> navigate</span>
          <span><span className="kbd">↵</span> open</span>
          <span><span className="kbd">Esc</span> close</span>
        </div>
      </div>
    </div>
  )
}
