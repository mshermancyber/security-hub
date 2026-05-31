import { useEffect, useState } from 'react'
import { openExternal } from '../lib/safeUrl'

type Node = { id: string; kind: string; label: string; [k: string]: any }
type Edge = { from: string; to: string; kind: string }
type GraphData = { cve: any; nodes: Node[]; edges: Edge[]; counts: Record<string, number> }

type EntityKind = 'sector' | 'org' | 'vendor' | 'actor'
type Props = {
  cveId?: string
  onSelectEntity?: (kind: EntityKind, id: string, name: string) => void
}

const KIND_COLOR: Record<string, string> = {
  cve:        '#ff4d6d',
  vendor:     '#5cc8ff',
  ai_company: '#b794f6',
  actor:      '#ff9f1c',
  malware:    '#ffd166',
  sector:     '#34f5c5',
  org:        '#ffcf6b',
  news:       '#8a93a6',
}

const KIND_RADIUS: Record<string, number> = {
  cve: 14, vendor: 9, ai_company: 9, actor: 9, malware: 9, sector: 9, org: 9, news: 6,
}

// Map node kinds → news filter kinds (where applicable)
const NEWS_FILTERABLE: Record<string, EntityKind | undefined> = {
  vendor: 'vendor',
  actor: 'actor',
  sector: 'sector',
  org: 'org',
  // ai_company → filtered against the same vendors slot? No — handled separately by aiwatch
  // malware → not currently a filterable dimension on news
}

export function NarrativeGraph({ cveId, onSelectEntity }: Props) {
  const [data, setData] = useState<GraphData | null>(null)
  const [hover, setHover] = useState<Node | null>(null)

  useEffect(() => {
    if (!cveId) { setData(null); return }
    let alive = true
    fetch(`/api/intel/graph/${encodeURIComponent(cveId)}`).then(r => r.json()).then(d => alive && setData(d)).catch(() => {})
    return () => { alive = false }
  }, [cveId])

  if (!cveId) return <div className="p-4 text-mute text-xs">Select a CVE to render its entity graph.</div>
  if (!data || !data.cve) return <div className="p-4 text-mute text-xs">loading graph…</div>

  const cx = 220, cy = 200, ringR = 140
  const cveNode = data.nodes.find(n => n.kind === 'cve')!
  const rest = data.nodes.filter(n => n.id !== cveNode.id)

  const kindOrder = ['vendor', 'ai_company', 'org', 'actor', 'malware', 'sector', 'news']
  const grouped: Record<string, Node[]> = {}
  for (const k of kindOrder) grouped[k] = rest.filter(n => n.kind === k)

  const positioned: Record<string, { x: number; y: number }> = {}
  positioned[cveNode.id] = { x: cx, y: cy }
  let i = 0
  const total = rest.length || 1
  for (const k of kindOrder) {
    for (const n of grouped[k]) {
      const angle = (i / total) * Math.PI * 2 - Math.PI / 2
      const r = k === 'news' ? ringR * 1.15 : ringR * (k === 'sector' ? 0.85 : 1.0)
      positioned[n.id] = { x: cx + Math.cos(angle) * r, y: cy + Math.sin(angle) * r }
      i++
    }
  }

  function onClickNode(n: Node) {
    if (n.kind === 'news' && n.url) {
      openExternal(n.url)
      return
    }
    const filterKind = NEWS_FILTERABLE[n.kind]
    if (filterKind && onSelectEntity) {
      // node IDs are "<kind>:<entity_id>" — strip the prefix
      const rawId = n.id.includes(':') ? n.id.split(':').slice(1).join(':') : n.id
      onSelectEntity(filterKind, rawId, n.label)
    }
  }

  return (
    <div className="p-3">
      <div className="text-[10px] uppercase tracking-[0.2em] text-amber/80 mb-1 flex items-center gap-2">
        Entity relationship graph
        <span className="text-mute normal-case tracking-normal">click vendor/actor/sector/org → filter news · click news → open</span>
      </div>
      <div className="flex flex-wrap gap-2 mb-2 text-[10px]">
        {kindOrder.map(k => grouped[k]?.length > 0 && (
          <span key={k} className="inline-flex items-center gap-1 chip">
            <span className="inline-block w-2 h-2 rounded-full" style={{ background: KIND_COLOR[k] }} />
            {k.replace('_', ' ')} {grouped[k].length}
          </span>
        ))}
      </div>
      <svg width="440" height="400" className="block">
        {data.edges.map((e, idx) => {
          const a = positioned[e.from], b = positioned[e.to]
          if (!a || !b) return null
          return <line key={idx} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                       stroke="#2a3140" strokeWidth="0.75" opacity="0.85" />
        })}
        {data.nodes.map(n => {
          const p = positioned[n.id]
          if (!p) return null
          const r = KIND_RADIUS[n.kind] ?? 7
          const color = KIND_COLOR[n.kind] ?? '#8a93a6'
          const lbl = n.kind === 'news' ? '' : (n.label || '').slice(0, 18)
          const interactive = n.kind === 'cve' ? false :
                              n.kind === 'news' ? !!n.url :
                              !!NEWS_FILTERABLE[n.kind] && !!onSelectEntity
          const isHover = hover?.id === n.id
          return (
            <g key={n.id}
               style={{ cursor: interactive ? 'pointer' : 'default' }}
               onMouseEnter={() => setHover(n)}
               onMouseLeave={() => setHover(h => h?.id === n.id ? null : h)}
               onClick={() => interactive && onClickNode(n)}>
              <circle cx={p.x} cy={p.y} r={isHover ? r + 2 : r}
                      fill={color} fillOpacity={isHover ? 0.4 : 0.18}
                      stroke={color} strokeWidth={isHover ? 2 : 1.5}>
                {interactive && <title>{n.kind === 'news' ? 'Open article' : `Filter news → ${n.label}`}</title>}
              </circle>
              {lbl && (
                <text x={p.x} y={p.y + r + 11} fontSize="9" fill="#cbd5e1" textAnchor="middle">
                  {lbl}
                </text>
              )}
            </g>
          )
        })}
      </svg>
      {hover && hover.kind === 'news' && (
        <div className="mt-2 text-[11px] text-mute border border-wire/40 rounded-sm p-2 bg-ink-800/40">
          <span className="text-amber/95">{hover.label}</span>
          {hover.source && <span className="text-cyber-blue/80 ml-2 uppercase tracking-wider text-[10px]">{hover.source}</span>}
        </div>
      )}
    </div>
  )
}
