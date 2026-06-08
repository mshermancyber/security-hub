import { useCallback, useEffect, useState } from 'react'
import { safeHref, openExternal } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type { NewsItem } from '../../api/types'
import { Panel } from '../Panel'
import { priorityClass, relTime, severityLabel, tagClass } from '../../lib/format'
import { useWSEvent } from '../../lib/useWebSocket'
import { usePanelKeys } from '../../lib/usePanelKeys'

type EntityFilter = {
  kind: 'sector' | 'org' | 'vendor' | 'actor';
  id: string;
  name: string;
  // Optional pre-selected tag (e.g. SectorPanel's BREACH chip arrives with
  // tag='breach'). Applied to the tag filter on entity change.
  tag?: string;
}

type Props = {
  onSelectCVE: (cve: string) => void
  filter?: string
  entity?: EntityFilter | null
  onClearEntity?: () => void
}

type SortKey = 'priority' | 'date' | 'severity'
type Quality = 'filtered' | 'all'

export function NewsPanel({ onSelectCVE, filter, entity, onClearEntity }: Props) {
  useEffect(() => trackPanelLifecycle('NewsPanel'), [])
  const [items, setItems] = useState<NewsItem[]>([])
  const [loading, setLoading] = useState(true)
  const [tagFilter, setTagFilter] = useState<string | undefined>(entity?.tag)

  // When the parent hands us a new entity (e.g. SectorPanel BREACH chip
  // click), apply or clear the tag filter to match.
  useEffect(() => {
    setTagFilter(entity?.tag)
  }, [entity?.kind, entity?.id, entity?.tag])
  const [sort, setSort] = useState<SortKey>('priority')
  const [quality, setQuality] = useState<Quality>('filtered')
  const [pending, setPending] = useState(0)

  const load = useCallback(() => {
    let alive = true
    setLoading(true)
    const opts: any = { limit: 150, tag: tagFilter, q: filter, sort, quality }
    if (entity) opts[entity.kind] = entity.id
    api.news(opts)
      .then(r => alive && setItems(r.items))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [tagFilter, filter, sort, entity, quality])

  const [starred, setStarred] = useState<Record<string, boolean>>({})
  useEffect(() => {
    api.listStars('news').then(r => {
      const m: Record<string, boolean> = {}
      for (const s of r.items) m[s.subject_id] = true
      setStarred(m)
    }).catch(() => {})
  }, [])

  const toggleStar = async (n: NewsItem) => {
    if (starred[n.id]) {
      await api.unstar('news', n.id)
      setStarred(s => { const c = { ...s }; delete c[n.id]; return c })
    } else {
      await api.star('news', n.id, n.title)
      setStarred(s => ({ ...s, [n.id]: true }))
    }
  }

  const { sel, setSel } = usePanelKeys(items.length, {
    onActivate: (i) => { const it = items[i]; if (it) openExternal(it.url) },
    onStar:     (i) => { const it = items[i]; if (it) toggleStar(it) },
    onAck:      async (i) => {
      const it = items[i]
      if (!it) return
      await api.ackNews(it.id)
      setItems(prev => prev.filter(p => p.id !== it.id))
    },
  })

  useEffect(() => { const stop = load(); return stop }, [load])

  // count pushed news items since last load
  useWSEvent('news.batch', (e) => setPending(n => n + (e.count ?? 0)))
  useWSEvent('news.item',  () => setPending(n => n + 1))

  const tagOpts = ['active-exploitation', 'zero-day', 'ransomware', 'breach', 'nation-state', 'ai-incident', 'supply-chain']

  return (
    <Panel
      code="NEWS"
      title={`Live intelligence feed${filter ? ` · ${filter}` : ''}${entity ? ` · ${entity.kind}:${entity.name}` : ''}`}
      hotkey="1"
      right={
        <div className="flex items-center gap-1">
          {entity && onClearEntity && (
            <button onClick={onClearEntity}
              className="chip chip-amber cursor-pointer">
              ✕ {entity.kind}:{entity.name}
            </button>
          )}
          {pending > 0 && (
            <button onClick={() => { setPending(0); load() }}
              className="chip chip-amber animate-pulseDot cursor-pointer">
              {pending} new ↻
            </button>
          )}
          <span className="text-mute text-[10px] uppercase tracking-wider px-1">qual</span>
          <button onClick={() => setQuality(quality === 'filtered' ? 'all' : 'filtered')}
            className={`chip cursor-pointer ${quality === 'filtered' ? 'chip-green' : 'chip-amber'}`}
            title={quality === 'filtered'
              ? 'Showing only signal items (7d age-out, KEV-linked items kept). Click for raw feed.'
              : 'Showing raw feed. Click to re-enable the quality gate.'}>
            {quality === 'filtered' ? '7D · SIGNAL' : 'RAW · ALL'}
          </button>
          <span className="text-mute text-[10px] uppercase tracking-wider px-1 border-l border-wire ml-1">sort</span>
          {(['priority','date','severity'] as SortKey[]).map(s => (
            <button key={s} onClick={() => setSort(s)}
              className={`chip cursor-pointer ${sort === s ? 'chip-amber' : ''}`}>
              {s}
            </button>
          ))}
          <span className="text-mute text-[10px] uppercase tracking-wider px-1 border-l border-wire ml-1">filter</span>
          <button onClick={() => setTagFilter(undefined)}
            className={`chip cursor-pointer ${!tagFilter ? 'chip-amber' : ''}`}>ALL</button>
          {tagOpts.map(t => (
            <button key={t} onClick={() => setTagFilter(t === tagFilter ? undefined : t)}
              className={`chip cursor-pointer ${tagFilter === t ? tagClass(t) : ''}`}>
              {t.replace('-', ' ')}
            </button>
          ))}
        </div>
      }
    >
      {loading && items.length === 0 ? (
        <div className="p-3 text-mute text-xs">loading...</div>
      ) : items.length === 0 ? (
        <div className="p-3 text-mute text-xs">no items match.</div>
      ) : (
        <ul className="text-[12px]">
          {items.map((n, i) => {
            const cs = (n as any).cluster_size as number | undefined
            const also = ((n as any).also_seen_in || []) as { source_name: string; url: string }[]
            const isStarred = !!starred[n.id]
            const isSel = i === sel
            return (
            <li key={n.id}
                onMouseEnter={() => setSel(i)}
                className={`row-link ${isSel ? 'active' : ''}`}>
              <div className="flex items-start gap-2">
                <span className={`chip ${priorityClass(n.priority)} shrink-0 w-12 justify-center`}>
                  {severityLabel(n.priority)}
                </span>
                <span className="shrink-0 text-mute w-9 text-right tabular-nums">{relTime(n.published_at)}</span>
                <span className="shrink-0 text-cyber-blue/80 w-28 truncate uppercase tracking-wider text-[10px]">
                  {n.source_name}
                </span>
                <a href={safeHref(n.url)} target="_blank" rel="noreferrer noopener" className="text-amber/95 hover:text-amber leading-snug flex-1">
                  {n.title}
                </a>
                <button onClick={(e) => { e.stopPropagation(); toggleStar(n) }}
                  className={`chip cursor-pointer ${isStarred ? 'chip-amber' : ''}`}
                  title={isStarred ? 'Unstar (s)' : 'Star (s)'}>★</button>
                <button onClick={async (e) => {
                  e.stopPropagation()
                  await api.ackNews(n.id)
                  setItems(prev => prev.filter(p => p.id !== n.id))
                }}
                  className="chip cursor-pointer"
                  title="Dismiss / acknowledge (a)">✓</button>
                {cs && cs > 1 && (
                  <span className="chip chip-blue shrink-0" title={also.map(s => s.source_name).join(', ')}>
                    +{cs - 1}
                  </span>
                )}
              </div>
              {(n.tags.length > 0 || n.cves.length > 0 || n.entities.threat_actors.length > 0) && (
                <div className="mt-1 ml-[88px] flex flex-wrap gap-1">
                  {n.tags.slice(0, 5).map(t => (
                    <span key={t} className={`chip ${tagClass(t)}`}>{t}</span>
                  ))}
                  {n.entities.threat_actors.slice(0, 3).map(a => (
                    <span key={a.id} className="chip chip-purple">{a.name}</span>
                  ))}
                  {n.cves.slice(0, 4).map(c => (
                    <button key={c} onClick={() => onSelectCVE(c)}
                      className="chip chip-red hover:bg-cyber-red/30 cursor-pointer">{c}</button>
                  ))}
                </div>
              )}
            </li>
          )})}
        </ul>
      )}
    </Panel>
  )
}
