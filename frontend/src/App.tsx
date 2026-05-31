import { Suspense, lazy, useCallback, useEffect, useState } from 'react'
import { Header } from './components/Header'
import { StatusBar } from './components/StatusBar'
import { CommandPalette } from './components/CommandPalette'
import { dlog, debugLazy } from './lib/debug'
// Overview panels — eagerly imported so first paint shows full dashboard.
import { NewsPanel } from './components/panels/NewsPanel'
import { VulnPanel } from './components/panels/VulnPanel'
import { AIWatchPanel } from './components/panels/AIWatchPanel'
import { ActorPanel, SectorPanel } from './components/panels/ActorPanel'
// Single-view panels — lazy-loaded; only fetched when their tab is opened.
const NarrativePanel    = lazy(debugLazy('NarrativePanel',    () => import('./components/panels/NarrativePanel').then(m => ({ default: m.NarrativePanel }))))
const OrgWatchPanel     = lazy(debugLazy('OrgWatchPanel',     () => import('./components/panels/OrgWatchPanel').then(m => ({ default: m.OrgWatchPanel }))))
const IndustryPanel     = lazy(debugLazy('IndustryPanel',     () => import('./components/panels/IndustryPanel').then(m => ({ default: m.IndustryPanel }))))
const IntegrationsPanel = lazy(debugLazy('IntegrationsPanel', () => import('./components/panels/IntegrationsPanel').then(m => ({ default: m.IntegrationsPanel }))))
const PatchesPanel      = lazy(debugLazy('PatchesPanel',      () => import('./components/panels/PatchesPanel').then(m => ({ default: m.PatchesPanel }))))

function PanelFallback({ name }: { name: string }) {
  useEffect(() => {
    dlog('Panel', `fallback ON  (${name} chunk loading…)`)
    return () => dlog('Panel', `fallback OFF (${name} ready)`)
  }, [name])
  return <div className="h-full flex items-center justify-center text-mute text-xs">loading {name}…</div>
}

type Active =
  | 'overview'
  | 'news'
  | 'vulns'
  | 'kev'
  | 'aiwatch'
  | 'actors'
  | 'sectors'
  | 'narrative'
  | 'orgs'
  | 'industry'
  | 'integrations'
  | 'patches'

type NewsEntity = {
  kind: 'sector' | 'org' | 'vendor' | 'actor';
  id: string;
  name: string;
  // Optional tag preset — used by SectorPanel's BREACH/RANSOM chips so
  // clicking them jumps to news pre-filtered by both entity and tag.
  tag?: string;
}

export default function App() {
  const [active, setActive] = useState<Active>('overview')
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [selectedCVE, setSelectedCVE] = useState<string | undefined>()
  const [newsFilter, setNewsFilter] = useState<string | undefined>()
  const [newsEntity, setNewsEntity] = useState<NewsEntity | null>(null)

  const selectSector = useCallback((id: string, name: string, tag?: string) => {
    setNewsEntity({ kind: 'sector', id, name, tag })
    setNewsFilter(undefined)
    setActive('news')
  }, [])

  const selectGraphEntity = useCallback((kind: NewsEntity['kind'], id: string, name: string) => {
    setNewsEntity({ kind, id, name })
    setNewsFilter(undefined)
    setActive('news')
  }, [])

  const jump = useCallback((panel: string, filter?: string) => {
    dlog('Panel', `jump → ${panel}`, filter ? `filter="${filter}"` : '')
    setActive(panel as Active)
    if (panel === 'news') setNewsFilter(filter)
  }, [])

  useEffect(() => {
    dlog('Panel', `active = ${active}`)
  }, [active])

  const onSelectCVE = useCallback((cve: string) => {
    setSelectedCVE(cve)
    setActive('narrative')
  }, [])

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen(p => !p)
        return
      }
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase()
      if (tag === 'input' || tag === 'textarea') return
      if (e.key === '`') { e.preventDefault(); setActive('overview'); return }
      const map: Record<string, Active> = {
        '1': 'news', '2': 'vulns', '3': 'kev', '4': 'aiwatch',
        '5': 'actors', '6': 'sectors', '7': 'narrative', '8': 'orgs', '9': 'industry',
        '0': 'integrations', '-': 'patches',
      }
      if (map[e.key]) { e.preventDefault(); setActive(map[e.key]) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="h-full flex flex-col text-amber relative">
      <Header onOpenPalette={() => setPaletteOpen(true)} active={active} onJump={jump} />
      <main className="flex-1 overflow-hidden p-1.5">
        {active === 'overview' && (
          <div className="grid grid-cols-12 grid-rows-6 gap-1.5 h-full">
            {/* Left col: News (rows 1-4) + Actors (rows 5-6).
                Right col: KEV (1-2) + AIWatch (3-4) + Sector (5-6). */}
            <div className="min-h-0 overflow-hidden" style={{ gridColumn: '1 / span 7', gridRow: '1 / span 4' }}>
              <NewsPanel onSelectCVE={onSelectCVE} filter={newsFilter} entity={newsEntity} onClearEntity={() => setNewsEntity(null)} />
            </div>
            <div className="min-h-0 overflow-hidden" style={{ gridColumn: '1 / span 7', gridRow: '5 / span 2' }}>
              <ActorPanel />
            </div>
            <div className="min-h-0 overflow-hidden" style={{ gridColumn: '8 / span 5', gridRow: '1 / span 2' }}>
              <VulnPanel mode="kev" onSelectCVE={onSelectCVE} selected={selectedCVE} />
            </div>
            <div className="min-h-0 overflow-hidden" style={{ gridColumn: '8 / span 5', gridRow: '3 / span 2' }}>
              <AIWatchPanel />
            </div>
            <div className="min-h-0 overflow-hidden" style={{ gridColumn: '8 / span 5', gridRow: '5 / span 2' }}>
              <SectorPanel onSelectSector={selectSector} />
            </div>
          </div>
        )}
        {active === 'news'     && <div className="h-full"><NewsPanel onSelectCVE={onSelectCVE} filter={newsFilter} entity={newsEntity} onClearEntity={() => setNewsEntity(null)} /></div>}
        {active === 'vulns'    && <div className="h-full"><VulnPanel onSelectCVE={onSelectCVE} selected={selectedCVE} /></div>}
        {active === 'kev'      && <div className="h-full"><VulnPanel mode="kev" onSelectCVE={onSelectCVE} selected={selectedCVE} /></div>}
        {active === 'aiwatch'  && <div className="h-full"><AIWatchPanel /></div>}
        {active === 'actors'   && <div className="h-full"><ActorPanel /></div>}
        {active === 'sectors'  && <div className="h-full"><SectorPanel onSelectSector={selectSector} /></div>}
        {active === 'narrative'&& <div className="h-full"><Suspense fallback={<PanelFallback name={active} />}><NarrativePanel selected={selectedCVE} onSelect={setSelectedCVE} onGraphEntity={selectGraphEntity} /></Suspense></div>}
        {active === 'orgs'     && <div className="h-full"><Suspense fallback={<PanelFallback name={active} />}><OrgWatchPanel onSelectCVE={onSelectCVE} /></Suspense></div>}
        {active === 'industry' && <div className="h-full"><Suspense fallback={<PanelFallback name={active} />}><IndustryPanel onSelectCVE={onSelectCVE} /></Suspense></div>}
        {active === 'integrations' && <div className="h-full"><Suspense fallback={<PanelFallback name={active} />}><IntegrationsPanel /></Suspense></div>}
        {active === 'patches'      && <div className="h-full"><Suspense fallback={<PanelFallback name={active} />}><PatchesPanel /></Suspense></div>}
      </main>
      <StatusBar />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} onJump={jump} onSelectCVE={onSelectCVE} />
    </div>
  )
}
