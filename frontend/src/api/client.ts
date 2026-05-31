import type {
  NewsItem, CVEItem, StatusResponse, AICompanyWatch, VendorWatch,
  ActorWatch, SectorEntry, Narrative, OrgSummary, OrgAlerts, OrgOverview,
  LayoffsResponse, FundingResponse, AcquisitionsResponse, ExecsResponse,
  ProductsResponse, IndustrySignals,
} from './types'

import { dlog, derror } from '../lib/debug'

async function j<T>(url: string): Promise<T> {
  const t0 = performance.now()
  dlog('API', `→ GET ${url}`)
  try {
    const r = await fetch(url)
    const dt = (performance.now() - t0).toFixed(0)
    if (!r.ok) {
      derror('API', `← ${r.status} ${url} (${dt}ms)`)
      throw new Error(`${url} → ${r.status}`)
    }
    const data = await r.json()
    const size = (() => { try { return JSON.stringify(data).length } catch { return '?' } })()
    dlog('API', `← ${r.status} ${url} (${dt}ms, ${size}B)`)
    return data as T
  } catch (err) {
    const dt = (performance.now() - t0).toFixed(0)
    derror('API', `✗ ${url} (${dt}ms)`, err)
    throw err
  }
}

export const api = {
  status: () => j<StatusResponse>('/api/status'),

  news: (opts: { limit?: number; min_priority?: number; tag?: string; q?: string;
                  sort?: 'priority'|'date'|'severity';
                  sector?: string; org?: string; vendor?: string; actor?: string;
                  quality?: 'filtered'|'all'; days?: number } = {}) => {
    const p = new URLSearchParams()
    if (opts.limit) p.set('limit', String(opts.limit))
    if (opts.min_priority) p.set('min_priority', String(opts.min_priority))
    if (opts.tag) p.set('tag', opts.tag)
    if (opts.q) p.set('q', opts.q)
    if (opts.sort) p.set('sort', opts.sort)
    if (opts.sector) p.set('sector', opts.sector)
    if (opts.org) p.set('org', opts.org)
    if (opts.vendor) p.set('vendor', opts.vendor)
    if (opts.actor) p.set('actor', opts.actor)
    if (opts.quality) p.set('quality', opts.quality)
    if (opts.days) p.set('days', String(opts.days))
    return j<{ items: NewsItem[] }>(`/api/news?${p}`)
  },

  vulns: (opts: { only_kev?: boolean; q?: string; limit?: number; min_priority?: number } = {}) => {
    const p = new URLSearchParams()
    if (opts.only_kev) p.set('only_kev', 'true')
    if (opts.q) p.set('q', opts.q)
    if (opts.limit) p.set('limit', String(opts.limit))
    if (opts.min_priority) p.set('min_priority', String(opts.min_priority))
    return j<{ items: CVEItem[] }>(`/api/vulns?${p}`)
  },

  kev: (limit = 200) => j<{ items: CVEItem[] }>(`/api/vulns/kev?limit=${limit}`),

  cve: (id: string) => j<CVEItem & { news: NewsItem[] }>(`/api/vulns/${encodeURIComponent(id)}`),

  aiWatch: (days = 14) => j<{ window_days: number; companies: AICompanyWatch[] }>(`/api/watch/ai?days=${days}`),
  vendorWatch: (days = 7) => j<{ window_days: number; vendors: VendorWatch[] }>(`/api/watch/vendors?days=${days}`),
  actorWatch: (days = 30) => j<{ window_days: number; actors: ActorWatch[] }>(`/api/watch/actors?days=${days}`),
  sectorWatch: (days = 30) => j<{ window_days: number; sectors: SectorEntry[] }>(`/api/watch/sectors?days=${days}`),

  narratives: (limit = 12) => j<{ items: CVEItem[] }>(`/api/narratives?limit=${limit}`),
  narrative:  (cve: string) => j<Narrative>(`/api/narratives/${encodeURIComponent(cve)}`),

  search: (q: string) =>
    j<{ entities: any[]; news: NewsItem[]; cves: CVEItem[] }>(`/api/search?q=${encodeURIComponent(q)}`),

  orgs:        (days = 14) => j<{ window_days: number; orgs: OrgSummary[] }>(`/api/orgs?days=${days}`),
  orgDetail:   (id: string, days = 14) => j<OrgOverview>(`/api/orgs/${encodeURIComponent(id)}?days=${days}`),
  orgAlerts:   (id: string, days = 14, limit = 60) =>
    j<OrgAlerts>(`/api/orgs/${encodeURIComponent(id)}/alerts?days=${days}&limit=${limit}`),
  orgIndustry: (id: string, days = 90) =>
    j<{ org: { id: string; name: string }; window_days: number;
        events: (NewsItem & { industry: Record<string, any> })[];
        buckets: Record<string, number> }>(`/api/orgs/${encodeURIComponent(id)}/industry?days=${days}`),

  industrySignals:     (days = 30) => j<IndustrySignals>(`/api/industry/signals?days=${days}`),
  industryLayoffs:     (days = 30, limit = 150) => j<LayoffsResponse>(`/api/industry/layoffs?days=${days}&limit=${limit}`),
  industryFunding:     (days = 30, limit = 150) => j<FundingResponse>(`/api/industry/funding?days=${days}&limit=${limit}`),
  industryAcquisitions:(days = 60, limit = 150) => j<AcquisitionsResponse>(`/api/industry/acquisitions?days=${days}&limit=${limit}`),
  industryExecs:       (days = 60, limit = 150) => j<ExecsResponse>(`/api/industry/execs?days=${days}&limit=${limit}`),
  industryProducts:    (days = 30, limit = 150) => j<ProductsResponse>(`/api/industry/products?days=${days}&limit=${limit}`),
  industryIPOs:        (days = 60, limit = 150) => j<{ window_days: number; items: NewsItem[]; totals: { events: number } }>(`/api/industry/ipos?days=${days}&limit=${limit}`),
  industryStartups:    (days = 60, limit = 150) => j<{ window_days: number; stealth: NewsItem[]; yc: NewsItem[]; seed_rounds: any[]; totals: { stealth: number; yc: number; seed_rounds: number } }>(`/api/industry/startups?days=${days}&limit=${limit}`),
  industryBankruptcy:  (days = 90, limit = 150, sort = 'date') => j<{ window_days: number; items: any[]; totals: { events: number; total_debt_usd: number; by_chapter: Record<string, number> } }>(`/api/industry/bankruptcy?days=${days}&limit=${limit}&sort=${sort}`),
  industryCryptoScams: (days = 30, limit = 150, sort = 'date') => j<{ window_days: number; items: any[]; totals: { events: number; total_stolen_usd: number; by_kind: Record<string, number>; by_asset: Record<string, number> } }>(`/api/industry/crypto-scams?days=${days}&limit=${limit}&sort=${sort}`),

  kevWatch: (limit = 40, minEpss = 0.5, minCvss = 7.5) =>
    j<{ items: any[]; criteria: any }>(`/api/intel/kev-watch?limit=${limit}&min_epss=${minEpss}&min_cvss=${minCvss}`),

  // Workspace: saved / stars / annotations
  listStars: (kind?: string) =>
    j<{ items: any[] }>(`/api/workspace/stars${kind ? `?kind=${kind}` : ''}`),
  star: (kind: string, subjectId: string, note?: string) =>
    fetch('/api/workspace/stars', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, subject_id: subjectId, note }),
    }).then(r => r.json()),
  unstar: (kind: string, subjectId: string) =>
    fetch(`/api/workspace/stars/${kind}/${encodeURIComponent(subjectId)}`,
          { method: 'DELETE' }).then(r => r.json()),
  starLookup: (kind: string, subjectId: string) =>
    j<{ starred: boolean; id?: number; note?: string; starred_at?: string }>(
      `/api/workspace/stars/lookup/${kind}/${encodeURIComponent(subjectId)}`),

  listAnnotations: (kind?: string, subjectId?: string) => {
    const p = new URLSearchParams()
    if (kind) p.set('kind', kind)
    if (subjectId) p.set('subject_id', subjectId)
    return j<{ items: any[] }>(`/api/workspace/annotations?${p}`)
  },
  createAnnotation: (kind: string, subjectId: string, body: string, tags: string[] = []) =>
    fetch('/api/workspace/annotations', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind, subject_id: subjectId, body, tags }),
    }).then(r => r.json()),
  deleteAnnotation: (id: number) =>
    fetch(`/api/workspace/annotations/${id}`, { method: 'DELETE' }).then(r => r.json()),

  listSaved: (kind?: string) =>
    j<{ items: any[] }>(`/api/workspace/saved${kind ? `?kind=${kind}` : ''}`),
  saveSearch: (name: string, kind: string, params: any) =>
    fetch('/api/workspace/saved', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, kind, params }),
    }).then(r => r.json()),
  deleteSaved: (id: number) =>
    fetch(`/api/workspace/saved/${id}`, { method: 'DELETE' }).then(r => r.json()),

  // Watchlist + spoofing + score breakdown + actor timeline + org execs + since
  listWatchlist: () => j<{ items: any[] }>(`/api/workspace/watchlist`),
  createWatchlist: (name: string, query: string, min_priority = 0, slack = false) =>
    fetch('/api/workspace/watchlist', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, query, min_priority, slack }),
    }).then(r => r.json()),
  deleteWatchlist: (id: number) =>
    fetch(`/api/workspace/watchlist/${id}`, { method: 'DELETE' }).then(r => r.json()),

  spoofingForOrg: (orgId: string) =>
    j<{ org_name: string; org_domains: string[]; candidates_scanned: number; matches: any[] }>(
      `/api/exposure/spoofing/${encodeURIComponent(orgId)}`),

  cveScoreBreakdown: (cveId: string) =>
    j<{ total: number; parts: { label: string; value: number }[] }>(
      `/api/vulns/${encodeURIComponent(cveId)}/score-breakdown`),

  actorTimeline: (actorId: string, days = 90) =>
    j<{ events: any[]; counts: { news: number; leak_posts: number } }>(
      `/api/watch/actors/${encodeURIComponent(actorId)}/timeline?days=${days}`),

  orgExecs: (orgId: string, days = 30) =>
    j<{ org: any; executives: string[]; mentions: any[] }>(
      `/api/orgs/${encodeURIComponent(orgId)}/execs?days=${days}`),

  digestSince: (hours = 4, force = false) =>
    j<any>(`/api/digest/since?hours=${hours}${force ? '&force=true' : ''}`),

  patches: (vendor: string, days = 60) =>
    j<{ vendor: string; label: string; window_days: number; total: number; groups: { month: string; count: number; items: any[] }[] }>(
      `/api/patches?vendor=${encodeURIComponent(vendor)}&days=${days}`),
  patchSummary: (days = 60) =>
    j<{ window_days: number; vendors: { vendor: string; label: string; count: number; latest: string | null }[] }>(
      `/api/patches/summary?days=${days}`),

  ackNews: (id: string) =>
    fetch(`/api/news/${encodeURIComponent(id)}/ack`, { method: 'POST' }).then(r => r.json()),
  unackNews: (id: string) =>
    fetch(`/api/news/${encodeURIComponent(id)}/ack`, { method: 'DELETE' }).then(r => r.json()),
  ackCluster: (clusterKey: string) =>
    fetch(`/api/news/ack-cluster?cluster_key=${encodeURIComponent(clusterKey)}`, { method: 'POST' }).then(r => r.json()),
}
