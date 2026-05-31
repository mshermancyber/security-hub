export type Entities = {
  vendors: { id: string; name: string; category?: string }[]
  ai_companies: { id: string; name: string; category?: string }[]
  threat_actors: { id: string; name: string; type?: string; origin?: string }[]
  malware: { id: string; name: string; type?: string }[]
  sectors: { id: string; name: string }[]
  orgs?: { id: string; name: string; sector?: string; country?: string }[]
  cves: string[]
}

export type OrgSummary = {
  id: string
  name: string
  sector?: string
  country?: string
  ticker?: string
  brand_count: number
  subsidiary_count: number
  domain_count: number
  direct_mentions: number
  keyword_hits: number
  max_priority: number
  signals: Record<string, number>
  stack_cves: number
  stack_kev: number
  latest: NewsItem[]
}

export type OrgConfig = {
  id: string
  name: string
  sector?: string
  country?: string
  ticker?: string
  brands: string[]
  subsidiaries: string[]
  domains: string[]
  aliases: string[]
  tech_stack: string[]
  watch_keywords: string[]
}

export type OrgStackAlert = {
  kind: 'cve'
  cve_id: string
  description: string
  cvss_score?: number | null
  is_kev?: number
  kev_added?: string | null
  kev_ransomware?: string | null
  priority?: number
  vendors: string[]
}

export type OrgAlerts = {
  org: { id: string; name: string; sector?: string; country?: string; ticker?: string }
  window_days: number
  news_alerts: NewsItem[]
  stack_alerts: OrgStackAlert[]
  signals: Record<string, number>
}

export type OrgOverview = {
  org: OrgConfig
  window_days: number
  direct_mentions: NewsItem[]
  keyword_hits: NewsItem[]
  stack_cves: CVEItem[]
}

// --- industry events ----------------------------------------------------

export type LayoffEvent = {
  detected: boolean
  headcount?: number | null
  percent?: number | null
  ai_driven?: boolean
  hiring_freeze?: boolean
}
export type FundingEvent = {
  detected: boolean
  amount_usd?: number | null
  valuation_usd?: number | null
  round?: string | null
}
export type AcquisitionEvent = {
  detected: boolean
  acquirer?: string | null
  target?: string | null
  amount_usd?: number | null
}
export type ExecChangeEvent = {
  detected: boolean
  role?: string | null
  direction?: 'in' | 'out' | 'transition' | null
}

export type IndustryNews<E> = NewsItem & { event: E }
export type CompanyAgg = { name: string; kind: string; events: number }

export type LayoffsResponse = {
  window_days: number
  items: IndustryNews<LayoffEvent>[]
  totals: {
    events: number
    total_headcount: number
    events_with_headcount: number
    ai_driven_events: number
    hiring_freezes: number
  }
  top_companies: CompanyAgg[]
}

export type FundingResponse = {
  window_days: number
  items: IndustryNews<FundingEvent>[]
  totals: {
    events: number
    total_raised_usd: number
    rounds: Record<string, number>
  }
  top_companies: CompanyAgg[]
}

export type AcquisitionsResponse = {
  window_days: number
  items: IndustryNews<AcquisitionEvent>[]
  totals: { events: number; total_value_usd: number; deals_with_amount: number }
}

export type ExecsResponse = {
  window_days: number
  items: IndustryNews<ExecChangeEvent>[]
  totals: {
    events: number
    by_role: Record<string, number>
    by_direction: Record<string, number>
  }
  top_companies: CompanyAgg[]
}

export type ProductsResponse = {
  window_days: number
  launches: IndustryNews<{ detected: boolean }>[]
  eols: IndustryNews<{ detected: boolean }>[]
  outages: IndustryNews<{ detected: boolean }>[]
  totals: { launches: number; eols: number; outages: number }
}

export type IndustrySignals = {
  window_days: number
  layoffs: number; funding: number; acquisitions: number; execs: number
  launches: number; eols: number; outages: number; ipos: number
  stealth: number; yc: number
}

export type NewsItem = {
  id: string
  source: string
  source_name: string
  title: string
  summary?: string
  url: string
  published_at: string
  fetched_at: string
  reliability: number
  severity: number
  priority: number
  tags: string[]
  entities: Entities
  cves: string[]
}

export type CVEItem = {
  cve_id: string
  published_at: string
  last_modified: string
  description: string
  cvss_score?: number | null
  cvss_severity?: string | null
  cvss_vector?: string | null
  epss_score?: number | null
  epss_percentile?: number | null
  is_kev: number
  kev_added?: string | null
  kev_ransomware?: string | null
  priority: number
  entities: Entities
  refs?: string[]
  cwe?: string[]
  news_count?: number
  last_seen?: string | null
}

export type FeedHealth = {
  source_id: string
  source_name: string
  last_success: string | null
  last_error: string | null
  last_error_at: string | null
  items_total: number
  last_items: number
}

export type StatusResponse = {
  counts: { news: number; cves: number; kev: number; critical_news: number }
  feeds: FeedHealth[]
  last_runs: Record<string, { at: string; count?: number; error?: string } | null>
}

export type AICompanyWatch = {
  id: string
  name: string
  category?: string
  mentions: number
  max_priority: number
  tags: Record<string, number>
  latest: NewsItem[]
}

export type VendorWatch = {
  id: string
  name: string
  category?: string
  mentions: number
  max_priority: number
  tags: Record<string, number>
  open_cves: number
  kev_cves: number
  top_cves: { cve_id: string; cvss_score?: number; is_kev: number; priority: number }[]
  latest_news: NewsItem[]
}

export type ActorWatch = {
  id: string
  name: string
  type?: string
  origin?: string
  attack_id?: string | null
  mentions: number
  max_priority: number
  tags: Record<string, number>
  latest: NewsItem[]
  ransom_postings?: number
  ransom_victims?: string[]
  ransom_last_seen?: string | null
  ioc_count?: number
  signal_score?: number
}

export type SectorEntry = {
  id: string
  name: string
  mentions: number
  max_priority: number
  ransomware: number
  breaches: number
  tags: Record<string, number>
}

export type TimelineEvent = {
  kind: 'cve_published' | 'kev_added' | 'news'
  at: string
  title: string
  detail?: string
  source?: string
  url?: string
  tags?: string[]
}

export type Narrative = {
  cve: CVEItem | null
  timeline: TimelineEvent[]
}
