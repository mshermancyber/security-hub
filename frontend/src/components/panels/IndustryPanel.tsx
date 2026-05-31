import { useEffect, useState } from 'react'
import { safeHref } from '../../lib/safeUrl'
import { trackPanelLifecycle } from '../../lib/debug'
import { api } from '../../api/client'
import type {
  AcquisitionsResponse, ExecsResponse, FundingResponse, IndustrySignals,
  LayoffsResponse, ProductsResponse,
} from '../../api/types'
import { Panel } from '../Panel'
import { priorityClass, relTime, severityLabel, tagClass } from '../../lib/format'
import { fmtCount, fmtUSD } from '../../lib/money'

type Tab = 'layoffs' | 'funding' | 'execs' | 'm&a' | 'products' | 'startups' | 'bankruptcy' | 'crypto-scams'

const TABS: { id: Tab; label: string }[] = [
  { id: 'layoffs',     label: 'LAYOFFS'  },
  { id: 'funding',     label: 'FUNDING'  },
  { id: 'm&a',         label: 'M&A / IPOs' },
  { id: 'execs',       label: 'EXECS'    },
  { id: 'products',    label: 'PRODUCTS' },
  { id: 'startups',    label: 'STARTUPS' },
  { id: 'bankruptcy',  label: 'BANKRUPTCY' },
  { id: 'crypto-scams',label: 'CRYPTO SCAMS' },
]

export function IndustryPanel({ onSelectCVE: _ }: { onSelectCVE: (cve: string) => void }) {
  useEffect(() => trackPanelLifecycle('IndustryPanel'), [])
  const [tab, setTab] = useState<Tab>('layoffs')
  const [days, setDays] = useState(30)
  const [signals, setSignals] = useState<IndustrySignals | null>(null)

  useEffect(() => {
    let alive = true
    api.industrySignals(days).then(r => alive && setSignals(r)).catch(() => {})
    return () => { alive = false }
  }, [days])

  return (
    <Panel
      code="INDUSTRY"
      title="Tech industry intelligence"
      hotkey="9"
      right={
        <div className="flex items-center gap-1">
          {[7, 14, 30, 60, 90].map(d => (
            <button key={d} onClick={() => setDays(d)}
              className={`chip cursor-pointer ${d === days ? 'chip-amber' : ''}`}>{d}D</button>
          ))}
        </div>
      }
    >
      {/* signal strip */}
      <div className="px-3 py-2 border-b border-wire/60 bg-ink-800/40 flex flex-wrap gap-2 text-[11px]">
        {signals && (
          <>
            <SignalChip label="LAYOFFS"      v={signals.layoffs}      color="red" />
            <SignalChip label="FUNDING"      v={signals.funding}      color="green" />
            <SignalChip label="ACQUISITIONS" v={signals.acquisitions} color="amber" />
            <SignalChip label="EXECS"        v={signals.execs}        color="purple" />
            <SignalChip label="IPOS"         v={signals.ipos}         color="blue" />
            <SignalChip label="LAUNCHES"     v={signals.launches}     color="green" />
            <SignalChip label="OUTAGES"      v={signals.outages}      color="red" />
            <SignalChip label="EOLs"         v={signals.eols}         color="yellow" />
            <SignalChip label="STEALTH"      v={signals.stealth}      color="purple" />
            <SignalChip label="YC"           v={signals.yc}           color="amber" />
            <SignalChip label="BANKRUPTCY"   v={(signals as any).bankruptcy ?? 0}   color="red" />
            <SignalChip label="CRYPTO SCAMS" v={(signals as any).crypto_scams ?? 0} color="red" />
          </>
        )}
      </div>

      {/* tab strip */}
      <div className="flex items-stretch border-b border-wire/60 bg-ink-800/30 text-[11px]">
        {TABS.map(t => (
          <button key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`px-3 py-1.5 border-r border-wire/60 tracking-[0.18em]
                    ${tab === t.id ? 'text-amber bg-amber/5' : 'text-mute hover:text-amber/80'}`}>
            {t.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        {tab === 'layoffs'  && <LayoffsTab days={days} />}
        {tab === 'funding'  && <FundingTab days={days} />}
        {tab === 'm&a'      && <MATab days={days} />}
        {tab === 'execs'    && <ExecsTab days={days} />}
        {tab === 'products' && <ProductsTab days={days} />}
        {tab === 'startups' && <StartupsTab days={days} />}
        {tab === 'bankruptcy'   && <BankruptcyTab days={days} />}
        {tab === 'crypto-scams' && <CryptoScamsTab days={days} />}
      </div>
    </Panel>
  )
}

function SignalChip({ label, v, color }: { label: string; v: number; color: 'red'|'amber'|'green'|'blue'|'purple'|'yellow' }) {
  const cls = `chip chip-${color}`
  return (
    <span className={cls} title={label}>
      <span className="mr-1.5 text-[10px] tracking-wider opacity-80">{label}</span>
      <span className="font-semibold tabular-nums">{v}</span>
    </span>
  )
}

function TopCompanies({ items }: { items: { name: string; kind: string; events: number }[] }) {
  if (!items?.length) return null
  return (
    <div className="px-3 py-2 flex flex-wrap gap-1 border-b border-wire/40">
      <span className="text-mute text-[10px] uppercase tracking-[0.18em] mr-1">Top</span>
      {items.slice(0, 8).map(c => (
        <span key={c.name + c.kind} className="chip chip-blue">{c.name} · {c.events}</span>
      ))}
    </div>
  )
}

function NewsRow({ item, leading, trailing }: { item: any; leading?: React.ReactNode; trailing?: React.ReactNode }) {
  return (
    <li className="row-link">
      <div className="flex items-start gap-2">
        <span className={`chip ${priorityClass(item.priority)} shrink-0 w-12 justify-center`}>
          {severityLabel(item.priority)}
        </span>
        <span className="shrink-0 text-mute w-9 text-right tabular-nums">{relTime(item.published_at)}</span>
        <span className="shrink-0 text-cyber-blue/80 w-28 truncate uppercase tracking-wider text-[10px]">
          {item.source_name}
        </span>
        {leading}
        <a href={safeHref(item.url)} target="_blank" rel="noreferrer noopener" className="text-amber/95 hover:text-amber leading-snug flex-1">
          {item.title}
        </a>
        {trailing}
      </div>
      {(item.tags?.length ?? 0) > 0 && (
        <div className="mt-1 ml-[88px] flex flex-wrap gap-1">
          {item.tags.slice(0, 5).map((t: string) => <span key={t} className={`chip ${tagClass(t)}`}>{t}</span>)}
        </div>
      )}
    </li>
  )
}

// ---------- tabs ---------------------------------------------------------

function LayoffsTab({ days }: { days: number }) {
  const [data, setData] = useState<LayoffsResponse | null>(null)
  useEffect(() => { api.industryLayoffs(days, 200).then(setData).catch(() => {}) }, [days])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const t = data.totals
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="EVENTS"             v={t.events} />
        <Metric label="HEADCOUNT TOTAL"    v={fmtCount(t.total_headcount)} accent="red" />
        <Metric label="AI-DRIVEN"          v={t.ai_driven_events} accent="amber" />
        <Metric label="HIRING FREEZES"     v={t.hiring_freezes} accent="yellow" />
        <Metric label="WITH HEADCOUNT"     v={t.events_with_headcount} />
      </div>
      <TopCompanies items={data.top_companies} />
      <ul className="text-[12px]">
        {data.items.map(it => {
          const ev = it.event
          return (
            <NewsRow key={it.id} item={it}
              leading={
                <div className="shrink-0 w-32 flex items-center gap-1">
                  {ev.headcount != null && <span className="chip chip-red">{fmtCount(ev.headcount)} cut</span>}
                  {ev.percent  != null  && <span className="chip chip-amber">{ev.percent}%</span>}
                  {ev.ai_driven        && <span className="chip chip-purple">AI</span>}
                  {ev.hiring_freeze    && <span className="chip chip-yellow">FREEZE</span>}
                </div>
              } />
          )
        })}
      </ul>
    </div>
  )
}

function FundingTab({ days }: { days: number }) {
  const [data, setData] = useState<FundingResponse | null>(null)
  useEffect(() => { api.industryFunding(days, 200).then(setData).catch(() => {}) }, [days])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const t = data.totals
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="EVENTS"        v={t.events} />
        <Metric label="TOTAL RAISED"  v={fmtUSD(t.total_raised_usd)} accent="green" />
        {Object.entries(t.rounds).map(([r, n]) => (
          <Metric key={r} label={r.toUpperCase()} v={n} accent="blue" />
        ))}
      </div>
      <TopCompanies items={data.top_companies} />
      <ul className="text-[12px]">
        {data.items.map(it => {
          const ev = it.event
          return (
            <NewsRow key={it.id} item={it}
              leading={
                <div className="shrink-0 w-32 flex items-center gap-1">
                  {ev.amount_usd != null && <span className="chip chip-green">{fmtUSD(ev.amount_usd)}</span>}
                  {ev.round              && <span className="chip chip-blue">{ev.round}</span>}
                </div>
              }
              trailing={ev.valuation_usd != null
                ? <span className="chip">val {fmtUSD(ev.valuation_usd)}</span>
                : null}
            />
          )
        })}
      </ul>
    </div>
  )
}

function MATab({ days }: { days: number }) {
  const [data, setData] = useState<AcquisitionsResponse | null>(null)
  const [ipos, setIpos] = useState<any>(null)
  useEffect(() => {
    api.industryAcquisitions(Math.max(days, 60), 200).then(setData).catch(() => {})
    api.industryIPOs(Math.max(days, 60), 100).then(setIpos).catch(() => {})
  }, [days])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const t = data.totals
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="ACQUISITIONS"   v={t.events} />
        <Metric label="TOTAL VALUE"    v={fmtUSD(t.total_value_usd)} accent="amber" />
        <Metric label="DEALS PRICED"   v={t.deals_with_amount} />
        {ipos && <Metric label="IPOs"  v={ipos.totals.events} accent="blue" />}
      </div>
      <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80">M&A</div>
      <ul className="text-[12px]">
        {data.items.map(it => {
          const ev = it.event
          return (
            <NewsRow key={it.id} item={it}
              leading={
                <div className="shrink-0 w-44 flex items-center gap-1">
                  {ev.acquirer && <span className="chip chip-amber">{ev.acquirer}</span>}
                  {ev.target   && <span className="chip chip-blue">→ {ev.target}</span>}
                </div>
              }
              trailing={ev.amount_usd != null ? <span className="chip chip-green">{fmtUSD(ev.amount_usd)}</span> : null} />
          )
        })}
      </ul>
      {ipos && ipos.items.length > 0 && (
        <>
          <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80">IPOs / S-1 / Listings</div>
          <ul className="text-[12px]">
            {ipos.items.map((it: any) => (
              <NewsRow key={it.id} item={it} leading={<span className="chip chip-blue shrink-0">IPO</span>} />
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

function ExecsTab({ days }: { days: number }) {
  const [data, setData] = useState<ExecsResponse | null>(null)
  useEffect(() => { api.industryExecs(Math.max(days, 60), 200).then(setData).catch(() => {}) }, [days])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const t = data.totals
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="EVENTS" v={t.events} />
        {Object.entries(t.by_role).map(([r, n]) => (
          <Metric key={r} label={r} v={n} accent="purple" />
        ))}
        {Object.entries(t.by_direction).map(([d, n]) => (
          <Metric key={d} label={d.toUpperCase()} v={n} accent={d === 'out' ? 'red' : 'green'} />
        ))}
      </div>
      <TopCompanies items={data.top_companies} />
      <ul className="text-[12px]">
        {data.items.map(it => {
          const ev = it.event
          const dirCls = ev.direction === 'out' ? 'chip-red'
                       : ev.direction === 'in'  ? 'chip-green'
                       : 'chip-amber'
          return (
            <NewsRow key={it.id} item={it}
              leading={
                <div className="shrink-0 w-32 flex items-center gap-1">
                  <span className="chip chip-purple">{ev.role}</span>
                  <span className={`chip ${dirCls}`}>{ev.direction}</span>
                </div>
              } />
          )
        })}
      </ul>
    </div>
  )
}

function ProductsTab({ days }: { days: number }) {
  const [data, setData] = useState<ProductsResponse | null>(null)
  useEffect(() => { api.industryProducts(days, 200).then(setData).catch(() => {}) }, [days])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const sections: { label: string; chip: string; cls: string; items: any[] }[] = [
    { label: 'LAUNCHES / GA',       chip: 'LAUNCH', cls: 'chip-green',  items: data.launches },
    { label: 'OUTAGES / INCIDENTS', chip: 'OUTAGE', cls: 'chip-red',    items: data.outages  },
    { label: 'END OF LIFE',         chip: 'EOL',    cls: 'chip-yellow', items: data.eols     },
  ]
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="LAUNCHES" v={data.totals.launches} accent="green" />
        <Metric label="OUTAGES"  v={data.totals.outages}  accent="red"   />
        <Metric label="EOLs"     v={data.totals.eols}     accent="yellow"/>
      </div>
      {sections.map(s => (
        <section key={s.label}>
          <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80">{s.label}</div>
          {s.items.length === 0 ? (
            <div className="px-3 py-1 text-mute text-xs">none in window.</div>
          ) : (
            <ul className="text-[12px]">
              {s.items.map(it => (
                <NewsRow key={it.id} item={it}
                         leading={<span className={`chip ${s.cls} shrink-0`}>{s.chip}</span>} />
              ))}
            </ul>
          )}
        </section>
      ))}
    </div>
  )
}

function StartupsTab({ days }: { days: number }) {
  const [data, setData] = useState<any>(null)
  useEffect(() => { api.industryStartups(Math.max(days, 60), 150).then(setData).catch(() => {}) }, [days])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="STEALTH"      v={data.totals.stealth} accent="purple" />
        <Metric label="YC BATCH"     v={data.totals.yc}      accent="amber" />
        <Metric label="SEED ROUNDS"  v={data.totals.seed_rounds} accent="green" />
      </div>
      {[
        { label: 'Stealth emergence', chip: 'STEALTH', cls: 'chip-purple', items: data.stealth },
        { label: 'Y Combinator',      chip: 'YC',      cls: 'chip-amber',  items: data.yc      },
        { label: 'Seed rounds',       chip: 'SEED',    cls: 'chip-green',  items: data.seed_rounds },
      ].map(s => (
        <section key={s.label}>
          <div className="px-3 pt-2 pb-1 text-[10px] uppercase tracking-[0.2em] text-amber/80">{s.label}</div>
          {s.items.length === 0 ? (
            <div className="px-3 py-1 text-mute text-xs">none in window.</div>
          ) : (
            <ul className="text-[12px]">
              {s.items.map((it: any) => (
                <NewsRow key={it.id} item={it}
                  leading={
                    <div className="shrink-0 w-32 flex items-center gap-1">
                      <span className={`chip ${s.cls}`}>{s.chip}</span>
                      {it.event?.amount_usd != null && <span className="chip chip-green">{fmtUSD(it.event.amount_usd)}</span>}
                    </div>
                  } />
              ))}
            </ul>
          )}
        </section>
      ))}
    </div>
  )
}

function BankruptcyTab({ days }: { days: number }) {
  const [data, setData] = useState<any>(null)
  const [sort, setSort] = useState<'date'|'debt'>('debt')
  useEffect(() => { api.industryBankruptcy(Math.max(days, 90), 200, sort).then(setData).catch(() => {}) }, [days, sort])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const t = data.totals
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="FILINGS"      v={t.events} accent="red" />
        <Metric label="TOTAL DEBT"   v={fmtUSD(t.total_debt_usd)} accent="red" />
        {Object.entries(t.by_chapter || {}).map(([c, n]) => (
          <Metric key={c} label={c.toUpperCase()} v={n as number} accent="yellow" />
        ))}
        <div className="ml-auto flex gap-1">
          {(['date','debt'] as const).map(s => (
            <button key={s} onClick={() => setSort(s)}
              className={`chip cursor-pointer ${sort === s ? 'chip-amber' : ''}`}>{s}</button>
          ))}
        </div>
      </div>
      <ul className="text-[12px]">
        {data.items.map((it: any) => {
          const ev = it.event || {}
          const sz = it.cluster_size as number | undefined
          return (
            <NewsRow key={it.id} item={it}
              leading={
                <div className="shrink-0 w-32 flex items-center gap-1">
                  {ev.chapter      && <span className="chip chip-red">CH-{ev.chapter}</span>}
                  {ev.debt_usd     && <span className="chip chip-red">{fmtUSD(ev.debt_usd)}</span>}
                  {ev.ceased_operations && <span className="chip chip-yellow">CEASED</span>}
                </div>
              }
              trailing={sz && sz > 1
                ? <span className="chip chip-blue" title={(it.also_seen_in || []).map((a:any) => a.source_name).join(', ')}>+{sz - 1}</span>
                : null}
            />
          )
        })}
      </ul>
    </div>
  )
}

function CryptoScamsTab({ days }: { days: number }) {
  const [data, setData] = useState<any>(null)
  const [sort, setSort] = useState<'date'|'amount'>('amount')
  useEffect(() => { api.industryCryptoScams(days, 200, sort).then(setData).catch(() => {}) }, [days, sort])
  if (!data) return <div className="p-3 text-mute text-xs">loading...</div>
  const t = data.totals
  return (
    <div>
      <div className="px-3 py-2 border-b border-wire/40 flex flex-wrap gap-2 text-[11px]">
        <Metric label="INCIDENTS"     v={t.events} accent="red" />
        <Metric label="TOTAL STOLEN"  v={fmtUSD(t.total_stolen_usd)} accent="red" />
        {Object.entries(t.by_kind || {}).slice(0, 5).map(([k, n]) => (
          <Metric key={k} label={k.toUpperCase()} v={n as number} accent="amber" />
        ))}
        <div className="ml-auto flex gap-1">
          {(['date','amount'] as const).map(s => (
            <button key={s} onClick={() => setSort(s)}
              className={`chip cursor-pointer ${sort === s ? 'chip-amber' : ''}`}>{s}</button>
          ))}
        </div>
      </div>
      <ul className="text-[12px]">
        {data.items.map((it: any) => {
          const ev = it.event || {}
          const sz = it.cluster_size as number | undefined
          return (
            <NewsRow key={it.id} item={it}
              leading={
                <div className="shrink-0 w-32 flex items-center gap-1">
                  {ev.amount_usd != null && <span className="chip chip-red">{fmtUSD(ev.amount_usd)}</span>}
                  {ev.kind                && <span className="chip chip-purple">{ev.kind}</span>}
                </div>
              }
              trailing={
                <>
                  {(ev.assets || []).slice(0, 3).map((a: string) => (
                    <span key={a} className="chip chip-blue">{a}</span>
                  ))}
                  {sz && sz > 1 && <span className="chip">+{sz - 1}</span>}
                </>
              }
            />
          )
        })}
      </ul>
    </div>
  )
}

function Metric({ label, v, accent }: { label: string; v: number | string; accent?: 'red'|'amber'|'green'|'blue'|'purple'|'yellow' }) {
  const cls = accent === 'red'    ? 'text-cyber-red'
            : accent === 'green'  ? 'text-cyber-green'
            : accent === 'amber'  ? 'text-amber'
            : accent === 'blue'   ? 'text-cyber-blue'
            : accent === 'purple' ? 'text-cyber-purple'
            : accent === 'yellow' ? 'text-cyber-yellow'
            : 'text-amber/90'
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 border border-wire-strong rounded-sm">
      <span className="text-mute text-[10px] uppercase tracking-wider">{label}</span>
      <span className={`font-semibold tabular-nums ${cls}`}>{v}</span>
    </span>
  )
}
