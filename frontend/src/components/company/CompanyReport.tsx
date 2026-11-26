import { Building2, Skull, KeyRound, DatabaseZap, Newspaper, Loader2, ExternalLink, CalendarClock } from 'lucide-react'
import type { QueryResult } from '@/registry'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'
import { countryName } from '@/lib/countries'
import { parseCompany } from '@/lib/company'
import { HideScores } from '@/components/results/scoreVisibility'

// The company report: who the company is (profile), how exposed it is (four exposure
// tiles; no risk/knowledge verdict for now), what happened to it (incident timeline), then the per-source
// detail passed in as `children`. Used live (CompanyReportPage) and for history
// entries (HistoryDetailPage), from the same per-source payloads the cards render.

/* eslint-disable @typescript-eslint/no-explicit-any */
type Results = Record<string, QueryResult>
type TileState = 'loading' | 'error' | 'needsDomain' | 'off' | 'ok'

/** A source's payload, or why there is none. */
function source(results: Results, id: string): { state: TileState; d: any } {
  const r = results[id]
  if (!r) return { state: 'off', d: null }
  if (r.loading) return { state: 'loading', d: null }
  const code = (r.data as any)?.error?.code
  if (code === 'NeedsDomain') return { state: 'needsDomain', d: null }
  if (r.error || !r.data || code) return { state: 'error', d: null }
  return { state: 'ok', d: r.data }
}

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : [])

// ── Profile ──────────────────────────────────────────────────────────────────

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  if (children == null || children === '' || (Array.isArray(children) && children.length === 0)) return null
  return (
    <div className="grid grid-cols-[150px_minmax(0,1fr)] gap-3 text-sm">
      <span className="text-xs text-muted-foreground uppercase tracking-wide pt-0.5">{label}</span>
      <span className="text-foreground min-w-0 break-words">{children}</span>
    </div>
  )
}

function Chip({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <span title={title} className="inline-flex px-1.5 py-0.5 mr-1 mb-1 rounded bg-muted border border-border text-xs text-muted-foreground">
      {children}
    </span>
  )
}

function Profile({ indicator, results }: { indicator: string; results: Results }) {
  const { t, locale } = useI18n()
  const wd = source(results, 'wikidata')
  const gl = source(results, 'gleif')
  const w = wd.d?.found ? wd.d : null
  const g = gl.d?.found ? gl.d : null
  const parsed = parseCompany(indicator)
  const name = w?.name ?? g?.legal_name ?? (parsed.name || parsed.domains[0] || indicator)
  const domain = w?.domain ?? parsed.domains[0]
  const hq = arr(w?.headquarters)[0]

  // Countries with a presence: Wikidata (own, HQ, subsidiaries) + GLEIF subsidiaries.
  const presence = new Map<string, Set<string>>()
  const add = (code: string | null | undefined, src: string) => {
    if (!code) return
    const c = code.split('-')[0].toUpperCase()
    if (!presence.has(c)) presence.set(c, new Set())
    presence.get(c)!.add(src)
  }
  for (const p of arr(w?.presence)) add(p?.code, 'Wikidata')
  add(g?.legal_address?.country, 'GLEIF')
  for (const c of Object.keys(g?.children_countries ?? {})) add(c, 'GLEIF')

  const loading = wd.state === 'loading' || gl.state === 'loading'
  const parent = arr(w?.parents)[0]?.name ?? g?.ultimate_parent?.legal_name ?? g?.direct_parent?.legal_name

  return (
    <div className="flex flex-col gap-4 min-w-0">
      <div className="flex items-start gap-3">
        <Building2 className="h-6 w-6 mt-1 text-muted-foreground shrink-0" />
        <div className="min-w-0">
          <h2 className="text-2xl font-semibold text-foreground">{name}</h2>
          {w?.description && <p className="text-sm text-muted-foreground">{w.description}</p>}
          <p className="text-xs text-muted-foreground font-mono break-all mt-0.5">{indicator}</p>
        </div>
      </div>
      {loading && !w && !g && (
        <p className="text-sm text-muted-foreground inline-flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />{t('report.profileLoading')}</p>
      )}
      {!loading && !w && !g && <p className="text-sm text-muted-foreground">{t('report.noProfile')}</p>}
      {w?.exact === false && <p className="text-xs text-amber-400">{t('wikidata.guess')}</p>}
      <div className="flex flex-col gap-2.5">
        <Row label={t('f.sector')}>{arr(w?.sectors).length ? arr(w?.sectors).slice(0, 6).map((s: string) => <Chip key={s}>{s}</Chip>) : null}</Row>
        <Row label={t('f.headquarters')}>
          {hq ? `${hq.name}${hq.country ? `, ${hq.country}` : ''}`
            : g?.hq_address ? [g.hq_address.city, g.hq_address.country && countryName(g.hq_address.country, locale)].filter(Boolean).join(', ') : null}
        </Row>
        <Row label={t('report.presence')}>
          {presence.size ? [...presence.entries()].map(([c, srcs]) => (
            <Chip key={c} title={[...srcs].join(', ')}>{countryName(c, locale)}</Chip>
          )) : null}
        </Row>
        <Row label={t('report.legalEntity')}>
          {g ? <>{g.legal_name} · <span className="font-mono text-xs">{g.lei}</span>{g.jurisdiction ? ` · ${g.jurisdiction}` : ''}</>
            : w?.lei ? <span className="font-mono text-xs">{w.lei}</span> : null}
        </Row>
        <Row label={t('f.parent')}>{parent ?? null}</Row>
        <Row label={t('f.employees')}>{w?.employees != null ? Number(w.employees).toLocaleString(locale) : null}</Row>
        <Row label={t('f.founded')}>{w?.inception ?? null}</Row>
        <Row label={t('f.website')}>
          {domain ? <a href={`https://${domain}`} target="_blank" rel="noreferrer noopener" className="text-primary hover:underline">{domain}</a> : null}
        </Row>
        <Row label={t('f.tickers')}>{arr(w?.tickers).join(', ') || null}</Row>
        <Row label={t('f.subsidiaries')}>
          {(w?.subsidiaries_total || g?.children_total)
            ? t('report.subsidiaries', { wd: w?.subsidiaries_total ?? 0, gl: g?.children_total ?? 0 }) : null}
        </Row>
      </div>
    </div>
  )
}

// ── Exposure tiles ───────────────────────────────────────────────────────────

type Tone = 'bad' | 'warn' | 'good' | 'neutral'
const TONE: Record<Tone, string> = {
  bad: 'border-red-500/40 bg-red-500/5',
  warn: 'border-amber-500/40 bg-amber-500/5',
  good: 'border-green-500/30 bg-green-500/5',
  neutral: 'border-border bg-muted/10',
}
const VALUE_TONE: Record<Tone, string> = {
  bad: 'text-red-400', warn: 'text-amber-400', good: 'text-green-400', neutral: 'text-foreground',
}

function Tile({ icon, title, sourceLabel, state, tone, value, detail }: {
  icon: React.ReactNode
  title: string
  sourceLabel: string
  state: TileState
  tone: Tone
  value?: React.ReactNode
  detail?: React.ReactNode
}) {
  const { t } = useI18n()
  const shownTone = state === 'ok' ? tone : 'neutral'
  return (
    <div className={`rounded-lg border p-4 flex flex-col gap-1.5 ${TONE[shownTone]}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-2 text-xs uppercase tracking-wide font-medium text-muted-foreground">{icon}{title}</span>
        <span className="text-[0.65rem] text-muted-foreground">{sourceLabel}</span>
      </div>
      {state === 'loading' && <span className="text-sm text-muted-foreground inline-flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />{t('summary.loading')}</span>}
      {state === 'error' && <span className="text-sm text-muted-foreground">{t('report.unavailable')}</span>}
      {state === 'needsDomain' && <span className="text-sm text-muted-foreground">{t('report.needsDomain')}</span>}
      {state === 'off' && <span className="text-sm text-muted-foreground">{t('report.off')}</span>}
      {state === 'ok' && (
        <>
          <span className={`text-lg font-semibold ${VALUE_TONE[shownTone]}`}>{value}</span>
          {detail && <span className="text-xs text-muted-foreground leading-relaxed">{detail}</span>}
        </>
      )}
    </div>
  )
}

function ExposureTiles({ results }: { results: Results }) {
  const { t, tn, locale } = useI18n()
  const rl = source(results, 'ransomwarelive')
  const hr = source(results, 'hudsonrock')
  const hb = source(results, 'hibp')
  const gd = source(results, 'gdelt')
  const n = (v: unknown) => Number(v ?? 0).toLocaleString(locale)

  const rlListed = rl.d?.listed === true
  const employees = Number(hr.d?.employees ?? 0)
  const hrTotal = Number(hr.d?.total ?? 0)
  const breaches = Number(hb.d?.count ?? 0)
  const headlines = Number(gd.d?.in_title ?? 0)

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <Tile
        icon={<Skull className="h-4 w-4" />} title={t('report.darkweb')} sourceLabel="ransomware.live" state={rl.state}
        tone={rlListed ? (Number(rl.d?.days_since_last ?? 9999) <= 365 ? 'bad' : 'warn') : 'good'}
        value={rlListed ? tn('report.claims', Number(rl.d?.match_count ?? 0)) : t('report.notOnLeakSites')}
        detail={rlListed
          ? t('report.claimsDetail', { groups: arr(rl.d?.groups).join(', '), date: fmtDate(rl.d?.last_claim, locale) ?? '—' })
          : t('report.leakSitesCaveat')}
      />
      <Tile
        icon={<KeyRound className="h-4 w-4" />} title={t('report.stealers')} sourceLabel="Hudson Rock" state={hr.state}
        tone={employees > 0 ? (Number(hr.d?.days_since_employee ?? 9999) <= 365 ? 'bad' : 'warn') : hrTotal > 0 ? 'warn' : 'good'}
        value={employees > 0 ? tn('report.employeesInfected', employees, { n: n(employees) }) : hrTotal > 0 ? tn('report.usersInfected', Number(hr.d?.users ?? 0), { n: n(hr.d?.users) }) : t('report.noInfections')}
        detail={hrTotal > 0
          ? t('report.stealersDetail', {
            users: n(hr.d?.users), date: fmtDate(hr.d?.last_employee_compromised ?? hr.d?.last_user_compromised, locale) ?? '—',
            families: arr(hr.d?.stealer_families).slice(0, 3).map((f: any) => f?.name).join(', ') || '—',
          })
          : undefined}
      />
      <Tile
        icon={<DatabaseZap className="h-4 w-4" />} title={t('report.breaches')} sourceLabel="Have I Been Pwned" state={hb.state}
        tone={breaches > 0 ? (Number(hb.d?.days_since_latest ?? 9999) <= 365 ? 'bad' : 'warn') : 'neutral'}
        value={breaches > 0 ? tn('hibp.breaches', breaches, { n: n(breaches) }) : t('report.noBreaches')}
        detail={breaches > 0 ? t('report.breachesDetail', { date: fmtDate(hb.d?.latest_breach, locale) ?? '—', n: n(hb.d?.accounts) }) : undefined}
      />
      <Tile
        icon={<Newspaper className="h-4 w-4" />} title={t('report.news')} sourceLabel="GDELT" state={gd.state}
        tone={headlines > 0 ? 'warn' : 'neutral'}
        value={headlines > 0 ? tn('report.headlines', headlines) : t('report.noHeadlines')}
        detail={headlines > 0 ? arr(gd.d?.articles).find((a: any) => a?.in_title)?.title : t('report.newsWindow')}
      />
    </div>
  )
}

// ── Incident timeline ────────────────────────────────────────────────────────

interface Event { date: string; kind: 'ransomware' | 'stealer' | 'breach' | 'news'; text: string; href?: string }

const KIND: Record<Event['kind'], { icon: React.ReactNode; cls: string }> = {
  ransomware: { icon: <Skull className="h-3.5 w-3.5" />, cls: 'text-red-400' },
  stealer: { icon: <KeyRound className="h-3.5 w-3.5" />, cls: 'text-amber-400' },
  breach: { icon: <DatabaseZap className="h-3.5 w-3.5" />, cls: 'text-amber-400' },
  news: { icon: <Newspaper className="h-3.5 w-3.5" />, cls: 'text-sky-400' },
}

function Timeline({ results }: { results: Results }) {
  const { t, locale } = useI18n()
  const events: Event[] = []
  const rl = source(results, 'ransomwarelive').d
  for (const v of rl?.listed ? arr(rl?.matches) : []) {
    const date = v?.discovered ?? v?.attack_date
    if (date) events.push({ date, kind: 'ransomware', text: t('report.ev.claim', { group: v?.group ?? '?', victim: v?.victim ?? '' }), href: v?.link ?? undefined })
  }
  const hr = source(results, 'hudsonrock').d
  if (hr?.last_employee_compromised) events.push({ date: hr.last_employee_compromised, kind: 'stealer', text: t('report.ev.employee') })
  if (hr?.last_user_compromised) events.push({ date: hr.last_user_compromised, kind: 'stealer', text: t('report.ev.user') })
  for (const b of arr(source(results, 'hibp').d?.breaches)) {
    if (b?.breach_date) events.push({ date: b.breach_date, kind: 'breach', text: t('report.ev.breach', { title: b?.title ?? b?.name, n: Number(b?.pwn_count ?? 0).toLocaleString(locale) }), href: b?.link })
  }
  for (const a of arr(source(results, 'gdelt').d?.articles).filter((x: any) => x?.in_title).slice(0, 8)) {
    if (a?.seen) events.push({ date: a.seen, kind: 'news', text: a?.title || a?.url, href: a?.url })
  }
  events.sort((a, b) => String(b.date).localeCompare(String(a.date)))
  if (events.length === 0) return null
  return (
    <div className="rounded-lg border border-border bg-muted/10 p-5 flex flex-col gap-3">
      <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium inline-flex items-center gap-2">
        <CalendarClock className="h-4 w-4" />{t('report.timeline')}
      </p>
      <ol className="flex flex-col gap-2">
        {events.slice(0, 20).map((e, i) => (
          <li key={i} className="grid grid-cols-[110px_20px_minmax(0,1fr)] items-baseline gap-2 text-sm">
            <span className="text-xs text-muted-foreground tabular-nums">{fmtDate(e.date, locale)}</span>
            <span className={KIND[e.kind].cls}>{KIND[e.kind].icon}</span>
            {e.href
              ? <a href={e.href} target="_blank" rel="noreferrer noopener" className="text-foreground hover:underline inline-flex items-start gap-1">{e.text}<ExternalLink className="h-3 w-3 mt-1 shrink-0 text-muted-foreground" /></a>
              : <span className="text-foreground">{e.text}</span>}
          </li>
        ))}
      </ol>
    </div>
  )
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ── Report ───────────────────────────────────────────────────────────────────

export default function CompanyReport({
  indicator, results, notice, children,
}: {
  indicator: string
  results: Results
  /** Shown above the report (history: "archived on…") */
  notice?: React.ReactNode
  /** Per-source cards */
  children: React.ReactNode
}) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-6">
      {notice}
      <div className="rounded-lg border border-border bg-muted/20 p-5">
        <Profile indicator={indicator} results={results} />
      </div>

      <div className="flex flex-col gap-3">
        <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('report.exposureTitle')}</p>
        <ExposureTiles results={results} />
      </div>

      <Timeline results={results} />

      <div className="flex flex-col gap-3">
        <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('report.bySource')}</p>
        <HideScores value><div className="grid grid-cols-1 gap-4">{children}</div></HideScores>
      </div>
    </div>
  )
}
