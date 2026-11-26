import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, AlertTriangle, Check, Copy, ExternalLink, Info, Search, UserRound, VenetianMask } from 'lucide-react'
import type { EngineConfig, QueryResult } from '@/registry'
import type { VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { computeActorProfile, nameKey, type ActorProfile, type ArtifactType, type Incident, type LeakSite, type ProfileItem } from '@/actorProfile'
import { computeActorActivity, ACTIVE_DAYS, RECENT_DAYS, type ActorActivity } from '@/actorActivity'
import type { ActorCandidate } from '@/components/ActorResolver'
import VerdictExplainerModal from '@/components/results/VerdictExplainerModal'
import { useAuth } from '@/auth/context'
import { apiJson } from '@/lib/api'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'
import { countryName } from '@/lib/countries'
import { knowledgeColor } from '@/lib/scoreColors'

// The threat actor report: a compact card (who it is, whether it's active, what it
// does) over a tabbed detail with fixed sections, then every source's card below, as
// on artifacts. Nothing here is tied to a particular source: each section gathers
// what the sources that answered provide, and says which one said it. Used live
// (ResultsPage) and for history entries (HistoryDetailPage, `asOf` = when it ran).
//
// What the card can claim depends on what the sources identified (actorProfile.ts
// `status`): a confirmed actor gets the full card; a single-source or closest match
// gets a warning; a forum handle a reduced "person" card; sources that disagree a
// list of the other matches; and no match at all no card, only suggestions and the
// unverified full-text mentions.

const lbl = 'text-xs text-muted-foreground uppercase tracking-wide font-medium'

// Provenance: every value on the card says where it comes from (short names keep it
// unobtrusive; the full list is in the tooltip).
const SHORT: Record<string, string> = { 'MITRE ATT&CK': 'MITRE', 'Recorded Future': 'RF', 'AlienVault OTX': 'OTX' }
const short = (s: string) => SHORT[s] ?? s
const union = (...lists: (string[] | undefined)[]) => [...new Set(lists.flat().filter((x): x is string => !!x))]
const sourcesOf = (items: ProfileItem[]) => union(...items.map(i => i.sources))

/** "MITRE · RF" in small muted type, full names on hover. */
function Src({ names, className = '' }: { names: (string | undefined)[]; className?: string }) {
  const { t } = useI18n()
  const list = union(names as string[])
  if (list.length === 0) return null
  return (
    <span title={t('ar.sources', { sources: list.join(', ') })}
      className={`text-[0.65rem] font-normal normal-case tracking-normal text-muted-foreground/80 ${className}`}>
      {list.map(short).join(' · ')}
    </span>
  )
}

/** A badge with its source inside, after a thin divider. */
function Badge({ children, src, tone = 'muted', mono = false }: { children: React.ReactNode; src?: string; tone?: 'muted' | 'red' | 'steel' | 'amber'; mono?: boolean }) {
  const { t } = useI18n()
  const cls = tone === 'red' ? 'border-red-500/40 bg-red-500/10 text-red-400'
    : tone === 'steel' ? 'border-primary/40 text-primary'
      : tone === 'amber' ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
        : 'border-border text-muted-foreground'
  return (
    <span title={src ? t('ar.sources', { sources: src }) : undefined}
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs ${cls}`}>
      <span className={mono ? 'font-mono' : undefined}>{children}</span>
      {src && <span className="pl-1.5 border-l border-border text-[0.65rem] opacity-75">{short(src)}</span>}
    </span>
  )
}

// ── Small pieces ─────────────────────────────────────────────────────────────

function Chip({ item, mono = false }: { item: ProfileItem; mono?: boolean }) {
  const { t, locale } = useI18n()
  const label = item.country ? countryName(item.country, locale) : item.value
  return (
    <span title={t('ar.sources', { sources: item.sources.join(', ') })}
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-border bg-muted/30 text-xs text-foreground/90 whitespace-nowrap">
      <span className={mono ? 'font-mono' : undefined}>{label}</span>
      {item.detail && <span className="text-muted-foreground">{item.detail}</span>}
      <span className={`text-[0.65rem] ${item.sources.length > 1 ? 'font-semibold text-primary' : 'text-muted-foreground/80'}`}>
        {item.sources.slice(0, 2).map(short).join(' · ')}{item.sources.length > 2 ? ` +${item.sources.length - 2}` : ''}
      </span>
    </span>
  )
}

function Chips({ items, max = 12, mono = false }: { items: ProfileItem[]; max?: number; mono?: boolean }) {
  const { t } = useI18n()
  const [all, setAll] = useState(false)
  if (items.length === 0) return <span className="text-sm text-muted-foreground">—</span>
  const shown = all ? items : items.slice(0, max)
  return (
    <div className="flex flex-wrap gap-1.5">
      {shown.map(i => <Chip key={i.value} item={i} mono={mono} />)}
      {items.length > shown.length && (
        <button type="button" onClick={() => setAll(true)} className="text-xs text-primary hover:underline">
          {t('ar.showAll', { n: items.length })}
        </button>
      )}
    </div>
  )
}

/** Top values with a count (victims per sector / country) as bars; otherwise chips. */
function Ranked({ items }: { items: ProfileItem[] }) {
  const { locale } = useI18n()
  const counted = items.filter(i => typeof i.count === 'number')
  if (counted.length === 0) return <Chips items={items} max={8} />
  const top = counted.slice(0, 5)
  const max = Math.max(1, ...top.map(i => i.count!))
  return (
    <div className="flex flex-col gap-1">
      {top.map(i => (
        <div key={i.value} className="grid grid-cols-[minmax(0,8rem)_1fr_2.5rem] items-center gap-2 text-xs">
          <span className="truncate text-foreground/90" title={i.value}>{i.country ? countryName(i.country, locale) : i.value}</span>
          <span className="h-1.5 rounded-full bg-muted overflow-hidden">
            <span className="block h-full rounded-full bg-primary/80" style={{ width: `${(100 * i.count!) / max}%` }} />
          </span>
          <span className="text-right text-muted-foreground tabular-nums">{i.count!.toLocaleString(locale)}</span>
        </div>
      ))}
    </div>
  )
}

function Kpi({ value, label, sub, src }: { value: React.ReactNode; label: string; sub?: string; src?: string[] }) {
  return (
    <div className="bg-background/60 px-3 py-2.5 flex flex-col gap-0.5 min-w-0">
      <span className="text-xl font-semibold tabular-nums text-foreground">{value}</span>
      <span className="text-xs text-muted-foreground">{label}</span>
      {sub && <span className="text-xs text-muted-foreground/80 truncate" title={sub}>{sub}</span>}
      {src && <Src names={src} className="truncate" />}
    </div>
  )
}

// ── Suggestions ("did you mean…") ────────────────────────────────────────────

function useSuggestions(query: string, exclude: string, enabled: boolean): ActorCandidate[] {
  const [data, setData] = useState<{ q: string; c: ActorCandidate[] }>({ q: '', c: [] })
  useEffect(() => {
    if (!enabled || !query) return
    let cancelled = false
    apiJson<{ candidates: ActorCandidate[] }>(`/actor/resolve?q=${encodeURIComponent(query)}`)
      .then(r => { if (!cancelled) setData({ q: query, c: r.candidates ?? [] }) })
      .catch(() => { if (!cancelled) setData({ q: query, c: [] }) })
    return () => { cancelled = true }
  }, [query, enabled])
  if (!enabled || data.q !== query) return []
  const ex = nameKey(exclude)
  return data.c.filter(c => !c.minor && nameKey(c.name) !== ex).slice(0, 4)
}

function Suggestions({ items }: { items: ActorCandidate[] }) {
  const { t } = useI18n()
  if (items.length === 0) return null
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs text-muted-foreground">{t('ar.didYouMean')}</span>
      {items.map(c => (
        <Link key={`${c.name}-${c.sources.join()}`} to={`/results?indicator=${encodeURIComponent(c.name)}&type=threat-actor`}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-primary/40 bg-primary/10 text-xs text-primary hover:bg-primary/20">
          <Search className="h-3 w-3" />{c.name}
          <span className="text-muted-foreground">· {c.sources.length}</span>
        </Link>
      ))}
    </div>
  )
}

// ── Status banner ────────────────────────────────────────────────────────────

function StatusBanner({ profile, suggestions }: { profile: ActorProfile; suggestions: ActorCandidate[] }) {
  const { t } = useI18n()
  const p = profile
  if (p.status === 'confirmed' || p.status === 'none') return null
  const one = p.identities[0]
  const text = p.status === 'persona'
    ? t('ar.status.persona', { name: p.name, source: one?.source ?? '' })
    : p.status === 'conflict'
      ? t('ar.status.conflict', { name: p.name })
      : one?.exact === false
        ? t('ar.status.closest', { name: p.name, source: one.source })
        : t('ar.status.single', { source: one?.source ?? '' })
  // One slim line at the top of the card: the warning, then (same line, wrapping
  // if needed) the other matches and the suggestions as small links.
  return (
    <div className="-mx-5 -mt-5 mb-1 px-5 py-1.5 rounded-t-lg border-b border-amber-500/30 bg-amber-500/5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span className="inline-flex items-center gap-1.5 text-amber-300"><AlertTriangle className="h-3.5 w-3.5 shrink-0" />{text}</span>
      {p.status === 'conflict' && p.others.map(o => (
        <Link key={o.name} to={`/results?indicator=${encodeURIComponent(o.name)}&type=threat-actor`}
          title={`${o.sources.join(', ')} · ${t('ar.searchThis')}`} className="text-primary hover:underline">
          {o.name} <span className="text-muted-foreground">({o.sources.join(', ')})</span>
        </Link>
      ))}
      <Suggestions items={suggestions} />
    </div>
  )
}

// ── Side column: activity + knowledge ────────────────────────────────────────

const LEVEL_STYLE: Record<ActorActivity['level'], string> = {
  active: 'text-red-400 bg-red-500/10 border-red-500/40',
  recent: 'text-amber-400 bg-amber-500/10 border-amber-500/40',
  dormant: 'text-slate-400 bg-slate-500/10 border-slate-500/40',
  unknown: 'text-muted-foreground bg-muted/30 border-border',
}

function Side({ profile, activity, verdict, thresholds, loading }: {
  profile: ActorProfile; activity: ActorActivity; verdict: VerdictResult; thresholds: VerdictThresholds | null; loading: boolean
}) {
  const { t, tn, locale } = useI18n()
  const [explain, setExplain] = useState(false)
  const rw = profile.ransomware
  const reports90 = activity.recent.filter(c => c.kind === 'report').reduce((n, c) => n + c.count, 0)
  const ago = activity.daysSince === 0 ? t('activity.today') : activity.daysSince != null ? tn('activity.daysAgo', activity.daysSince) : null
  const row = (k: string, v: React.ReactNode, src?: (string | undefined)[]) => (
    <div className="flex justify-between gap-3 text-sm">
      <span className="text-muted-foreground">{k}</span>
      <span className="flex flex-col items-end text-right tabular-nums text-foreground leading-tight">{v ?? '—'}{v != null && src && <Src names={src} />}</span>
    </div>
  )
  const reportSources = activity.recent.filter(c => c.kind === 'report').map(c => c.source)
  const k = verdict.knowledge ?? 0
  return (
    <aside className="flex flex-col gap-4 md:border-l md:border-border md:pl-5 border-t md:border-t-0 border-border pt-4 md:pt-0">
      {/* Knowledge first, then activity, then the rest */}
      <div className="flex flex-col gap-1.5">
        <div className="flex justify-between items-baseline gap-2">
          <span className={lbl}>{t('score.knowledge')}</span>
          <span className="text-sm tabular-nums"><b>{k}</b><span className="text-muted-foreground"> / 10</span></span>
        </div>
        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
          <div className="h-full rounded-full" style={{ width: `${k * 10}%`, background: knowledgeColor(k) }} />
        </div>
        <div className="flex justify-between gap-2 text-xs text-muted-foreground">
          <span>{t('summary.answered', { responded: verdict.responded, queried: verdict.queried })}</span>
          <button type="button" onClick={() => setExplain(true)} className="inline-flex items-center gap-1 hover:text-foreground">
            <Info className="h-3 w-3" />{t('summary.howCalculated')}
          </button>
        </div>
      </div>
      <div className="flex flex-col gap-1.5" title={t('activity.legend', { active: ACTIVE_DAYS, recent: RECENT_DAYS })}>
        <span className={lbl}>{t('activity.title')}</span>
        <span className={`inline-flex w-fit items-center gap-2 px-3 py-1 rounded-full border text-xs font-bold uppercase tracking-wider ${LEVEL_STYLE[activity.level]}`}>
          <Activity className="h-3.5 w-3.5" />{t(`activity.level.${activity.level}`)}
        </span>
        <span className="text-xs text-muted-foreground">
          {loading && activity.level === 'unknown' ? t('activity.loading') : ago ?? t('activity.hint.unknown')}
        </span>
      </div>
      <div className="flex flex-col gap-1.5">
        {row(t('activity.lastOperation'), fmtDate(activity.lastOperation?.date, locale), [activity.lastOperation?.source])}
        {row(t('activity.lastReport'), fmtDate(activity.lastReport?.date, locale), [activity.lastReport?.source])}
        {rw ? <>
          {row(t('ar.victims30'), rw.d30.toLocaleString(locale), [profile.prov.ransomware])}
          {row(t('ar.victims90'), rw.d90.toLocaleString(locale), [profile.prov.ransomware])}
        </> : row(t('ar.reports90'), reports90, reportSources)}
        {rw?.first && row(t('ar.activeSince'), fmtDate(rw.first, locale), [profile.prov.ransomware])}
      </div>
      {profile.identities.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className={lbl}>{t('ar.identifiedBy', { n: profile.identities.length })}</span>
          <div className="flex flex-wrap gap-1">
            {profile.identities.map(i => (
              <span key={i.engineId} title={i.name} className="px-1.5 py-0.5 rounded bg-muted/50 text-xs text-muted-foreground">
                {i.source}{i.exact ? '' : ' ~'}
              </span>
            ))}
          </div>
        </div>
      )}
      <VerdictExplainerModal open={explain} onClose={() => setExplain(false)} verdict={verdict} thresholds={thresholds} type="threat-actor" />
    </aside>
  )
}

// ── Card ─────────────────────────────────────────────────────────────────────

/** The actor's other names as tags (sources on hover, ×N when several give it). */
function AliasTags({ aliases, variants }: { aliases: ProfileItem[]; variants: string[] }) {
  const { t } = useI18n()
  const [all, setAll] = useState(false)
  const shown = all ? aliases : aliases.slice(0, 12)
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {shown.map(a => (
        <span key={a.value} title={t('ar.sources', { sources: a.sources.join(', ') })}
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border border-primary/40 bg-primary/10 text-sm font-medium text-foreground cursor-help">
          {a.value}
          <span className={`text-[0.65rem] font-normal ${a.sources.length > 1 ? 'text-primary' : 'text-muted-foreground'}`}>
            {a.sources.slice(0, 2).map(short).join(' · ')}{a.sources.length > 2 ? ` +${a.sources.length - 2}` : ''}
          </span>
        </span>
      ))}
      {aliases.length > shown.length && (
        <button type="button" onClick={() => setAll(true)} className="text-xs text-primary hover:underline">
          {t('ar.more', { n: aliases.length - shown.length })}
        </button>
      )}
      {variants.length > 0 && (
        <span className="text-xs text-muted-foreground cursor-help" title={variants.join(', ')}>
          {t('ar.variants', { n: variants.length })}
        </span>
      )}
    </div>
  )
}

const ARTIFACT_TYPES: ArtifactType[] = ['ip', 'domain', 'url', 'hash']

function Card({ profile, activity, side, banner }: { profile: ActorProfile; activity: ActorActivity; side: React.ReactNode; banner?: React.ReactNode }) {
  const { t, locale } = useI18n()
  const p = profile
  const rw = p.ransomware
  const persona = p.status === 'persona'
  const arts = ARTIFACT_TYPES.flatMap(k => p.artifacts[k])
  const corroborated = p.ttps.filter(x => x.sources.length > 1)
  const reports90 = activity.recent.filter(c => c.kind === 'report').reduce((n, c) => n + c.count, 0)
  const kpis: { value: React.ReactNode; label: string; sub?: string; src?: string[] }[] = []
  const rwSrc = p.prov.ransomware ? [p.prov.ransomware] : undefined
  if (rw) {
    kpis.push({ value: rw.victims.toLocaleString(locale), label: t('ar.kpi.victims'), sub: t('ar.kpi.in12m', { n: rw.d365.toLocaleString(locale) }), src: rwSrc })
    kpis.push({ value: rw.d90.toLocaleString(locale), label: t('ar.kpi.victims90'), sub: t('ar.kpi.in30d', { n: rw.d30.toLocaleString(locale) }), src: rwSrc })
  } else if (!persona) {
    kpis.push({ value: reports90, label: t('ar.kpi.reports90'), sub: activity.lastReport ? t('ar.kpi.lastOn', { date: fmtDate(activity.lastReport.date, locale) ?? '' }) : undefined,
      src: union(activity.recent.filter(c => c.kind === 'report').map(c => c.source)) })
  }
  if (p.ttps.length) kpis.push({ value: p.ttps.length, label: t('ar.kpi.ttps'), sub: corroborated.length ? t('ar.kpi.corroborated', { n: corroborated.length }) : undefined, src: sourcesOf(p.ttps) })
  if (arts.length) kpis.push({ value: arts.length, label: t('ar.kpi.artifacts'), sub: t('ar.kpi.malicious', { n: arts.filter(a => (a.risk ?? 0) >= 65).length }), src: sourcesOf(arts) })
  if (p.vulns.length) kpis.push({ value: p.vulns.length, label: t('ar.kpi.cves'), src: sourcesOf(p.vulns) })
  if (p.arsenal.length || p.arsenalMentioned.length) {
    kpis.push({ value: p.arsenal.length, label: t('ar.kpi.tools'), sub: p.arsenalMentioned.length ? t('ar.kpi.mentioned', { n: p.arsenalMentioned.length }) : undefined, src: sourcesOf(p.arsenal) })
  }
  const hasTargets = p.sectors.length + p.countries.length > 0
  return (
    <section className="rounded-lg border border-border bg-muted/20 p-5 grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_260px] gap-5">
      {banner && <div className="md:col-span-2">{banner}</div>}
      <div className="flex flex-col gap-4 min-w-0">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            {persona ? <UserRound className="h-5 w-5 text-muted-foreground" /> : <VenetianMask className="h-5 w-5 text-muted-foreground" />}
            <h2 className="text-2xl font-bold tracking-tight text-foreground">{p.name}</h2>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {persona && <Badge tone="amber" src={p.prov.categories}>{t('ar.badge.persona')}</Badge>}
            {p.mitreId && <Badge tone="steel" mono src={p.prov.mitreId}>{p.mitreId}</Badge>}
            {(rw || p.ransomwareCategory) && (
              <Badge tone="red" src={rw ? p.prov.ransomware : p.prov.categories}>{rw?.raas ? t('ar.badge.raas') : t('ar.badge.ransomware')}</Badge>
            )}
            {rw && rw.leakSites > 0 && (
              <Badge src={p.prov.ransomware}>{t('ar.badge.leakSites', { n: rw.leakSites, up: rw.leakSitesUp })}</Badge>
            )}
            {p.country && <Badge src={p.prov.country}>{t('ar.badge.country', { country: countryName(p.country, locale) })}</Badge>}
            {p.categories.filter(c => !/ransomware|extortion|forum member/i.test(c)).slice(0, 2).map(c => (
              <Badge key={c} src={p.prov.categories}>{c}</Badge>
            ))}
          </div>
        </div>

        {(p.aliases.length > 0 || p.nameVariants.length > 0) && (
          <div className="flex flex-col gap-1">
            <span className={`${lbl} flex items-baseline gap-2`}>{t('ar.aka')}<Src names={sourcesOf(p.aliases)} /></span>
            <AliasTags aliases={p.aliases} variants={p.nameVariants} />
          </div>
        )}

        {p.description && (
          <div className="flex flex-col gap-0.5 max-w-prose">
            <p className="text-sm text-foreground/80 leading-relaxed line-clamp-3" title={p.description}>{p.description}</p>
            <Src names={[p.prov.description]} />
          </div>
        )}

        {kpis.length > 0 && (
          <div className="grid gap-px bg-border border border-border rounded-md overflow-hidden" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(8.5rem, 1fr))' }}>
            {kpis.map(k => <Kpi key={k.label} {...k} />)}
          </div>
        )}

        {hasTargets && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {p.sectors.length > 0 && <div className="flex flex-col gap-1.5"><span className={`${lbl} flex items-baseline gap-2`}>{t('ar.topSectors')}<Src names={sourcesOf(p.sectors)} /></span><Ranked items={p.sectors} /></div>}
            {p.countries.length > 0 && <div className="flex flex-col gap-1.5"><span className={`${lbl} flex items-baseline gap-2`}>{t('ar.topCountries')}<Src names={sourcesOf(p.countries)} /></span><Ranked items={p.countries} /></div>}
          </div>
        )}

        {(p.ttps.length > 0 || p.arsenal.length > 0) && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            {p.ttps.length > 0 && (
              <div className="flex flex-col gap-1.5">
                <span className={`${lbl} flex items-baseline gap-2`}>{corroborated.length ? t('ar.keyTtps') : t('ar.firstTtps')}<Src names={sourcesOf(corroborated.length ? corroborated : p.ttps)} /></span>
                <Chips items={(corroborated.length ? corroborated : p.ttps).slice(0, 6)} max={6} mono />
              </div>
            )}
            {p.arsenal.length > 0 && (
              <div className="flex flex-col gap-1.5"><span className={`${lbl} flex items-baseline gap-2`}>{t('ar.ownArsenal')}<Src names={sourcesOf(p.arsenal)} /></span><Chips items={p.arsenal} max={6} /></div>
            )}
          </div>
        )}
      </div>
      {side}
    </section>
  )
}

// ── No profile ───────────────────────────────────────────────────────────────

function IncidentTable({ items, max = 15 }: { items: Incident[]; max?: number }) {
  const { t, locale } = useI18n()
  const [all, setAll] = useState(false)
  const shown = all ? items : items.slice(0, max)
  return (
    <div className="flex flex-col gap-1.5">
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-sm">
          <tbody>
            {shown.map((i, n) => (
              <tr key={n} className="border-b border-border last:border-0">
                <td className="px-3 py-1.5 text-xs text-muted-foreground tabular-nums whitespace-nowrap w-28">{fmtDate(i.date, locale) ?? '—'}</td>
                <td className="px-2 py-1.5 w-24"><span className="text-[0.65rem] font-semibold uppercase tracking-wide text-muted-foreground">{t(`ar.kind.${i.kind}`)}</span></td>
                <td className="px-2 py-1.5 text-foreground">{i.title}</td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground whitespace-nowrap">{i.source}</td>
                <td className="px-2 py-1.5 w-6">{i.link && <a href={i.link} target="_blank" rel="noreferrer" className="text-primary" title={t('ar.open')}><ExternalLink className="h-3 w-3" /></a>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {items.length > shown.length && (
        <button type="button" onClick={() => setAll(true)} className="text-xs text-primary hover:underline w-fit">{t('ar.showAll', { n: items.length })}</button>
      )}
    </div>
  )
}

function NoProfile({ profile, query, suggestions, loading }: { profile: ActorProfile; query: string; suggestions: ActorCandidate[]; loading: boolean }) {
  const { t } = useI18n()
  return (
    <section className="rounded-lg border border-border bg-muted/20 p-5 flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h2 className="text-lg font-semibold text-foreground">
          {loading ? t('ar.none.loading') : t('ar.none.title', { q: query })}
        </h2>
        {!loading && <p className="text-sm text-muted-foreground">{t('ar.none.text', { sources: profile.consulted.join(', ') })}</p>}
      </div>
      <Suggestions items={suggestions} />
      {profile.mentions.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className={lbl}>{t('ar.none.mentions', { n: profile.mentions.length })}</span>
          <p className="text-xs text-muted-foreground">{t('ar.none.mentionsHint', { sources: [...new Set(profile.mentions.map(m => m.source))].join(', ') })}</p>
          <IncidentTable items={profile.mentions} max={8} />
        </div>
      )}
    </section>
  )
}

// ── Detail tabs ──────────────────────────────────────────────────────────────

type TabId = 'victims' | 'ttps' | 'vulns' | 'artifacts' | 'arsenal' | 'leaks'

function riskClass(r?: number) {
  return r == null ? 'text-muted-foreground bg-muted/40' : r >= 65 ? 'text-red-400 bg-red-500/10' : r >= 25 ? 'text-amber-400 bg-amber-500/10' : 'text-muted-foreground bg-muted/40'
}

function VictimsTab({ p }: { p: ActorProfile }) {
  const { t, locale } = useI18n()
  const rw = p.ransomware
  return (
    <div className="flex flex-col gap-5">
      {rw && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span><b className="text-foreground tabular-nums">{rw.d30.toLocaleString(locale)}</b> {t('ar.v.in30')}</span>
            <span><b className="text-foreground tabular-nums">{rw.d90.toLocaleString(locale)}</b> {t('ar.v.in90')}</span>
            <span><b className="text-foreground tabular-nums">{rw.d365.toLocaleString(locale)}</b> {t('ar.v.in365')}</span>
            {rw.first && <span>{t('ar.v.first', { date: fmtDate(rw.first, locale) ?? '' })}</span>}
            <span>{t('ar.v.latest', { n: rw.recent.length, source: p.prov.ransomware ?? '' })}</span>
          </div>
          {rw.recent.length > 0 && (
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-sm">
                <thead><tr className="border-b border-border text-left">
                  {[t('ar.v.date'), t('ar.v.victim'), t('ar.v.sector'), t('ar.v.country')].map(h => <th key={h} className={`${lbl} px-3 py-1.5`}>{h}</th>)}
                </tr></thead>
                <tbody>
                  {rw.recent.map((v, i) => (
                    <tr key={i} className="border-b border-border last:border-0">
                      <td className="px-3 py-1.5 text-xs text-muted-foreground tabular-nums whitespace-nowrap">{fmtDate(v.date, locale) ?? '—'}</td>
                      <td className="px-3 py-1.5 text-foreground">{v.name}</td>
                      <td className="px-3 py-1.5 text-muted-foreground">{v.sector ?? '—'}</td>
                      <td className="px-3 py-1.5 text-muted-foreground">{v.country ? countryName(v.country, locale) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {p.incidents.length > 0 && (
        <div className="flex flex-col gap-1.5"><span className={lbl}>{t('ar.v.incidents', { n: p.incidents.length })}</span><IncidentTable items={p.incidents} /></div>
      )}
      {p.organizations.length > 0 && (
        <div className="flex flex-col gap-1.5"><span className={lbl}>{t('ar.v.orgs')}</span><Chips items={p.organizations} max={16} /></div>
      )}
    </div>
  )
}

function PivotRows({ items, type }: { items: ProfileItem[]; type?: string }) {
  const { t } = useI18n()
  const canAnalyze = useAuth().can('analyze')
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full text-sm">
        <tbody>
          {items.map(a => (
            <tr key={`${a.pivot}-${a.value}`} className="border-b border-border last:border-0">
              {type == null && <td className="px-3 py-1.5 text-xs text-muted-foreground whitespace-nowrap w-20">{a.pivot ? t(`type.${a.pivot}`) : ''}</td>}
              <td className="px-3 py-1.5 font-mono text-xs break-all text-foreground">{a.value}</td>
              <td className="px-3 py-1.5 w-16">{a.risk != null && <span className={`inline-block min-w-7 text-center rounded px-1 text-xs font-semibold ${riskClass(a.risk)}`} title={t('ar.riskBy', { source: a.riskSource ?? '' })}>{a.risk}</span>}</td>
              <td className="px-3 py-1.5 text-xs text-muted-foreground whitespace-nowrap">{a.sources.join(', ')}</td>
              <td className="px-3 py-1.5 w-24 text-right">
                {canAnalyze && a.pivot && (
                  <Link to={`/results?indicator=${encodeURIComponent(a.value)}&type=${a.pivot}`} className="text-xs text-primary hover:underline whitespace-nowrap">
                    {t('ar.lookUp')}
                  </Link>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ArtifactsTab({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  const types = ARTIFACT_TYPES.filter(k => p.artifacts[k].length > 0)
  const [filter, setFilter] = useState<ArtifactType | 'all'>('all')
  const items = (filter === 'all' ? types.flatMap(k => p.artifacts[k]) : p.artifacts[filter])
    .slice().sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1))
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5" role="group" aria-label={t('ar.filter')}>
        {(['all', ...types] as const).map(k => (
          <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}
            className={`px-2.5 py-0.5 rounded-full border text-xs ${filter === k ? 'border-primary text-foreground' : 'border-border text-muted-foreground hover:text-foreground'}`}>
            {k === 'all' ? t('ar.all') : t(`type.${k}`)} <span className="text-muted-foreground">{k === 'all' ? items.length : p.artifacts[k].length}</span>
          </button>
        ))}
      </div>
      <PivotRows items={items} />
    </div>
  )
}

function TtpsTab({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-4">
      {p.ttps.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-border text-left">
              {['ID', t('ar.t.technique'), t('ar.t.sources')].map(h => <th key={h} className={`${lbl} px-3 py-1.5`}>{h}</th>)}
            </tr></thead>
            <tbody>
              {p.ttps.map(x => (
                <tr key={x.value} className="border-b border-border last:border-0">
                  <td className="px-3 py-1.5 font-mono text-xs whitespace-nowrap">
                    {/^T/.test(x.value) && x.detail
                      ? <a href={`https://attack.mitre.org/${x.value.startsWith('TA') ? 'tactics' : 'techniques'}/${x.value.replace('.', '/')}`} target="_blank" rel="noreferrer" className="text-primary hover:underline">{x.value}</a>
                      : x.value}
                  </td>
                  <td className="px-3 py-1.5 text-foreground">{x.detail ?? (x.value.match(/^T/) ? '' : x.value)}</td>
                  <td className="px-3 py-1.5 text-xs text-muted-foreground">{x.sources.join(' · ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {p.attackVectors.length > 0 && (
        <div className="flex flex-col gap-1.5"><span className={lbl}>{t('ar.t.vectors')}</span><Chips items={p.attackVectors} max={20} /></div>
      )}
    </div>
  )
}

function ArsenalTab({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="flex flex-col gap-1.5"><span className={lbl}>{t('ar.a.own')}</span><Chips items={p.arsenal} max={40} /></div>
      {p.arsenalMentioned.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className={lbl}>{t('ar.a.mentioned')}</span>
          <Chips items={p.arsenalMentioned} max={40} />
          <p className="text-xs text-muted-foreground">{t('ar.a.mentionedHint')}</p>
        </div>
      )}
    </div>
  )
}

function CopyAddress({ value }: { value: string }) {
  const { t } = useI18n()
  const [done, setDone] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1500) }).catch(() => {})
  }
  return (
    <button type="button" onClick={copy} title={done ? t('ar.l.copied') : t('ar.l.copy')} aria-label={t('ar.l.copy')}
      className="shrink-0 text-muted-foreground hover:text-foreground">
      {done ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

function LeakSitesTab({ sites }: { sites: LeakSite[] }) {
  const { t, locale } = useI18n()
  const status = (s: LeakSite) => s.online === true
    ? <span className="inline-flex items-center gap-1 text-xs text-red-400"><span className="h-2 w-2 rounded-full bg-red-500" />{t('ar.l.online')}</span>
    : s.online === false
      ? <span className="inline-flex items-center gap-1 text-xs text-muted-foreground"><span className="h-2 w-2 rounded-full bg-muted-foreground/50" />{t('ar.l.offline')}</span>
      : <span className="text-xs text-muted-foreground">{t('ar.l.unknown')}</span>
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-muted-foreground">{t('ar.l.hint')}</p>
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-border text-left">
            {[t('ar.l.status'), t('ar.l.type'), t('ar.l.address'), t('ar.l.title'), t('ar.l.checked'), t('ar.l.source')].map(h => <th key={h} className={`${lbl} px-3 py-1.5`}>{h}</th>)}
          </tr></thead>
          <tbody>
            {sites.map((s, i) => (
              <tr key={i} className="border-b border-border last:border-0 align-top">
                <td className="px-3 py-1.5 whitespace-nowrap">{status(s)}</td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground whitespace-nowrap">{s.type ?? '—'}</td>
                <td className="px-3 py-1.5">
                  {/* Attacker infrastructure: plain, selectable text — never a link. */}
                  <span className="flex items-start gap-2"><span className="font-mono text-xs break-all select-all text-foreground">{s.address}</span><CopyAddress value={s.address} /></span>
                </td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground">{s.title ?? '—'}</td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground tabular-nums whitespace-nowrap">{fmtDate(s.lastCheck, locale) ?? '—'}</td>
                <td className="px-3 py-1.5 text-xs text-muted-foreground whitespace-nowrap">{s.source}{s.group ? ` · ${s.group}` : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** A fixed section with nothing in it: say which sources were asked. */
function EmptyTab({ p, what }: { p: ActorProfile; what: TabId }) {
  const { t } = useI18n()
  return <p className="text-sm text-muted-foreground">{t('ar.empty', { sources: p.consulted.join(', '), what: t(`ar.what.${what}`) })}</p>
}

function Tabs({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  const arts = ARTIFACT_TYPES.reduce((n, k) => n + p.artifacts[k].length, 0)
  // Fixed sections, whatever sources are deployed: an empty one says so.
  const victims = p.ransomware?.victims ?? 0
  const tabs: { id: TabId; label: string; count: number }[] = p.status === 'none' ? [] : [
    { id: 'victims', label: t('ar.tab.victims'), count: victims || p.incidents.length + p.organizations.length },
    { id: 'ttps', label: t('ar.tab.ttps'), count: p.ttps.length },
    { id: 'vulns', label: t('ar.tab.vulns'), count: p.vulns.length },
    { id: 'artifacts', label: t('ar.tab.artifacts'), count: arts },
    { id: 'arsenal', label: t('ar.tab.arsenal'), count: p.arsenal.length + p.arsenalMentioned.length },
    { id: 'leaks', label: t('ar.tab.leaks'), count: p.leakSites.length },
  ]
  const [picked, setPicked] = useState<TabId | null>(null)
  // Open on the first section that has data.
  const active = tabs.find(x => x.id === picked)?.id ?? tabs.find(x => x.count > 0)?.id ?? tabs[0]?.id
  if (!active) return null
  return (
    <section className="rounded-lg border border-border">
      <div role="tablist" aria-label={t('ar.detail')} className="flex gap-1 border-b border-border px-2 overflow-x-auto">
        {tabs.map(x => (
          <button key={x.id} role="tab" type="button" aria-selected={active === x.id} onClick={() => setPicked(x.id)}
            className={`search-tab inline-flex items-center gap-1.5 px-4 py-2.5 -mb-px border-b-[3px] text-sm whitespace-nowrap transition-colors ${
              active === x.id ? 'font-semibold text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            <span className={x.count === 0 ? 'opacity-60' : undefined}>{x.label}</span><span className="text-xs font-normal text-muted-foreground tabular-nums">{x.count.toLocaleString()}</span>
          </button>
        ))}
      </div>
      <div className="p-4">
        {tabs.find(x => x.id === active)?.count === 0 ? <EmptyTab p={p} what={active} /> : <>
          {active === 'victims' && <VictimsTab p={p} />}
          {active === 'ttps' && <TtpsTab p={p} />}
          {active === 'vulns' && <PivotRows items={p.vulns} type="cve" />}
          {active === 'artifacts' && <ArtifactsTab p={p} />}
          {active === 'arsenal' && <ArsenalTab p={p} />}
          {active === 'leaks' && <LeakSitesTab sites={p.leakSites} />}
        </>}
      </div>
    </section>
  )
}

// ── Report ───────────────────────────────────────────────────────────────────

export default function ActorReport({ indicator, engines, results, verdict, thresholds, asOf, children }: {
  indicator: string
  engines: EngineConfig[]
  results: Record<string, QueryResult>
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
  /** History: activity is measured from when the lookup ran */
  asOf?: Date
  /** Per-source cards (below the detail) */
  children: React.ReactNode
}) {
  const { t } = useI18n()
  const canAnalyze = useAuth().can('analyze')
  const profile = useMemo(() => computeActorProfile(engines, results, indicator), [engines, results, indicator])
  const activity = useMemo(
    () => computeActorActivity(engines.filter(e => profile.engineIds.has(e.id)), results, asOf, profile.allNames),
    [engines, results, asOf, profile])
  const loading = engines.some(e => results[e.id]?.loading)
  const unsure = !loading && profile.status !== 'confirmed'
  const suggestions = useSuggestions(indicator, profile.name, unsure && canAnalyze)

  return (
    <div className="flex flex-col gap-4">
      {profile.status === 'none'
        ? <NoProfile profile={profile} query={indicator} suggestions={suggestions} loading={loading} />
        : <Card profile={profile} activity={activity}
            banner={!loading && profile.status !== 'confirmed' ? <StatusBanner profile={profile} suggestions={suggestions} /> : undefined}
            side={<Side profile={profile} activity={activity} verdict={verdict} thresholds={thresholds} loading={loading} />} />}
      <Tabs p={profile} />
      <div className="flex flex-col gap-3 mt-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('results.byEngine')}</p>
        <div className="grid grid-cols-1 gap-4">{children}</div>
      </div>
    </div>
  )
}
