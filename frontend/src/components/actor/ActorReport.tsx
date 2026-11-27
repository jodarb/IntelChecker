import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, AlertTriangle, Bug, Check, ChevronDown, Copy, Download, FileText, Fingerprint, ExternalLink, Info, Search, Swords, Users, Wrench, X } from 'lucide-react'
import type { EngineConfig, QueryResult } from '@/registry'
import type { VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { computeActorProfile, nameKey, type ActorDescription, type ActorProfile, type ArtifactType, type Incident, type ProfileItem } from '@/actorProfile'
import { computeActorActivity, ACTIVE_DAYS, RECENT_DAYS, type ActorActivity } from '@/actorActivity'
import type { ActorCandidate } from '@/components/ActorResolver'
import VerdictExplainerModal from '@/components/results/VerdictExplainerModal'
import { HideScores } from '@/components/results/scoreVisibility'
import { useAuth } from '@/auth/context'
import { apiJson } from '@/lib/api'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'
import { countryName } from '@/lib/countries'
import { knowledgeColor } from '@/lib/scoreColors'

// The threat actor report: a Summary (name, aliases, descriptions, a few "field:
// value" rows, most targeted sectors / countries, and two buttons that open the TTPs
// and arsenal as exportable tables), then every source's card below, as on
// artifacts. Every value names the sources that give it, in full. Used live
// (ResultsPage) and for history entries (HistoryDetailPage, `asOf` = when it ran).
//
// What the summary can claim depends on what the sources identified (actorProfile.ts
// `status`): a single-source or closest match, a forum handle or sources that
// disagree get a warning line on top; no match at all gets no summary, only
// suggestions and the unverified full-text mentions.

const lbl = 'text-xs text-muted-foreground uppercase tracking-wide font-medium'

// ── Sources ──────────────────────────────────────────────────────────────────

/** The sources that give a value, as small named pills: always the full name. */
function Sources({ names, className = '' }: { names: (string | undefined)[]; className?: string }) {
  const list = [...new Set(names.filter((x): x is string => !!x))]
  if (list.length === 0) return null
  return (
    <span className={`inline-flex flex-wrap gap-1 ${className}`}>
      {list.map(n => (
        <span key={n} className="px-1.5 py-px rounded border border-border bg-muted/40 text-[0.68rem] leading-4 text-muted-foreground whitespace-nowrap">{n}</span>
      ))}
    </span>
  )
}

const sourcesOf = (items: ProfileItem[]) => [...new Set(items.flatMap(i => i.sources))]

// ── Exportable table (modal) ─────────────────────────────────────────────────

interface Column<R> {
  header: string
  /** Text used by the filter and the export */
  value: (r: R) => string
  render?: (r: R) => React.ReactNode
  className?: string
  /** false: shown only (a "Look up" link), left out of the export */
  exportable?: boolean
}

function download(name: string, type: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

const csvCell = (v: string) => (/[",\n;]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v)

function TableModal<R>({ title, subtitle, columns, rows, file, onClose }: {
  title: string; subtitle?: string; columns: Column<R>[]; rows: R[]; file: string; onClose: () => void
}) {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])
  const shown = useMemo(() => {
    const k = q.trim().toLowerCase()
    return k ? rows.filter(r => columns.some(c => c.value(r).toLowerCase().includes(k))) : rows
  }, [q, rows, columns])
  const base = file.replace(/[^\w.-]+/g, '_')
  const cols = columns.filter(c => c.exportable !== false)
  // Exports what is shown (the filter applies); BOM so Excel reads UTF-8.
  const exportCsv = () => download(`${base}.csv`, 'text/csv;charset=utf-8',
    '\ufeff' + [cols.map(c => csvCell(c.header)).join(','), ...shown.map(r => cols.map(c => csvCell(c.value(r))).join(','))].join('\n'))
  const exportJson = () => download(`${base}.json`, 'application/json',
    JSON.stringify(shown.map(r => Object.fromEntries(cols.map(c => [c.header, c.value(r)]))), null, 2))
  const btn = 'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium border border-border hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground'
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div role="dialog" aria-modal="true" aria-label={title}
        className="relative w-full max-w-4xl mx-4 rounded-lg border border-border bg-background shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        onClick={e => e.stopPropagation()}>
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-border bg-muted/40 shrink-0">
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-semibold text-foreground">{title} <span className="text-muted-foreground font-normal">({rows.length.toLocaleString()})</span></span>
            {subtitle && <span className="text-xs text-muted-foreground">{subtitle}</span>}
          </div>
          <div className="flex items-center gap-2">
            <input value={q} onChange={e => setQ(e.target.value)} placeholder={t('ar.x.filter')} aria-label={t('ar.x.filter')}
              className="h-7 w-40 rounded border border-border bg-background px-2 text-xs text-foreground placeholder:text-muted-foreground" />
            <button type="button" onClick={exportCsv} className={btn}><Download className="h-3.5 w-3.5" />CSV</button>
            <button type="button" onClick={exportJson} className={btn}><Download className="h-3.5 w-3.5" />JSON</button>
            <button type="button" onClick={onClose} aria-label={t('common.close')}
              className="p-1 rounded hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
          </div>
        </div>
        <div className="overflow-auto flex-1">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-background">
              <tr className="border-b border-border text-left">
                {columns.map(c => <th key={c.header} className={`${lbl} px-3 py-2`}>{c.header}</th>)}
              </tr>
            </thead>
            <tbody>
              {shown.map((r, i) => (
                <tr key={i} className="border-b border-border last:border-0 align-top">
                  {columns.map(c => <td key={c.header} className={`px-3 py-1.5 ${c.className ?? ''}`}>{c.render ? c.render(r) : c.value(r)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <p className="px-4 py-6 text-sm text-muted-foreground">{t('ar.x.noMatch')}</p>}
        </div>
        {shown.length !== rows.length && (
          <div className="px-4 py-2 border-t border-border text-xs text-muted-foreground">{t('ar.x.filtered', { n: shown.length, total: rows.length })}</div>
        )}
      </div>
    </div>
  )
}

const srcColumn = <R extends { sources: string[] }>(header: string): Column<R> => ({
  header, value: r => r.sources.join(', '), render: r => <Sources names={r.sources} />,
})
/** "Look up →" to analyse the value (artifacts, CVEs); only for who can run lookups. */
function LookUp({ value, type }: { value: string; type?: string }) {
  const { t } = useI18n()
  const canAnalyze = useAuth().can('analyze')
  if (!canAnalyze || !type) return null
  return (
    <Link to={`/results?indicator=${encodeURIComponent(value)}&type=${type}`} className="text-xs text-primary hover:underline whitespace-nowrap">
      {t('ar.lookUp')}
    </Link>
  )
}
const lookUpColumn = <R extends { value: string; pivot?: string }>(): Column<R> => ({
  header: '', value: () => '', exportable: false, render: r => <LookUp value={r.value} type={r.pivot} />, className: 'text-right',
})

const countColumn = <R extends { sources: string[] }>(header: string): Column<R> => ({
  header, value: r => String(r.sources.length), className: 'tabular-nums text-muted-foreground',
})

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
  return (
    <div className="-mx-5 -mt-5 mb-1 px-5 py-1.5 rounded-t-lg border-b border-amber-500/30 bg-amber-500/5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span className="inline-flex items-center gap-1.5 text-amber-700 dark:text-amber-300"><AlertTriangle className="h-3.5 w-3.5 shrink-0" />{text}</span>
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

// ── Summary pieces ───────────────────────────────────────────────────────────

/** Alias tags without sources; "see more" opens the table of which source gives each. */
const MAX_ALIAS_TAGS = 10

function Aliases({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  const [table, setTable] = useState(false)
  if (p.aliasTable.length === 0) return null
  // Every other name, real aliases first, then spellings of the name; capped.
  const own = nameKey(p.name)
  const real = new Set(p.aliases.map(a => a.value))
  const others = p.aliasTable.filter(a => nameKey(a.value) !== own)
  const tags = [...others.filter(a => real.has(a.value)), ...others.filter(a => !real.has(a.value))].slice(0, MAX_ALIAS_TAGS)
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {tags.map(a => (
        <span key={a.value} className="px-2.5 py-0.5 rounded-md border border-primary/40 bg-primary/10 text-sm font-medium text-foreground">{a.value}</span>
      ))}
      <button type="button" onClick={() => setTable(true)} className="text-xs text-primary hover:underline ml-1">
        {t('ar.aliasAll', { n: p.aliasTable.length })}
      </button>
      {table && (
        <TableModal title={t('ar.aliasTitle', { name: p.name })} subtitle={t('ar.aliasHint')} file={`${p.name}_aliases`} onClose={() => setTable(false)}
          rows={p.aliasTable} columns={[
            { header: t('ar.x.alias'), value: r => r.value, className: 'font-medium text-foreground' },
            countColumn(t('ar.x.n')),
            srcColumn(t('ar.x.sources')),
          ]} />
      )}
    </div>
  )
}

/** One source's description: its source above, the text cut to 3 lines with "Read more". */
function Description({ d }: { d: ActorDescription }) {
  const { t } = useI18n()
  const ref = useRef<HTMLParagraphElement>(null)
  const [open, setOpen] = useState(false)
  const [cut, setCut] = useState(false)
  useEffect(() => {
    const el = ref.current
    if (!el || open) return
    // Fires once on observe, then on every resize: is the clamped text hiding lines?
    const ro = new ResizeObserver(() => setCut(el.scrollHeight > el.clientHeight + 1))
    ro.observe(el)
    return () => ro.disconnect()
  }, [open, d.text])
  return (
    <div className="flex flex-col gap-1">
      <Sources names={d.sources} />
      <p ref={ref} className="text-sm text-foreground/85 leading-relaxed whitespace-pre-line"
        style={open ? undefined : { display: '-webkit-box', WebkitBoxOrient: 'vertical', WebkitLineClamp: 3, overflow: 'hidden' }}>
        {d.text}
      </p>
      {(cut || open) && (
        <button type="button" onClick={() => setOpen(o => !o)} className="text-xs text-primary hover:underline w-fit">
          {open ? t('ar.readLess') : t('ar.readMore')}
        </button>
      )}
    </div>
  )
}

/** A "field: value(s)" row: one line per value, its sources next to it. */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className={`${lbl} pt-1`}>{label}</dt>
      <dd className="min-w-0 flex flex-col gap-1.5">{children}</dd>
    </>
  )
}

function Value({ children, sources }: { children: React.ReactNode; sources?: (string | undefined)[] }) {
  return (
    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-sm text-foreground">
      <span className="min-w-0">{children}</span>
      {sources && <Sources names={sources} />}
    </div>
  )
}

const LEVEL_STYLE: Record<ActorActivity['level'], string> = {
  active: 'text-red-700 dark:text-red-400 bg-red-500/10 border-red-500/40',
  recent: 'text-amber-700 dark:text-amber-400 bg-amber-500/10 border-amber-500/40',
  dormant: 'text-slate-600 dark:text-slate-400 bg-slate-500/10 border-slate-500/40',
  unknown: 'text-muted-foreground bg-muted/30 border-border',
}

/** Top right of the Summary: only whether / since when it's active, then the Knowledge level. */
function StatusBox({ activity, verdict, loading, onExplain }: {
  activity: ActorActivity; verdict: VerdictResult; loading: boolean; onExplain: () => void
}) {
  const { t, tn, locale } = useI18n()
  const k = verdict.knowledge ?? 0
  const last = activity.lastOperation ?? activity.lastReport
  const ago = activity.daysSince === 0 ? t('activity.today') : activity.daysSince != null ? tn('activity.daysAgo', activity.daysSince) : null
  return (
    <aside className="rounded-lg border border-border bg-background/60 p-4 flex flex-col gap-4 h-fit">
      <div className="flex flex-col gap-1.5" title={t('activity.legend', { active: ACTIVE_DAYS, recent: RECENT_DAYS })}>
        <span className={lbl}>{t('activity.title')}</span>
        <span className={`inline-flex w-fit items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-bold uppercase tracking-wider ${LEVEL_STYLE[activity.level]}`}>
          <Activity className="h-3.5 w-3.5" />{t(`activity.level.${activity.level}`)}
        </span>
        <span className="text-sm text-foreground">
          {loading && activity.level === 'unknown' ? t('activity.loading') : ago ?? t('activity.hint.unknown')}
        </span>
        {last && (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span>{t(activity.lastOperation ? 'ar.f.lastOperation' : 'ar.f.lastReport', { date: fmtDate(last.date, locale) ?? '' })}</span>
            <Sources names={[last.source]} />
          </div>
        )}
      </div>
      <div className="flex flex-col gap-1.5 pt-4 border-t border-border">
        <div className="flex justify-between items-baseline gap-2">
          <span className={lbl}>{t('score.knowledge')}</span>
          <span className="tabular-nums"><b className="text-2xl text-foreground">{k}</b><span className="text-muted-foreground"> / 10</span></span>
        </div>
        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
          <div className="h-full rounded-full" style={{ width: `${k * 10}%`, background: knowledgeColor(k) }} />
        </div>
        <div className="flex justify-between gap-2 text-xs text-muted-foreground">
          <span>{t('summary.answered', { responded: verdict.responded, queried: verdict.queried })}</span>
          <button type="button" onClick={onExplain} className="inline-flex items-center gap-1 hover:text-foreground">
            <Info className="h-3 w-3" />{t('summary.howCalculated')}
          </button>
        </div>
      </div>
    </aside>
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
      {done ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

// ransomware.live's "DLS" (data leak site) reads better spelled out; other types as given.
const siteType = (type: string) => (/^dls$/i.test(type.trim()) ? 'Leak Site' : type)

interface Site { address: string; type?: string; online: boolean | null; sources: string[] }

/** The actor's sites (leak sites, negotiation chats, file servers), one per address, with
 *  every source that reports it. Attacker infrastructure: text to copy, never a link. */
function Sites({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  const [all, setAll] = useState(false)
  const sites = useMemo(() => {
    const m = new Map<string, Site>()
    for (const s of p.leakSites) {
      const cur = m.get(s.address)
      if (!cur) { m.set(s.address, { address: s.address, type: s.type, online: s.online, sources: [s.source] }); continue }
      if (!cur.sources.includes(s.source)) cur.sources.push(s.source)
      if (s.online === true || cur.online == null) cur.online = s.online
      cur.type ??= s.type
    }
    return [...m.values()]
  }, [p.leakSites])
  if (sites.length === 0) return null
  const shown = all ? sites : sites.slice(0, 5)
  const state = (o: boolean | null) => (o === true ? t('ar.l.online') : o === false ? t('ar.l.offline') : t('ar.l.unknown'))
  return (
    <Field label={t('ar.f.sites')}>
      {shown.map(s => (
        <div key={s.address} className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-sm min-w-0">
          <span className="inline-flex items-center gap-2 min-w-0 max-w-full">
            <span title={state(s.online)} aria-label={state(s.online)}
              className={`h-2 w-2 shrink-0 rounded-full ${s.online === true ? 'bg-red-500' : s.online === false ? 'bg-muted-foreground/50' : 'border border-muted-foreground/50'}`} />
            <span className="font-mono text-xs break-all select-all text-foreground">{s.address}</span>
            <CopyAddress value={s.address} />
          </span>
          {s.type && <span className="text-xs text-muted-foreground" title={s.type}>{siteType(s.type)}</span>}
          <Sources names={s.sources} />
        </div>
      ))}
      {sites.length > shown.length && (
        <button type="button" onClick={() => setAll(true)} className="text-xs text-primary hover:underline w-fit">
          {t('ar.aliasMore', { n: sites.length - shown.length })}
        </button>
      )}
    </Field>
  )
}

/** Next to "Victims claimed": every victim the source lists, as an exportable table. */
function VictimsButton({ p }: { p: ActorProfile }) {
  const { t, locale } = useI18n()
  const [open, setOpen] = useState(false)
  const rw = p.ransomware
  if (!rw || rw.all.length === 0) return null
  const src = p.prov.ransomware ?? ''
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border border-border bg-background/60 text-xs font-medium text-foreground hover:border-primary hover:bg-primary/5 transition-colors">
        <Users className="h-3.5 w-3.5" />{t('ar.v.button')}
      </button>
      {open && (
        <TableModal title={`${t('ar.v.title')} · ${p.name}`} file={`${p.name}_victims`} onClose={() => setOpen(false)}
          subtitle={rw.complete ? t('ar.v.hint', { source: src }) : t('ar.v.hintPartial', { n: rw.all.length, source: src })}
          rows={rw.all} columns={[
            { header: t('ar.v.date'), value: r => r.date ?? '', render: r => fmtDate(r.date, locale) ?? '—', className: 'text-xs text-muted-foreground tabular-nums whitespace-nowrap' },
            { header: t('ar.v.victim'), value: r => r.name, className: 'text-foreground' },
            { header: t('ar.v.domain'), value: r => r.domain ?? '', className: 'font-mono text-xs break-all',
              render: r => (r.domain ? <span className="inline-flex flex-wrap items-baseline gap-x-2">{r.domain}<LookUp value={r.domain} type="domain" /></span> : '—') },
            { header: t('ar.v.sector'), value: r => r.sector ?? '', className: 'text-muted-foreground' },
            { header: t('ar.v.country'), value: r => (r.country ? countryName(r.country, locale) : ''), className: 'text-muted-foreground whitespace-nowrap' },
          ]} />
      )}
    </>
  )
}

function Fields({ p, loading }: { p: ActorProfile; loading: boolean }) {
  const { t, locale } = useI18n()
  const none = <span className="text-sm text-muted-foreground">{loading ? t('activity.loading') : t('ar.f.none')}</span>
  const rw = p.ransomware
  return (
    <dl className="grid grid-cols-[minmax(0,8rem)_minmax(0,1fr)] sm:grid-cols-[11rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <Field label={t('ar.f.type')}>
        {p.types.length === 0 ? none : p.types.map(x => (
          <Value key={x.key ?? x.value} sources={x.sources}>
            <span className={x.key === 'ransomware' || x.key === 'raas' ? 'font-medium text-red-700 dark:text-red-400' : 'font-medium'}>
              {x.key ? t(`ar.type.${x.key}`) : x.value}
            </span>
          </Value>
        ))}
      </Field>
      <Field label={t('ar.f.mitre')}>
        {p.mitreId
          ? <Value sources={[p.prov.mitreId]}>
              <a href={`https://attack.mitre.org/groups/${p.mitreId}/`} target="_blank" rel="noreferrer"
                className="inline-flex items-center gap-1 font-mono text-primary hover:underline">{p.mitreId}<ExternalLink className="h-3 w-3" /></a>
            </Value>
          : none}
      </Field>
      <Field label={t('ar.f.country')}>
        {p.origins.length === 0 ? none : <>
          {p.origins.map(o => (
            <Value key={o.country} sources={o.sources}>
              <span className="font-mono text-xs px-1 py-px mr-1.5 rounded border border-border text-muted-foreground">{o.country}</span>
              <span className="font-medium">{countryName(o.country, locale)}</span>
            </Value>
          ))}
          {p.origins.length > 1 && <span className="text-xs text-amber-700 dark:text-amber-400">{t('ar.originConflict')}</span>}
        </>}
      </Field>
      <Sites p={p} />
      {p.since.length > 0 && (
        <Field label={t('ar.f.since')}>
          {p.since.map(x => (
            <Value key={x.source} sources={[x.source]}><span className="font-medium tabular-nums">{fmtDate(x.date, locale)}</span></Value>
          ))}
        </Field>
      )}
      {p.lineage.length > 0 && (
        <Field label={t('ar.f.lineage')}>
          {p.lineage.map(l => (
            <Value key={l.value} sources={l.sources}>
              <span className="text-muted-foreground">{t('ar.f.lineageFrom')} </span>
              <Link to={`/results?indicator=${encodeURIComponent(l.value)}&type=threat-actor`} title={t('ar.searchThis')}
                className="font-medium text-primary hover:underline">{l.value}</Link>
            </Value>
          ))}
        </Field>
      )}
      {rw && (
        <Field label={t('ar.f.victims')}>
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-sm text-foreground">
            <span>
              <b className="tabular-nums">{rw.victims.toLocaleString(locale)}</b>
              <span className="text-muted-foreground"> · {t('ar.f.victims90', { n: rw.d90.toLocaleString(locale) })}</span>
            </span>
            <Sources names={[p.prov.ransomware]} />
            <VictimsButton p={p} />
          </div>
        </Field>
      )}
      <Field label={t('ar.f.identifiedBy')}>
        {p.identities.length === 0 ? none : (
          <span className="inline-flex flex-wrap gap-1">
            {p.identities.map(i => (
              <span key={i.engineId} title={i.exact ? i.name : t('ar.f.closest', { name: i.name })}
                className="px-1.5 py-px rounded border border-border bg-muted/40 text-[0.68rem] leading-4 text-muted-foreground whitespace-nowrap">
                {i.source}{i.exact ? '' : ' ~'}
              </span>
            ))}
          </span>
        )}
      </Field>
    </dl>
  )
}

/** Top values with a count (victims per sector / country) as bars; otherwise plain tags. */
function Ranked({ items }: { items: ProfileItem[] }) {
  const { locale } = useI18n()
  const label = (i: ProfileItem) => (i.country ? countryName(i.country, locale) : i.value)
  const counted = items.filter(i => typeof i.count === 'number')
  if (counted.length === 0) {
    return (
      <div className="flex flex-wrap gap-1.5">
        {items.slice(0, 8).map(i => <span key={i.value} className="px-2 py-0.5 rounded-full border border-border bg-muted/30 text-xs text-foreground/90">{label(i)}</span>)}
      </div>
    )
  }
  const top = counted.slice(0, 5)
  const max = Math.max(1, ...top.map(i => i.count!))
  return (
    <div className="flex flex-col gap-1">
      {top.map(i => (
        <div key={i.value} className="grid grid-cols-[minmax(0,8rem)_1fr_2.5rem] items-center gap-2 text-xs">
          <span className="truncate text-foreground/90" title={i.value}>{label(i)}</span>
          <span className="h-1.5 rounded-full bg-muted overflow-hidden">
            <span className="block h-full rounded-full bg-primary/80" style={{ width: `${(100 * i.count!) / max}%` }} />
          </span>
          <span className="text-right text-muted-foreground tabular-nums">{i.count!.toLocaleString(locale)}</span>
        </div>
      ))}
    </div>
  )
}

function Targets({ p }: { p: ActorProfile }) {
  const { t } = useI18n()
  if (p.sectors.length + p.countries.length === 0) return null
  const block = (title: string, items: ProfileItem[]) => items.length > 0 && (
    <div className="flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center gap-2"><span className={lbl}>{title}</span><Sources names={sourcesOf(items)} /></div>
      <Ranked items={items} />
    </div>
  )
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-5 pt-4 border-t border-border">
      {block(t('ar.topSectors'), p.sectors)}
      {block(t('ar.topCountries'), p.countries)}
    </div>
  )
}

// ── TTPs, arsenal, CVEs, IOCs and reports: big buttons → exportable tables ───────────────────────

type ArsenalRow = ProfileItem & { attribution: string }

function BigButton({ icon, label, count, sub, onClick }: { icon: React.ReactNode; label: string; count: number; sub?: string; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} disabled={count === 0}
      className="flex-1 min-w-[12rem] flex items-center gap-3 px-5 py-4 rounded-lg border border-border bg-background/60 text-left transition-colors hover:border-primary hover:bg-primary/5 disabled:opacity-50 disabled:hover:border-border disabled:hover:bg-background/60 disabled:cursor-not-allowed">
      <span className="text-primary">{icon}</span>
      <span className="flex flex-col">
        <span className="text-lg font-semibold text-foreground">{label} <span className="tabular-nums text-muted-foreground">({count.toLocaleString()})</span></span>
        {sub && <span className="text-xs text-muted-foreground">{sub}</span>}
      </span>
    </button>
  )
}

const ARTIFACT_TYPES: ArtifactType[] = ['ip', 'domain', 'url', 'hash']
const riskClass = (r: number) => (r >= 65 ? 'text-red-700 dark:text-red-400 bg-red-500/10' : r >= 25 ? 'text-amber-700 dark:text-amber-400 bg-amber-500/10' : 'text-muted-foreground bg-muted/40')

const TECHNIQUE = /^(T\d{4}(\.\d{3})?|TA\d{4})$/i
const attackUrl = (id: string) => `https://attack.mitre.org/${id.startsWith('TA') ? 'tactics' : 'techniques'}/${id.replace('.', '/')}`

function Lists({ p }: { p: ActorProfile }) {
  const { t, locale } = useI18n()
  const [open, setOpen] = useState<'ttps' | 'arsenal' | 'cves' | 'iocs' | 'reports' | null>(null)
  const corroborated = p.ttps.filter(x => x.sources.length > 1).length
  const arsenal: ArsenalRow[] = [
    ...p.arsenal.map(a => ({ ...a, attribution: t('ar.x.attributed') })),
    ...p.arsenalMentioned.map(a => ({ ...a, attribution: t('ar.x.mentioned') })),
  ]
  const noSource = t('ar.x.noneFrom', { sources: p.consulted.join(', ') })
  const iocs = ARTIFACT_TYPES.flatMap(k => p.artifacts[k]).sort((a, b) => (b.risk ?? -1) - (a.risk ?? -1))
  const highRisk = iocs.filter(a => (a.risk ?? 0) >= 65).length
  const cvesCorroborated = p.vulns.filter(x => x.sources.length > 1).length
  const reports = p.incidents.filter(i => i.kind === 'report').length
  return (
    <div className="flex flex-wrap gap-3 pt-4 border-t border-border">
      <BigButton icon={<Swords className="h-6 w-6" />} label="TTPs" count={p.ttps.length} onClick={() => setOpen('ttps')}
        sub={p.ttps.length ? t('ar.x.ttpsSub', { n: corroborated }) : noSource} />
      <BigButton icon={<Wrench className="h-6 w-6" />} label={t('ar.x.arsenal')} count={arsenal.length} onClick={() => setOpen('arsenal')}
        sub={arsenal.length ? t('ar.x.arsenalSub', { own: p.arsenal.length, mentioned: p.arsenalMentioned.length }) : noSource} />
      <BigButton icon={<Bug className="h-6 w-6" />} label={t('ar.x.cves')} count={p.vulns.length} onClick={() => setOpen('cves')}
        sub={p.vulns.length ? t('ar.x.cvesSub', { n: cvesCorroborated }) : noSource} />
      <BigButton icon={<Fingerprint className="h-6 w-6" />} label="IOCs" count={iocs.length} onClick={() => setOpen('iocs')}
        sub={iocs.length ? t('ar.x.iocsSub', { n: highRisk }) : noSource} />
      <BigButton icon={<FileText className="h-6 w-6" />} label={t('ar.x.reports')} count={p.incidents.length} onClick={() => setOpen('reports')}
        sub={p.incidents.length ? t('ar.x.reportsSub', { r: reports, c: p.incidents.length - reports }) : noSource} />
      {open === 'reports' && (
        <TableModal title={`${t('ar.x.reports')} · ${p.name}`} subtitle={t('ar.x.reportsHint')} file={`${p.name}_reports`} onClose={() => setOpen(null)}
          rows={p.incidents} columns={[
            { header: t('ar.x.date'), value: r => r.date?.slice(0, 10) ?? '', render: r => fmtDate(r.date, locale) ?? '—', className: 'text-xs text-muted-foreground tabular-nums whitespace-nowrap' },
            { header: t('ar.x.kind'), value: r => t(`ar.kind.${r.kind}`), className: 'text-[0.7rem] font-semibold uppercase tracking-wide text-muted-foreground whitespace-nowrap' },
            { header: t('ar.x.title'), value: r => r.title, className: 'text-foreground' },
            { header: t('ar.x.source'), value: r => r.source, render: r => <Sources names={[r.source]} /> },
            { header: 'URL', value: r => r.link ?? '',
              render: r => (r.link ? <a href={r.link} target="_blank" rel="noreferrer" title={t('ar.open')} className="text-primary"><ExternalLink className="h-3.5 w-3.5" /></a> : null) },
          ]} />
      )}
      {open === 'cves' && (
        <TableModal title={`${t('ar.x.cves')} · ${p.name}`} subtitle={t('ar.x.cvesHint')} file={`${p.name}_cves`} onClose={() => setOpen(null)}
          rows={p.vulns} columns={[
            { header: 'CVE', value: r => r.value, className: 'font-mono text-xs whitespace-nowrap',
              render: r => <a href={`https://nvd.nist.gov/vuln/detail/${r.value}`} target="_blank" rel="noreferrer" className="text-primary hover:underline">{r.value}</a> },
            countColumn(t('ar.x.n')),
            srcColumn(t('ar.x.sources')),
            lookUpColumn(),
          ]} />
      )}
      {open === 'iocs' && (
        <TableModal title={`IOCs · ${p.name}`} subtitle={t('ar.x.iocsHint')} file={`${p.name}_iocs`} onClose={() => setOpen(null)}
          rows={iocs} columns={[
            { header: t('ar.x.iocType'), value: r => (r.pivot ? t(`type.${r.pivot}`) : ''), className: 'text-xs text-muted-foreground whitespace-nowrap' },
            { header: t('ar.x.value'), value: r => r.value, className: 'font-mono text-xs break-all text-foreground' },
            { header: t('ar.x.risk'), value: r => (r.risk != null ? String(r.risk) : ''), className: 'whitespace-nowrap',
              render: r => (r.risk != null
                ? <span title={t('ar.riskBy', { source: r.riskSource ?? '' })} className={`inline-block min-w-7 text-center rounded px-1 text-xs font-semibold ${riskClass(r.risk)}`}>{r.risk}</span>
                : <span className="text-muted-foreground">—</span>) },
            { header: t('ar.x.riskBy'), value: r => r.riskSource ?? '', className: 'text-xs text-muted-foreground whitespace-nowrap' },
            countColumn(t('ar.x.n')),
            srcColumn(t('ar.x.sources')),
            lookUpColumn(),
          ]} />
      )}
      {open === 'ttps' && (
        <TableModal title={`TTPs · ${p.name}`} subtitle={t('ar.x.ttpsHint')} file={`${p.name}_ttps`} onClose={() => setOpen(null)}
          rows={p.ttps} columns={[
            { header: 'ID', value: r => (TECHNIQUE.test(r.value) ? r.value : ''), className: 'font-mono text-xs whitespace-nowrap',
              render: r => (TECHNIQUE.test(r.value)
                ? <a href={attackUrl(r.value)} target="_blank" rel="noreferrer" className="text-primary hover:underline">{r.value}</a> : '—') },
            { header: t('ar.t.technique'), value: r => r.detail ?? (TECHNIQUE.test(r.value) ? '' : r.value), className: 'text-foreground' },
            countColumn(t('ar.x.n')),
            srcColumn(t('ar.x.sources')),
          ]} />
      )}
      {open === 'arsenal' && (
        <TableModal title={`${t('ar.x.arsenal')} · ${p.name}`} subtitle={t('ar.x.arsenalHint')} file={`${p.name}_arsenal`} onClose={() => setOpen(null)}
          rows={arsenal} columns={[
            { header: t('ar.x.name'), value: r => r.value, className: 'font-medium text-foreground' },
            { header: t('ar.x.attribution'), value: r => r.attribution, className: 'text-xs text-muted-foreground whitespace-nowrap' },
            countColumn(t('ar.x.n')),
            srcColumn(t('ar.x.sources')),
          ]} />
      )}
    </div>
  )
}

/** The description of the source with the most Knowledge weight; the rest behind a button. */
function Descriptions({ list, verdict }: { list: ActorDescription[]; verdict: VerdictResult }) {
  const { t } = useI18n()
  const [more, setMore] = useState(false)
  // Weights as they were for this lookup (saved contributions, so history replays them).
  const weight = useMemo(() => {
    const w = new Map(verdict.contributions.knowledge.map(c => [c.label, c.weight]))
    return (d: ActorDescription) => Math.max(0, ...d.sources.map(x => w.get(x) ?? 0))
  }, [verdict])
  if (list.length === 0) return null
  // Stable sort: on equal weight the profile's order (most authoritative first) stays.
  const [main, ...rest] = [...list].sort((a, b) => weight(b) - weight(a))
  return (
    <div className="flex flex-col gap-3 max-w-prose">
      <Description d={main} />
      {rest.length > 0 && (
        <button type="button" onClick={() => setMore(m => !m)} aria-expanded={more}
          className="inline-flex w-fit items-center gap-1.5 px-3 py-1 rounded-md border border-border bg-background/60 text-xs font-medium text-foreground hover:border-primary hover:bg-primary/5 transition-colors">
          {t('ar.descMore')}
          <ChevronDown className={`h-3.5 w-3.5 transition-transform ${more ? 'rotate-180' : ''}`} />
        </button>
      )}
      {more && (
        <div className="flex flex-col gap-3 pl-3 border-l-2 border-border">
          {rest.map(d => <Description key={d.sources.join()} d={d} />)}
        </div>
      )}
    </div>
  )
}

// ── Summary ──────────────────────────────────────────────────────────────────

function Summary({ p, activity, verdict, thresholds, loading, banner }: {
  p: ActorProfile; activity: ActorActivity; verdict: VerdictResult; thresholds: VerdictThresholds | null; loading: boolean; banner?: React.ReactNode
}) {
  const [explain, setExplain] = useState(false)
  return (
    <section className="rounded-lg border border-border bg-muted/20 p-5 flex flex-col gap-4">
      {banner}
      <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_260px] gap-5">
        <div className="flex flex-col gap-4 min-w-0">
          <h2 className="text-3xl font-bold tracking-tight text-foreground">{p.name}</h2>
          <Aliases p={p} />
          <Descriptions list={p.descriptions} verdict={verdict} />
        </div>
        <StatusBox activity={activity} verdict={verdict} loading={loading} onExplain={() => setExplain(true)} />
      </div>
      <div className="pt-4 border-t border-border">
        <Fields p={p} loading={loading} />
      </div>
      <Targets p={p} />
      <Lists p={p} />
      <VerdictExplainerModal open={explain} onClose={() => setExplain(false)} verdict={verdict} thresholds={thresholds} type="threat-actor" />
    </section>
  )
}

// ── No actor identified ──────────────────────────────────────────────────────

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

// ── Report ───────────────────────────────────────────────────────────────────

export default function ActorReport({ indicator, engines, results, verdict, thresholds, asOf, children }: {
  indicator: string
  engines: EngineConfig[]
  results: Record<string, QueryResult>
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
  /** History: activity is measured from when the lookup ran */
  asOf?: Date
  /** Per-source cards (below the summary) */
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
        : <Summary p={profile} activity={activity} verdict={verdict} thresholds={thresholds} loading={loading}
            banner={!loading && profile.status !== 'confirmed' ? <StatusBanner profile={profile} suggestions={suggestions} /> : undefined} />}
      <div className="flex flex-col gap-3 mt-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('results.byEngine')}</p>
        {/* No Risk for an actor: the cards drop their subscore chip and R weight */}
        <HideScores value="risk"><div className="grid grid-cols-1 gap-4">{children}</div></HideScores>
      </div>
    </div>
  )
}
