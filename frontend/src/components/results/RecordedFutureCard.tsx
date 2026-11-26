import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2, ChevronDown, FileCode2, ExternalLink, Search, Sparkles } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { useAuth } from '@/auth/context'
import { RF_LINKS_MIN_RISK } from '@/intelAggregates'
import { fmtDate } from '@/lib/format'
import { Chips } from './SourceCard'

interface EvidenceDetail {
  rule?: string
  evidenceString?: string
  criticality?: number
  criticalityLabel?: string
  timestamp?: string
}

interface RiskInfo {
  score?: number
  riskString?: string
  riskSummary?: string
  criticality?: number
  criticalityLabel?: string
  evidenceDetails?: EvidenceDetail[]
}

interface LinkItem { id?: string; name: string; source?: string; risk_score?: number; criticality?: string; label?: string }
type LinkGroup = 'actors' | 'malware' | 'mitre' | 'attack_vectors' | 'organizations' | 'vulnerabilities' | 'ips' | 'domains' | 'urls' | 'hashes'
type Links = Partial<Record<LinkGroup, LinkItem[]>>

interface RecordedFutureResponse {
  // IOC lookups
  risk?: RiskInfo
  entity?: { id?: string; name?: string; type?: string }
  intelCard?: string
  timestamps?: { firstSeen?: string; lastSeen?: string }
  aiInsights?: { text?: string; numberOfReferences?: number } | null
  threatLists?: { id?: string; name: string }[]
  // threat actor lookups
  kind?: 'actor'
  found?: boolean
  exact?: boolean
  query?: string
  name?: string
  categories?: string[]
  aliases?: string[]
  aliases_total?: number
  threat_map?: { intent?: number; opportunity?: number; date?: string; log?: { date?: string; axis?: string; severity?: number }[] } | null
  on_threat_map?: boolean | null
  link?: string
  // both
  insikt_links?: Links
  links_error?: { code: string; message: string }
  threat_map_error?: { code: string; message: string }
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: RecordedFutureResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const CRITICALITY_STYLES: Record<string, string> = {
  None: 'text-green-400 bg-green-500/10 border-green-500/30',
  Unusual: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  Suspicious: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  Malicious: 'text-red-400 bg-red-500/10 border-red-500/30',
  Critical: 'text-red-400 bg-red-500/10 border-red-500/30',
}

function RiskBadge({ risk }: { risk: RiskInfo }) {
  const { t } = useI18n()
  const label = risk.criticalityLabel ?? 'None'
  const style = CRITICALITY_STYLES[label] ?? CRITICALITY_STYLES.None
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold ${style}`}>
      {t('rf.risk', { score: risk.score ?? 0, label: label in CRITICALITY_STYLES ? t(`rf.crit.${label as 'None' | 'Unusual' | 'Suspicious' | 'Malicious' | 'Critical'}`) : label })}
    </span>
  )
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

const GROUP_LABEL: Record<LinkGroup, 'rf.g.actors' | 'rf.g.malware' | 'rf.g.mitre' | 'rf.g.attack_vectors' | 'rf.g.organizations' | 'rf.g.vulnerabilities' | 'rf.g.ips' | 'rf.g.domains' | 'rf.g.urls' | 'rf.g.hashes'> = {
  actors: 'rf.g.actors', malware: 'rf.g.malware', mitre: 'rf.g.mitre', attack_vectors: 'rf.g.attack_vectors',
  organizations: 'rf.g.organizations', vulnerabilities: 'rf.g.vulnerabilities',
  ips: 'rf.g.ips', domains: 'rf.g.domains', urls: 'rf.g.urls', hashes: 'rf.g.hashes',
}
const CONTEXT_GROUPS: LinkGroup[] = ['actors', 'malware', 'mitre', 'attack_vectors', 'organizations', 'vulnerabilities']
const IOC_GROUPS: [LinkGroup, string][] = [['ips', 'ip'], ['domains', 'domain'], ['urls', 'url'], ['hashes', 'hash']]

function riskClass(score?: number) {
  if (typeof score !== 'number') return 'text-muted-foreground border-border'
  if (score >= 65) return 'text-red-400 border-red-500/40'
  if (score >= 25) return 'text-amber-400 border-amber-500/40'
  return 'text-muted-foreground border-border'
}

function LinksBlock({ links }: { links: Links }) {
  const { t } = useI18n()
  const groups = CONTEXT_GROUPS.filter(g => (links[g] ?? []).length > 0)
  if (groups.length === 0) return null
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
      {groups.map(g => (
        <Field key={g} label={t(GROUP_LABEL[g], { n: links[g]!.length })}
          value={<Chips items={links[g]!.map(l => l.label ?? l.name)} max={10} />} />
      ))}
    </div>
  )
}

/** Infrastructure linked to an actor (or to an IOC), each one a click away from its own lookup. */
function IocBlock({ links }: { links: Links }) {
  const { t } = useI18n()
  const canAnalyze = useAuth().can('analyze')
  const groups = IOC_GROUPS.filter(([g]) => (links[g] ?? []).length > 0)
  if (groups.length === 0) return null
  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('rf.iocs')}</span>
      {groups.map(([g, type]) => (
        <div key={g} className="flex flex-col gap-1">
          <span className="text-xs text-muted-foreground">{t(GROUP_LABEL[g], { n: links[g]!.length })}</span>
          <div className="flex flex-wrap gap-1">
            {links[g]!.map(l => {
              const chip = (
                <>
                  <span className="font-mono">{l.name.length > 48 ? `${l.name.slice(0, 20)}…${l.name.slice(-12)}` : l.name}</span>
                  {typeof l.risk_score === 'number' && <span className="opacity-80">{l.risk_score}</span>}
                  {canAnalyze && <Search className="h-3 w-3 opacity-60" />}
                </>
              )
              const cls = `inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-xs ${riskClass(l.risk_score)}`
              return canAnalyze
                ? <Link key={l.name} to={`/results?indicator=${encodeURIComponent(l.name)}&type=${type}`} title={t('rf.pivot', { value: l.name })}
                    className={`${cls} hover:bg-muted/60`}>{chip}</Link>
                : <span key={l.name} className={cls}>{chip}</span>
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

function Meter({ label, value }: { label: string; value?: number }) {
  const v = typeof value === 'number' ? Math.max(0, Math.min(100, value)) : null
  return (
    <div className="flex flex-col gap-1">
      <div className="flex justify-between text-xs"><span className="text-muted-foreground uppercase tracking-wide">{label}</span><span className="text-foreground font-medium">{v ?? '—'}</span></div>
      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
        {v != null && <div className="h-full rounded-full bg-primary" style={{ width: `${v}%` }} />}
      </div>
    </div>
  )
}

function ActorView({ data }: { data: RecordedFutureResponse }) {
  const { t, locale } = useI18n()
  const links = data.insikt_links ?? {}
  if (!data.found) return <p className="text-sm text-muted-foreground">{t('rf.actorNotFound')}</p>
  const tm = data.threat_map
  return (
    <>
      {data.exact === false && <p className="text-sm text-amber-400">{t('rf.closestActor', { name: data.name ?? '' })}</p>}
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-base font-semibold text-foreground">{data.name}</span>
        {data.query && data.name && data.query.toLowerCase() !== data.name.toLowerCase() && (
          <span className="text-xs text-muted-foreground">{t('rf.searchedAs', { query: data.query })}</span>
        )}
      </div>
      <Field label={t('rf.categories')} value={<Chips items={data.categories ?? []} />} />
      <Field label={t('rf.aliases', { n: data.aliases_total ?? 0 })} value={<Chips items={data.aliases ?? []} max={18} />} />
      {tm ? (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 flex flex-col gap-2">
          <span className="text-sm font-medium text-amber-400">{t('rf.onMap')}</span>
          <div className="grid grid-cols-2 gap-4">
            <Meter label={t('rf.intent')} value={tm.intent} />
            <Meter label={t('rf.opportunity')} value={tm.opportunity} />
          </div>
          {(tm.log ?? []).length > 0 && (
            <span className="text-xs text-muted-foreground">
              {t('rf.mapLog')} {tm.log!.map(e => `${fmtDate(e.date, locale) ?? e.date} · ${e.axis} (${e.severity})`).join(' — ')}
            </span>
          )}
        </div>
      ) : data.on_threat_map === false ? (
        <p className="text-xs text-muted-foreground">{t('rf.notOnMap')}</p>
      ) : null}
      {data.threat_map_error && <p className="text-xs text-muted-foreground">{t('rf.mapUnavailable', { reason: data.threat_map_error.message })}</p>}
      <LinksBlock links={links} />
      <IocBlock links={links} />
      {data.link && (
        <a href={data.link} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit">
          <ExternalLink className="h-3 w-3" /> {t('rf.openPortal')}
        </a>
      )}
    </>
  )
}

function EvidenceRow({ evidence }: { evidence: EvidenceDetail }) {
  const label = evidence.criticalityLabel ?? 'None'
  const style = CRITICALITY_STYLES[label] ?? CRITICALITY_STYLES.None
  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium text-foreground">{evidence.rule}</span>
        <span className={`px-1.5 py-0.5 rounded-full border text-xs font-medium shrink-0 ${style}`}>{label}</span>
      </div>
      {evidence.evidenceString && (
        <p className="text-xs text-muted-foreground">{evidence.evidenceString}</p>
      )}
    </div>
  )
}

export default function RecordedFutureCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const risk = !apiError ? data?.risk : undefined
  const evidence = risk?.evidenceDetails ?? []
  const isActor = !apiError && data?.kind === 'actor'
  const links = data?.insikt_links ?? {}
  const lowRiskLinks = typeof risk?.score === 'number' && risk.score < RF_LINKS_MIN_RISK && Object.keys(links).length > 0

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">Recorded Future</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} />}
          {!loading && data && (
            <button
              onClick={e => { e.stopPropagation(); setRawOpen(true) }}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
              title={t('raw.buttonTitle')}
            >
              <FileCode2 className="h-3 w-3" />
              RAW
            </button>
          )}
          <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {open && (
        <div className="px-4 py-4 flex flex-col gap-4">
          {loading && (
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'Recorded Future' })}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'Recorded Future')}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiErrorText(i18n, apiError, 'Recorded Future')}</p>
          )}

          {!loading && isActor && data && <ActorView data={data} />}

          {!loading && risk && (
            <>
              {data?.aiInsights?.text && (
                <div className="rounded-md border border-border bg-muted/20 px-3 py-2 flex flex-col gap-1">
                  <span className="inline-flex items-center gap-1 text-xs text-muted-foreground uppercase tracking-wide">
                    <Sparkles className="h-3 w-3" /> {t('rf.ai', { n: data.aiInsights.numberOfReferences ?? 0 })}
                  </span>
                  <p className="text-sm text-foreground/90 leading-relaxed">{data.aiInsights.text}</p>
                </div>
              )}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label={t('f.riskScore')} value={<RiskBadge risk={risk} />} />
                <Field label={t('f.rulesTriggered')} value={risk.riskString} />
                <Field label={t('f.firstSeen')} value={data?.timestamps?.firstSeen ? new Date(data.timestamps.firstSeen).toLocaleString(locale) : undefined} />
                <Field label={t('f.lastSeen')} value={data?.timestamps?.lastSeen ? new Date(data.timestamps.lastSeen).toLocaleString(locale) : undefined} />
              </div>

              {risk.riskSummary && (
                <p className="text-sm text-muted-foreground">{risk.riskSummary}</p>
              )}

              {evidence.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('rf.rules', { n: evidence.length })}
                  </span>
                  {evidence.map((e, i) => (
                    <EvidenceRow key={e.rule ?? i} evidence={e} />
                  ))}
                </div>
              )}

              {(data?.threatLists ?? []).length > 0 && (
                <Field label={t('rf.threatLists', { n: data!.threatLists!.length })} value={<Chips items={data!.threatLists!.map(l => l.name)} />} />
              )}

              {Object.keys(links).length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('rf.linksTitle')}</span>
                  {lowRiskLinks && <p className="text-xs text-muted-foreground">{t('rf.lowRiskLinks', { min: RF_LINKS_MIN_RISK })}</p>}
                  <LinksBlock links={links} />
                  <IocBlock links={links} />
                </div>
              )}

              {data?.intelCard && (
                <a
                  href={data.intelCard}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> {t('rf.intelCard')}
                </a>
              )}
            </>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="Recorded Future" />
    </div>
  )
}
