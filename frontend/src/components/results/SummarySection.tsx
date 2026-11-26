import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Users, ExternalLink } from 'lucide-react'
import type { EngineConfig, QueryResult, IndicatorType } from '@/registry'
import {
  SUMMARY_REGISTRY,
  SUMMARY_FIELD_META,
  SUMMARY_FIELDS,
  type SummaryField,
} from '@/summaryRegistry'
import type { VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { aggregateIntel, type AggregatedValue, type IntelSummary, type SeenDate } from '@/intelAggregates'
import { useMitreAliases } from '@/hooks/useMitreAliases'
import VerdictPanel from './VerdictPanel'
import { riskColor } from '@/lib/scoreColors'
import { useI18n } from '@/i18n/useI18n'
import { useAuth } from '@/auth/context'

// ── Aggregation ──────────────────────────────────────────────────────────────

function aggregateField(
  field: SummaryField,
  type: IndicatorType,
  engines: EngineConfig[],
  results: Record<string, QueryResult>,
): { value: string; count: number; engines: string[] }[] {
  const map: Record<string, string[]> = {}
  for (const engine of engines) {
    const result = results[engine.id]
    if (!result?.data) continue
    const extractors = SUMMARY_REGISTRY[engine.id]?.[type] ?? []
    const extractor = extractors.find(e => e.field === field)
    if (!extractor) continue
    const value = extractor.extract(result.data)
    if (!value) continue
    if (!map[value]) map[value] = []
    map[value].push(engine.label)
  }
  return Object.entries(map)
    .map(([value, engineLabels]) => ({ value, count: engineLabels.length, engines: engineLabels }))
    .sort((a, b) => b.count - a.count)
}

// ── Per-field block ──────────────────────────────────────────────────────────

function SummaryItem({
  field,
  type,
  engines,
  results,
}: {
  field: SummaryField
  type: IndicatorType
  engines: EngineConfig[]
  results: Record<string, QueryResult>
}) {
  const meta = SUMMARY_FIELD_META[field]
  const { t, locale } = useI18n()

  const relevantEngines = engines.filter(engine =>
    (SUMMARY_REGISTRY[engine.id]?.[type] ?? []).some(e => e.field === field),
  )

  const anyLoading = relevantEngines.some(e => results[e.id]?.loading)
  const entries = aggregateField(field, type, engines, results)

  if (!anyLoading && entries.length === 0) return null

  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide font-medium">
        {t(`summaryField.${field}`)}
      </span>
      {anyLoading && entries.length === 0 && (
        <span className="text-xs text-muted-foreground">{t('summary.loading')}</span>
      )}
      {entries.map(({ value, count, engines: srcs }) => (
        <div key={value} className="flex items-baseline gap-2 text-sm">
          <span className="text-foreground font-medium">
            {meta.format(value, { locale, yes: t('common.yes') })}
            <span className="text-muted-foreground font-normal ml-1">({count})</span>
          </span>
          <span className="text-xs text-muted-foreground">— {srcs.join(', ')}</span>
        </div>
      ))}
    </div>
  )
}

// ── Cross-source intel blocks ────────────────────────────────────────────────

function BlockTitle({ children }: { children: React.ReactNode }) {
  return <span className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{children}</span>
}

const fmtScore = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1))

function FlaggedBlock({ intel, weighted, unconfigured, type }: { intel: IntelSummary; weighted: Set<string>; unconfigured: number; type: IndicatorType }) {
  const { t, tn } = useI18n()
  if (intel.responded === 0) return null
  const { flagged, clean } = intel
  return (
    <div className="flex flex-col gap-1.5">
      <BlockTitle>{t('summary.flaggedBy')}</BlockTitle>
      <span className="text-sm text-foreground">
        <span className="font-semibold" style={{ color: flagged.length ? riskColor(10) : undefined }}>
          {flagged.length}
        </span>
        <span className="text-muted-foreground">{tn(type === 'company' ? 'summary.exposedCount' : 'summary.flaggedCount', flagged.length)}</span>
        <span className="text-muted-foreground">{tn('summary.respondedCount', intel.responded)}</span>
        {unconfigured > 0 && (
          <span className="text-muted-foreground/70">{tn('summary.unconfiguredCount', unconfigured)}</span>
        )}
        {intel.loading && <span className="text-xs text-muted-foreground">{t('summary.stillLoading')}</span>}
      </span>
      {flagged.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {flagged.map(f => {
            const counted = weighted.has(f.engineId)
            return (
              <span
                key={f.engineId}
                title={counted
                  ? t('summary.subscoreTitle', { s: fmtScore(f.subscore) })
                  : t('summary.subscoreUnweighted', { s: fmtScore(f.subscore) })}
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-border bg-muted/30 text-xs ${counted ? '' : 'opacity-60 border-dashed'}`}
              >
                <span className="text-foreground font-medium">{f.label}</span>
                <span className="font-semibold" style={{ color: riskColor(f.subscore) }}>{fmtScore(f.subscore)}</span>
              </span>
            )
          })}
        </div>
      )}
      {clean.length > 0 && (
        <span className="text-xs text-muted-foreground">
          <span className="text-green-400 font-medium">{t('summary.cleanVerdict')}</span> {clean.join(', ')}
        </span>
      )}
    </div>
  )
}

const shortEngine = (label: string) => label.split(' · ')[0]

const CTX_KEY: Record<string, 'summary.ctx.pulse' | 'summary.ctx.event' | 'summary.ctx.sample' | 'summary.ctx.scan'> = {
  otx: 'summary.ctx.pulse', misp: 'summary.ctx.event', hybrid: 'summary.ctx.sample', urlscan: 'summary.ctx.scan',
}

function ProvenancePanel({ item }: { item: AggregatedValue }) {
  const { t, tn } = useI18n()
  return (
    <div className="rounded-md border border-border bg-background/60 px-3 py-2.5 flex flex-col gap-2 text-xs">
      <span className="text-muted-foreground uppercase tracking-wide font-medium">{t('summary.provTitle', { value: item.value })}</span>
      <ul className="flex flex-col gap-1.5">
        {item.sources.map((src, i) => {
          const ctxKey = CTX_KEY[src.field.split('.')[0]]
          return (
            <li key={i} className="flex flex-col gap-0.5">
              <span className="text-muted-foreground">
                <span className="text-foreground font-medium">{src.engine}</span>
                {' — '}{t(`prov.${src.field}`)}
                {src.raw !== item.value && <> {t('summary.provAs', { raw: src.raw })}</>}
              </span>
              {src.context && (
                <span className="text-muted-foreground pl-3 break-words">
                  {ctxKey && <>{t(ctxKey)}: </>}
                  <span className="text-foreground/90">{src.context}</span>
                  {src.size != null && <> · {tn('summary.indicators', src.size)}</>}
                </span>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

const CHIP_STYLES = {
  plain: 'border-border bg-muted/30 text-foreground',
  strong: 'border-red-500/30 bg-red-500/10 text-red-400 font-medium',
} as const

// Chips with their sources inline; clicking one opens its provenance underneath.
function ChipList({
  items, max = 12, variant = 'plain',
}: {
  items: AggregatedValue[]
  max?: number
  variant?: keyof typeof CHIP_STYLES
}) {
  const [expanded, setExpanded] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const { t } = useI18n()
  const shown = expanded ? items : items.slice(0, max)
  const current = items.find(i => i.value === selected)
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1.5">
        {shown.map(item => {
          const names = item.engines.map(shortEngine)
          const isOpen = selected === item.value
          return (
            <button
              key={item.value}
              type="button"
              aria-expanded={isOpen}
              title={t('summary.clickSource')}
              onClick={() => setSelected(isOpen ? null : item.value)}
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs transition-colors hover:brightness-125 ${CHIP_STYLES[variant]} ${isOpen ? 'ring-1 ring-primary/60' : ''}`}
            >
              {item.value}
              <span className="font-normal text-muted-foreground">
                · {names.slice(0, 2).join(', ')}{names.length > 2 ? ` +${names.length - 2}` : ''}
              </span>
            </button>
          )
        })}
        {items.length > max && (
          <button
            type="button"
            onClick={() => setExpanded(e => !e)}
            className="px-2 py-0.5 text-xs text-primary hover:underline"
          >
            {expanded ? t('common.showLess') : t('common.more', { n: items.length - max })}
          </button>
        )}
      </div>
      {current && <ProvenancePanel item={current} />}
    </div>
  )
}

function FamiliesBlock({ intel }: { intel: IntelSummary }) {
  const { t } = useI18n()
  if (intel.families.length === 0) return null
  return (
    <div className="flex flex-col gap-1.5">
      <BlockTitle>{t('summary.families')}</BlockTitle>
      <ChipList items={intel.families} max={8} variant="strong" />
    </div>
  )
}

const CTX_PREFIX: Record<string, 'summary.ctx.pulse' | 'summary.ctx.event'> = { otx: 'summary.ctx.pulse', misp: 'summary.ctx.event' }

// One row per actor with every source that relates the indicator to it, visible
// without clicking; plus sources that link it to an unnamed APT. When sources
// answered and none relates it to an actor, say so explicitly.
function ActorsBlock({ intel, indicator, type }: { intel: IntelSummary; indicator: string; type: IndicatorType }) {
  const { t } = useI18n()
  const canAnalyze = useAuth().can('analyze')
  const actors = intel.actors.filter(a => a.value.toLowerCase() !== indicator.toLowerCase())
  const isActorLookup = type === 'threat-actor'
  // A CVE isn't expected to name actors: only show the block when a source does.
  const quietWhenEmpty = isActorLookup || type === 'cve' || type === 'company'
  const none = actors.length === 0 && intel.unnamedActorLinks.length === 0
  if (intel.responded === 0 || (quietWhenEmpty && none && intel.campaigns.length === 0)) return null
  return (
    <div className="flex flex-col gap-1.5">
      <BlockTitle>{t('summary.actorRelations')}</BlockTitle>
      {none && !isActorLookup && (
        <span className="text-sm text-muted-foreground">
          {intel.loading ? t('summary.loading') : t('summary.noActorRelation')}
        </span>
      )}
      {actors.map(actor => (
        <div key={actor.value} className="flex flex-col gap-1 rounded-md border border-primary/30 bg-primary/5 px-3 py-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-sm font-semibold text-primary">{actor.value}</span>
            {canAnalyze && (
              <Link
                to={`/results?indicator=${encodeURIComponent(actor.value)}&type=threat-actor`}
                className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
              >
                <ExternalLink className="h-3 w-3" /> {t('summary.lookupThisActor', { name: actor.value })}
              </Link>
            )}
          </div>
          <ul className="flex flex-col gap-0.5 text-xs text-muted-foreground">
            {actor.sources.map((src, i) => {
              const ctxKey = CTX_PREFIX[src.field.split('.')[0]]
              return (
                <li key={i}>
                  <span className="text-foreground font-medium">{src.engine}</span>
                  {' — '}{t(`prov.${src.field}`)}
                  {src.raw !== actor.value && <> {t('summary.provAs', { raw: src.raw })}</>}
                  {src.context && <>{' · '}{ctxKey && <>{t(ctxKey)}: </>}<span className="text-foreground/90">{src.context}</span></>}
                </li>
              )
            })}
          </ul>
        </div>
      ))}
      {intel.unnamedActorLinks.map((link, i) => (
        <div key={i} className="flex flex-col gap-0.5 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs" title={link.evidence}>
          <span>
            <span className="text-foreground font-medium">{link.engine}</span>
            <span className="text-muted-foreground"> — {link.rule}</span>
          </span>
          <span className="text-muted-foreground">{t('summary.unnamedActor')}</span>
          {link.evidence && <span className="text-muted-foreground/80 line-clamp-2">{link.evidence}</span>}
        </div>
      ))}
      {intel.campaigns.length > 0 && (
        <div className="flex items-start gap-2 mt-1">
          <Users className="h-3.5 w-3.5 mt-1 shrink-0 text-muted-foreground" />
          <ChipList items={intel.campaigns} max={6} />
        </div>
      )}
    </div>
  )
}

function relative(date: Date, locale: string, today: string) {
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  const days = Math.round((date.getTime() - Date.now()) / 86_400_000)
  if (Math.abs(days) < 1) return today
  if (Math.abs(days) < 60) return rtf.format(days, 'day')
  if (Math.abs(days) < 730) return rtf.format(Math.round(days / 30.4), 'month')
  return rtf.format(Math.round(days / 365), 'year')
}

function SeenRow({ label, seen }: { label: string; seen: SeenDate | null }) {
  const { t, locale } = useI18n()
  if (!seen) return null
  return (
    <div className="flex items-baseline gap-2 text-sm">
      <span className="text-muted-foreground w-32 shrink-0">{label}</span>
      <span className="text-foreground font-medium" title={seen.date.toISOString()}>
        {seen.date.toISOString().slice(0, 10)}
      </span>
      <span className="text-xs text-muted-foreground">{relative(seen.date, locale, t('summary.today'))} — {seen.engine}</span>
    </div>
  )
}

function SeenBlock({ intel }: { intel: IntelSummary }) {
  const { t } = useI18n()
  if (!intel.firstSeen && !intel.lastSeen) return null
  return (
    <div className="flex flex-col gap-1">
      <BlockTitle>{t('summary.activity')}</BlockTitle>
      <SeenRow label={t('summary.firstSeen')} seen={intel.firstSeen} />
      <SeenRow label={t('summary.lastSeen')} seen={intel.lastSeen} />
    </div>
  )
}

// ── Main component ───────────────────────────────────────────────────────────

interface Props {
  type: IndicatorType
  /** The looked-up value (used to avoid listing a threat actor as related to itself) */
  indicator?: string
  engines: EngineConfig[]
  results: Record<string, QueryResult>
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
  /** Sources for this type left out because their API key isn't configured */
  unconfigured?: number
}

export default function SummarySection({
  type, indicator = '', engines, results, verdict, thresholds, unconfigured = 0,
}: Props) {
  const { t } = useI18n()
  const mitre = useMitreAliases()
  const intel = useMemo(() => aggregateIntel(type, engines, results, mitre), [type, engines, results, mitre])
  const weighted = useMemo(() => new Set(verdict.contributions.risk.map(c => c.engineId)), [verdict])

  return (
    <div className="rounded-lg border border-border bg-muted/20 p-5">
      <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium mb-4">{t('summary.title')}</p>
      <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_380px] gap-6">
        <div className="flex flex-col gap-4 min-w-0">
          <FlaggedBlock intel={intel} weighted={weighted} unconfigured={unconfigured} type={type} />
          <FamiliesBlock intel={intel} />
          <ActorsBlock intel={intel} indicator={indicator} type={type} />
          <SeenBlock intel={intel} />
          {SUMMARY_FIELDS.map(field => (
            <SummaryItem
              key={field}
              field={field}
              type={type}
              engines={engines}
              results={results}
            />
          ))}
        </div>
        <VerdictPanel verdict={verdict} thresholds={thresholds} type={type} />
      </div>
    </div>
  )
}
