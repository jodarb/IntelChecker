import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Info, Grid2x2, Users } from 'lucide-react'
import type { EngineConfig, QueryResult, IndicatorType } from '@/registry'
import {
  SUMMARY_REGISTRY,
  SUMMARY_FIELD_META,
  SUMMARY_FIELDS,
  type SummaryField,
} from '@/summaryRegistry'
import type { Quadrant, VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { QUADRANT_META, quadrantHint, quadrantLabel } from '@/quadrants'
import { aggregateIntel, type AggregatedValue, type IntelSummary, type SeenDate } from '@/intelAggregates'
import { useMitreAliases } from '@/hooks/useMitreAliases'
import VerdictExplainerModal from './VerdictExplainerModal'
import MatrixModal from './MatrixModal'
import { useI18n } from '@/i18n/useI18n'

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

function FlaggedBlock({ intel, weighted }: { intel: IntelSummary; weighted: Set<string> }) {
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
        <span className="text-muted-foreground">{tn('summary.ofResponding', intel.responded)}</span>
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

function ChipList({
  items, max = 12, render, variant = 'plain',
}: {
  items: AggregatedValue[]
  max?: number
  render?: (item: AggregatedValue, chip: React.ReactNode) => React.ReactNode
  variant?: 'plain' | 'strong'
}) {
  const [expanded, setExpanded] = useState(false)
  const { t } = useI18n()
  const shown = expanded ? items : items.slice(0, max)
  return (
    <div className="flex flex-wrap gap-1.5">
      {shown.map(item => {
        const chip = (
          <span
            title={item.engines.join(', ')}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs ${variant === 'strong'
              ? 'border-red-500/30 bg-red-500/10 text-red-400 font-medium'
              : 'border-border bg-muted/30 text-foreground'}`}
          >
            {item.value}
            {item.engines.length > 1 && <span className="text-muted-foreground">×{item.engines.length}</span>}
          </span>
        )
        return <span key={item.value}>{render ? render(item, chip) : chip}</span>
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

function TagsBlock({ intel }: { intel: IntelSummary }) {
  const { t } = useI18n()
  if (intel.tags.length === 0) return null
  return (
    <div className="flex flex-col gap-1.5">
      <BlockTitle>{t('summary.tags')}</BlockTitle>
      <ChipList items={intel.tags} max={8} />
    </div>
  )
}

function ActorsBlock({ intel, indicator }: { intel: IntelSummary; indicator: string }) {
  const { t } = useI18n()
  const actors = intel.actors.filter(a => a.value.toLowerCase() !== indicator.toLowerCase())
  if (actors.length === 0 && intel.campaigns.length === 0) return null
  return (
    <div className="flex flex-col gap-1.5">
      <BlockTitle>{t('summary.actors')}</BlockTitle>
      {actors.length > 0 && (
        <ChipList
          items={actors}
          render={(item, chip) => (
            <Link
              to={`/results?indicator=${encodeURIComponent(item.value)}&type=threat-actor`}
              title={t('summary.lookupActor', { name: item.value, sources: item.engines.join(', ') })}
              className="inline-flex hover:opacity-80 [&>span]:border-primary/40 [&>span]:text-primary"
            >
              {chip}
            </Link>
          )}
        />
      )}
      {intel.campaigns.length > 0 && (
        <div className="flex items-start gap-2">
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

// ── Score Gauge ──────────────────────────────────────────────────────────────

function riskColor(score: number) {
  return score <= 3 ? '#4ade80' : score <= 6 ? '#fbbf24' : '#f87171'
}

// Knowledge isn't good or bad, just more or less — a single-hue scale.
function knowledgeColor(score: number) {
  return score <= 3 ? '#94a3b8' : score <= 6 ? '#60a5fa' : '#3b82f6'
}

function ScoreGauge({
  title, score, color, emptyLabel,
}: {
  title: string
  score: number | null
  color: (s: number) => string
  emptyLabel: string
}) {
  const r = 68
  const cx = 86
  const cy = 78
  const arcLen = Math.PI * r
  const pct = (score ?? 0) / 10
  const stroke = score == null ? 'currentColor' : color(score)

  return (
    <div className="flex flex-col items-center">
      <span className="text-xs text-muted-foreground uppercase tracking-wide mb-2">{title}</span>
      <svg viewBox="0 0 172 100" className="w-40">
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="currentColor"
          strokeOpacity="0.12"
          strokeWidth="13"
          strokeLinecap="round"
        />
        {score != null && (
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke={stroke}
            strokeWidth="13"
            strokeLinecap="round"
            strokeDasharray={`${pct * arcLen} ${arcLen}`}
          />
        )}
        <text
          x={cx}
          y={cy - 10}
          textAnchor="middle"
          fontSize={score == null ? '18' : '30'}
          fontWeight="700"
          fill={stroke}
          opacity={score == null ? 0.4 : 1}
        >
          {score ?? emptyLabel}
        </text>
        {score != null && (
          <text x={cx} y={cy + 7} textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.4">
            / 10
          </text>
        )}
        <text x={cx - r + 4} y={cy + 15} fontSize="9" fill="currentColor" opacity="0.35">0</text>
        <text x={cx + r - 10} y={cy + 15} fontSize="9" fill="currentColor" opacity="0.35">10</text>
      </svg>
    </div>
  )
}

// Knowledge is a horizontal bar under the risk gauge, filling left → right.
function KnowledgeBar({
  score, threshold,
}: {
  score: number | null
  threshold: number | null
}) {
  const pct = Math.min(100, Math.max(0, ((score ?? 0) / 10) * 100))
  const color = score == null ? undefined : knowledgeColor(score)
  const { t } = useI18n()
  return (
    <div className="flex flex-col w-40 gap-1">
      <div className="flex items-baseline justify-between">
        <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('score.knowledge')}</span>
        {score == null ? (
          <span className="text-xs font-semibold text-muted-foreground/60">{t('score.na')}</span>
        ) : (
          <span className="text-sm font-bold" style={{ color }}>
            {score}<span className="text-xs font-normal text-muted-foreground"> / 10</span>
          </span>
        )}
      </div>
      <div
        className="relative h-2.5 w-full rounded-full bg-foreground/10"
        role="meter"
        aria-label={t('summary.knowledgeAria')}
        aria-valuemin={0}
        aria-valuemax={10}
        aria-valuenow={score ?? undefined}
      >
        {score != null && (
          <div
            className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-500"
            style={{ width: `${pct}%`, backgroundColor: color }}
          />
        )}
        {threshold != null && threshold > 0 && threshold < 10 && (
          <div
            className="absolute -top-0.5 -bottom-0.5 w-0.5 rounded bg-foreground/50"
            style={{ left: `calc(${threshold * 10}% - 1px)` }}
            title={t('summary.knownThreshold', { n: threshold })}
          />
        )}
      </div>
      <div className="flex justify-between text-[9px] text-muted-foreground/60">
        <span>0</span>
        <span>10</span>
      </div>
    </div>
  )
}

function QuadrantBadge({ quadrant }: { quadrant: Quadrant | null }) {
  const { t } = useI18n()
  if (!quadrant) {
    return <span className="text-xs text-muted-foreground">{t('summary.waiting')}</span>
  }
  const meta = QUADRANT_META[quadrant]
  return (
    <div className="flex flex-col items-center gap-1 max-w-xs mb-1">
      <span className={`inline-flex items-center px-3 py-1 rounded-full border text-sm font-semibold ${meta.className}`}>
        {quadrantLabel(quadrant, t)}
      </span>
      <span className="text-xs text-muted-foreground text-center">{quadrantHint(quadrant, t)}</span>
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
}

export default function SummarySection({ type, indicator = '', engines, results, verdict, thresholds }: Props) {
  const [explainerOpen, setExplainerOpen] = useState(false)
  const [matrixOpen, setMatrixOpen] = useState(false)
  const { t } = useI18n()
  const mitre = useMitreAliases()
  const intel = useMemo(() => aggregateIntel(type, engines, results, mitre), [type, engines, results, mitre])
  const weighted = useMemo(() => new Set(verdict.contributions.risk.map(c => c.engineId)), [verdict])
  const hasContributions = verdict.contributions.knowledge.length > 0 || verdict.contributions.risk.length > 0

  return (
    <div className="rounded-lg border border-border bg-muted/20 p-5">
      <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium mb-4">{t('summary.title')}</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="flex flex-col gap-4 min-w-0">
          <FlaggedBlock intel={intel} weighted={weighted} />
          <FamiliesBlock intel={intel} />
          <TagsBlock intel={intel} />
          <ActorsBlock intel={intel} indicator={indicator} />
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
        <div className="flex flex-col items-center sm:items-end gap-3">
          <div className="flex flex-col items-center gap-2">
            <QuadrantBadge quadrant={verdict.quadrant} />
            <ScoreGauge title={t('score.risk')} score={verdict.risk} color={riskColor} emptyLabel={t('score.noData')} />
            <KnowledgeBar score={verdict.knowledge} threshold={thresholds?.knowledge ?? null} />
          </div>
          <span className="text-xs text-muted-foreground">
            {t('summary.answered', { responded: verdict.responded, queried: verdict.queried })}
          </span>
          <div className="flex flex-wrap justify-center sm:justify-end gap-2">
          <button
            onClick={() => setMatrixOpen(true)}
            disabled={!hasContributions}
            title={hasContributions ? t('summary.matrixTitle') : t('summary.matrixDisabled')}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-primary/40 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 transition-colors disabled:opacity-40 disabled:pointer-events-none"
          >
            <Grid2x2 className="h-3 w-3" />
            {t('summary.viewMatrix')}
          </button>
          <button
            onClick={() => setExplainerOpen(true)}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
          >
            <Info className="h-3 w-3" />
            {t('summary.howCalculated')}
          </button>
          </div>
        </div>
      </div>
      <MatrixModal
        open={matrixOpen}
        onClose={() => setMatrixOpen(false)}
        verdict={verdict}
        thresholds={thresholds}
      />
      <VerdictExplainerModal
        open={explainerOpen}
        onClose={() => setExplainerOpen(false)}
        verdict={verdict}
        thresholds={thresholds}
      />
    </div>
  )
}
