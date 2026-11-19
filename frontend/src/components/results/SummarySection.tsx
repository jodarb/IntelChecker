import { useState } from 'react'
import { Info, Grid2x2 } from 'lucide-react'
import type { EngineConfig, QueryResult, IndicatorType } from '@/registry'
import {
  SUMMARY_REGISTRY,
  SUMMARY_FIELD_META,
  SUMMARY_FIELDS,
  type SummaryField,
} from '@/summaryRegistry'
import type { Quadrant, VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { QUADRANT_META } from '@/quadrants'
import VerdictExplainerModal from './VerdictExplainerModal'
import MatrixModal from './MatrixModal'

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

  const relevantEngines = engines.filter(engine =>
    (SUMMARY_REGISTRY[engine.id]?.[type] ?? []).some(e => e.field === field),
  )

  const anyLoading = relevantEngines.some(e => results[e.id]?.loading)
  const entries = aggregateField(field, type, engines, results)

  if (!anyLoading && entries.length === 0) return null

  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide font-medium">
        {meta.label}
      </span>
      {anyLoading && entries.length === 0 && (
        <span className="text-xs text-muted-foreground">Loading...</span>
      )}
      {entries.map(({ value, count, engines: srcs }) => (
        <div key={value} className="flex items-baseline gap-2 text-sm">
          <span className="text-foreground font-medium">
            {meta.format(value)}
            <span className="text-muted-foreground font-normal ml-1">({count})</span>
          </span>
          <span className="text-xs text-muted-foreground">— {srcs.join(', ')}</span>
        </div>
      ))}
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

function QuadrantBadge({ quadrant }: { quadrant: Quadrant | null }) {
  if (!quadrant) {
    return <span className="text-xs text-muted-foreground">Waiting for sources…</span>
  }
  const meta = QUADRANT_META[quadrant]
  return (
    <div className="flex flex-col items-center sm:items-end gap-1 max-w-xs">
      <span className={`inline-flex items-center px-3 py-1 rounded-full border text-sm font-semibold ${meta.className}`}>
        {meta.label}
      </span>
      <span className="text-xs text-muted-foreground text-center sm:text-right">{meta.hint}</span>
    </div>
  )
}

// ── Main component ───────────────────────────────────────────────────────────

interface Props {
  type: IndicatorType
  engines: EngineConfig[]
  results: Record<string, QueryResult>
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
}

export default function SummarySection({ type, engines, results, verdict, thresholds }: Props) {
  const [explainerOpen, setExplainerOpen] = useState(false)
  const [matrixOpen, setMatrixOpen] = useState(false)
  const hasContributions = verdict.contributions.knowledge.length > 0 || verdict.contributions.risk.length > 0

  return (
    <div className="rounded-lg border border-border bg-muted/20 p-5">
      <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium mb-4">Summary</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="flex flex-col gap-4">
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
          <div className="flex flex-wrap justify-center sm:justify-end gap-2">
            <ScoreGauge title="Knowledge" score={verdict.knowledge} color={knowledgeColor} emptyLabel="N/A" />
            <ScoreGauge title="Risk" score={verdict.risk} color={riskColor} emptyLabel="No data" />
          </div>
          <QuadrantBadge quadrant={verdict.quadrant} />
          <span className="text-xs text-muted-foreground">
            {verdict.responded} of {verdict.queried} sources answered
          </span>
          <div className="flex flex-wrap justify-center sm:justify-end gap-2">
          <button
            onClick={() => setMatrixOpen(true)}
            disabled={!hasContributions}
            title={hasContributions ? 'Plot knowledge vs risk, source by source' : 'No source contributions to plot'}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-primary/40 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 transition-colors disabled:opacity-40 disabled:pointer-events-none"
          >
            <Grid2x2 className="h-3 w-3" />
            View matrix
          </button>
          <button
            onClick={() => setExplainerOpen(true)}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
          >
            <Info className="h-3 w-3" />
            How is this calculated?
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
