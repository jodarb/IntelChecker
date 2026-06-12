import type { EngineConfig, QueryResult, IndicatorType } from '@/registry'
import {
  SUMMARY_REGISTRY,
  SUMMARY_FIELD_META,
  SUMMARY_FIELDS,
  type SummaryField,
} from '@/summaryRegistry'

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

function ScoreGauge({ score }: { score: number }) {
  const r = 68
  const cx = 86
  const cy = 78
  const arcLen = Math.PI * r
  const pct = score / 10
  const color = score <= 3 ? '#4ade80' : score <= 6 ? '#fbbf24' : '#f87171'

  return (
    <div className="flex flex-col items-center">
      <span className="text-xs text-muted-foreground uppercase tracking-wide mb-2">Threat Score</span>
      <svg viewBox="0 0 172 92" className="w-44">
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="currentColor"
          strokeOpacity="0.12"
          strokeWidth="13"
          strokeLinecap="round"
        />
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth="13"
          strokeLinecap="round"
          strokeDasharray={`${pct * arcLen} ${arcLen}`}
        />
        <text x={cx} y={cy - 10} textAnchor="middle" fontSize="30" fontWeight="700" fill={color}>
          {score}
        </text>
        <text x={cx} y={cy + 7} textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.4">
          / 10
        </text>
        <text x={cx - r + 4} y={cy + 15} fontSize="9" fill="currentColor" opacity="0.35">0</text>
        <text x={cx + r - 10} y={cy + 15} fontSize="9" fill="currentColor" opacity="0.35">10</text>
      </svg>
    </div>
  )
}

// ── Main component ───────────────────────────────────────────────────────────

interface Props {
  type: IndicatorType
  engines: EngineConfig[]
  results: Record<string, QueryResult>
  score: number
}

export default function SummarySection({ type, engines, results, score }: Props) {
  return (
    <div className="rounded-lg border border-border bg-muted/20 p-5">
      <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium mb-4">Summary</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
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
        <div className="flex items-start justify-center sm:justify-end">
          <ScoreGauge score={score} />
        </div>
      </div>
    </div>
  )
}
