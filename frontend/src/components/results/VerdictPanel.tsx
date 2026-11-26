import { useId, useState } from 'react'
import { Info, Grid2x2 } from 'lucide-react'
import type { IndicatorType } from '@/registry'
import type { Quadrant, VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { QUADRANT_META, quadrantHint, quadrantLabel } from '@/quadrants'
import VerdictExplainerModal from './VerdictExplainerModal'
import MatrixModal from './MatrixModal'
import { useI18n } from '@/i18n/useI18n'
import { knowledgeColor, riskColor } from '@/lib/scoreColors'

// The verdict card shared by the artifact Summary and the company report: quadrant,
// Risk gauge, Knowledge bar, answered count and the matrix / explainer modals.

// ── Score Gauge ──────────────────────────────────────────────────────────────


const clamp10 = (n: number) => Math.min(10, Math.max(0, n))

// Semicircular risk gauge: the arc is painted with a green → amber → red
// gradient up to the score, with a tick on the "high risk" threshold.
function ScoreGauge({
  title, score, threshold, emptyLabel,
}: {
  title: string
  score: number | null
  threshold: number | null
  emptyLabel: string
}) {
  const { t } = useI18n()
  const gradId = useId()
  const r = 92
  const cx = 110
  const cy = 104
  const arc = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`
  const arcLen = Math.PI * r
  const pct = clamp10(score ?? 0) / 10
  const color = score == null ? 'currentColor' : riskColor(score)
  const point = (v: number, radius: number) => {
    const a = Math.PI * (1 - clamp10(v) / 10)
    return { x: cx + radius * Math.cos(a), y: cy - radius * Math.sin(a) }
  }
  const showTick = threshold != null && threshold > 0 && threshold < 10
  const tickIn = showTick ? point(threshold, r - 13) : null
  const tickOut = showTick ? point(threshold, r + 13) : null

  return (
    <div className="flex flex-col items-center w-full">
      <span className="text-xs text-muted-foreground uppercase tracking-[0.2em] mb-1">{title}</span>
      <svg viewBox="0 0 220 128" className="w-60 max-w-full" role="meter" aria-label={title}
        aria-valuemin={0} aria-valuemax={10} aria-valuenow={score ?? undefined}>
        <defs>
          <linearGradient id={gradId} x1={cx - r} y1="0" x2={cx + r} y2="0" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#4ade80" />
            <stop offset="50%" stopColor="#fbbf24" />
            <stop offset="100%" stopColor="#f87171" />
          </linearGradient>
        </defs>
        <path d={arc} fill="none" stroke="currentColor" strokeOpacity="0.1" strokeWidth="16" strokeLinecap="round" />
        {score != null && score > 0 && (
          <path
            d={arc}
            fill="none"
            stroke={`url(#${CSS.escape(gradId)})`}
            strokeWidth="16"
            strokeLinecap="round"
            strokeDasharray={`${pct * arcLen} ${arcLen}`}
            className="transition-[stroke-dasharray] duration-700"
          />
        )}
        {tickIn && tickOut && (
          <line x1={tickIn.x} y1={tickIn.y} x2={tickOut.x} y2={tickOut.y}
            stroke="currentColor" strokeOpacity="0.55" strokeWidth="2" strokeLinecap="round">
            <title>{t('summary.riskThreshold', { n: threshold ?? 0 })}</title>
          </line>
        )}
        <text
          x={cx} y={cy - 18} textAnchor="middle"
          fontSize={score == null ? '20' : '46'} fontWeight="800"
          fill={color} opacity={score == null ? 0.4 : 1}
          style={{ fontVariantNumeric: 'tabular-nums' }}
        >
          {score ?? emptyLabel}
        </text>
        {score != null && (
          <text x={cx} y={cy + 2} textAnchor="middle" fontSize="12" fill="currentColor" opacity="0.45">/ 10</text>
        )}
        <text x={cx - r} y={cy + 22} textAnchor="middle" fontSize="10" fill="currentColor" opacity="0.4">0</text>
        <text x={cx + r} y={cy + 22} textAnchor="middle" fontSize="10" fill="currentColor" opacity="0.4">10</text>
      </svg>
    </div>
  )
}

// Knowledge is a horizontal bar under the risk gauge, filling left → right.
function KnowledgeBar({
  score, threshold, title,
}: {
  score: number | null
  threshold: number | null
  title?: string
}) {
  const pct = (clamp10(score ?? 0) / 10) * 100
  const color = score == null ? undefined : knowledgeColor(score)
  const { t } = useI18n()
  const showTick = threshold != null && threshold > 0 && threshold < 10
  return (
    <div className="flex flex-col w-full gap-1.5">
      <div className="flex items-baseline justify-between">
        <span className="text-xs text-muted-foreground uppercase tracking-[0.2em]">{title ?? t('score.knowledge')}</span>
        {score == null ? (
          <span className="text-sm font-semibold text-muted-foreground/60">{t('score.na')}</span>
        ) : (
          <span className="text-xl font-extrabold tabular-nums" style={{ color }}>
            {score}<span className="text-xs font-normal text-muted-foreground"> / 10</span>
          </span>
        )}
      </div>
      <div
        className="relative h-3.5 w-full rounded-full bg-foreground/10"
        role="meter"
        aria-label={t('summary.knowledgeAria')}
        aria-valuemin={0}
        aria-valuemax={10}
        aria-valuenow={score ?? undefined}
      >
        {score != null && (
          <div
            className="absolute inset-y-0 left-0 rounded-full transition-[width] duration-700"
            style={{ width: `${pct}%`, background: `linear-gradient(90deg, #94a3b8, ${color})` }}
          />
        )}
        {showTick && (
          <div
            className="absolute -top-1 -bottom-1 w-0.5 rounded bg-foreground/60"
            style={{ left: `calc(${threshold * 10}% - 1px)` }}
            title={t('summary.knownThreshold', { n: threshold })}
          />
        )}
      </div>
      <div className="relative h-3 text-[10px] text-muted-foreground/60">
        <span className="absolute left-0">0</span>
        {showTick && (
          <span className="absolute -translate-x-1/2 whitespace-nowrap" style={{ left: `${threshold * 10}%` }}>
            {t('summary.thresholdShort', { n: threshold })}
          </span>
        )}
        <span className="absolute right-0">10</span>
      </div>
    </div>
  )
}

function QuadrantBadge({ quadrant, type }: { quadrant: Quadrant | null; type: IndicatorType }) {
  const { t } = useI18n()
  if (!quadrant) {
    return <span className="text-xs text-muted-foreground">{t('summary.waiting')}</span>
  }
  const meta = QUADRANT_META[quadrant]
  return (
    <div className="flex flex-col items-center gap-1.5">
      <span className={`inline-flex items-center gap-2 px-3.5 py-1 rounded-full border text-sm font-semibold uppercase tracking-wide ${meta.className}`}>
        <span className="h-2 w-2 rounded-full bg-current" />
        {quadrantLabel(quadrant, t, type)}
      </span>
      <span className="text-xs text-muted-foreground text-center leading-snug">{quadrantHint(quadrant, t, type)}</span>
    </div>
  )
}

export default function VerdictPanel({
  verdict, thresholds, type, riskTitle, knowledgeTitle, className = '',
}: {
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
  type: IndicatorType
  /** Gauge titles; companies read Risk as exposure and Knowledge as identification */
  riskTitle?: string
  knowledgeTitle?: string
  className?: string
}) {
  const { t } = useI18n()
  const [explainerOpen, setExplainerOpen] = useState(false)
  const [matrixOpen, setMatrixOpen] = useState(false)
  const hasContributions = verdict.contributions.knowledge.length > 0 || verdict.contributions.risk.length > 0
  return (
    <>
        <div
          className={`${className} self-start w-full flex flex-col gap-5 rounded-xl border bg-gradient-to-b from-background/70 to-muted/30 p-5 transition-shadow duration-500 ${
            verdict.quadrant ? QUADRANT_META[verdict.quadrant].panel : 'border-border'
          }`}
        >
          <QuadrantBadge quadrant={verdict.quadrant} type={type} />
          <ScoreGauge
            title={riskTitle ?? t('score.risk')}
            score={verdict.risk}
            threshold={thresholds?.risk ?? null}
            emptyLabel={t('score.noData')}
          />
          <KnowledgeBar score={verdict.knowledge} threshold={thresholds?.knowledge ?? null} title={knowledgeTitle} />
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3">
            <span className="text-xs text-muted-foreground">
              {t('summary.answered', { responded: verdict.responded, queried: verdict.queried })}
            </span>
            <div className="flex flex-wrap gap-2">
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
        type={type}
      />
      <VerdictExplainerModal
        open={explainerOpen}
        onClose={() => setExplainerOpen(false)}
        verdict={verdict}
        thresholds={thresholds}
        type={type}
      />
    </>
  )
}
