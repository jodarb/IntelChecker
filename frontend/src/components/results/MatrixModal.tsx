import { useEffect, useMemo, useState } from 'react'
import { X } from 'lucide-react'
import type { VerdictResult, VerdictThresholds } from '@/verdictEngine'
import type { IndicatorType } from '@/registry'
import { computeTrajectory, type TrajectoryStep } from '@/trajectory'
import { OUTCOME_META, QUADRANT_META, depthLabel, outcomeLabel, quadrantLabel } from '@/quadrants'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'

interface Props {
  open: boolean
  onClose: () => void
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
  /** Indicator type: CVEs word the quadrants differently */
  type?: IndicatorType
}

// ── Geometry ────────────────────────────────────────────────────────────────
const SIZE = 520
const PAD_L = 52
const PAD_B = 44
const PAD_T = 16
const PAD_R = 16
const W = SIZE - PAD_L - PAD_R
const H = SIZE - PAD_T - PAD_B
const px = (k: number) => PAD_L + (k / 10) * W
const py = (r: number) => PAD_T + ((10 - r) / 10) * H

const OUTCOME_COLOR: Record<string, string> = {
  hit: '#f87171',
  clean: '#4ade80',
  context: '#38bdf8',
  no_data: '#94a3b8',
  excluded: '#94a3b8',
}

const fmt = (n: number) => n.toFixed(1)

function delta(a: number | null, b: number | null): string {
  if (a == null && b == null) return '—'
  if (a == null) return 'new'
  if (b == null) return '—'
  const d = b - a
  if (Math.abs(d) < 0.05) return '±0'
  return `${d > 0 ? '+' : '−'}${fmt(Math.abs(d))}`
}

function deltaClass(a: number | null, b: number | null, upIsBad: boolean): string {
  if (a == null && b != null) return upIsBad ? 'text-amber-400' : 'text-sky-400'
  if (a == null || b == null || Math.abs(b - a) < 0.05) return 'text-muted-foreground'
  const up = b > a
  if (!upIsBad) return up ? 'text-sky-400' : 'text-muted-foreground'
  return up ? 'text-red-400' : 'text-green-400'
}

// ── Chart ───────────────────────────────────────────────────────────────────

function Tooltip({ step, index }: { step: TrajectoryStep; index: number }) {
  const x = px(step.to.knowledge)
  const y = py(step.to.risk ?? 0)
  const w = 196
  const h = 58
  const tx = x + 16 + w > PAD_L + W ? x - 16 - w : x + 16
  const ty = Math.min(Math.max(y - h / 2, PAD_T), PAD_T + H - h)
  const { t } = useI18n()
  const riskTxt = step.to.risk == null ? t('matrix.noVerdictYet') : `${delta(step.from.risk, step.to.risk)} → ${fmt(step.to.risk)}`
  return (
    <g pointerEvents="none">
      <rect x={tx} y={ty} width={w} height={h} rx="6" fill="var(--color-background)" stroke="currentColor" strokeOpacity="0.3" />
      <text x={tx + 10} y={ty + 17} fontSize="11" fontWeight="700" fill="currentColor">{index + 1}. {step.label}</text>
      <text x={tx + 10} y={ty + 33} fontSize="10" fill="currentColor" opacity="0.8">
        {t('matrix.tooltipKnowledge', { delta: delta(step.from.knowledge, step.to.knowledge), value: fmt(step.to.knowledge) })}
      </text>
      <text x={tx + 10} y={ty + 48} fontSize="10" fill="currentColor" opacity="0.8">{t('matrix.tooltipRisk', { text: riskTxt })}</text>
    </g>
  )
}

function Chart({
  steps, thresholds, final, active, setActive,
}: {
  steps: TrajectoryStep[]
  thresholds: VerdictThresholds
  final: { knowledge: number | null; risk: number | null }
  active: number | null
  setActive: (i: number | null) => void
}) {
  const { t } = useI18n()
  const tk = px(thresholds.knowledge)
  const tr = py(thresholds.risk)
  const last = steps.at(-1)?.to

  return (
    <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full h-auto select-none" role="img" aria-label={t('matrix.aria')}>
      {/* Quadrant regions */}
      <rect x={PAD_L} y={PAD_T} width={tk - PAD_L} height={tr - PAD_T} fill="#fb923c" opacity="0.08" />
      <rect x={tk} y={PAD_T} width={PAD_L + W - tk} height={tr - PAD_T} fill="#f87171" opacity="0.10" />
      <rect x={PAD_L} y={tr} width={tk - PAD_L} height={PAD_T + H - tr} fill="#94a3b8" opacity="0.06" />
      <rect x={tk} y={tr} width={PAD_L + W - tk} height={PAD_T + H - tr} fill="#4ade80" opacity="0.07" />
      <g fontSize="10" fill="currentColor" opacity="0.55">
        <text x={PAD_L + 6} y={PAD_T + 14}>{t('matrix.region.isolated')}</text>
        <text x={PAD_L + W - 6} y={PAD_T + 14} textAnchor="end">{t('matrix.region.confirmed')}</text>
        <text x={PAD_L + 6} y={tr + 14}>{t('matrix.region.unknown')}</text>
        <text x={PAD_L + W - 6} y={tr + 14} textAnchor="end">{t('matrix.region.known')}</text>
      </g>

      {/* Grid + axes */}
      <g stroke="currentColor" strokeOpacity="0.08">
        {Array.from({ length: 11 }, (_, i) => (
          <g key={i}>
            <line x1={px(i)} y1={PAD_T} x2={px(i)} y2={PAD_T + H} />
            <line x1={PAD_L} y1={py(i)} x2={PAD_L + W} y2={py(i)} />
          </g>
        ))}
      </g>
      <g stroke="currentColor" strokeOpacity="0.35" strokeDasharray="4 4">
        <line x1={tk} y1={PAD_T} x2={tk} y2={PAD_T + H} />
        <line x1={PAD_L} y1={tr} x2={PAD_L + W} y2={tr} />
      </g>
      <g stroke="currentColor" strokeOpacity="0.4">
        <line x1={PAD_L} y1={PAD_T + H} x2={PAD_L + W} y2={PAD_T + H} />
        <line x1={PAD_L} y1={PAD_T} x2={PAD_L} y2={PAD_T + H} />
      </g>
      <g fontSize="10" fill="currentColor" opacity="0.6">
        {Array.from({ length: 11 }, (_, i) => (
          <g key={i}>
            <text x={px(i)} y={PAD_T + H + 14} textAnchor="middle">{i}</text>
            <text x={PAD_L - 8} y={py(i) + 3} textAnchor="end">{i}</text>
          </g>
        ))}
      </g>
      <text x={PAD_L + W / 2} y={SIZE - 8} textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.8">{t('matrix.axisKnowledge')}</text>
      <text x={14} y={PAD_T + H / 2} textAnchor="middle" fontSize="11" fill="currentColor" opacity="0.8" transform={`rotate(-90 14 ${PAD_T + H / 2})`}>{t('matrix.axisRisk')}</text>

      {/* Staircase: per engine, horizontal (knowledge) then vertical (risk).
          Two layers — every line first, every point on top — so later steps never hide earlier points. */}
      {steps.map((s, i) => {
        const x0 = px(s.from.knowledge)
        const x1 = px(s.to.knowledge)
        const y0 = py(s.from.risk ?? 0)
        const y1 = py(s.to.risk ?? 0)
        const color = OUTCOME_COLOR[s.outcome]
        const width = active === i ? 4.5 : 2.5
        return (
          <g key={`l-${s.engineId}`} opacity={active != null && active !== i ? 0.15 : 0.9} pointerEvents="none">
            <line x1={x0} y1={y0} x2={x1} y2={y0} stroke={color} strokeWidth={width}
              strokeDasharray={s.from.risk == null ? '5 4' : undefined} strokeLinecap="round" />
            <line x1={x1} y1={y0} x2={x1} y2={y1} stroke={color} strokeWidth={width} strokeLinecap="round" />
          </g>
        )
      })}

      {/* Start */}
      <circle cx={px(0)} cy={py(0)} r={4} fill="currentColor" opacity="0.7" pointerEvents="none" />
      <text x={px(0) + 8} y={py(0) - 8} fontSize="10" fill="currentColor" opacity="0.7" pointerEvents="none">{t('matrix.start')}</text>

      {steps.map((s, i) => {
        const x1 = px(s.to.knowledge)
        const y1 = py(s.to.risk ?? 0)
        const color = OUTCOME_COLOR[s.outcome]
        const noRiskYet = s.to.risk == null
        return (
          <g
            key={`p-${s.engineId}`}
            opacity={active != null && active !== i ? 0.25 : 1}
            onMouseEnter={() => setActive(i)}
            onMouseLeave={() => setActive(null)}
            className="cursor-pointer"
          >
            <circle cx={x1} cy={y1} r={active === i ? 11 : 9} fill={noRiskYet ? 'var(--color-background)' : color}
              stroke={color} strokeWidth="2" />
            <text x={x1} y={y1 + 3.5} textAnchor="middle" fontSize="9.5" fontWeight="700" pointerEvents="none"
              fill={noRiskYet ? color : '#0b1020'}>{i + 1}</text>
          </g>
        )
      })}

      {/* Final */}
      {last && (
        <g pointerEvents="none">
          <circle cx={px(last.knowledge)} cy={py(last.risk ?? 0)} r={15} fill="none" stroke="currentColor" strokeWidth="2" opacity="0.8" />
          <text
            x={Math.min(px(last.knowledge) + 20, PAD_L + W - 4)}
            y={Math.max(py(last.risk ?? 0) - 18, PAD_T + 28)}
            textAnchor={px(last.knowledge) > PAD_L + W - 110 ? 'end' : 'start'}
            fontSize="11" fontWeight="700" fill="currentColor"
          >
            {t('matrix.final', { k: final.knowledge ?? t('score.na'), r: final.risk ?? t('score.noData') })}
          </text>
        </g>
      )}

      {active != null && steps[active] && <Tooltip step={steps[active]} index={active} />}
    </svg>
  )
}

// ── Modal ───────────────────────────────────────────────────────────────────

export default function MatrixModal({ open, onClose, verdict, thresholds, type }: Props) {
  const [active, setActive] = useState<number | null>(null)
  const steps = useMemo(() => computeTrajectory(verdict.contributions), [verdict.contributions])
  const th = thresholds ?? { knowledge: 4, risk: 5 }
  const { t } = useI18n()

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null
  const q = verdict.quadrant

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="relative w-full max-w-6xl mx-4 rounded-lg border border-border bg-background shadow-2xl overflow-hidden flex flex-col max-h-[92vh]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <span className="text-sm font-semibold text-foreground">{t('matrix.title')}</span>
            {q && (
              <span className={`hidden sm:inline-flex px-2 py-0.5 rounded-full border text-xs font-medium ${QUADRANT_META[q].className}`}>
                {quadrantLabel(q, t, type)}
              </span>
            )}
          </div>
          <button onClick={onClose} aria-label={t('common.close')} className="p-1 rounded hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-auto flex-1 p-4 grid grid-cols-1 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] gap-5">
          <div className="flex flex-col gap-2 text-foreground">
            {steps.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('matrix.empty')}</p>
            ) : (
              <Chart steps={steps} thresholds={th} final={{ knowledge: verdict.knowledge, risk: verdict.risk }} active={active} setActive={setActive} />
            )}
            <p className="text-xs text-muted-foreground">
              {rich(t('matrix.explanation', { k: th.knowledge, r: th.risk }))}
            </p>
          </div>

          <div className="flex flex-col gap-2 min-w-0">
            <div className="grid grid-cols-[1.5rem_1fr_auto_auto] gap-x-3 px-2 text-xs text-muted-foreground uppercase tracking-wide font-medium">
              <span>#</span>
              <span>{t('explainer.source')}</span>
              <span className="w-24 text-right">{t('score.knowledge')}</span>
              <span className="w-24 text-right">{t('score.risk')}</span>
            </div>
            {steps.map((s, i) => (
              <div
                key={s.engineId}
                onMouseEnter={() => setActive(i)}
                onMouseLeave={() => setActive(null)}
                className={`grid grid-cols-[1.5rem_1fr_auto_auto] gap-x-3 items-center rounded-md border px-2 py-1.5 text-sm transition-colors ${
                  active === i ? 'border-primary/60 bg-muted/50' : 'border-border bg-muted/20'
                }`}
              >
                <span
                  className="h-5 w-5 rounded-full text-[10px] font-bold flex items-center justify-center"
                  style={{ background: OUTCOME_COLOR[s.outcome], color: '#0b1020' }}
                >
                  {i + 1}
                </span>
                <div className="flex flex-col min-w-0">
                  <span className="text-foreground font-medium truncate">{s.label}</span>
                  <span className="text-xs text-muted-foreground truncate">
                    <span className={OUTCOME_META[s.outcome].className}>{outcomeLabel(s.outcome, t)}</span>
                    {s.knowledgeWeight > 0 && <> · K {s.knowledgeWeight} × {depthLabel(s.depth, t)}</>}
                    {s.riskWeight > 0 && s.subscore != null && <> · R {s.riskWeight} × {fmt(s.subscore)}</>}
                  </span>
                </div>
                <span className="w-24 text-right font-mono text-xs">
                  <span className={deltaClass(s.from.knowledge, s.to.knowledge, false)}>{delta(s.from.knowledge, s.to.knowledge)}</span>
                  <span className="text-muted-foreground"> → {fmt(s.to.knowledge)}</span>
                </span>
                <span className="w-24 text-right font-mono text-xs">
                  <span className={deltaClass(s.from.risk, s.to.risk, true)}>{delta(s.from.risk, s.to.risk)}</span>
                  <span className="text-muted-foreground"> → {s.to.risk == null ? '—' : fmt(s.to.risk)}</span>
                </span>
              </div>
            ))}
            {steps.length > 0 && (
              <p className="text-xs text-muted-foreground px-1 pt-1">
                {rich(t('matrix.final.rounded', {
                  k: verdict.knowledge ?? t('score.na'),
                  r: verdict.risk ?? t('score.noData'),
                  responded: verdict.responded,
                  queried: verdict.queried,
                }))}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
