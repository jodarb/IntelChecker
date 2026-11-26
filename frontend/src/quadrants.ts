import type { EngineOutcome, Quadrant } from '@/verdictEngine'
import type { TFunction } from '@/i18n/types'
import type { IndicatorType } from '@/registry'

// Labels and hints live in the i18n dictionaries (messages/verdict.ts):
// `quadrant.<id>.label`, `quadrant.<id>.hint`, `outcome.<id>`, `depth.*`.
// className: the badge; panel: border + soft glow of the Summary score panel.
export const QUADRANT_META: Record<Quadrant, { className: string; panel: string }> = {
  confirmed_malicious: {
    className: 'text-red-400 bg-red-500/10 border-red-500/40',
    panel: 'border-red-500/40 shadow-[0_0_48px_-16px] shadow-red-500/50',
  },
  isolated_signal: {
    className: 'text-orange-400 bg-orange-500/10 border-orange-500/40',
    panel: 'border-orange-500/40 shadow-[0_0_48px_-16px] shadow-orange-500/50',
  },
  known_benign: {
    className: 'text-green-400 bg-green-500/10 border-green-500/40',
    panel: 'border-green-500/40 shadow-[0_0_48px_-16px] shadow-green-500/40',
  },
  known_low_signals: {
    className: 'text-amber-400 bg-amber-500/10 border-amber-500/40',
    panel: 'border-amber-500/40 shadow-[0_0_48px_-16px] shadow-amber-500/40',
  },
  known_no_verdict: {
    className: 'text-sky-400 bg-sky-500/10 border-sky-500/40',
    panel: 'border-sky-500/40 shadow-[0_0_48px_-16px] shadow-sky-500/40',
  },
  unknown: { className: 'text-muted-foreground bg-muted/30 border-border', panel: 'border-border' },
}

export const OUTCOME_META: Record<EngineOutcome, { className: string }> = {
  hit: { className: 'text-red-400' },
  clean: { className: 'text-green-400' },
  context: { className: 'text-sky-400' },
  no_data: { className: 'text-muted-foreground' },
  excluded: { className: 'text-red-400/80' },
}

// Vulnerabilities (CVE) reuse the same quadrants, but "risk" there is exploitation
// risk, not maliciousness: they get their own wording (`quadrant.cve.<id>.*`).
export const quadrantLabel = (q: Quadrant, t: TFunction, type?: IndicatorType) =>
  t(type === 'cve' ? `quadrant.cve.${q}.label` : `quadrant.${q}.label`)
export const quadrantHint = (q: Quadrant, t: TFunction, type?: IndicatorType) =>
  t(type === 'cve' ? `quadrant.cve.${q}.hint` : `quadrant.${q}.hint`)
export const outcomeLabel = (o: EngineOutcome, t: TFunction) => t(`outcome.${o}`)

export function depthLabel(depth: number | null | undefined, t: TFunction): string {
  if (depth == null) return '—'
  if (depth >= 1) return t('depth.rich')
  if (depth > 0) return t('depth.basic')
  return t('depth.none')
}
