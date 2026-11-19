import type { EngineOutcome, Quadrant } from '@/verdictEngine'
import type { TFunction } from '@/i18n/types'

// Labels and hints live in the i18n dictionaries (messages/verdict.ts):
// `quadrant.<id>.label`, `quadrant.<id>.hint`, `outcome.<id>`, `depth.*`.
export const QUADRANT_META: Record<Quadrant, { className: string }> = {
  confirmed_malicious: { className: 'text-red-400 bg-red-500/10 border-red-500/40' },
  isolated_signal: { className: 'text-orange-400 bg-orange-500/10 border-orange-500/40' },
  known_benign: { className: 'text-green-400 bg-green-500/10 border-green-500/40' },
  known_low_signals: { className: 'text-amber-400 bg-amber-500/10 border-amber-500/40' },
  known_no_verdict: { className: 'text-sky-400 bg-sky-500/10 border-sky-500/40' },
  unknown: { className: 'text-muted-foreground bg-muted/30 border-border' },
}

export const OUTCOME_META: Record<EngineOutcome, { className: string }> = {
  hit: { className: 'text-red-400' },
  clean: { className: 'text-green-400' },
  context: { className: 'text-sky-400' },
  no_data: { className: 'text-muted-foreground' },
  excluded: { className: 'text-red-400/80' },
}

export const quadrantLabel = (q: Quadrant, t: TFunction) => t(`quadrant.${q}.label`)
export const quadrantHint = (q: Quadrant, t: TFunction) => t(`quadrant.${q}.hint`)
export const outcomeLabel = (o: EngineOutcome, t: TFunction) => t(`outcome.${o}`)

export function depthLabel(depth: number | null | undefined, t: TFunction): string {
  if (depth == null) return '—'
  if (depth >= 1) return t('depth.rich')
  if (depth > 0) return t('depth.basic')
  return t('depth.none')
}
