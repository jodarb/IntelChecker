import type { EngineOutcome, Quadrant } from '@/verdictEngine'

export const QUADRANT_META: Record<Quadrant, { label: string; hint: string; className: string }> = {
  confirmed_malicious: {
    label: 'Malicious · Confirmed',
    hint: 'Well-known indicator with a high risk verdict across sources.',
    className: 'text-red-400 bg-red-500/10 border-red-500/40',
  },
  isolated_signal: {
    label: 'Isolated signal · Verify',
    hint: 'High risk, but few sources know this indicator — corroborate before acting.',
    className: 'text-orange-400 bg-orange-500/10 border-orange-500/40',
  },
  known_benign: {
    label: 'Known · Benign',
    hint: 'Well-known indicator: at least one source explicitly evaluated it as clean and none raised a strong signal.',
    className: 'text-green-400 bg-green-500/10 border-green-500/40',
  },
  known_low_signals: {
    label: 'Known · Low-level signals',
    hint: 'Well-known indicator with risk signals that are too weak on average to reach high risk. This is not a benign confirmation.',
    className: 'text-amber-400 bg-amber-500/10 border-amber-500/40',
  },
  known_no_verdict: {
    label: 'Known · No risk verdict',
    hint: 'Sources have context on this indicator, but none issued a risk verdict. This is not a benign confirmation.',
    className: 'text-sky-400 bg-sky-500/10 border-sky-500/40',
  },
  unknown: {
    label: 'Unknown',
    hint: 'Little or no information about this indicator. Absence of data is not evidence of safety.',
    className: 'text-muted-foreground bg-muted/30 border-border',
  },
}

export const OUTCOME_META: Record<EngineOutcome, { label: string; className: string }> = {
  hit: { label: 'Risk signal', className: 'text-red-400' },
  clean: { label: 'Evaluated clean', className: 'text-green-400' },
  context: { label: 'Context only', className: 'text-sky-400' },
  no_data: { label: 'No record', className: 'text-muted-foreground' },
  excluded: { label: 'No answer (error)', className: 'text-red-400/80' },
}

export function depthLabel(depth: number | null | undefined): string {
  if (depth == null) return '—'
  if (depth >= 1) return 'Rich'
  if (depth > 0) return 'Basic'
  return 'None'
}
