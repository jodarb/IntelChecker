import type { QueryResult } from '@/registry'
import type { EngineAssessment } from '@/verdictEngine'

// Order of the source cards on the results and history detail pages:
//
//   1. Sources with a result (hit, clean or context), highest risk subscore first;
//      clean (0) before context-only (no subscore). Ties: the larger Knowledge
//      contribution (knowledge weight × depth), then the larger weights.
//   2. Sources still loading.
//   3. Sources without a result: no record, then errors, then switched off.
//
// Unconfigured sources (no API key) are not shown at all. Array#sort is stable, so
// full ties keep the registry order.

export type CardState = 'result' | 'loading' | 'empty' | 'error' | 'off'

export interface CardRank {
  state: CardState
  subscore: number | null
  depth: number | null
  riskWeight: number
  knowledgeWeight: number
}

const GROUP: Record<CardState, number> = { result: 0, loading: 1, empty: 2, error: 3, off: 4 }

export function cardState(result: QueryResult | undefined, assessment: EngineAssessment): CardState {
  if (!result || result.loading) return 'loading'
  const { outcome } = assessment
  if (outcome === 'hit' || outcome === 'clean' || outcome === 'context') return 'result'
  if (outcome === 'no_data') return 'empty'
  return 'error'
}

export function compareCards(a: CardRank, b: CardRank): number {
  const g = GROUP[a.state] - GROUP[b.state]
  if (g !== 0) return g
  if (a.state === 'result') {
    const s = (b.subscore ?? -1) - (a.subscore ?? -1)
    if (s !== 0) return s
    const k = b.knowledgeWeight * (b.depth ?? 0) - a.knowledgeWeight * (a.depth ?? 0)
    if (k !== 0) return k
  }
  return b.riskWeight - a.riskWeight || b.knowledgeWeight - a.knowledgeWeight
}
