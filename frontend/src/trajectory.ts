import type { EngineOutcome, VerdictContributions } from '@/verdictEngine'

export interface TrajectoryStep {
  engineId: string
  label: string
  outcome: EngineOutcome
  knowledgeWeight: number
  riskWeight: number
  depth: number | null
  subscore: number | null
  /** Unrounded cumulative scores before / after adding this engine. Risk is null while no verdict exists. */
  from: { knowledge: number; risk: number | null }
  to: { knowledge: number; risk: number | null }
}

/**
 * Replays the verdict one engine at a time, starting from (0, 0). Knowledge is
 * cumulative over a fixed denominator (the total knowledge weight of every source
 * in the verdict), so it only ever grows; risk is the weighted average of the
 * verdicts added so far, so it can go up or down. Same formulas as computeVerdict
 * (unrounded). Built only from the verdict's
 * contributions, so it works the same for live results and archived history.
 *
 * Engines are added in the same order as the result cards: risk weight first,
 * then knowledge weight (stable for ties).
 */
export function computeTrajectory(contributions: VerdictContributions): TrajectoryStep[] {
  const byId = new Map<string, {
    label: string; outcome: EngineOutcome; kw: number; depth: number | null; rw: number; subscore: number | null; order: number
  }>()
  let order = 0
  for (const k of contributions.knowledge) {
    byId.set(k.engineId, { label: k.label, outcome: k.outcome, kw: k.weight, depth: k.depth, rw: 0, subscore: null, order: order++ })
  }
  for (const r of contributions.risk) {
    const existing = byId.get(r.engineId)
    if (existing) {
      existing.rw = r.weight
      existing.subscore = r.subscore
    } else {
      byId.set(r.engineId, {
        label: r.label, outcome: r.subscore > 0 ? 'hit' : 'clean', kw: 0, depth: null,
        rw: r.weight, subscore: r.subscore, order: order++,
      })
    }
  }

  const ordered = [...byId.entries()].sort(([, a], [, b]) => (b.rw - a.rw) || (b.kw - a.kw) || (a.order - b.order))

  const kTotal = contributions.knowledge.reduce((sum, k) => sum + k.weight, 0)
  let kNum = 0, rNum = 0, rDen = 0
  const current = () => {
    const knowledge = kTotal > 0 ? (10 * kNum) / kTotal : 0
    // Same rule as computeVerdict: no risk verdict while nothing is known at all.
    const risk = rDen > 0 && kNum > 0 ? Math.max(0, Math.min(10, rNum / rDen)) : null
    return { knowledge, risk }
  }

  const steps: TrajectoryStep[] = []
  for (const [engineId, e] of ordered) {
    const from = current()
    if (e.kw > 0) kNum += e.kw * (e.depth ?? 0)
    if (e.rw > 0 && e.subscore != null) { rDen += e.rw; rNum += e.rw * e.subscore }
    steps.push({
      engineId, label: e.label, outcome: e.outcome,
      knowledgeWeight: e.kw, riskWeight: e.rw, depth: e.depth, subscore: e.subscore,
      from, to: current(),
    })
  }
  return steps
}
