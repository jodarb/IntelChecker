import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'

export interface VerdictWeights {
  [engineId: string]: number
}

export interface VerdictContribution {
  engineId: string
  label: string
  weight: number
  subscore: number
}

export interface VerdictResult {
  score: number | null
  contributions: VerdictContribution[]
}

// ── Per-engine normalizers: raw API response → 0-10 subscore, or null if no signal ──
// Stepped thresholds (not raw ratios) so a handful of independent hits isn't
// diluted by a large denominator (e.g. 5/70 VT engines reading as ~0.7).

function vtSubscore(d: unknown): number | null {
  const stats = (d as any)?.data?.attributes?.last_analysis_stats
  if (!stats) return null
  const flagged = (stats.malicious ?? 0) + (stats.suspicious ?? 0)
  if (flagged === 0) return 0
  if (flagged <= 2) return 3
  if (flagged <= 5) return 6
  return 10
}

function abuseipdbSubscore(d: unknown): number | null {
  const score = (d as any)?.data?.abuseConfidenceScore
  if (score == null) return null
  return Math.min(10, score / 10)
}

function alienvaultSubscore(d: unknown): number | null {
  const count = (d as any)?.pulse_info?.count
  if (count == null) return null
  if (count === 0) return 0
  if (count <= 2) return 4
  if (count <= 5) return 7
  return 10
}

function abusechSubscore(d: unknown): number | null {
  const iocs = (d as any)?.data
  if (!Array.isArray(iocs)) return null
  if (iocs.length === 0) return 0
  const topConfidence = Math.max(...iocs.map((i: any) => i.confidence_level ?? 0))
  return Math.min(10, 7 + (topConfidence / 100) * 3)
}

// Registry: engineId → indicatorType → normalizer.
// Engines absent here (Shodan, IPinfo) are not maliciousness signals and never
// participate in the threat score, regardless of configured weight.
const VERDICT_NORMALIZERS: Record<string, Partial<Record<IndicatorType, (data: unknown) => number | null>>> = {
  virustotal: { ip: vtSubscore, domain: vtSubscore, url: vtSubscore, hash: vtSubscore },
  abuseipdb: { ip: abuseipdbSubscore },
  alienvault: { ip: alienvaultSubscore, domain: alienvaultSubscore, url: alienvaultSubscore, hash: alienvaultSubscore },
  abusech: { ip: abusechSubscore, hash: abusechSubscore },
}

export function computeVerdict(
  weights: VerdictWeights,
  engines: EngineConfig[],
  results: Record<string, QueryResult>,
  type: IndicatorType,
): VerdictResult {
  const contributions: VerdictContribution[] = []

  for (const engine of engines) {
    const weight = weights[engine.id]
    if (!weight || weight <= 0) continue

    const normalizer = VERDICT_NORMALIZERS[engine.id]?.[type]
    if (!normalizer) continue

    const result = results[engine.id]
    if (!result || result.loading || !result.data) continue
    if ((result.data as any)?.error) continue

    const subscore = normalizer(result.data)
    if (subscore == null) continue

    contributions.push({ engineId: engine.id, label: engine.label, weight, subscore })
  }

  if (contributions.length === 0) {
    return { score: null, contributions }
  }

  const totalWeight = contributions.reduce((sum, c) => sum + c.weight, 0)
  const weightedSum = contributions.reduce((sum, c) => sum + c.weight * c.subscore, 0)
  const score = Math.max(0, Math.min(10, Math.round(weightedSum / totalWeight)))

  return { score, contributions }
}
