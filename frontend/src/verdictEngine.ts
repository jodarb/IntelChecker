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
  // Zero pulses means no researcher has flagged this indicator, not that OTX
  // actively verified it's safe — treat as "no signal", not a clean verdict.
  if (count === 0) return null
  if (count <= 2) return 4
  if (count <= 5) return 7
  return 10
}

function abusechSubscore(d: unknown): number | null {
  const iocs = (d as any)?.data
  if (!Array.isArray(iocs)) return null
  // No match in ThreatFox's feed ≠ confirmed clean, just not (yet) reported.
  if (iocs.length === 0) return null
  const topConfidence = Math.max(...iocs.map((i: any) => i.confidence_level ?? 0))
  return Math.min(10, 7 + (topConfidence / 100) * 3)
}

function recordedFutureSubscore(d: unknown): number | null {
  const score = (d as any)?.risk?.score
  if (score == null) return null
  // Recorded Future's score is already 0-99, pre-normalized by their own rules engine.
  return Math.min(10, score / 9.9)
}

function torExitListSubscore(d: unknown): number | null {
  const isExit = (d as any)?.is_tor_exit
  if (isExit == null) return null
  // Being an active exit node isn't malicious per se, just a noteworthy elevated-risk signal.
  return isExit ? 7 : 0
}

function urlhausSubscore(d: unknown): number | null {
  const payload = d as any
  // Not in URLhaus's malware/phishing URL feed ≠ confirmed clean, just not (yet) reported.
  if (payload?.query_status === 'no_results') return null
  // Single indicator (/url/) lookup shape.
  if (typeof payload?.url_status === 'string') {
    return payload.url_status === 'online' ? 9 : 6
  }
  // Host/hash lookup shape: a list of URLs associated with the indicator.
  if (Array.isArray(payload?.urls)) {
    if (payload.urls.length === 0) return null
    const anyOnline = payload.urls.some((u: any) => u.url_status === 'online')
    return anyOnline ? 9 : 6
  }
  return null
}

function urlscanSubscore(d: unknown): number | null {
  const total = (d as any)?.total
  if (total == null) return null
  // No prior scans on record ≠ verified clean, just never submitted — no signal either way.
  if (total === 0) return null
  if (total <= 2) return 3
  if (total <= 5) return 5
  return 6
}

function malwareBazaarSubscore(d: unknown): number | null {
  const payload = d as any
  // Hash not on file ≠ confirmed benign, just not a known sample in this specific DB.
  if (payload?.query_status === 'no_results') return null
  if (Array.isArray(payload?.data)) {
    if (payload.data.length === 0) return null
    // The indicator is the hash of a sample MalwareBazaar has on file — high-confidence match.
    return 10
  }
  return null
}

function phishtankSubscore(d: unknown): number | null {
  const payload = d as any
  if (payload?.in_database == null) return null
  // Not submitted to PhishTank's crowdsourced DB ≠ verified legitimate — no signal either way.
  if (!payload.in_database) return null
  if (payload.valid === false) return 0
  if (payload.verified === false) return 5
  return 10
}

function anyrunSubscore(d: unknown): number | null {
  const threatLevel = (d as any)?.summary?.threatLevel
  // null means no sandbox intelligence record at all — not the same as "checked,
  // found clean" (threatLevel 0, ANY.RUN's own "No info" verdict).
  if (threatLevel == null) return null
  if (threatLevel === 0) return 0
  if (threatLevel === 1) return 5
  return 9
}

function greynoiseSubscore(d: unknown): number | null {
  const payload = d as any
  // Neither an internet-scanner hit nor a known-good RIOT match means GreyNoise
  // has no observation for this IP at all — not a "clean" verdict, just no data.
  if (!payload?.noise && !payload?.riot) return null
  if (payload.classification === 'malicious') return 9
  // RIOT = a verified known-good business service (search engine, CDN...); an
  // explicit "benign" classification is the same kind of confident clean result.
  if (payload.riot || payload.classification === 'benign') return 0
  // Seen actively scanning the internet but not yet classified — a real, if
  // mild, elevated-risk signal (comparable to being a Tor exit node).
  return 4
}

function hybridAnalysisSubscore(d: unknown): number | null {
  const results = (d as any)?.result
  if (!Array.isArray(results) || results.length === 0) return null
  const verdicts = results.map((r: any) => String(r?.verdict ?? '').toLowerCase())
  if (verdicts.includes('malicious')) return 9
  if (verdicts.includes('suspicious')) return 5
  if (verdicts.some((v: string) => v === 'whitelisted' || v === 'no specific threat')) return 0
  // Only "no verdict" entries — sandboxed but never classified, no usable signal.
  return null
}

function safeBrowsingSubscore(d: unknown): number | null {
  // Safe Browsing is a real-time authoritative check, not a community feed — an
  // empty match list is a genuine "checked, not on any threat list" clean result,
  // not an absence of data. So unlike most normalizers here, this never returns
  // null once we have a response at all.
  const matches = (d as any)?.matches
  return Array.isArray(matches) && matches.length > 0 ? 9 : 0
}

function mispSubscore(d: unknown): number | null {
  const attrs = (d as any)?.Attribute
  if (!Array.isArray(attrs)) return null
  // No matching attribute in this instance ≠ confirmed clean, just not (yet) shared.
  if (attrs.length === 0) return null
  // Any match is a real analyst-curated IOC hit — treat as high-confidence.
  return 9
}

// Registry: engineId → indicatorType → normalizer.
// Purely contextual engines (Shodan, IPinfo, RIPEstat, MITRE ATT&CK) have no
// maliciousness signal in their API response, so they're absent here — their
// weight in weights.json is kept at 0 and has no effect even if raised.
const VERDICT_NORMALIZERS: Record<string, Partial<Record<IndicatorType, (data: unknown) => number | null>>> = {
  virustotal: { ip: vtSubscore, domain: vtSubscore, url: vtSubscore, hash: vtSubscore },
  abuseipdb: { ip: abuseipdbSubscore },
  alienvault: { ip: alienvaultSubscore, domain: alienvaultSubscore, url: alienvaultSubscore, hash: alienvaultSubscore },
  abusech: { ip: abusechSubscore, hash: abusechSubscore },
  recordedfuture: { ip: recordedFutureSubscore, domain: recordedFutureSubscore, url: recordedFutureSubscore, hash: recordedFutureSubscore },
  torexitlist: { ip: torExitListSubscore },
  urlhaus: { ip: urlhausSubscore, domain: urlhausSubscore, url: urlhausSubscore, hash: urlhausSubscore },
  urlscan: { url: urlscanSubscore, domain: urlscanSubscore },
  malwarebazaar: { hash: malwareBazaarSubscore },
  phishtank: { url: phishtankSubscore },
  anyrun: { ip: anyrunSubscore, domain: anyrunSubscore, url: anyrunSubscore, hash: anyrunSubscore },
  greynoise: { ip: greynoiseSubscore },
  hybridanalysis: { ip: hybridAnalysisSubscore, domain: hybridAnalysisSubscore, url: hybridAnalysisSubscore, hash: hybridAnalysisSubscore },
  safebrowsing: { url: safeBrowsingSubscore },
}

// Per-engine 0-10 score for a single result, independent of weight — this is what
// each result card displays. Returns null when there's no signal to score: the
// engine errored, is still loading, or its response carries no maliciousness data
// (distinct from an explicit 0, which means "checked and found clean").
export function getEngineSubscore(engineId: string, type: IndicatorType, data: unknown): number | null {
  if (!data || (data as any)?.error) return null
  // MISP instance ids (misp_1, misp_2...) are only known at deploy time, so they
  // can't be pre-registered in VERDICT_NORMALIZERS like the static engines above.
  if (engineId.startsWith('misp_')) return mispSubscore(data)
  const normalizer = VERDICT_NORMALIZERS[engineId]?.[type]
  if (!normalizer) return null
  return normalizer(data)
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

    const result = results[engine.id]
    if (!result || result.loading || !result.data) continue

    const subscore = getEngineSubscore(engine.id, type, result.data)
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
