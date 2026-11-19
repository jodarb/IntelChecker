import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'

// ═════════════════════════════════════════════════════════════════════════════
// Two-score verdict model
//
//  * Knowledge Score (0-10): how much of the available intel coverage has
//    information on the indicator, regardless of whether it's good or bad.
//    Each source adds  knowledgeWeight × depth  (depth ∈ {0, 0.5, 1}) out of the
//    total knowledge weight of every configured, enabled source for that type —
//    so knowledge only ever grows as sources contribute, no single source can max
//    it out, and a source that fails simply contributes nothing.
//  * Risk Score (0-10): weighted average of the maliciousness subscores, using
//    only engines that returned an actual verdict (hit or explicit clean).
//
// "No data" is never treated as "benign": a source that doesn't know the
// indicator adds 0 knowledge and stays out of the risk calculation entirely.
// ═════════════════════════════════════════════════════════════════════════════

export interface EngineWeight {
  risk: number
  knowledge: number
  knowledge_by_type?: Partial<Record<IndicatorType, number>>
}

export interface VerdictThresholds {
  knowledge: number
  risk: number
}

export interface VerdictConfig {
  engines: Record<string, EngineWeight>
  thresholds: VerdictThresholds
}

/**
 * hit      — returned a maliciousness signal (subscore > 0)
 * clean    — explicitly evaluated it as benign (subscore = 0)
 * context  — has a record but no maliciousness verdict (Shodan ports, IPinfo geo…)
 * no_data  — answered, but has no record of the indicator (incl. NotFound)
 * excluded — errored, not configured, unsupported or still loading
 */
export type EngineOutcome = 'hit' | 'clean' | 'context' | 'no_data' | 'excluded'

export interface EngineAssessment {
  outcome: EngineOutcome
  subscore: number | null
  depth: number | null
}

export interface RiskContribution {
  engineId: string
  label: string
  weight: number
  subscore: number
}
/** @deprecated kept for callers that predate the two-score model */
export type VerdictContribution = RiskContribution

export interface KnowledgeContribution {
  engineId: string
  label: string
  weight: number
  depth: number
  outcome: EngineOutcome
}

export type Quadrant =
  | 'confirmed_malicious'
  | 'known_benign'
  | 'known_low_signals'
  | 'known_no_verdict'
  | 'isolated_signal'
  | 'unknown'

export interface VerdictContributions {
  risk: RiskContribution[]
  knowledge: KnowledgeContribution[]
}

export interface VerdictResult {
  risk: number | null
  knowledge: number | null
  quadrant: Quadrant | null
  contributions: VerdictContributions
  /** Engines that answered (not excluded) / engines queried */
  responded: number
  queried: number
}

export const EMPTY_VERDICT: VerdictResult = {
  risk: null, knowledge: null, quadrant: null,
  contributions: { risk: [], knowledge: [] }, responded: 0, queried: 0,
}

export function riskWeightOf(config: VerdictConfig | null, engineId: string): number {
  return config?.engines[engineId]?.risk ?? 0
}

export function knowledgeWeightOf(config: VerdictConfig | null, engineId: string, type: IndicatorType): number {
  const w = config?.engines[engineId]
  if (!w) return 0
  return w.knowledge_by_type?.[type] ?? w.knowledge
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

// For IPs and domains VT keeps a profile for almost anything, and "0 detections"
// on an otherwise empty profile only means nobody has flagged it — absence of data,
// not a benign verdict. Only count it as clean when the community has actually
// weighed in (votes) or VT has classified it (tags). For URLs and files, 0/70
// engines is a genuine scan result and stays a clean 0.
function vtHostSubscore(d: unknown): number | null {
  const score = vtSubscore(d)
  if (score !== 0) return score
  const a = (d as any)?.data?.attributes
  const votes = (a?.total_votes?.harmless ?? 0) + (a?.total_votes?.malicious ?? 0)
  const tags = Array.isArray(a?.tags) ? a.tags.length : 0
  return votes > 0 || tags > 0 ? 0 : null
}

function abuseipdbSubscore(d: unknown): number | null {
  const data = (d as any)?.data
  const score = data?.abuseConfidenceScore
  if (score == null) return null
  // Zero reports means nobody has reported this IP — that's absence of data, not an
  // explicit benign verdict. A whitelisted IP *is* an explicit benign verdict.
  if (score === 0 && !data.totalReports && !data.isWhitelisted) return null
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
  const risk = (d as any)?.risk
  const score = risk?.score
  if (score == null) return null
  // No risk rule triggered means RF simply has nothing on it yet — not that it
  // assessed the indicator as benign. Same principle as VirusTotal's empty profiles.
  const evidence = Array.isArray(risk.evidenceDetails) ? risk.evidenceDetails.length : 0
  if (evidence === 0 && score === 0) return null
  // Recorded Future's score is already 0-99, pre-normalized by their own rules engine.
  return Math.min(10, score / 9.9)
}

function torExitListSubscore(d: unknown): number | null {
  const isExit = (d as any)?.is_tor_exit
  // Not being on the exit list says nothing about the IP being benign — only a match
  // is a signal. Being an active exit node isn't malicious per se, just elevated risk.
  if (!isExit) return null
  return 7
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

// TweetFeed: community IOC reports from X/Twitter — unvetted, so capped at 7.
// Not reported ≠ clean: never returns 0.
const TWEETFEED_GENERIC_TAGS = new Set(['#phishing', '#malware', '#scam', '#spam', '#opendir', '#ioc', '#iocs', '#threatintel'])

function tweetFeedSignals(d: unknown) {
  const p = d as any
  const records: any[] = p?.found && Array.isArray(p?.records) ? p.records : []
  const users = new Set(records.flatMap(r => (Array.isArray(r?.users) ? r.users : [])))
  const tweets = new Set(records.flatMap(r => (Array.isArray(r?.tweets) ? r.tweets : [])))
  const tags: string[] = records.flatMap(r => (Array.isArray(r?.tags) ? r.tags : []))
  const inCampaign = Array.isArray(p?.campaigns) && p.campaigns.length > 0
  const hasFamily = inCampaign || !!p?.ai?.family
    || tags.some(t => !TWEETFEED_GENERIC_TAGS.has(String(t).toLowerCase()))
  return { found: records.length > 0, users: users.size, tweets: tweets.size, inCampaign, hasFamily }
}

function tweetFeedSubscore(d: unknown): number | null {
  const s = tweetFeedSignals(d)
  if (!s.found) return null
  if (s.users >= 3 || s.hasFamily) return 7
  if (s.users === 2) return 6
  return 5
}

function mispSubscore(d: unknown): number | null {
  const attrs = (d as any)?.Attribute
  if (!Array.isArray(attrs)) return null
  // No matching attribute in this instance ≠ confirmed clean, just not (yet) shared.
  if (attrs.length === 0) return null
  // Only attributes flagged for detection (to_ids) are actionable IOCs — a match
  // with to_ids off is context (e.g. a resolver or benign infra referenced in an
  // event), so it feeds Knowledge but issues no risk verdict, and never a clean one.
  const idsHit = attrs.some((a: any) => a?.to_ids === true || a?.to_ids === 1 || a?.to_ids === '1')
  return idsHit ? 9 : null
}

// Registry: engineId → indicatorType → normalizer.
// Purely contextual engines (Shodan, IPinfo, RIPEstat, MITRE ATT&CK) have no
// maliciousness signal in their API response, so they're absent here — they
// only feed the Knowledge Score.
const VERDICT_NORMALIZERS: Record<string, Partial<Record<IndicatorType, (data: unknown) => number | null>>> = {
  virustotal: { ip: vtHostSubscore, domain: vtHostSubscore, url: vtSubscore, hash: vtSubscore },
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
  tweetfeed: { ip: tweetFeedSubscore, domain: tweetFeedSubscore, url: tweetFeedSubscore, hash: tweetFeedSubscore },
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

// ── Per-engine depth: raw API response → 0 / 0.5 / 1 ─────────────────────────
// 0 = no record, 0.5 = basic/generic record, 1 = rich record. Independent of the
// risk subscore: Safe Browsing "not listed" is a clean verdict with depth 0.

// Raw third-party payloads are untyped by nature; each fn guards every access.
/* eslint-disable @typescript-eslint/no-explicit-any */

type Depth = 0 | 0.5 | 1

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : [])
const byCount = (n: number, basicMax: number): Depth => (n <= 0 ? 0 : n <= basicMax ? 0.5 : 1)

function vtDepth(d: any): Depth {
  const a = d?.data?.attributes
  if (!a) return 0
  const s = a.last_analysis_stats ?? {}
  const detections = (s.malicious ?? 0) + (s.suspicious ?? 0)
  const votes = (a.total_votes?.harmless ?? 0) + (a.total_votes?.malicious ?? 0)
  if (detections > 0 || votes > 0 || arr(a.tags).length > 0) return 1
  return 0.5
}

function alienvaultDepth(d: any): Depth {
  // Indicator lookup → pulse_info.count; threat-actor pulse search → count/results.
  const count = d?.pulse_info?.count ?? d?.count ?? arr(d?.results).length
  return byCount(count ?? 0, 2)
}

function recordedFutureDepth(d: any): Depth {
  if (!d?.risk && !d?.entity) return 0
  return arr(d?.risk?.evidenceDetails).length > 0 ? 1 : 0.5
}

function mispDepth(d: any): Depth {
  const attrs = arr(d?.Attribute)
  if (attrs.length === 0) return 0
  const events = new Set(attrs.map(a => a?.event_id ?? a?.Event?.id).filter(Boolean))
  return attrs.length >= 3 || events.size >= 2 ? 1 : 0.5
}

function mitreDepth(d: any): Depth {
  if (!d?.name) return 0
  return arr(d.techniques).length > 0 || arr(d.software).length > 0 ? 1 : 0.5
}

function abuseipdbDepth(d: any): Depth {
  const data = d?.data
  if (!data) return 0
  if (data.isWhitelisted) return 1
  return byCount(data.totalReports ?? 0, 9)
}

function listHitDepth(d: any): Depth {
  // ThreatFox / MalwareBazaar: any match is already a specific, rich record.
  return arr(d?.data).length > 0 ? 1 : 0
}

function urlhausDepth(d: any): Depth {
  if (d?.query_status === 'no_results') return 0
  if (typeof d?.url_status === 'string') return arr(d.payloads).length > 0 ? 1 : 0.5
  return byCount(arr(d?.urls).length, 1)
}

function anyrunDepth(d: any): Depth {
  const level = d?.summary?.threatLevel
  if (level == null) return 0
  return level >= 1 ? 1 : 0.5
}

function shodanDepth(d: any): Depth {
  if (d?.ip_str) {
    if (arr(d.ports).length >= 3 || arr(d.vulns).length > 0 || arr(d.tags).length > 0) return 1
    return 0.5
  }
  if (typeof d?.total === 'number') return d.total > 0 ? 1 : 0
  return 0
}

function hybridAnalysisDepth(d: any): Depth {
  const results = arr(d?.result)
  if (results.length === 0) return 0
  const hasVerdict = results.some(r => {
    const v = String(r?.verdict ?? '').toLowerCase()
    return v !== '' && v !== 'no verdict'
  })
  return hasVerdict ? 1 : 0.5
}

function urlscanDepth(d: any): Depth {
  return byCount(d?.total ?? 0, 2)
}

function greynoiseDepth(d: any): Depth {
  if (!d?.noise && !d?.riot) return 0
  if (d.riot || d.classification === 'malicious' || d.classification === 'benign') return 1
  return 0.5
}

function phishtankDepth(d: any): Depth {
  if (!d?.in_database) return 0
  return d.verified ? 1 : 0.5
}

function safeBrowsingDepth(d: any): Depth {
  return arr(d?.matches).length > 0 ? 1 : 0
}

function torDepth(d: any): Depth {
  return d?.is_tor_exit ? 1 : 0
}

function ipinfoDepth(d: any): Depth {
  if (!d || d.bogon) return 0
  return 0.5
}

function ripestatDepth(d: any): Depth {
  if (d?.as_overview) return d.as_overview.holder ? 1 : 0
  return arr(d?.network_info?.asns).length > 0 ? 0.5 : 0
}

function tweetFeedDepth(d: any): Depth {
  const s = tweetFeedSignals(d)
  if (!s.found) return 0
  return s.users >= 2 || s.tweets >= 2 || s.inCampaign ? 1 : 0.5
}

const DEPTH_FNS: Record<string, (data: any) => Depth> = {
  tweetfeed: tweetFeedDepth,
  virustotal: vtDepth,
  alienvault: alienvaultDepth,
  recordedfuture: recordedFutureDepth,
  mitreattack: mitreDepth,
  abuseipdb: abuseipdbDepth,
  abusech: listHitDepth,
  malwarebazaar: listHitDepth,
  urlhaus: urlhausDepth,
  anyrun: anyrunDepth,
  shodan: shodanDepth,
  hybridanalysis: hybridAnalysisDepth,
  urlscan: urlscanDepth,
  greynoise: greynoiseDepth,
  phishtank: phishtankDepth,
  safebrowsing: safeBrowsingDepth,
  torexitlist: torDepth,
  ipinfo: ipinfoDepth,
  ripestat: ripestatDepth,
}

/* eslint-enable @typescript-eslint/no-explicit-any */

// ── Assessment & aggregation ─────────────────────────────────────────────────

// "Not found" is the source telling us it has no record — an answer, not a failure.
const NO_DATA_ERROR_CODES = new Set(['NotFound'])

export function getEngineAssessment(engineId: string, type: IndicatorType, result: QueryResult | undefined): EngineAssessment {
  const excluded: EngineAssessment = { outcome: 'excluded', subscore: null, depth: null }
  if (!result || result.loading || result.error || !result.data) return excluded

  const errorCode = (result.data as { error?: { code?: string } })?.error?.code
  if (errorCode) {
    return NO_DATA_ERROR_CODES.has(errorCode)
      ? { outcome: 'no_data', subscore: null, depth: 0 }
      : excluded
  }

  const subscore = getEngineSubscore(engineId, type, result.data)
  const depthFn = engineId.startsWith('misp_') ? mispDepth : DEPTH_FNS[engineId]
  const depth: number = depthFn ? depthFn(result.data) : 0

  let outcome: EngineOutcome
  if (subscore != null) outcome = subscore > 0 ? 'hit' : 'clean'
  else outcome = depth > 0 ? 'context' : 'no_data'
  return { outcome, subscore, depth }
}

function classify(
  knowledge: number, risk: number | null, riskRows: RiskContribution[], t: VerdictThresholds,
): Quadrant {
  const knownWell = knowledge >= t.knowledge
  if (risk != null && risk >= t.risk) return knownWell ? 'confirmed_malicious' : 'isolated_signal'
  if (!knownWell) return 'unknown'
  if (risk == null) return 'known_no_verdict'
  // A low average alone doesn't make an indicator benign: that claim needs at least
  // one source that explicitly evaluated it as clean, and no source raising a
  // signal that would on its own reach the risk threshold.
  const anyClean = riskRows.some(c => c.subscore === 0)
  const anyRelevantHit = riskRows.some(c => c.subscore >= t.risk)
  return anyClean && !anyRelevantHit ? 'known_benign' : 'known_low_signals'
}

export function computeVerdict(
  config: VerdictConfig,
  engines: EngineConfig[],
  results: Record<string, QueryResult>,
  type: IndicatorType,
): VerdictResult {
  const risk: RiskContribution[] = []
  const knowledge: KnowledgeContribution[] = []
  let responded = 0
  let knowledgeDenominator = 0
  let knowledgeNumerator = 0

  let queried = 0
  for (const engine of engines) {
    // Sources without credentials aren't really part of this deployment.
    if ((results[engine.id]?.data as { error?: { code?: string } })?.error?.code === 'MissingApiKey') continue
    queried++
    const a = getEngineAssessment(engine.id, type, results[engine.id])

    // Knowledge: every configured & enabled source counts in the denominator, even
    // if it errored or is still loading — it just contributes 0 until it answers.
    const kw = knowledgeWeightOf(config, engine.id, type)
    if (kw > 0) {
      const depth = a.outcome === 'excluded' ? 0 : (a.depth ?? 0)
      knowledge.push({ engineId: engine.id, label: engine.label, weight: kw, depth, outcome: a.outcome })
      knowledgeDenominator += kw
      knowledgeNumerator += kw * depth
    }

    if (a.outcome === 'excluded') continue
    responded++

    const rw = riskWeightOf(config, engine.id)
    if (rw > 0 && a.subscore != null) {
      risk.push({ engineId: engine.id, label: engine.label, weight: rw, subscore: a.subscore })
    }
  }

  // Until at least one source answers (e.g. everything still loading) there is no
  // knowledge reading yet — not a knowledge of 0.
  const knowledgeScore = knowledgeDenominator > 0 && responded > 0
    ? Math.round((10 * knowledgeNumerator) / knowledgeDenominator)
    : null

  // Nothing known at all → no risk verdict either ("No data", never a clean 0).
  let riskScore: number | null = null
  if (risk.length > 0 && knowledgeNumerator > 0) {
    const tw = risk.reduce((s, c) => s + c.weight, 0)
    const ws = risk.reduce((s, c) => s + c.weight * c.subscore, 0)
    riskScore = Math.max(0, Math.min(10, Math.round(ws / tw)))
  }

  const quadrant = knowledgeScore == null ? null : classify(knowledgeScore, riskScore, risk, config.thresholds)

  return {
    risk: riskScore,
    knowledge: knowledgeScore,
    quadrant,
    contributions: { risk, knowledge },
    responded,
    queried,
  }
}
