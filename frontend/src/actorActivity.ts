import type { EngineConfig, QueryResult } from '@/registry'
import { relevantPulses } from '@/actorProfile'

// Threat actor activity: how recently the actor has been seen operating or reported
// on, from the dated evidence the sources already return. It replaces the Risk score
// for actors (no source issues a risk verdict on an actor) and is not part of the
// verdict: Knowledge is still computed as usual, this is shown next to it.
//
//   operation — the actor acting: a victim claimed on its leak site (ransomware.live),
//               OpenCTI's last_seen for the intrusion set / threat actor.
//   report    — intelligence published about it: OTX pulses, OpenCTI reports,
//               Recorded Future Threat Map changes (intent / opportunity).
//
// Profile edits (MITRE ATT&CK, Malpedia) are not activity and are ignored.

/* eslint-disable @typescript-eslint/no-explicit-any */
export type ActivityKind = 'operation' | 'report'
export type ActivityLevel = 'active' | 'recent' | 'dormant' | 'unknown'

export interface ActivitySignal {
  engineId: string
  source: string
  kind: ActivityKind
  /** ISO date (day precision is enough) */
  date: string
  /** What happened: victim name, report title… */
  detail?: string
}

export interface ActivityCount {
  engineId: string
  source: string
  kind: ActivityKind
  count: number
}

export interface ActorActivity {
  level: ActivityLevel
  /** Days from the most recent signal to `asOf` */
  daysSince: number | null
  lastOperation: ActivitySignal | null
  lastReport: ActivitySignal | null
  /** Signals in the last 90 days, per source */
  recent: ActivityCount[]
  /** Sources that answered with dated evidence */
  sources: number
}

export const ACTIVE_DAYS = 90
export const RECENT_DAYS = 365
const DAY = 86_400_000

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : [])
const time = (v: unknown): number | null => {
  if (typeof v !== 'string' || !v) return null
  const t = Date.parse(v)
  return Number.isNaN(t) ? null : t
}

type Extracted = { signals: ActivitySignal[]; /** pre-counted (sources that summarise) */ counts?: ActivityCount[] }

function extract(engineId: string, source: string, d: any, names: string[]): Extracted {
  const sig = (kind: ActivityKind, date: unknown, detail?: unknown): ActivitySignal[] =>
    typeof date === 'string' && time(date) != null
      ? [{ engineId, source, kind, date, detail: typeof detail === 'string' ? detail : undefined }]
      : []
  if (engineId === 'ransomwarelive') {
    if (d?.kind !== 'group' || d?.found !== true) return { signals: [] }
    const recent = arr(d?.recent)
    return {
      signals: [
        ...sig('operation', d?.last_claim, recent[0]?.victim),
        ...recent.flatMap(v => sig('operation', v?.discovered ?? v?.attack_date, v?.victim)),
      ],
      // The dump has every victim: its 90-day count is exact, the `recent` list is not.
      counts: typeof d?.claims_90d === 'number'
        ? [{ engineId, source, kind: 'operation', count: d.claims_90d }] : undefined,
    }
  }
  if (engineId.startsWith('opencti_')) {
    if (d?.kind !== 'actor' || d?.found !== true) return { signals: [] }
    return {
      signals: [
        ...sig('operation', d?.actor?.last_seen),
        ...arr(d?.reports).flatMap(r => sig('report', r?.published, r?.name)),
      ],
    }
  }
  if (engineId === 'alienvault') {
    // Only pulses that name the actor (OTX search is full text: see relevantPulses).
    return { signals: relevantPulses(d?.results, names).flatMap(p => sig('report', p?.created, p?.name)) }
  }
  if (engineId === 'recordedfuture') {
    if (d?.kind !== 'actor' || d?.found !== true) return { signals: [] }
    return { signals: arr(d?.threat_map?.log).flatMap(e => sig('report', e?.date, e?.axis ? `Threat Map · ${e.axis}` : 'Threat Map')) }
  }
  return { signals: [] }
}

const latest = (xs: ActivitySignal[]): ActivitySignal | null =>
  xs.reduce<ActivitySignal | null>((best, s) => (best && time(best.date)! >= time(s.date)! ? best : s), null)

export function computeActorActivity(
  engines: EngineConfig[], results: Record<string, QueryResult | undefined>, asOf: Date = new Date(),
  /** The actor's name and aliases (from the profile), to filter OTX pulses */
  names: string[] = [],
): ActorActivity {
  const now = asOf.getTime()
  const all: ActivitySignal[] = []
  const recent: ActivityCount[] = []
  let sources = 0
  for (const engine of engines) {
    const r = results[engine.id]
    if (!r || r.loading || r.error || !r.data || (r.data as any)?.error) continue
    const { signals, counts } = extract(engine.id, engine.label, r.data, names)
    // Future-dated values (clock skew, typos) would read as "active": ignore them.
    const valid = signals.filter(s => time(s.date)! <= now + DAY)
    if (valid.length === 0 && !counts?.some(c => c.count > 0)) continue
    sources++
    all.push(...valid)
    if (counts) recent.push(...counts.filter(c => c.count > 0))
    else {
      for (const kind of ['operation', 'report'] as const) {
        const count = valid.filter(s => s.kind === kind && now - time(s.date)! <= ACTIVE_DAYS * DAY).length
        if (count > 0) recent.push({ engineId: engine.id, source: engine.label, kind, count })
      }
    }
  }
  const last = latest(all)
  const daysSince = last ? Math.max(0, Math.floor((now - time(last.date)!) / DAY)) : null
  const level: ActivityLevel = daysSince == null ? 'unknown'
    : daysSince <= ACTIVE_DAYS ? 'active' : daysSince <= RECENT_DAYS ? 'recent' : 'dormant'
  return {
    level,
    daysSince,
    lastOperation: latest(all.filter(s => s.kind === 'operation')),
    lastReport: latest(all.filter(s => s.kind === 'report')),
    recent,
    sources,
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */
