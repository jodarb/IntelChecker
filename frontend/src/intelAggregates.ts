/* eslint-disable @typescript-eslint/no-explicit-any */
// Cross-source aggregates for the Summary panel: malware families, threat actor
// relations, campaigns, first/last seen and which sources flagged the indicator.
// Extractors read each engine's raw payload (the same JSON the cards render), so
// they work identically for live lookups and frozen history entries.
//
// Families come only from structured fields (ThreatFox malware, MalwareBazaar
// signature, OTX malware_families, MISP malware galaxies, VT threat names…).
// Free-text tags are not shown; they're only scanned for threat actor names
// (matched against MITRE ATT&CK groups), so a feed that only tags an actor still
// counts as a relation.
//
// Every value keeps its provenance (source, field, pulse/event) so the Summary can
// show where it came from. Families and actors taken from a *bulk* OTX pulse (a
// weekly roundup or a feed with ≥ BULK_PULSE_MIN indicators) are dropped: they
// describe the report, not necessarily this indicator.
import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'
import { getEngineAssessment } from '@/verdictEngine'

/** Where a value was read from — i18n key `prov.<field>` describes it. */
export type ProvField =
  | 'vt.threatName' | 'vt.category' | 'vt.tag'
  | 'tf.family' | 'tf.threatType' | 'tf.tag'
  | 'bazaar.signature' | 'bazaar.tag'
  | 'urlhaus.payload' | 'urlhaus.threat' | 'urlhaus.tag'
  | 'otx.family' | 'otx.tag' | 'otx.adversary' | 'otx.related'
  | 'tweetfeed.family' | 'tweetfeed.tag' | 'tweetfeed.campaign'
  | 'anyrun.threat' | 'anyrun.tag'
  | 'hybrid.family'
  | 'urlscan.tag'
  | 'mitre.group' | 'mitre.software'
  | 'malpedia.actor' | 'malpedia.family'
  | 'sslbl.reason'
  | 'misp.galaxyActor' | 'misp.galaxyFamily' | 'misp.tag'
  | 'opencti.malware' | 'opencti.actor' | 'opencti.campaign' | 'opencti.label'
  | 'rf.rule' | 'rf.link' | 'rf.malware'
  | 'rlive.group' | 'hrock.stealer'

/** A raw value plus where it came from. */
interface Item {
  value: unknown
  field: ProvField
  /** Pulse name, MISP event title… */
  context?: string
  /** Number of indicators in that pulse/report, when known */
  size?: number
  /** From a bulk report: describes the report, not necessarily this indicator */
  indirect?: boolean
}

interface EngineIntel {
  families: Item[]
  /** family name → aliases a source declares for it (ThreatFox malware_alias) */
  aliases: [string, string[]][]
  tags: Item[]
  actors: Item[]
  /** A source links the indicator to an actor without naming it (Recorded Future "Linked to APT") */
  unnamedActorLinks: { rule: string; evidence?: string }[]
  campaigns: Item[]
  firstSeen: (string | number | null | undefined)[]
  lastSeen: (string | number | null | undefined)[]
}

const empty = (): EngineIntel => ({
  families: [], aliases: [], tags: [], actors: [], unnamedActorLinks: [], campaigns: [], firstSeen: [], lastSeen: [],
})

const arr = <T = any>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : [])
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)

/**
 * An OTX pulse with more tags than this was almost certainly auto-generated from a
 * scraped page/report (dozens of words like "copy sha1", "read", "next"): its tags
 * are ignored, but its malware families, adversary and dates still count.
 */
const MAX_TAGS_PER_PULSE = 15

/** Recorded Future risk from which an IOC's Insikt links (actors, malware) describe the
 *  IOC itself and feed the Summary ("Suspicious" and above). Below it they're only shown on the card. */
export const RF_LINKS_MIN_RISK = 25

/** An OTX pulse with at least this many indicators is a bulk feed / report. */
export const BULK_PULSE_MIN = 100

const it = (field: ProvField, extra: Omit<Item, 'value' | 'field'> = {}) =>
  (value: unknown): Item => ({ value, field, ...extra })

// ── Date parsing ─────────────────────────────────────────────────────────────

/** Accepts ISO strings, "YYYY-MM-DD HH:MM:SS[ UTC]", unix seconds (number or numeric string). */
export function parseDate(v: string | number | null | undefined): Date | null {
  if (v == null || v === '') return null
  let d: Date
  if (typeof v === 'number' || /^\d{9,11}$/.test(String(v))) {
    d = new Date(Number(v) * 1000)
  } else {
    const s = String(v).trim().replace(/ UTC$/, 'Z')
    // "2024-01-02 03:04:05" → ISO; date-only strings parse as UTC already.
    const iso = /^\d{4}-\d{2}-\d{2} \d/.test(s) ? s.replace(' ', 'T') : s
    d = new Date(/T\d{2}:\d{2}(:\d{2})?(\.\d+)?$/.test(iso) ? `${iso}Z` : iso)
  }
  const t = d.getTime()
  // Ignore nonsense (epoch 0, far future).
  if (Number.isNaN(t) || t < Date.UTC(1995, 0, 1) || t > Date.now() + 86_400_000) return null
  return d
}

// ── MISP tags ────────────────────────────────────────────────────────────────

/** `misp-galaxy:threat-actor="APT28"` → { ns: 'misp-galaxy:threat-actor', value: 'APT28' } */
function machineTag(name: string): { ns: string; value: string } | null {
  const m = name.match(/^([^=]+)="?([^"]+)"?$/)
  return m ? { ns: m[1].toLowerCase(), value: m[2] } : null
}

const MISP_ACTOR_NS = /threat-actor|intrusion-set/
const MISP_FAMILY_NS = /malpedia|mitre-malware|mitre-tool|ransomware|rat|botnet|banker|stealer|backdoor|android|tool/
// Namespaced tags whose value says something about the threat. Anything else with
// a namespace (tlp:, pap:, workflow:, org-specific taxonomies…) is dropped.
const MISP_TAG_NS = /^(ecsirt:malicious-code|malware_classification|ms-caro-malware|kill-chain|circl:incident-classification)/

function mispIntel(d: any): EngineIntel {
  const out = empty()
  const events = (d?.Events ?? {}) as Record<string, any>
  const tagged: { name: string; context?: string }[] = [
    ...arr(d?.Attribute).flatMap(a => arr(a?.Tag).map(t => ({
      name: t?.name, context: events[a?.event_id]?.info ?? a?.Event?.info,
    }))),
    ...Object.values(events).flatMap((e: any) => arr(e?.Tag).map(t => ({ name: t?.name, context: e?.info }))),
  ].filter(x => typeof x.name === 'string')

  for (const { name, context } of tagged) {
    const mt = machineTag(name)
    if (mt) {
      if (mt.ns.startsWith('misp-galaxy:') && MISP_ACTOR_NS.test(mt.ns)) out.actors.push({ value: mt.value, field: 'misp.galaxyActor', context })
      else if (mt.ns.startsWith('misp-galaxy:') && MISP_FAMILY_NS.test(mt.ns)) out.families.push({ value: mt.value, field: 'misp.galaxyFamily', context })
      else if (MISP_TAG_NS.test(mt.ns)) out.tags.push({ value: mt.value, field: 'misp.tag', context })
    } else if (!name.includes(':')) {
      out.tags.push({ value: name, field: 'misp.tag', context })
    }
  }
  for (const a of arr(d?.Attribute)) {
    out.firstSeen.push(a?.first_seen, a?.Event?.date)
    out.lastSeen.push(a?.last_seen, a?.timestamp)
  }
  for (const e of Object.values(d?.Events ?? {}) as any[]) out.firstSeen.push(e?.date)
  return out
}

// ── Per-engine extractors ────────────────────────────────────────────────────

const splitList = (v: unknown) => (str(v) ?? '').split(',').map(s => s.trim()).filter(Boolean)

const EXTRACTORS: Record<string, (d: any) => EngineIntel> = {
  virustotal: d => {
    const a = d?.data?.attributes ?? {}
    const out = empty()
    const ptc = a.popular_threat_classification
    out.families.push(...arr(ptc?.popular_threat_name).map(x => x?.value).map(it('vt.threatName')))
    out.tags.push(...arr(ptc?.popular_threat_category).map(x => x?.value).map(it('vt.category')), ...arr(a.tags).map(it('vt.tag')))
    out.firstSeen.push(a.first_submission_date)
    out.lastSeen.push(a.last_submission_date)
    return out
  },
  abusech: d => {
    const out = empty()
    for (const ioc of arr(d?.data)) {
      const family = str(ioc?.malware_printable)
      if (family && !/^unknown/i.test(family)) {
        out.families.push({ value: family, field: 'tf.family' })
        out.aliases.push([family, splitList(ioc?.malware_alias)])
      }
      out.tags.push({ value: ioc?.threat_type, field: 'tf.threatType' }, ...arr(ioc?.tags).map(it('tf.tag')))
      out.firstSeen.push(ioc?.first_seen)
      out.lastSeen.push(ioc?.last_seen ?? ioc?.first_seen)
    }
    return out
  },
  malwarebazaar: d => {
    const out = empty()
    for (const s of arr(d?.data)) {
      out.families.push({ value: s?.signature, field: 'bazaar.signature' })
      out.tags.push(...arr(s?.tags).map(it('bazaar.tag')))
      out.firstSeen.push(s?.first_seen)
      out.lastSeen.push(s?.last_seen ?? s?.first_seen)
    }
    return out
  },
  urlhaus: d => {
    const out = empty()
    out.families.push(...arr(d?.payloads).map(p => p?.signature).map(it('urlhaus.payload')))
    out.tags.push({ value: d?.threat, field: 'urlhaus.threat' }, ...arr(d?.tags).map(it('urlhaus.tag')))
    out.firstSeen.push(d?.date_added)
    out.lastSeen.push(d?.last_online, d?.date_added)
    for (const u of arr(d?.urls)) {
      out.tags.push({ value: u?.threat, field: 'urlhaus.threat' }, ...arr(u?.tags).map(it('urlhaus.tag')))
      out.firstSeen.push(u?.date_added)
      out.lastSeen.push(u?.date_added)
    }
    return out
  },
  alienvault: d => {
    const out = empty()
    const pulses = [...arr(d?.pulse_info?.pulses), ...arr(d?.results)]
    for (const p of pulses) {
      // Lower-case multi-word tags ("registry keys", "copy sha1") are keyword
      // extraction artifacts, not labels an analyst chose.
      // Tags that are just the pulse author / feed handle ("Nextray" on
      // "IOC Records Provided by @NextRayAI") say who reported it, not what it is.
      const handles = [
        ...[...String(p?.name ?? '').matchAll(/@(\w{3,})/g)].map(m => norm(m[1])),
        ...[p?.author_name, p?.author?.username].filter(Boolean).map(a => norm(String(a))),
      ].filter(h => h.length >= 4)
      const tags = arr<string>(p?.tags).filter(t =>
        typeof t === 'string'
        && !/^[a-z0-9]+( [a-z0-9]+)+$/.test(t)
        && !handles.some(h => norm(t).length >= 4 && h.startsWith(norm(t))))
      const context = str(p?.name) ?? undefined
      const size = typeof p?.indicator_count === 'number' ? p.indicator_count : undefined
      // A roundup / bulk feed lists many campaigns: its families and adversary
      // describe the report, not necessarily this indicator. Its *tags* (proxy,
      // tor, scanner…) do apply to every indicator in the feed, so they stay direct.
      const indirect = (size ?? 0) >= BULK_PULSE_MIN || /round-?up/i.test(context ?? '')
      if (arr(p?.tags).length <= MAX_TAGS_PER_PULSE) out.tags.push(...tags.map(it('otx.tag', { context, size })))
      out.families.push(...arr(p?.malware_families)
        .map(m => (typeof m === 'string' ? m : m?.display_name))
        .map(it('otx.family', { context, size, indirect })))
      out.actors.push({ value: p?.adversary, field: 'otx.adversary', context, size, indirect })
      out.firstSeen.push(p?.created)
      out.lastSeen.push(p?.modified ?? p?.created)
    }
    // OTX's own summary of adversaries across every pulse that references the indicator.
    for (const group of Object.values(d?.pulse_info?.related ?? {}) as any[]) {
      out.actors.push(...arr(group?.adversary).map(it('otx.related')))
    }
    return out
  },
  recordedfuture: d => {
    const out = empty()
    const links = d?.insikt_links ?? {}
    if (d?.kind === 'actor' || d?.kind === 'company') {
      // The profile itself is the looked-up actor under RF's name (APT28 → BlueDelta):
      // listing it as a "related" actor would relate the actor to itself. For a
      // company, the linked actors / malware are the ones RF ties to it (targeting it).
      if (!d?.found) return out
      out.actors.push(...arr(links.actors).map(a => a?.name).map(it('rf.link')))
      out.families.push(...arr(links.malware).map(m => m?.name).map(it('rf.malware')))
      return out
    }
    // Links say what uses this infrastructure; on a benign IOC (8.8.8.8, google.com)
    // that's every malware that queries it. Only a risky IOC's links describe it.
    const score = d?.risk?.score
    const indirect = !(typeof score === 'number' && score >= RF_LINKS_MIN_RISK)
    out.actors.push(...arr(links.actors).map(a => a?.name).map(it('rf.link', { indirect })))
    out.families.push(...arr(links.malware).map(m => m?.name).map(it('rf.malware', { indirect })))
    for (const e of arr(d?.risk?.evidenceDetails)) {
      const rule = str(e?.rule)
      if (!rule || !/linked to (apt|threat actor)/i.test(rule)) continue
      const evidence = str(e?.evidenceString) ?? undefined
      // When RF names the actors ("… related threat actors including APT28, …"), keep them.
      const named = evidence?.match(/related (?:threat actors?|APT groups?|actors?) including ([^.]+)/i)?.[1]
      if (named) out.actors.push(...named.split(',').map(x => x.trim()).filter(Boolean).map(it('rf.rule', { context: rule })))
      else out.unnamedActorLinks.push({ rule, evidence })
    }
    out.firstSeen.push(d?.timestamps?.firstSeen)
    out.lastSeen.push(d?.timestamps?.lastSeen)
    return out
  },
  tweetfeed: d => {
    const out = empty()
    out.families.push({ value: d?.ai?.family, field: 'tweetfeed.family' })
    for (const r of arr(d?.records)) {
      out.tags.push(...arr(r?.tags).map(it('tweetfeed.tag')))
      out.firstSeen.push(r?.first_seen)
      out.lastSeen.push(r?.last_seen)
    }
    for (const c of arr(d?.campaigns)) {
      out.campaigns.push({ value: c?.name, field: 'tweetfeed.campaign' })
      out.lastSeen.push(c?.last_seen)
    }
    return out
  },
  greynoise: d => {
    const out = empty()
    out.firstSeen.push(d?.first_seen)
    out.lastSeen.push(d?.last_seen)
    return out
  },
  anyrun: d => {
    const out = empty()
    out.tags.push(...arr(d?.summary?.tags).map(it('anyrun.tag')))
    for (const k of ['destinationIP', 'relatedDNS', 'relatedURLs']) {
      for (const x of arr(d?.[k])) out.families.push(...arr(x?.threatName).map(it('anyrun.threat')))
    }
    out.lastSeen.push(d?.summary?.lastSeen)
    return out
  },
  hybridanalysis: d => {
    const out = empty()
    for (const r of arr(d?.result)) {
      out.families.push({ value: r?.vx_family, field: 'hybrid.family', context: str(r?.submit_name) ?? undefined })
      out.firstSeen.push(r?.analysis_start_time)
      out.lastSeen.push(r?.analysis_start_time)
    }
    return out
  },
  urlscan: d => {
    const out = empty()
    for (const r of arr(d?.results)) {
      out.tags.push(...arr(r?.task?.tags).map(it('urlscan.tag', { context: str(r?.task?.url) ?? undefined })))
      out.firstSeen.push(r?.task?.time)
      out.lastSeen.push(r?.task?.time)
    }
    return out
  },
  abuseipdb: d => {
    const out = empty()
    out.lastSeen.push(d?.data?.lastReportedAt)
    return out
  },
  crowdsec: d => {
    const out = empty()
    out.firstSeen.push(d?.history?.first_seen)
    out.lastSeen.push(d?.history?.last_seen)
    return out
  },
  malpedia: d => {
    const out = empty()
    if (!d?.found) return out
    if (str(d?.name)) out.actors.push({ value: d.name, field: 'malpedia.actor' })
    out.families.push(...arr(d?.families).map(f => f?.common_name).map(it('malpedia.family')))
    return out
  },
  sslbl: d => {
    const out = empty()
    // "Vidar C&C" → family "Vidar" (generic reasons like "Malware C&C" are dropped as GENERIC)
    const family = str(d?.reason)?.replace(/\s+(C&C|C2|distribution|malware)$/i, '')
    if (d?.listed && family) out.families.push({ value: family, field: 'sslbl.reason' })
    if (d?.listed) out.firstSeen.push(d?.listing_date)
    return out
  },
  nvd: d => {
    const out = empty()
    // A CVE is "first seen" when it was published.
    if (d?.found) out.firstSeen.push(d?.published)
    return out
  },
  // Companies: the ransomware groups that claimed it are its actor relations; first /
  // last seen are its first / last incident (leak-site claim, breach, infostealer).
  ransomwarelive: d => {
    const out = empty()
    // Threat actor: the group's own leak-site activity window.
    if (d?.kind === 'group') {
      if (d?.found === true) {
        out.firstSeen.push(d?.first_claim)
        out.lastSeen.push(d?.last_claim)
      }
      return out
    }
    if (d?.listed !== true) return out
    for (const v of arr(d?.matches)) {
      if (str(v?.group)) out.actors.push({ value: v.group, field: 'rlive.group', context: str(v?.victim) ?? undefined })
      out.firstSeen.push(v?.discovered ?? v?.attack_date)
      out.lastSeen.push(v?.discovered ?? v?.attack_date)
    }
    return out
  },
  hudsonrock: d => {
    const out = empty()
    if (typeof d?.total !== 'number' || d.total <= 0) return out
    out.families.push(...arr(d?.stealer_families).map(f => f?.name).map(it('hrock.stealer')))
    out.lastSeen.push(d?.last_employee_compromised, d?.last_user_compromised)
    return out
  },
  hibp: d => {
    const out = empty()
    for (const b of arr(d?.breaches)) {
      out.firstSeen.push(b?.breach_date)
      out.lastSeen.push(b?.breach_date)
    }
    return out
  },
  mitreattack: d => {
    const out = empty()
    if (str(d?.name)) out.actors.push({ value: d.name, field: 'mitre.group' })
    out.families.push(...arr(d?.software).map(s => s?.name).map(it('mitre.software')))
    return out
  },
}

// OpenCTI: related malware / actors / campaigns come from the knowledge graph
// (relationships of the matched entity); labels are analyst-set tags. For a threat
// actor lookup the matched entity itself is the actor.
const OPENCTI_ACTOR_TYPES = new Set(['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Threat-Actor'])

function openctiIntel(d: any): EngineIntel {
  const out = empty()
  if (!d?.found) return out
  const e = d?.entity
  if (d?.kind === 'actor' && str(e?.value)) out.actors.push({ value: e.value, field: 'opencti.actor' })
  for (const r of arr(d?.relations)) {
    const name = str(r?.name)
    if (!name) continue
    if (r?.entity_type === 'Malware') out.families.push({ value: name, field: 'opencti.malware', context: r?.type })
    else if (OPENCTI_ACTOR_TYPES.has(r?.entity_type)) out.actors.push({ value: name, field: 'opencti.actor', context: r?.type })
    else if (r?.entity_type === 'Campaign') out.campaigns.push({ value: name, field: 'opencti.campaign', context: r?.type })
  }
  out.tags.push(...arr(e?.labels).map(l => l?.value).map(it('opencti.label')))
  out.firstSeen.push(e?.created_at)
  out.lastSeen.push(e?.updated_at)
  return out
}

function extract(engineId: string, data: unknown): EngineIntel | null {
  const fn = engineId.startsWith('misp_') ? mispIntel : engineId.startsWith('opencti_') ? openctiIntel : EXTRACTORS[engineId]
  if (!fn || !data || (data as any)?.error) return null
  try {
    return fn(data)
  } catch {
    return null
  }
}

// ── Filtering & merging ──────────────────────────────────────────────────────

/** "Gh0st RAT", "gh0st_rat", "win.gh0st-rat" → "gh0strat" */
const norm = (v: string) => v.toLowerCase().replace(/^(win|elf|osx|apk|jar|js|ps1|py)\./, '').replace(/[^a-z0-9]/g, '')

// Labels that say nothing about the threat on their own.
const GENERIC = new Set([
  'unknown', 'none', 'null', 'na', 'other', 'generic', 'malware', 'malicious', 'ioc', 'iocs', 'indicator',
  'windows', 'linux', 'macos', 'android', 'win32', 'win64', 'elf', 'exe', 'dll', 'pe', 'pdf', 'zip', 'doc',
  'virustotal', 'misp', 'otx', 'alienvault', 'threatfox', 'urlhaus', 'malwarebazaar',
  'cybersecurity', 'threatintel', 'threatintelligence', 'infosec',
  // Feed bookkeeping: honeypot sensor names and pulse cadence, not threat labels.
  'honeypot', 'tpot', 'cowrie', 'dionaea', 'honeytrap', 'p0f', 'fatt', 'mailoney', 'tanner', 'sentrypeer',
  'suricata', 'snort', 'zeek', 'sensortagged', 'autogenerated', 'autogeneratedsecurity',
  'daily', 'weekly', 'monthly', 'feed', 'blocklist', 'blacklist',
  'genericstealer',
])

// Common malware families and their aliases (first entry = display name). Works
// offline; when the backend can reach MITRE ATT&CK its software aliases are added.
const FAMILY_ALIASES: string[][] = [
  ['QakBot', 'Qbot', 'Qakbot', 'Pinkslipbot', 'QuackBot'],
  ['Gh0st RAT', 'Ghost RAT', 'Gh0st', 'Farfli', 'PCRat'],
  ['Emotet', 'Geodo', 'Heodo'],
  ['TrickBot', 'Trickster', 'TheTrick'],
  ['IcedID', 'BokBot'],
  ['Dridex', 'Bugat', 'Cridex'],
  ['Ursnif', 'Gozi', 'ISFB', 'Dreambot'],
  ['Cobalt Strike', 'CobaltStrike', 'CS Beacon'],
  ['Sliver'],
  ['Metasploit', 'Meterpreter'],
  ['Agent Tesla', 'AgentTesla'],
  ['FormBook', 'XLoader'],
  ['RedLine Stealer', 'RedLine', 'RedLineStealer'],
  ['Lumma Stealer', 'Lumma', 'LummaC2', 'LummaStealer'],
  ['Raccoon Stealer', 'Raccoon', 'RecordBreaker'],
  ['Vidar'],
  ['AsyncRAT'],
  ['njRAT', 'Bladabindi'],
  ['Remcos', 'RemcosRAT'],
  ['NanoCore'],
  ['DarkGate'],
  ['Pikabot'],
  ['Bumblebee'],
  ['SmokeLoader', 'Smoke Loader', 'Dofoil'],
  ['Mirai'],
  ['Gafgyt', 'Bashlite', 'Qbot-linux'],
  ['Tofsee'],
  ['Upatre'],
  ['Ursu'],
  ['Tinba', 'Tiny Banker'],
  ['PlugX', 'Korplug'],
  ['ShadowPad'],
  ['LockBit'],
  ['Conti'],
  ['BlackCat', 'ALPHV'],
]

// MITRE group aliases that are also everyday words / common tags: never treat a
// tag as a threat actor because of them.
const AMBIGUOUS_ACTOR_ALIASES = new Set([
  'play', 'snake', 'karma', 'silence', 'mirage', 'reaper', 'tick', 'mantis', 'cicada', 'elfin',
  'thrip', 'axiom', 'chimera', 'machete', 'krypton', 'mercury', 'monsoon', 'strider', 'cleaver',
  'akira', 'windigo', 'rocke', 'chafer', 'bitter', 'zinc', 'nickel', 'radium', 'silicon',
])

/** MITRE ATT&CK names + aliases served by GET /mitre/aliases (best-effort). */
export interface MitreAliases {
  groups: string[][]
  software: string[][]
}

type Bucket = Map<string, { value: string; engines: Set<string>; sources: Provenance[]; direct: boolean }>

function add(target: Bucket, key: string, raw: string, engine: string, item: Item, display?: string) {
  const entry = target.get(key) ?? { value: display ?? raw, engines: new Set<string>(), sources: [], direct: false }
  entry.engines.add(engine)
  const indirect = !!item.indirect
  if (!indirect) entry.direct = true
  const dup = entry.sources.some(s => s.engine === engine && s.field === item.field && s.context === item.context && s.raw === raw)
  if (!dup) entry.sources.push({ engine, field: item.field, raw, context: item.context, size: item.size, indirect })
  target.set(key, entry)
}

const ranked = (m: Bucket): AggregatedValue[] =>
  [...m.values()]
    .map(e => ({ value: e.value, engines: [...e.engines], sources: e.sources, indirect: !e.direct }))
    // Direct before indirect, then by number of sources; stable for ties.
    .sort((a, b) => Number(a.indirect) - Number(b.indirect) || b.engines.length - a.engines.length)

// ── Public API ───────────────────────────────────────────────────────────────

export interface Provenance {
  /** Engine label */
  engine: string
  field: ProvField
  /** The value exactly as the source wrote it */
  raw: string
  /** Pulse name, MISP event title… */
  context?: string
  /** Indicators in that pulse/report */
  size?: number
  indirect: boolean
}

export interface AggregatedValue {
  value: string
  /** Engine labels that reported it */
  engines: string[]
  sources: Provenance[]
  /** Every source for it is indirect (bulk report) */
  indirect: boolean
}

export interface SeenDate {
  date: Date
  engine: string
}

export interface FlaggedSource {
  engineId: string
  label: string
  subscore: number
}

export interface UnnamedActorLink {
  engine: string
  rule: string
  evidence?: string
}

export interface IntelSummary {
  /** Families attributed directly to the indicator (bulk-report mentions dropped) */
  families: AggregatedValue[]
  /** Named threat actors some source relates the indicator to */
  actors: AggregatedValue[]
  /** Sources that link it to an actor without naming one */
  unnamedActorLinks: UnnamedActorLink[]
  campaigns: AggregatedValue[]
  firstSeen: SeenDate | null
  lastSeen: SeenDate | null
  flagged: FlaggedSource[]
  clean: string[]
  /** Engines that answered (not loading / errored / unconfigured) */
  responded: number
  loading: boolean
}

export function aggregateIntel(
  type: IndicatorType,
  engines: EngineConfig[],
  results: Record<string, QueryResult>,
  mitre: MitreAliases | null = null,
): IntelSummary {
  const flagged: FlaggedSource[] = []
  const clean: string[] = []
  let responded = 0
  let loading = false
  const perEngine: { label: string; intel: EngineIntel }[] = []

  for (const engine of engines) {
    const result = results[engine.id]
    if (result?.loading) loading = true
    const a = getEngineAssessment(engine.id, type, result)
    if (a.outcome === 'excluded') continue
    responded++
    if (a.outcome === 'hit' && a.subscore != null) flagged.push({ engineId: engine.id, label: engine.label, subscore: a.subscore })
    if (a.outcome === 'clean') clean.push(engine.label)

    const intel = extract(engine.id, result?.data)
    if (intel) perEngine.push({ label: engine.label, intel })
  }

  // Family alias map: every known spelling points at one canonical key, so
  // "Ghost RAT" (ThreatFox), "Gh0st RAT" (MISP) and the tag "Gh0st" merge, and
  // "Qbot" (OTX) meets "QakBot" (MITRE). Variants with and without a trailing
  // "rat" are registered too ("Gh0st RAT" ↔ "Gh0st").
  const aliasOf = new Map<string, string>()
  const familyName = new Map<string, string>() // canonical key → display name
  const variants = (v: string) => [norm(v), norm(v).replace(/rat$/, '')].filter(k => k.length >= 3)
  const register = (names: string[]) => {
    const first = names.find(n => norm(n).length >= 3)
    if (!first) return
    // Join an existing group if any spelling is already known.
    const key = names.map(n => aliasOf.get(norm(n))).find(Boolean) ?? norm(first)
    if (!familyName.has(key)) familyName.set(key, first)
    for (const n of names) for (const k of variants(n)) if (!aliasOf.has(k)) aliasOf.set(k, key)
  }
  for (const names of FAMILY_ALIASES) register(names)
  for (const names of mitre?.software ?? []) register(names)
  for (const { intel } of perEngine) {
    for (const [family, aliases] of intel.aliases) register([family, ...aliases])
  }
  const canon = (v: string) => {
    const n = norm(v)
    return aliasOf.get(n) ?? aliasOf.get(n.replace(/rat$/, '')) ?? n
  }

  // Threat actor names (MITRE groups and their aliases): an actor that a feed only
  // mentions as a tag ("Kimsuky" in an OTX pulse) is moved to the actors list.
  const actorOf = new Map<string, string>()
  for (const names of mitre?.groups ?? []) {
    for (const n of names) {
      const k = norm(n)
      if (k.length >= 4 && !AMBIGUOUS_ACTOR_ALIASES.has(k) && !actorOf.has(k)) actorOf.set(k, names[0])
    }
  }

  const families: Bucket = new Map()
  const actors: Bucket = new Map()
  const unnamedActorLinks: UnnamedActorLink[] = []
  const campaigns: Bucket = new Map()
  let firstSeen: SeenDate | null = null
  let lastSeen: SeenDate | null = null

  for (const { label, intel } of perEngine) {
    for (const link of intel.unnamedActorLinks) unnamedActorLinks.push({ engine: label, ...link })
    for (const item of intel.families) {
      if (item.indirect) continue
      const v = str(item.value)
      if (v && !GENERIC.has(norm(v)) && norm(v).length >= 2) {
        const key = canon(v)
        add(families, key, v, label, item, familyName.get(key))
      }
    }
    for (const item of intel.actors) {
      if (item.indirect) continue
      const v = str(item.value)
      if (!v) continue
      const name = actorOf.get(norm(v))
      add(actors, name ? norm(name) : norm(v), v, label, item, name)
    }
    for (const item of intel.campaigns) {
      const v = str(item.value)
      if (v) add(campaigns, norm(v), v, label, item)
    }
    for (const v of intel.firstSeen) {
      const d = parseDate(v)
      if (d && (!firstSeen || d < firstSeen.date)) firstSeen = { date: d, engine: label }
    }
    for (const v of [...intel.lastSeen, ...intel.firstSeen]) {
      const d = parseDate(v)
      if (d && (!lastSeen || d > lastSeen.date)) lastSeen = { date: d, engine: label }
    }
  }

  // Tags aren't shown, but a tag that is a known actor name ("Kimsuky" on an OTX
  // pulse) is a relation to that actor.
  for (const { label, intel } of perEngine) {
    for (const item of intel.tags) {
      for (const part of typeof item.value === 'string' ? item.value.split(',') : []) {
        const v = str(part)
        const actor = v ? actorOf.get(norm(v)) : undefined
        if (v && actor) add(actors, norm(actor), v, label, item, actor)
      }
    }
  }

  flagged.sort((x, y) => y.subscore - x.subscore)
  return {
    families: ranked(families),
    actors: ranked(actors),
    unnamedActorLinks,
    campaigns: ranked(campaigns),
    firstSeen,
    lastSeen,
    flagged,
    clean,
    responded,
    loading,
  }
}
