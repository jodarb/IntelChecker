/* eslint-disable @typescript-eslint/no-explicit-any */
// Cross-source aggregates for the Summary panel: malware families, tags, threat
// actors / campaigns, first/last seen and which sources flagged the indicator.
// Extractors read each engine's raw payload (the same JSON the cards render), so
// they work identically for live lookups and frozen history entries.
//
// Families and tags are kept apart on purpose:
//   * families come only from structured fields (ThreatFox malware, MalwareBazaar
//     signature, OTX malware_families, MISP malware galaxies, VT threat names…);
//   * tags are free text, so they're filtered hard — OTX pulses that dump scraped
//     keywords, MISP org-specific namespaces, ASN / ISP names, file-format words.
import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'
import { getEngineAssessment } from '@/verdictEngine'
import { SUMMARY_REGISTRY } from '@/summaryRegistry'

interface EngineIntel {
  families: string[]
  /** family name → aliases a source declares for it (ThreatFox malware_alias) */
  aliases: [string, string[]][]
  tags: string[]
  actors: string[]
  campaigns: string[]
  firstSeen: (string | number | null | undefined)[]
  lastSeen: (string | number | null | undefined)[]
}

const empty = (): EngineIntel => ({
  families: [], aliases: [], tags: [], actors: [], campaigns: [], firstSeen: [], lastSeen: [],
})

const arr = <T = any>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : [])
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)

/**
 * An OTX pulse with more tags than this was almost certainly auto-generated from a
 * scraped page/report (dozens of words like "copy sha1", "read", "next"): its tags
 * are ignored, but its malware families, adversary and dates still count.
 */
const MAX_TAGS_PER_PULSE = 15

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
  const tagNames = [
    ...arr(d?.Attribute).flatMap(a => arr(a?.Tag).map(t => t?.name)),
    ...Object.values(d?.Events ?? {}).flatMap((e: any) => arr(e?.Tag).map(t => t?.name)),
  ].filter((n): n is string => typeof n === 'string')

  for (const name of tagNames) {
    const mt = machineTag(name)
    if (mt) {
      if (mt.ns.startsWith('misp-galaxy:') && MISP_ACTOR_NS.test(mt.ns)) out.actors.push(mt.value)
      else if (mt.ns.startsWith('misp-galaxy:') && MISP_FAMILY_NS.test(mt.ns)) out.families.push(mt.value)
      else if (MISP_TAG_NS.test(mt.ns)) out.tags.push(mt.value)
    } else if (!name.includes(':')) {
      out.tags.push(name)
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
    out.families.push(...arr(ptc?.popular_threat_name).map(x => x?.value))
    out.tags.push(...arr(ptc?.popular_threat_category).map(x => x?.value), ...arr(a.tags))
    out.firstSeen.push(a.first_submission_date)
    out.lastSeen.push(a.last_submission_date)
    return out
  },
  abusech: d => {
    const out = empty()
    for (const ioc of arr(d?.data)) {
      const family = str(ioc?.malware_printable)
      if (family && !/^unknown/i.test(family)) {
        out.families.push(family)
        out.aliases.push([family, splitList(ioc?.malware_alias)])
      }
      out.tags.push(ioc?.threat_type, ...arr(ioc?.tags))
      out.firstSeen.push(ioc?.first_seen)
      out.lastSeen.push(ioc?.last_seen ?? ioc?.first_seen)
    }
    return out
  },
  malwarebazaar: d => {
    const out = empty()
    for (const s of arr(d?.data)) {
      out.families.push(s?.signature)
      out.tags.push(...arr(s?.tags))
      out.firstSeen.push(s?.first_seen)
      out.lastSeen.push(s?.last_seen ?? s?.first_seen)
    }
    return out
  },
  urlhaus: d => {
    const out = empty()
    out.families.push(...arr(d?.payloads).map(p => p?.signature))
    out.tags.push(d?.threat, ...arr(d?.tags))
    out.firstSeen.push(d?.date_added)
    out.lastSeen.push(d?.last_online, d?.date_added)
    for (const u of arr(d?.urls)) {
      out.tags.push(u?.threat, ...arr(u?.tags))
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
      if (arr(p?.tags).length <= MAX_TAGS_PER_PULSE) out.tags.push(...tags)
      out.families.push(...arr(p?.malware_families).map(m => (typeof m === 'string' ? m : m?.display_name)))
      out.actors.push(p?.adversary)
      out.firstSeen.push(p?.created)
      out.lastSeen.push(p?.modified ?? p?.created)
    }
    return out
  },
  recordedfuture: d => {
    const out = empty()
    out.firstSeen.push(d?.timestamps?.firstSeen)
    out.lastSeen.push(d?.timestamps?.lastSeen)
    return out
  },
  tweetfeed: d => {
    const out = empty()
    out.families.push(d?.ai?.family)
    for (const r of arr(d?.records)) {
      out.tags.push(...arr(r?.tags))
      out.firstSeen.push(r?.first_seen)
      out.lastSeen.push(r?.last_seen)
    }
    for (const c of arr(d?.campaigns)) {
      out.campaigns.push(c?.name)
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
    out.tags.push(...arr(d?.summary?.tags))
    for (const k of ['destinationIP', 'relatedDNS', 'relatedURLs']) {
      for (const x of arr(d?.[k])) out.families.push(...arr(x?.threatName))
    }
    out.lastSeen.push(d?.summary?.lastSeen)
    return out
  },
  hybridanalysis: d => {
    const out = empty()
    for (const r of arr(d?.result)) {
      out.families.push(r?.vx_family)
      out.firstSeen.push(r?.analysis_start_time)
      out.lastSeen.push(r?.analysis_start_time)
    }
    return out
  },
  urlscan: d => {
    const out = empty()
    for (const r of arr(d?.results)) {
      out.tags.push(...arr(r?.task?.tags))
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
  mitreattack: d => {
    const out = empty()
    if (str(d?.name)) out.actors.push(d.name)
    out.families.push(...arr(d?.software).map(s => s?.name))
    return out
  },
}

function extract(engineId: string, data: unknown): EngineIntel | null {
  const fn = engineId.startsWith('misp_') ? mispIntel : EXTRACTORS[engineId]
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
])

function isNoiseTag(v: string, orgNames: Set<string>): boolean {
  const n = norm(v)
  return n.length < 2 || v.length > 40 || GENERIC.has(n)
    || /^as\d+$/i.test(v.trim()) // ASN — already shown in the ASN field
    || orgNames.has(n) // ISP / org name — already shown in the ISP field
    || /^\d+(\.\d+)*$/.test(v) // bare numbers / versions / IPs
}

// Common malware families and their aliases (first entry = display name). Works
// offline; when the backend can reach MITRE ATT&CK its software aliases are added.
// Anything here is also promoted from a free-text tag to a malware family.
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

// Different spellings of the same concept collapse into one tag.
const SYNONYMS: Record<string, string> = {
  c2: 'c2', cc: 'c2', cnc: 'c2', botnetcc: 'c2', c2server: 'c2', commandandcontrol: 'c2', c2c: 'c2',
  phishing: 'phishing', phish: 'phishing',
  rat: 'rat', remoteaccesstrojan: 'rat',
  ransomware: 'ransomware', ransom: 'ransomware',
  stealer: 'stealer', infostealer: 'stealer',
  scanner: 'scanner', scanning: 'scanner', webscan: 'scanner', webscanner: 'scanner', probing: 'scanner',
  bruteforce: 'bruteforce', sshbruteforce: 'bruteforce',
}
const DISPLAY: Record<string, string> = { c2: 'C2', rat: 'RAT', phishing: 'Phishing', ransomware: 'Ransomware', stealer: 'Stealer', scanner: 'Scanner', bruteforce: 'Brute force' }

type Bucket = Map<string, { value: string; engines: Set<string> }>

function add(target: Bucket, key: string, value: string, engine: string, display?: string) {
  const entry = target.get(key) ?? { value: display ?? DISPLAY[key] ?? value, engines: new Set<string>() }
  entry.engines.add(engine)
  target.set(key, entry)
}

const ranked = (m: Bucket): AggregatedValue[] =>
  [...m.values()]
    .map(e => ({ value: e.value, engines: [...e.engines] }))
    // Stable sort: insertion order breaks ties.
    .sort((a, b) => b.engines.length - a.engines.length)

// ── Public API ───────────────────────────────────────────────────────────────

export interface AggregatedValue {
  value: string
  /** Engine labels that reported it */
  engines: string[]
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

export interface IntelSummary {
  families: AggregatedValue[]
  tags: AggregatedValue[]
  actors: AggregatedValue[]
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
  const orgNames = new Set<string>()

  for (const engine of engines) {
    const result = results[engine.id]
    if (result?.loading) loading = true
    const a = getEngineAssessment(engine.id, type, result)
    if (a.outcome === 'excluded') continue
    responded++
    if (a.outcome === 'hit' && a.subscore != null) flagged.push({ engineId: engine.id, label: engine.label, subscore: a.subscore })
    if (a.outcome === 'clean') clean.push(engine.label)

    for (const ex of SUMMARY_REGISTRY[engine.id]?.[type] ?? []) {
      if (ex.field !== 'isp') continue
      const v = ex.extract(result?.data)
      if (v) orgNames.add(norm(v))
    }
    const intel = extract(engine.id, result?.data)
    if (intel) perEngine.push({ label: engine.label, intel })
  }

  // Family alias map: every known spelling points at one canonical key, so
  // "Ghost RAT" (ThreatFox), "Gh0st RAT" (MISP) and the tag "Gh0st" merge, and
  // "Qbot" (OTX) meets "QakBot" (MITRE). Variants with and without a trailing
  // "rat" are registered too ("Gh0st RAT" ↔ "Gh0st").
  const aliasOf = new Map<string, string>()
  const familyName = new Map<string, string>() // canonical key → display name
  const knownFamily = new Set<string>() // keys that may be promoted from tags
  const variants = (v: string) => [norm(v), norm(v).replace(/rat$/, '')].filter(k => k.length >= 3)
  const register = (names: string[], promote: boolean) => {
    const first = names.find(n => norm(n).length >= 3)
    if (!first) return
    // Join an existing group if any spelling is already known.
    const key = names.map(n => aliasOf.get(norm(n))).find(Boolean) ?? norm(first)
    if (!familyName.has(key)) familyName.set(key, first)
    if (promote) knownFamily.add(key)
    for (const n of names) for (const k of variants(n)) if (!aliasOf.has(k)) aliasOf.set(k, key)
  }
  for (const names of FAMILY_ALIASES) register(names, true)
  // MITRE software only merges spellings; it isn't used to promote tags because it
  // also lists generic utilities ("at", "ping", "Tor") that are common tags.
  for (const names of mitre?.software ?? []) register(names, false)
  for (const { intel } of perEngine) {
    for (const [family, aliases] of intel.aliases) register([family, ...aliases], false)
  }
  const canon = (v: string) => {
    const n = norm(v)
    return SYNONYMS[n] ?? aliasOf.get(n) ?? aliasOf.get(n.replace(/rat$/, '')) ?? n
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
  const tags: Bucket = new Map()
  const actors: Bucket = new Map()
  const campaigns: Bucket = new Map()
  let firstSeen: SeenDate | null = null
  let lastSeen: SeenDate | null = null

  for (const { label, intel } of perEngine) {
    for (const raw of intel.families) {
      const v = str(raw)
      if (v && !GENERIC.has(norm(v)) && norm(v).length >= 2) {
        const key = canon(v)
        add(families, key, v, label, familyName.get(key))
      }
    }
    for (const raw of intel.actors) {
      const v = str(raw)
      if (!v) continue
      const name = actorOf.get(norm(v))
      add(actors, name ? norm(name) : norm(v), name ?? v, label)
    }
    for (const raw of intel.campaigns) {
      const v = str(raw)
      if (v) add(campaigns, norm(v), v, label)
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

  // Tags last, so anything that is already a family (or an alias of one) isn't
  // repeated as a tag.
  for (const { label, intel } of perEngine) {
    // Some feeds pack several labels into one tag ("webscanner, bruteforce").
    for (const raw of intel.tags.flatMap(t => (typeof t === 'string' ? t.split(',') : []))) {
      const v = str(raw)
      if (!v || isNoiseTag(v, orgNames)) continue
      const actor = actorOf.get(norm(v))
      if (actor) { add(actors, norm(actor), actor, label); continue }
      const key = canon(v)
      if (families.has(key) || knownFamily.has(key)) { add(families, key, v, label, familyName.get(key)); continue }
      add(tags, key, v, label)
    }
  }

  flagged.sort((x, y) => y.subscore - x.subscore)
  return {
    families: ranked(families),
    tags: ranked(tags),
    actors: ranked(actors),
    campaigns: ranked(campaigns),
    firstSeen,
    lastSeen,
    flagged,
    clean,
    responded,
    loading,
  }
}
