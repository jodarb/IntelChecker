import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'
import { originCountriesInText, toCountryCode } from '@/lib/countries'

// Threat actor report data (ActorReport): which actor each source identified, whether
// they agree, and the profile merged from the sources that do — aliases, TTPs,
// vulnerabilities, related artifacts, victims and incidents, targets and arsenal.
//
//   MITRE ATT&CK     aliases, techniques, software, description
//   Malpedia         synonyms, CFR victims / target categories, malware families
//   Recorded Future  aliases, categories, ATT&CK links, attack vectors, CVEs, infrastructure, malware, organisations
//   OpenCTI          aliases, relationships (attack patterns, CVEs, targets, indicators /
//                    observables, campaigns, incidents, malware / tools), reports
//   ransomware.live  group profile, victims, top sectors / countries
//   AlienVault OTX   pulses that name the actor (full-text search, filtered)
//
// A search "as typed" can match different things in each source (RF's forum member
// "Gentleman", nothing elsewhere), so the sources are first grouped by shared names:
// the report is built from the main group only and `status` says how sure it is.

/* eslint-disable @typescript-eslint/no-explicit-any */
export type ArtifactType = Extract<IndicatorType, 'ip' | 'domain' | 'url' | 'hash'>

export interface ProfileItem {
  value: string
  /** Secondary text (technique name…) */
  detail?: string
  sources: string[]
  /** A value the analyst can look up (artifact, CVE) */
  pivot?: IndicatorType
  /** Country code, localised on display */
  country?: string
  /** Victims count (ransomware.live sectors / countries) */
  count?: number
  /** Risk score 0-100 given by `riskSource` (artifacts) */
  risk?: number
  riskSource?: string
}

/** A leak site (wall of shame), negotiation chat, file server… of the actor. */
export interface LeakSite {
  /** Attacker infrastructure (.onion mostly): shown as text, never linked */
  address: string
  type?: string
  title?: string
  /** Up at the source's last check (null: unknown) */
  online: boolean | null
  lastCheck?: string
  group?: string
  source: string
}

export interface Incident {
  date?: string
  title: string
  kind: 'campaign' | 'incident' | 'report'
  source: string
  link?: string
}

export interface Victim {
  date?: string
  name: string
  domain?: string
  sector?: string
  country?: string
}

/** What one source matched for the query. */
export interface SourceIdentity {
  engineId: string
  source: string
  name: string
  names: string[]
  /** The query equals its name or an alias (false: the source's closest hit) */
  exact: boolean
  /** A person / forum handle, not a group (Recorded Future) */
  persona: boolean
  /** A curated actor catalogue (MITRE, Malpedia, OpenCTI, ransomware.live) */
  curated: boolean
}

/**
 * confirmed — a curated catalogue matched it exactly, or two sources agree
 * single    — only one source knows it, or only by a closest match
 * persona   — the only match is a person / forum handle, not a group
 * conflict  — sources matched different actors (the main one is shown)
 * none      — no source identified an actor
 */
export type ProfileStatus = 'confirmed' | 'single' | 'persona' | 'conflict' | 'none'

export interface RansomwareGroup {
  victims: number
  d30: number
  d90: number
  d365: number
  first?: string
  last?: string
  raas: boolean | null
  leakSites: number
  leakSitesUp: number
  recent: Victim[]
  /** Every victim the source lists (older history entries: only `recent`) */
  all: Victim[]
  /** `all` is the full list, not just the latest ones */
  complete: boolean
}

/** What kind of actor a source says it is, normalised so sources agree on one row. */
export type ActorTypeKey = 'ransomware' | 'raas' | 'state' | 'espionage' | 'crime' | 'hacktivist' | 'sabotage' | 'insider' | 'persona'

export interface ActorType {
  /** Normalised type (translated on display); null: the source's own wording, in `value` */
  key: ActorTypeKey | null
  value: string
  sources: string[]
}

export interface ActorDescription {
  text: string
  /** Every source that gives this text (OpenCTI often copies MITRE's) */
  sources: string[]
}

export interface ActorProfile {
  status: ProfileStatus
  /** Sources the report is built from */
  identities: SourceIdentity[]
  /** The other actors the sources matched (status conflict) */
  others: { name: string; sources: string[] }[]
  name: string
  mitreId: string | null
  /** Every source's description, most authoritative first, identical texts merged */
  descriptions: ActorDescription[]
  /** Which source each single-source field comes from (shown next to it) */
  prov: { mitreId?: string; ransomware?: string }
  /** Every country of origin a source gives, normalised to ISO codes, most sources first */
  origins: { country: string; sources: string[] }[]
  /** What kind of actor each source says it is, most sources first */
  types: ActorType[]
  ransomware: RansomwareGroup | null
  /** When each source first saw it (earliest first; one date per source) */
  since: { date: string; source: string }[]
  /** Groups it descends from or rebrands (ransomware.live lineage), with their sources */
  lineage: { value: string; sources: string[] }[]
  /** Aliases that are not just a spelling of the name ("Storm-2697", not "TheGentlemen") */
  aliases: ProfileItem[]
  /** Spellings of the name itself ("The Gentlemen Ransomware Group") */
  nameVariants: string[]
  /** Every name any source gives (aliases and spellings), with its sources */
  aliasTable: ProfileItem[]
  ttps: ProfileItem[]
  attackVectors: ProfileItem[]
  vulns: ProfileItem[]
  artifacts: Record<ArtifactType, ProfileItem[]>
  incidents: Incident[]
  sectors: ProfileItem[]
  countries: ProfileItem[]
  organizations: ProfileItem[]
  /** Malware and tools attributed to it: a source says it uses them, they are named
   *  after it, or several sources agree */
  arsenal: ProfileItem[]
  /** Families a single source only mentions alongside it (often other groups' tools) */
  arsenalMentioned: ProfileItem[]
  leakSites: LeakSite[]
  /** Every actor source that was queried (for "no source has…" messages) */
  consulted: string[]
  /** OTX pulses that merely contain the query (status none): unverified mentions */
  mentions: Incident[]
  /** Engines whose data the report uses (activity is computed on these) */
  engineIds: Set<string>
  /** Every name the actor goes by, to filter full-text results */
  allNames: string[]
  loading: boolean
}

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : [])
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v.trim() : null)
export const nameKey = (v: string) => v.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '')

/** Items merged by key; first value seen wins, sources accumulate. */
class Bucket {
  private map = new Map<string, ProfileItem>()
  add(value: unknown, source: string, extra: Partial<ProfileItem> = {}, key?: string) {
    const v = str(value)
    if (!v) return
    const k = key ?? nameKey(v)
    if (!k) return
    const cur = this.map.get(k)
    if (cur) {
      if (!cur.sources.includes(source)) cur.sources.push(source)
      if (!cur.detail && extra.detail) cur.detail = extra.detail
      if (cur.count == null && extra.count != null) cur.count = extra.count
    } else {
      this.map.set(k, { value: v, sources: [source], ...extra })
    }
  }
  /** Most corroborated first, then by count, then alphabetical. */
  list(): ProfileItem[] {
    return [...this.map.values()].sort((a, b) =>
      b.sources.length - a.sources.length || (b.count ?? 0) - (a.count ?? 0) || a.value.localeCompare(b.value))
  }
}

// Techniques (T1566, T1566.001) and tactics (TA0011).
const TECHNIQUE_ID = /^(T\d{4}(\.\d{3})?|TA\d{4})$/i
const CVE_ID = /^CVE-\d{4}-\d{4,}$/i

/** "T1566 (Phishing | ATT&CK Enterprise)" → name "Phishing" */
const rfTechniqueName = (label: unknown) => str(label)?.match(/^\S+\s+\(([^|)]+)/)?.[1]?.trim()

const OBSERVABLE_TYPES: Record<string, ArtifactType> = {
  'IPv4-Addr': 'ip', 'IPv6-Addr': 'ip', 'Domain-Name': 'domain', Hostname: 'domain', Url: 'url', StixFile: 'hash', Artifact: 'hash',
}
const HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i
/** "[ipv4-addr:value = '1.2.3.4']" → "1.2.3.4" (single-comparison STIX patterns only) */
const patternValue = (p: unknown) => {
  const m = str(p)?.match(/^\[\s*[\w-]+:[\w.'-]+\s*=\s*'([^']+)'\s*\]$/)
  return m?.[1]
}

// English country names, to tell Malpedia's CFR victims (countries and organisations
// mixed: "Ukraine", "European Commission") apart.
let countryNames: Set<string> | null = null
function isCountryName(v: string): boolean {
  if (!countryNames) {
    countryNames = new Set()
    try {
      const dn = new Intl.DisplayNames(['en'], { type: 'region' })
      for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
        const code = String.fromCharCode(a, b)
        const name = dn.of(code)
        if (name && name !== code) countryNames.add(nameKey(name))
      }
    } catch { /* no Intl: everything reads as an organisation */ }
    // Common short forms the CFR uses.
    for (const n of ['USA', 'United States', 'UK', 'Russia', 'South Korea', 'North Korea', 'Iran', 'Syria', 'Vietnam', 'Taiwan', 'Palestine']) countryNames.add(nameKey(n))
  }
  return countryNames.has(nameKey(v))
}

/**
 * OTX pulse search is full text over community reports: "Akira" returns phishing
 * feeds and NFT domain lists. A pulse counts only when its title, description or
 * adversary names the actor or one of its aliases (4+ characters, whole words).
 */
export function relevantPulses(pulses: unknown, names: string[]): any[] {
  const terms = [...new Set(names.map(n => n.toLowerCase().trim()).filter(n => n.length >= 4))]
  if (terms.length === 0) return []
  const res = terms.map(n => new RegExp(`(^|[^\\p{L}\\p{N}])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}($|[^\\p{L}\\p{N}])`, 'iu'))
  return arr(pulses).filter(p => {
    const text = [p?.name, p?.description, p?.adversary].filter(x => typeof x === 'string').join(' \n ')
    return res.some(re => re.test(text))
  })
}

// ── Identities ─────────────────────────────────────────────────────────────

const CURATED = (id: string) => id === 'mitreattack' || id === 'malpedia' || id === 'ransomwarelive' || id.startsWith('opencti_')
// Whose name to show when the sources agree: the most authoritative first.
const NAME_PRIORITY = (id: string) =>
  id === 'mitreattack' ? 0 : id === 'malpedia' ? 1 : id.startsWith('opencti_') ? 2 : id === 'recordedfuture' ? 3 : 4

function identify(engineId: string, source: string, d: any, query: string): SourceIdentity | null {
  const qk = nameKey(query)
  const mk = (name: unknown, names: unknown[], exact?: unknown, persona = false): SourceIdentity | null => {
    const n = str(name)
    if (!n) return null
    const all = [...new Set([n, ...names.map(str).filter((x): x is string => !!x)])]
    // Older history entries have no `exact`: an alias equal to the query is one.
    const ex = typeof exact === 'boolean' ? exact : all.some(x => nameKey(x) === qk)
    return { engineId, source, name: n, names: all, exact: ex, persona, curated: CURATED(engineId) }
  }
  if (engineId === 'mitreattack') return mk(d?.name, arr(d?.aliases), true)
  if (engineId === 'malpedia') return d?.found === true ? mk(d?.name, arr(d?.synonyms), d?.exact) : null
  if (engineId === 'recordedfuture') {
    if (d?.kind !== 'actor' || d?.found !== true) return null
    const persona = d?.persona === true || arr(d?.categories).some(c => /forum member|community member/i.test(String(c)))
    return mk(d?.name, [...arr(d?.common_names), ...arr(d?.aliases)], d?.exact, persona)
  }
  if (engineId.startsWith('opencti_')) {
    return d?.kind === 'actor' && d?.found === true ? mk(d?.entity?.value, arr(d?.actor?.aliases), d?.exact) : null
  }
  if (engineId === 'ransomwarelive') {
    if (d?.kind !== 'group' || d?.found !== true) return null
    const groups = arr(d?.groups)
    const names = groups.flatMap(g => [g?.name, ...String(g?.altname ?? '').split(/[/,;|]/)])
    // ransomware.live matched the brand by name (versions included): an exact match,
    // unless it was found under another name of the actor (a MITRE alias).
    return mk(groups[0]?.name, names, !d?.matched_alias)
  }
  return null
}

/** Groups of sources that share a name or alias; persona matches never join a group. */
function cluster(ids: SourceIdentity[]): SourceIdentity[][] {
  const groups: { keys: Set<string>; persona: boolean; items: SourceIdentity[] }[] = []
  for (const id of ids) {
    const keys = new Set(id.names.map(nameKey).filter(k => k.length >= 3))
    const hit = groups.filter(g => g.persona === id.persona && [...keys].some(k => g.keys.has(k)))
    if (hit.length === 0) { groups.push({ keys, persona: id.persona, items: [id] }); continue }
    const [target, ...rest] = hit
    for (const other of rest) {
      other.keys.forEach(k => target.keys.add(k))
      target.items.push(...other.items)
      groups.splice(groups.indexOf(other), 1)
    }
    keys.forEach(k => target.keys.add(k))
    target.items.push(id)
  }
  // Main group: a group over a persona, curated catalogues, more sources, an exact match.
  const rank = (g: SourceIdentity[]) => [
    g.every(i => i.persona) ? 0 : 1, g.filter(i => i.curated).length, g.length, g.some(i => i.exact) ? 1 : 0,
  ]
  return groups.map(g => g.items).sort((a, b) => {
    const ra = rank(a), rb = rank(b)
    for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return rb[i] - ra[i]
    return 0
  })
}

/** Malware family key: "The Gentlemen Ransomware", "Gentlemen" → "gentlemen". */
const familyKey = (v: string) => nameKey(v).replace(/^the(?=.{4})/, '').replace(/(ransomware|locker)$/, '') || nameKey(v)

// Tie-break between countries given by as many sources: the most authoritative first.
const NAME_PRIORITY_LABEL = (label: string) =>
  ['MITRE ATT&CK', 'Malpedia', 'OpenCTI', 'Recorded Future'].findIndex(l => label.startsWith(l)) >>> 0

// Types: the sources' wording (RF categories, OpenCTI threat_actor_types, Malpedia's
// CFR incident type) mapped onto a few common ones; the rest is kept as written.
const TYPE_RULES: [ActorTypeKey, RegExp][] = [
  ['persona', /forum member|community member|individual/i],
  ['raas', /\braas\b|as[\s-]a[\s-]service/i],
  ['ransomware', /ransomware|extortion/i],
  ['state', /nation[\s-]?state|state[\s-]sponsor/i],
  ['espionage', /espionage|^spy$/i],
  ['crime', /crim|financial/i],
  ['hacktivist', /hacktivis/i],
  ['sabotage', /sabotage|destructi/i],
  ['insider', /insider/i],
]
const GENERIC_TYPE = /^(threat[\s-]?)?actors?$|^intrusion[\s-]set$|^unknown$/i
const typeKey = (v: string): ActorTypeKey | null => TYPE_RULES.find(([, re]) => re.test(v))?.[0] ?? null
/** "crime-syndicate" → "Crime syndicate" */
const typeLabel = (v: string) => { const s = v.replace(/[-_]+/g, ' ').trim(); return s.charAt(0).toUpperCase() + s.slice(1) }

const toVictim = (v: any): Victim => ({
  date: str(v.discovered ?? v.attack_date) ?? undefined, name: v.victim, domain: str(v.domain) ?? undefined,
  sector: str(v.sector) ?? undefined, country: str(v.country) ?? undefined,
})

const pick = (ids: SourceIdentity[]) => [...ids].sort((a, b) => NAME_PRIORITY(a.engineId) - NAME_PRIORITY(b.engineId))[0]

// ── Profile ────────────────────────────────────────────────────────────────

export function computeActorProfile(
  engines: EngineConfig[], results: Record<string, QueryResult | undefined>, query = '',
): ActorProfile {
  let loading = false
  const answered: { engine: EngineConfig; d: any }[] = []
  for (const engine of engines) {
    const r = results[engine.id]
    if (!r) continue
    if (r.loading) { loading = true; continue }
    if (r.error || !r.data || (r.data as any).error) continue
    answered.push({ engine, d: r.data })
  }

  const identities = answered
    .map(({ engine, d }) => identify(engine.id, engine.label, d, query))
    .filter((x): x is SourceIdentity => !!x)
  const groups = cluster(identities)
  const main = groups[0] ?? []
  const others = groups.slice(1).map(g => ({ name: pick(g).name, sources: g.map(i => i.source) }))
  const status: ProfileStatus = main.length === 0 ? 'none'
    : main.every(i => i.persona) ? 'persona'
      : others.length > 0 ? 'conflict'
        : main.length >= 2 || main.some(i => i.curated && i.exact) ? 'confirmed' : 'single'
  const engineIds = new Set(main.map(i => i.engineId))
  const lead = main.length ? pick(main) : null
  const name = lead?.name ?? query

  const aliases = new Bucket(), ttps = new Bucket(), vectors = new Bucket(), vulns = new Bucket()
  const sectors = new Bucket(), countries = new Bucket(), orgs = new Bucket()
  // Attributed: the source states the relation (MITRE "uses", Malpedia families,
  // OpenCTI uses). Mentioned: the source links them by co-occurrence (RF links).
  const arsenalOwn = new Bucket(), arsenalMentions = new Bucket()
  const leakSites: LeakSite[] = []
  const artifacts = { ip: new Bucket(), domain: new Bucket(), url: new Bucket(), hash: new Bucket() }
  const incidents: Incident[] = []
  let mitreId: string | null = null
  let ransomware: RansomwareGroup | null = null
  const descriptions: Record<string, { text: string; src: string }> = {}
  const prov: ActorProfile['prov'] = {}
  const types = new Map<string, ActorType>()
  const since: { date: string; source: string }[] = []
  // OpenCTI fills an unknown first_seen with the epoch: only plausible dates count.
  const addSince = (v: unknown, src: string) => {
    const d = str(v)?.slice(0, 10)
    if (d && /^\d{4}-\d{2}-\d{2}$/.test(d) && d >= '1990-01-01' && !since.some(x => x.source === src)) since.push({ date: d, source: src })
  }
  const lineage = new Bucket()
  const addType = (value: unknown, src: string, key?: ActorTypeKey) => {
    const v = str(value)
    if (!v || (!key && GENERIC_TYPE.test(v))) return
    const k = key ?? typeKey(v)
    const id = k ?? nameKey(v)
    const cur = types.get(id) ?? { key: k, value: typeLabel(v), sources: [] }
    if (!cur.sources.includes(src)) cur.sources.push(src)
    types.set(id, cur)
  }
  // Country of origin / sponsor, per source: MITRE (description), Malpedia (country,
  // state sponsor), RF ("China Nation State Sponsored"), OpenCTI (originates-from).
  const origins = new Map<string, string[]>()
  const addOrigin = (value: unknown, src: string) => {
    const cc = toCountryCode(value)
    if (!cc) return
    const list = origins.get(cc) ?? []
    if (!list.includes(src)) list.push(src)
    origins.set(cc, list)
  }

  const technique = (id: unknown, tname: unknown, src: string) => {
    const tid = str(id)?.toUpperCase()
    if (tid && TECHNIQUE_ID.test(tid)) ttps.add(tid, src, { detail: str(tname) ?? undefined }, tid)
    else if (str(tname)) ttps.add(tname, src)
  }
  const vuln = (id: unknown, src: string) => {
    const v = str(id)?.toUpperCase()
    if (v && CVE_ID.test(v)) vulns.add(v, src, { pivot: 'cve' }, v)
  }
  const artifact = (type: ArtifactType, value: unknown, src: string, risk?: unknown) => {
    const v = str(value)
    if (!v || (type === 'hash' && !HASH.test(v))) return
    artifacts[type].add(v, src, typeof risk === 'number' ? { pivot: type, risk, riskSource: src } : { pivot: type }, v.toLowerCase())
  }
  const addCountry = (value: unknown, src: string, count?: number) => {
    const v = str(value)
    if (!v) return
    // ISO codes (ransomware.live) are localised on display; names (Malpedia, OpenCTI) as given.
    if (/^[A-Z]{2}$/.test(v)) {
      let en = v
      try { en = new Intl.DisplayNames(['en'], { type: 'region' }).of(v) ?? v } catch { /* keep the code */ }
      countries.add(v, src, { country: v, count }, nameKey(en))
    } else countries.add(v, src, { count })
  }

  for (const { engine, d } of answered) {
    if (!engineIds.has(engine.id)) continue
    const src = engine.label
    const id = engine.id
    if (id === 'mitreattack') {
      mitreId = str(d.attack_id)
      if (mitreId) prov.mitreId = src
      if (str(d.description)) descriptions.mitre = { text: d.description, src }
      originCountriesInText(d.description).forEach(cc => addOrigin(cc, src))
      arr(d.aliases).forEach(a => aliases.add(a, src))
      arr(d.techniques).forEach(t => technique(t?.attack_id, t?.name, src))
      arr(d.software).forEach(s => str(s?.name) && arsenalOwn.add(s.name, src, {}, familyKey(s.name)))
    } else if (id === 'malpedia') {
      if (str(d.description)) descriptions.malpedia = { text: d.description, src }
      addOrigin(d.country, src)
      addOrigin(d.state_sponsor, src)
      if (str(d.state_sponsor)) addType('state', src, 'state')
      addType(d.incident_type, src)
      aliases.add(d.name, src)
      arr(d.synonyms).forEach(a => aliases.add(a, src))
      arr(d.victims).forEach(v => (typeof v === 'string' && isCountryName(v) ? addCountry(v, src) : orgs.add(v, src)))
      arr(d.target_category).forEach(c => sectors.add(c, src))
      arr(d.families).forEach(f => str(f?.common_name) && arsenalOwn.add(f.common_name, src, {}, familyKey(f.common_name)))
    } else if (id === 'recordedfuture') {
      const categories = arr(d.categories).filter((c): c is string => typeof c === 'string')
      categories.forEach(c => { addOrigin(c.match(/^(.+?)\s+Nation[\s-]State Sponsored$/i)?.[1], src); addType(c, src) })
      if (d.persona === true) addType('persona', src, 'persona')
      aliases.add(d.name, src)
      arr(d.common_names).forEach(a => aliases.add(a, src))
      arr(d.aliases).forEach(a => aliases.add(a, src))
      const l = d.insikt_links ?? {}
      arr(l.mitre).forEach(m => technique(m?.name, rfTechniqueName(m?.label), src))
      arr(l.attack_vectors).forEach(v => vectors.add(v?.name, src))
      arr(l.vulnerabilities).forEach(v => vuln(v?.name, src))
      arr(l.malware).forEach(m => str(m?.name) && arsenalMentions.add(m.name, src, {}, familyKey(m.name)))
      arr(l.organizations).forEach(o => orgs.add(o?.name, src))
      for (const [group, type] of [['ips', 'ip'], ['domains', 'domain'], ['urls', 'url'], ['hashes', 'hash']] as const) {
        arr(l[group]).forEach(x => artifact(type, x?.name, src, x?.risk_score))
      }
    } else if (id.startsWith('opencti_')) {
      if (str(d.entity?.description)) descriptions.opencti = { text: d.entity.description, src }
      aliases.add(d.entity?.value, src)
      arr(d.actor?.types).forEach(x => addType(x, src))
      addSince(d.actor?.first_seen, src)
      if (d.entity?.type === 'Threat-Actor-Individual') addType('persona', src, 'persona')
      arr(d.actor?.aliases).forEach(a => aliases.add(a, src))
      for (const rel of arr(d.relations)) {
        const et = rel?.entity_type
        const rname = rel?.name
        if (et === 'Attack-Pattern') technique(rel?.x_mitre_id, rname, src)
        else if (et === 'Vulnerability') vuln(rname, src)
        else if ((et === 'Malware' || et === 'Tool') && str(rname)) arsenalOwn.add(rname, src, {}, familyKey(rname))
        else if (et === 'Sector') sectors.add(rname, src)
        // The actor's own country (intrusion set → originates-from → country), not a target.
        else if (et === 'Country' && rel?.type === 'originates-from' && rel?.direction !== 'in') addOrigin(rname, src)
        else if (et === 'Country') addCountry(rname, src)
        else if (et === 'Organization' && rel?.type === 'targets') orgs.add(rname, src)
        else if (et === 'Campaign') incidents.push({ title: rname, kind: 'campaign', source: src, link: rel?.link })
        else if (et === 'Incident') incidents.push({ title: rname, kind: 'incident', source: src, link: rel?.link })
        else if (et === 'Indicator') {
          const type = OBSERVABLE_TYPES[rel?.x_opencti_main_observable_type]
          if (type) artifact(type, patternValue(rel?.pattern) ?? rname, src)
        } else if (OBSERVABLE_TYPES[et]) artifact(OBSERVABLE_TYPES[et], rel?.observable_value ?? rname, src)
      }
      arr(d.reports).forEach(rep => str(rep?.name) && incidents.push({
        date: str(rep?.published) ?? undefined, title: rep.name, kind: 'report', source: src, link: rep?.link,
      }))
    } else if (id === 'ransomwarelive') {
      const groups = arr(d.groups)
      if (str(groups[0]?.description)) descriptions.rlive = { text: groups[0].description, src }
      prov.ransomware = src
      // A ransomware catalogue: every group in it is one.
      addType('ransomware', src, 'ransomware')
      if (groups.some(g => g?.raas === true)) addType('raas', src, 'raas')
      for (const g of groups) str(g?.lineage)?.split(/[/,;|]/).forEach(l => lineage.add(l.trim(), src))
      for (const g of groups) {
        aliases.add(g?.name, src)
        String(g?.altname ?? '').split(/[/,;|]/).forEach(a => aliases.add(a, src))
        for (const loc of arr(g?.locations)) {
          if (!str(loc?.address)) continue
          leakSites.push({
            address: loc.address, type: str(loc.type) ?? undefined, title: str(loc.title) ?? undefined,
            online: typeof loc.available === 'boolean' ? loc.available : null,
            lastCheck: str(loc.last_scrape) ?? str(loc.updated) ?? undefined, group: str(g?.name) ?? undefined, source: src,
          })
        }
      }
      arr(d.top_sectors).filter(s => s?.name !== 'Other').forEach(s => sectors.add(s?.name, src, { count: s?.count }))
      arr(d.top_countries).forEach(c => addCountry(c?.name, src, c?.count))
      const num = (v: unknown) => (typeof v === 'number' ? v : 0)
      ransomware = {
        victims: num(d.victim_count), d30: num(d.claims_30d), d90: num(d.claims_90d), d365: num(d.claims_365d),
        first: str(d.first_claim) ?? str(groups[0]?.first_seen) ?? undefined, last: str(d.last_claim) ?? undefined,
        raas: typeof groups[0]?.raas === 'boolean' ? groups[0].raas : null,
        leakSites: groups.reduce((n, g) => n + num(g?.leak_sites), 0),
        leakSitesUp: groups.reduce((n, g) => n + num(g?.leak_sites_up), 0),
        recent: arr(d.recent).filter(v => str(v?.victim)).map(toVictim),
        all: arr(Array.isArray(d.victims) ? d.victims : d.recent).filter(v => str(v?.victim)).map(toVictim),
        complete: Array.isArray(d.victims),
      }
      addSince(ransomware.first, src)
    }
  }

  // Aliases that are only spellings of the name ("TheGentlemen", "The Gentlemen
  // Ransomware Group") are counted, not listed.
  const nk = nameKey(name)
  const allAliases = aliases.list()
  const isVariant = (v: string) => { const k = nameKey(v); return k === nk || (nk.length >= 4 && (k.includes(nk) || nk.includes(k))) }
  const allNames = [...new Set([query, name, ...allAliases.map(a => a.value)].filter(Boolean))]

  // OTX: pulses that name the actor (or, with no actor, the query: unverified mentions).
  const otx = answered.find(a => a.engine.id === 'alienvault')
  const mentions: Incident[] = []
  if (otx) {
    const toIncident = (p: any): Incident => ({
      date: str(p?.created) ?? undefined, title: p.name, kind: 'report', source: otx.engine.label,
      link: str(p?.id) ? `https://otx.alienvault.com/pulse/${p.id}` : undefined,
    })
    if (status === 'none') mentions.push(...relevantPulses(otx.d.results, [query]).filter(p => str(p?.name)).map(toIncident))
    else {
      const pulses = relevantPulses(otx.d.results, allNames).filter(p => str(p?.name))
      if (pulses.length) engineIds.add(otx.engine.id)
      incidents.push(...pulses.map(toIncident))
    }
  } else if (results.alienvault?.loading) loading = true

  incidents.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''))
  const seen = new Set<string>()
  const dedup = incidents.filter(i => {
    const k = `${i.kind}|${nameKey(i.title)}|${(i.date ?? '').slice(0, 10)}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })

  // Arsenal: what a source attributes to it, plus mentioned families named after it
  // ("Gentlemen Ransomware") or mentioned by several sources; the rest are co-mentions.
  const own = arsenalOwn.list()
  const nameKeys = new Set([nk, ...allAliases.filter(a => isVariant(a.value)).map(a => nameKey(a.value))].map(k => k.replace(/^the(?=.{4})/, '')).filter(k => k.length >= 4))
  const related: ProfileItem[] = []
  for (const m of arsenalMentions.list()) {
    const k = familyKey(m.value)
    const same = own.find(a => familyKey(a.value) === k)
    if (same) m.sources.forEach(x => { if (!same.sources.includes(x)) same.sources.push(x) })
    else if (m.sources.length > 1 || (k.length >= 4 && [...nameKeys].some(n => n.includes(k) || k.includes(n)))) own.push(m)
    else related.push(m)
  }

  const originList = [...origins.entries()]
    .map(([cc, sources]) => ({ country: cc, sources }))
    .sort((a, b) => b.sources.length - a.sources.length || NAME_PRIORITY_LABEL(a.sources[0]) - NAME_PRIORITY_LABEL(b.sources[0]))

  // Descriptions, most authoritative first; the same text from two sources is one entry.
  const descList: ActorDescription[] = []
  for (const k of ['mitre', 'malpedia', 'opencti', 'rlive']) {
    const d = descriptions[k]
    if (!d) continue
    const key = nameKey(d.text).slice(0, 160)
    const same = descList.find(x => { const xk = nameKey(x.text).slice(0, 160); return xk.startsWith(key) || key.startsWith(xk) })
    if (same) { if (!same.sources.includes(d.src)) same.sources.push(d.src); if (d.text.length > same.text.length) same.text = d.text }
    else descList.push({ text: d.text, sources: [d.src] })
  }

  return {
    status,
    identities: main,
    others,
    name,
    mitreId,
    descriptions: descList,
    prov,
    origins: originList,
    types: [...types.values()].sort((a, b) => b.sources.length - a.sources.length),
    ransomware,
    since: since.sort((a, b) => a.date.localeCompare(b.date)),
    // A group listed as its own lineage (another brand of the same name) says nothing.
    lineage: lineage.list().filter(l => nameKey(l.value) !== nameKey(name)).map(l => ({ value: l.value, sources: l.sources })),
    aliases: allAliases.filter(a => !isVariant(a.value)),
    nameVariants: allAliases.filter(a => isVariant(a.value) && nameKey(a.value) !== nk).map(a => a.value),
    aliasTable: allAliases,
    ttps: ttps.list(),
    attackVectors: vectors.list(),
    vulns: vulns.list(),
    artifacts: {
      ip: artifacts.ip.list(), domain: artifacts.domain.list(), url: artifacts.url.list(), hash: artifacts.hash.list(),
    },
    incidents: dedup,
    sectors: sectors.list(),
    countries: countries.list(),
    organizations: orgs.list(),
    arsenal: own,
    arsenalMentioned: related,
    // Online first, then the most recently checked.
    leakSites: leakSites.sort((a, b) => Number(b.online === true) - Number(a.online === true) || (b.lastCheck ?? '').localeCompare(a.lastCheck ?? '')),
    consulted: engines.map(e => e.label),
    mentions,
    engineIds,
    allNames,
    loading,
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */
