import type { IndicatorType } from '@/registry'

export type SummaryField = 'country' | 'asn' | 'isp' | 'torExit' | 'openPorts' | 'cvss' | 'kev' | 'epss'
  | 'sector' | 'hqCountry' | 'presence' | 'legalEntity' | 'employees' | 'ransomware' | 'infostealers' | 'breaches' | 'news'

export interface SummaryExtractorDef {
  field: SummaryField
  extract: (data: unknown) => string | null
}

// Labels are i18n keys `summaryField.<field>`. Extractors return raw values
// ('Yes' for torExit, ISO country codes); `format` localises them for display.
const regionName = (code: string, locale: string) => {
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}

export const SUMMARY_FIELD_META: Record<SummaryField, { format: (v: string, ctx: { locale: string; yes: string }) => string }> = {
  country: { format: (code, { locale }) => regionName(code, locale) },
  asn: { format: (v) => v },
  isp: { format: (v) => v },
  torExit: { format: (v, { yes }) => (v === 'Yes' ? yes : v) },
  openPorts: { format: (v) => v },
  cvss: { format: (v) => v },
  kev: { format: (v, { yes }) => (v === 'Yes' ? yes : v) },
  epss: { format: (v) => v },
  sector: { format: (v) => v },
  hqCountry: { format: (code, { locale }) => regionName(code, locale) },
  // Comma-separated ISO codes → localised names
  presence: { format: (v, { locale }) => v.split(',').map(c => regionName(c, locale)).join(', ') },
  legalEntity: { format: (v) => v },
  employees: { format: (v, { locale }) => Number(v).toLocaleString(locale) },
  ransomware: { format: (v) => v },
  infostealers: { format: (v) => v },
  breaches: { format: (v) => v },
  news: { format: (v) => v },
}

interface WikidataSummary {
  found?: boolean
  sectors?: string[]
  presence?: { code?: string | null; via?: string[] }[]
  lei?: string | null
  employees?: number | null
}
interface GleifSummary {
  found?: boolean
  lei?: string
  hq_address?: { country?: string | null } | null
  children_countries?: Record<string, number>
}
const asWikidata = (d: unknown) => d as WikidataSummary | null
const asGleif = (d: unknown) => d as GleifSummary | null

// Source responses are untyped JSON: `at` walks a path without failing on a missing
// level, `val` keeps a non-empty string or number as text (falsy → null, as `x || null`).
const at = (d: unknown, ...path: (string | number)[]): unknown =>
  path.reduce<unknown>((o, k) => (o != null && typeof o === 'object' ? (o as Record<string | number, unknown>)[k] : undefined), d)
const val = (v: unknown): string | null => ((typeof v === 'string' || typeof v === 'number') && v ? String(v) : null)
const text = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined)
/** 15169 → "AS15169" (0 / missing → null) */
const asNumber = (v: unknown): string | null => (v != null && v !== '' ? `AS${v}` : null)

// Display order of summary fields
export const SUMMARY_FIELDS: SummaryField[] = [
  'country', 'asn', 'isp', 'torExit', 'openPorts', 'cvss', 'kev', 'epss',
  'ransomware', 'infostealers', 'breaches', 'news', 'sector', 'hqCountry', 'presence', 'legalEntity', 'employees',
]

// Registry: engineId → indicatorType → extractors
// Add new fields here when new summary data points are needed.
export const SUMMARY_REGISTRY: Record<string, Partial<Record<IndicatorType, SummaryExtractorDef[]>>> = {
  // Companies. Exposure values are plain counts and dates (ISO, not localised: source data).
  wikidata: {
    company: [
      { field: 'sector', extract: (d) => (asWikidata(d)?.found ? (asWikidata(d)?.sectors ?? []).slice(0, 3).join(', ') || null : null) },
      {
        field: 'hqCountry',
        extract: (d) => {
          const p = asWikidata(d)?.presence ?? []
          return p.find(x => x.code && x.via?.includes('headquarters'))?.code
            ?? p.find(x => x.code && x.via?.includes('company'))?.code ?? null
        },
      },
      {
        field: 'presence',
        extract: (d) => {
          const codes = (asWikidata(d)?.presence ?? []).filter(x => x.code && x.via?.includes('subsidiary')).map(x => x.code as string)
          return codes.length ? codes.slice(0, 15).join(',') : null
        },
      },
      { field: 'legalEntity', extract: (d) => asWikidata(d)?.lei || null },
      { field: 'employees', extract: (d) => (typeof asWikidata(d)?.employees === 'number' ? String(asWikidata(d)?.employees) : null) },
    ],
  },
  gleif: {
    company: [
      { field: 'hqCountry', extract: (d) => (asGleif(d)?.found ? asGleif(d)?.hq_address?.country ?? null : null) },
      {
        field: 'presence',
        extract: (d) => {
          const c = Object.keys(asGleif(d)?.children_countries ?? {})
          return asGleif(d)?.found && c.length ? c.slice(0, 15).join(',') : null
        },
      },
      { field: 'legalEntity', extract: (d) => (asGleif(d)?.found ? asGleif(d)?.lei ?? null : null) },
    ],
  },
  ransomwarelive: {
    company: [{
      field: 'ransomware',
      extract: (d) => {
        const p = d as { listed?: unknown; match_count?: number; groups?: string[]; last_claim?: string | null } | null
        if (p?.listed !== true) return null
        return `${p.match_count} · ${(p.groups ?? []).join(', ')} · ${p.last_claim ?? '?'}`
      },
    }],
  },
  hudsonrock: {
    company: [{
      field: 'infostealers',
      extract: (d) => {
        const p = d as { total?: unknown; employees?: number; users?: number; last_employee_compromised?: string | null } | null
        if (typeof p?.total !== 'number' || p.total <= 0) return null
        return `${p.employees ?? 0} / ${p.users ?? 0}${p.last_employee_compromised ? ` · ${p.last_employee_compromised}` : ''}`
      },
    }],
  },
  hibp: {
    company: [{
      field: 'breaches',
      extract: (d) => {
        const p = d as { count?: unknown; latest_breach?: string | null } | null
        return typeof p?.count === 'number' && p.count > 0 ? `${p.count} · ${p.latest_breach ?? '?'}` : null
      },
    }],
  },
  gdelt: {
    company: [{
      field: 'news',
      extract: (d) => {
        const p = d as { in_title?: unknown; latest?: string | null } | null
        return typeof p?.in_title === 'number' && p.in_title > 0 ? `${p.in_title} · ${(p.latest ?? '').slice(0, 10)}` : null
      },
    }],
  },
  // Vulnerabilities: NVD also carries CISA's KEV flag, so "exploited" is corroborated by two sources.
  nvd: {
    cve: [
      {
        field: 'cvss',
        extract: (d) => {
          const c = (d as { cvss?: { score?: unknown; severity?: string; version?: string } } | null)?.cvss
          if (typeof c?.score !== 'number') return null
          return `${c.score.toFixed(1)}${c.severity ? ` ${c.severity}` : ''} · v${c.version}`
        },
      },
      { field: 'kev', extract: (d) => ((d as { kev?: { date_added?: string } } | null)?.kev?.date_added ? 'Yes' : null) },
    ],
  },
  cisakev: {
    cve: [{ field: 'kev', extract: (d) => ((d as { listed?: unknown } | null)?.listed === true ? 'Yes' : null) }],
  },
  vulncheckkev: {
    cve: [{ field: 'kev', extract: (d) => ((d as { listed?: unknown } | null)?.listed === true ? 'Yes' : null) }],
  },
  epss: {
    cve: [
      {
        field: 'epss',
        extract: (d) => {
          const p = d as { found?: boolean; epss?: unknown; percentile?: unknown } | null
          if (!p?.found || typeof p?.epss !== 'number') return null
          const pctile = typeof p.percentile === 'number' ? ` · p${Math.floor(p.percentile * 100)}` : ''
          return `${(p.epss * 100).toFixed(2)} %${pctile}`
        },
      },
    ],
  },
  // TweetFeed only carries geo/network context once the indicator has been
  // reported (net for IPs, reg for domains/URLs).
  tweetfeed: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'net', 'country')) },
      { field: 'asn', extract: (d) => text(at(d, 'net', 'org'))?.match(/^AS\d+/)?.[0] || null },
      { field: 'isp', extract: (d) => text(at(d, 'net', 'org'))?.replace(/^AS\d+\s*/, '') || null },
    ],
    domain: [
      { field: 'asn', extract: (d) => val(at(d, 'reg', 'asn')) },
      { field: 'isp', extract: (d) => val(at(d, 'reg', 'org')) },
    ],
    url: [
      { field: 'asn', extract: (d) => val(at(d, 'reg', 'asn')) },
      { field: 'isp', extract: (d) => val(at(d, 'reg', 'org')) },
    ],
  },
  abuseipdb: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'data', 'countryCode')) },
      { field: 'isp', extract: (d) => val(at(d, 'data', 'isp')) },
      { field: 'torExit', extract: (d) => (at(d, 'data', 'isTor') ? 'Yes' : null) },
    ],
  },
  virustotal: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'data', 'attributes', 'country')) },
      { field: 'asn', extract: (d) => asNumber(at(d, 'data', 'attributes', 'asn')) },
      { field: 'isp', extract: (d) => val(at(d, 'data', 'attributes', 'as_owner')) },
    ],
  },
  alienvault: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'country_code')) },
      // OTX returns "AS15169 GOOGLE - Google LLC, US" — normalize to "AS15169"
      { field: 'asn', extract: (d) => text(at(d, 'asn'))?.split(' ')[0] || null },
    ],
  },
  ipinfo: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'country')) },
      // IPinfo returns "AS15169 Google LLC" — normalize to "AS15169"
      { field: 'asn', extract: (d) => text(at(d, 'org'))?.split(' ')[0] || null },
      // ...and the ISP/org name is everything after that leading ASN token.
      { field: 'isp', extract: (d) => text(at(d, 'org'))?.split(' ').slice(1).join(' ') || null },
    ],
  },
  shodan: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'country_code')) },
      { field: 'asn', extract: (d) => val(at(d, 'asn')) },
      { field: 'isp', extract: (d) => val(at(d, 'isp')) },
      {
        field: 'openPorts',
        extract: (d) => {
          const ports = at(d, 'ports')
          if (!Array.isArray(ports) || ports.length === 0) return null
          return ports.filter((p): p is number => typeof p === 'number').sort((a, b) => a - b).join(', ') || null
        },
      },
    ],
  },
  ripestat: {
    ip: [
      {
        field: 'asn',
        extract: (d) => {
          const asns = at(d, 'network_info', 'asns')
          return Array.isArray(asns) && asns.length > 0 ? `AS${asns[0]}` : null
        },
      },
    ],
  },
  crowdsec: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'location', 'country')) },
      { field: 'asn', extract: (d) => asNumber(at(d, 'as_num')) },
      { field: 'isp', extract: (d) => val(at(d, 'as_name')) },
    ],
  },
  torexitlist: {
    ip: [
      { field: 'torExit', extract: (d) => (at(d, 'is_tor_exit') ? 'Yes' : null) },
    ],
  },
  anyrun: {
    ip: [
      { field: 'country', extract: (d) => val(at(d, 'destinationIPgeo', 0)) },
      { field: 'asn', extract: (d) => val(at(d, 'destinationIpAsn', 0, 'asn')) },
    ],
  },
}
