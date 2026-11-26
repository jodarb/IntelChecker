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
      { field: 'country', extract: (d) => ((d as any)?.net?.country) || null },
      { field: 'asn', extract: (d) => ((d as any)?.net?.org as string)?.match(/^AS\d+/)?.[0] || null },
      { field: 'isp', extract: (d) => ((d as any)?.net?.org as string)?.replace(/^AS\d+\s*/, '') || null },
    ],
    domain: [
      { field: 'asn', extract: (d) => ((d as any)?.reg?.asn) || null },
      { field: 'isp', extract: (d) => ((d as any)?.reg?.org) || null },
    ],
    url: [
      { field: 'asn', extract: (d) => ((d as any)?.reg?.asn) || null },
      { field: 'isp', extract: (d) => ((d as any)?.reg?.org) || null },
    ],
  },
  abuseipdb: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.data?.countryCode) || null },
      { field: 'isp', extract: (d) => ((d as any)?.data?.isp) || null },
      { field: 'torExit', extract: (d) => ((d as any)?.data?.isTor ? 'Yes' : null) },
    ],
  },
  virustotal: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.data?.attributes?.country) || null },
      {
        field: 'asn',
        extract: (d) => {
          const n = (d as any)?.data?.attributes?.asn
          return n != null ? `AS${n}` : null
        },
      },
      { field: 'isp', extract: (d) => ((d as any)?.data?.attributes?.as_owner) || null },
    ],
  },
  alienvault: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.country_code) || null },
      // OTX returns "AS15169 GOOGLE - Google LLC, US" — normalize to "AS15169"
      { field: 'asn', extract: (d) => ((d as any)?.asn as string)?.split(' ')[0] || null },
    ],
  },
  ipinfo: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.country) || null },
      // IPinfo returns "AS15169 Google LLC" — normalize to "AS15169"
      { field: 'asn', extract: (d) => ((d as any)?.org as string)?.split(' ')[0] || null },
      // ...and the ISP/org name is everything after that leading ASN token.
      {
        field: 'isp',
        extract: (d) => {
          const org = (d as any)?.org as string | undefined
          if (!org) return null
          const rest = org.split(' ').slice(1).join(' ')
          return rest || null
        },
      },
    ],
  },
  shodan: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.country_code) || null },
      { field: 'asn', extract: (d) => ((d as any)?.asn) || null },
      { field: 'isp', extract: (d) => ((d as any)?.isp) || null },
      {
        field: 'openPorts',
        extract: (d) => {
          const ports = (d as any)?.ports as number[] | undefined
          if (!ports || ports.length === 0) return null
          return [...ports].sort((a, b) => a - b).join(', ')
        },
      },
    ],
  },
  ripestat: {
    ip: [
      {
        field: 'asn',
        extract: (d) => {
          const asns = (d as any)?.network_info?.asns as string[] | undefined
          return asns && asns.length > 0 ? `AS${asns[0]}` : null
        },
      },
    ],
  },
  crowdsec: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.location?.country) || null },
      {
        field: 'asn',
        extract: (d) => {
          const n = (d as any)?.as_num
          return n != null ? `AS${n}` : null
        },
      },
      { field: 'isp', extract: (d) => ((d as any)?.as_name) || null },
    ],
  },
  torexitlist: {
    ip: [
      { field: 'torExit', extract: (d) => ((d as any)?.is_tor_exit ? 'Yes' : null) },
    ],
  },
  anyrun: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.destinationIPgeo?.[0]) || null },
      { field: 'asn', extract: (d) => ((d as any)?.destinationIpAsn?.[0]?.asn) || null },
    ],
  },
}
