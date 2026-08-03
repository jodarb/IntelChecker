import type { IndicatorType } from '@/registry'

export type SummaryField = 'country' | 'asn' | 'openPorts'

export interface SummaryExtractorDef {
  field: SummaryField
  extract: (data: unknown) => string | null
}

export const SUMMARY_FIELD_META: Record<SummaryField, { label: string; format: (v: string) => string }> = {
  country: {
    label: 'GeoIP',
    format: (code) => {
      try {
        return new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase()) ?? code
      } catch {
        return code
      }
    },
  },
  asn: {
    label: 'ASN',
    format: (v) => v,
  },
  openPorts: {
    label: 'Open Ports',
    format: (v) => v,
  },
}

// Display order of summary fields
export const SUMMARY_FIELDS: SummaryField[] = ['country', 'asn', 'openPorts']

// Registry: engineId → indicatorType → extractors
// Add new fields here when new summary data points are needed.
export const SUMMARY_REGISTRY: Record<string, Partial<Record<IndicatorType, SummaryExtractorDef[]>>> = {
  abuseipdb: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.data?.countryCode) || null },
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
    ],
  },
  shodan: {
    ip: [
      { field: 'country', extract: (d) => ((d as any)?.country_code) || null },
      { field: 'asn', extract: (d) => ((d as any)?.asn) || null },
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
}
