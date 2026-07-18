import { useState } from 'react'
import { Loader2, AlertCircle, ChevronDown, FileCode2, ShieldAlert } from 'lucide-react'
import RawJsonModal from './RawJsonModal'

interface ShodanFacetEntry {
  value: string
  count: number
}

interface ShodanResponse {
  // host lookup (type=ip)
  ip_str?: string
  org?: string | null
  isp?: string | null
  asn?: string | null
  city?: string | null
  country_name?: string | null
  country_code?: string | null
  hostnames?: string[]
  ports?: number[]
  vulns?: string[]
  os?: string | null
  last_update?: string
  // host count (type=asn)
  total?: number
  facets?: {
    port?: ShodanFacetEntry[]
    org?: ShodanFacetEntry[]
    country?: ShodanFacetEntry[]
  }
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: ShodanResponse | null
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

function VulnBadge({ count }: { count: number }) {
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
      <ShieldAlert className="h-3 w-3" />
      {count} vuln{count === 1 ? '' : 's'}
    </span>
  )
}

function CountBadge({ label }: { label: string }) {
  return (
    <span className="inline-flex px-2.5 py-0.5 rounded-full border text-xs font-semibold text-blue-400 bg-blue-500/10 border-blue-500/30">
      {label}
    </span>
  )
}

function formatFacets(entries?: ShodanFacetEntry[]) {
  if (!entries || entries.length === 0) return null
  return entries.map(f => `${f.value} (${f.count})`).join(', ')
}

export default function ShodanCard({ loading, error, data }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null

  const isHost = !apiError && !!data?.ip_str
  const isAsnSummary = !apiError && !isHost && data?.total !== undefined

  const vulnCount = data?.vulns?.length ?? 0
  const portCount = data?.ports?.length ?? 0

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">Shodan</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          {!loading && (error || apiError) && <AlertCircle className="h-4 w-4 text-red-400" />}
          {!loading && isHost && vulnCount > 0 && <VulnBadge count={vulnCount} />}
          {!loading && isHost && portCount > 0 && (
            <CountBadge label={`${portCount} open port${portCount === 1 ? '' : 's'}`} />
          )}
          {!loading && isAsnSummary && <CountBadge label={`${data!.total} hosts`} />}
          {!loading && data && (
            <button
              onClick={e => { e.stopPropagation(); setRawOpen(true) }}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
              title="View raw JSON"
            >
              <FileCode2 className="h-3 w-3" />
              RAW
            </button>
          )}
          <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {open && (
        <div className="px-4 py-4">
          {loading && (
            <p className="text-sm text-muted-foreground">Querying Shodan...</p>
          )}

          {!loading && (error || apiError) && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isHost && (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label="Organization" value={data?.org} />
                <Field label="ISP" value={data?.isp} />
                <Field label="ASN" value={data?.asn} />
                <Field label="Country" value={data?.country_name} />
                <Field label="City" value={data?.city} />
                <Field label="Operating System" value={data?.os} />
                <Field
                  label="Last Update"
                  value={data?.last_update ? new Date(data.last_update).toLocaleString() : undefined}
                />
              </div>
              {portCount > 0 && <Field label="Open Ports" value={data!.ports!.join(', ')} />}
              {vulnCount > 0 && <Field label="Vulnerabilities (CVEs)" value={data!.vulns!.join(', ')} />}
              {(data?.hostnames?.length ?? 0) > 0 && (
                <Field label="Hostnames" value={data!.hostnames!.join(', ')} />
              )}
            </div>
          )}

          {!loading && isAsnSummary && (
            <div className="flex flex-col gap-4">
              <Field label="Total Hosts Found" value={data?.total} />
              {formatFacets(data?.facets?.org) && (
                <Field label="Top Organizations" value={formatFacets(data?.facets?.org)} />
              )}
              {formatFacets(data?.facets?.port) && (
                <Field label="Top Ports" value={formatFacets(data?.facets?.port)} />
              )}
              {formatFacets(data?.facets?.country) && (
                <Field label="Top Countries" value={formatFacets(data?.facets?.country)} />
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="Shodan" />
    </div>
  )
}
