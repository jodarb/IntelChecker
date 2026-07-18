import { useState } from 'react'
import { Loader2, AlertCircle, CheckCircle2, ShieldX, ShieldAlert, SearchX, ChevronDown, FileCode2 } from 'lucide-react'
import RawJsonModal from './RawJsonModal'

interface AnalysisStats {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  timeout: number
}

interface VTAttributes {
  last_analysis_stats: AnalysisStats
  country: string | null
  asn: number | null
  as_owner: string | null
  network: string | null
  reputation: number
  last_analysis_date: number | null
  total_votes: { harmless: number; malicious: number }
}

interface VTData {
  id: string
  attributes: VTAttributes
}

interface VTResponse {
  data?: VTData
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: VTResponse | null
}

function DetectionBadge({ stats }: { stats: AnalysisStats }) {
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected + stats.timeout
  const flagged = stats.malicious + stats.suspicious

  if (stats.malicious >= 4) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
        <ShieldX className="h-3 w-3" />
        {stats.malicious}/{total} · Malicious
      </span>
    )
  }
  if (flagged > 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-yellow-400 bg-yellow-500/10 border-yellow-500/30">
        <ShieldAlert className="h-3 w-3" />
        {flagged}/{total} · Suspicious
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
      <CheckCircle2 className="h-3 w-3" />
      0/{total} · Clean
    </span>
  )
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

export default function VirusTotalCard({ loading, error, data }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const attrs = data?.data?.attributes ?? null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">VirusTotal</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          {!loading && isRealError && <AlertCircle className="h-4 w-4 text-red-400" />}
          {!loading && isNotFound && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-medium text-muted-foreground bg-muted/40 border-border">
              <SearchX className="h-3 w-3" />
              Not Found
            </span>
          )}
          {!loading && attrs && <DetectionBadge stats={attrs.last_analysis_stats} />}
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
            <p className="text-sm text-muted-foreground">Querying VirusTotal...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiError?.message}</p>
          )}

          {!loading && attrs && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
              <Field
                label="Detection"
                value={<DetectionBadge stats={attrs.last_analysis_stats} />}
              />
              <Field label="Malicious Engines" value={attrs.last_analysis_stats.malicious} />
              <Field label="Suspicious Engines" value={attrs.last_analysis_stats.suspicious} />
              <Field label="Community Reputation" value={attrs.reputation} />
              <Field label="Country" value={attrs.country} />
              <Field label="AS Owner" value={attrs.as_owner} />
              <Field label="ASN" value={attrs.asn ? `AS${attrs.asn}` : null} />
              <Field label="Network" value={attrs.network} />
              <Field
                label="Last Analysis"
                value={
                  attrs.last_analysis_date
                    ? new Date(attrs.last_analysis_date * 1000).toLocaleString()
                    : '—'
                }
              />
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="VirusTotal" />
    </div>
  )
}
