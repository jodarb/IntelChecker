import { useState } from 'react'
import { Loader2, AlertCircle, CheckCircle2, ShieldX, ChevronDown, FileCode2 } from 'lucide-react'
import RawJsonModal from './RawJsonModal'

interface AbuseData {
  ipAddress: string
  isPublic: boolean
  ipVersion: number
  isWhitelisted: boolean
  abuseConfidenceScore: number
  countryCode: string | null
  usageType: string | null
  isp: string | null
  domain: string | null
  hostnames: string[]
  isTor: boolean
  totalReports: number
  numDistinctUsers: number
  lastReportedAt: string | null
}

interface AbuseIPDBResponse {
  data?: AbuseData
  errors?: { detail: string; status: number }[]
}

interface Props {
  loading: boolean
  error: string | null
  data: AbuseIPDBResponse | null
}

function ScoreBadge({ score }: { score: number }) {
  if (score >= 76) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
        <ShieldX className="h-3 w-3" />
        {score}/100 · Malicious
      </span>
    )
  }
  if (score >= 26) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-yellow-400 bg-yellow-500/10 border-yellow-500/30">
        <AlertCircle className="h-3 w-3" />
        {score}/100 · Suspicious
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
      <CheckCircle2 className="h-3 w-3" />
      {score}/100 · Clean
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

export default function AbuseIPDBCard({ loading, error, data }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.errors?.[0]?.detail ?? null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">AbuseIPDB</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          {!loading && (error || apiError) && <AlertCircle className="h-4 w-4 text-red-400" />}
          {!loading && data?.data && <ScoreBadge score={data.data.abuseConfidenceScore} />}
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
            <p className="text-sm text-muted-foreground">Querying AbuseIPDB...</p>
          )}

          {!loading && (error || apiError) && (
            <p className="text-sm text-red-400">{error ?? apiError}</p>
          )}

          {!loading && data?.data && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
              <Field label="Confidence Score" value={<ScoreBadge score={data.data.abuseConfidenceScore} />} />
              <Field label="Total Reports" value={data.data.totalReports} />
              <Field label="Distinct Reporters" value={data.data.numDistinctUsers} />
              <Field label="Country" value={data.data.countryCode} />
              <Field label="ISP" value={data.data.isp} />
              <Field label="Domain" value={data.data.domain} />
              <Field label="Usage Type" value={data.data.usageType} />
              <Field label="TOR Exit Node" value={data.data.isTor ? 'Yes' : 'No'} />
              <Field
                label="Last Reported"
                value={
                  data.data.lastReportedAt
                    ? new Date(data.data.lastReportedAt).toLocaleString()
                    : 'Never'
                }
              />
              {data.data.hostnames.length > 0 && (
                <div className="col-span-2 sm:col-span-3">
                  <Field label="Hostnames" value={data.data.hostnames.join(', ')} />
                </div>
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="AbuseIPDB" />
    </div>
  )
}
