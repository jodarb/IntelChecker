import { useState } from 'react'
import { Loader2, AlertCircle, SearchX, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'

interface EvidenceDetail {
  rule?: string
  evidenceString?: string
  criticality?: number
  criticalityLabel?: string
  timestamp?: string
}

interface RiskInfo {
  score?: number
  riskString?: string
  riskSummary?: string
  criticality?: number
  criticalityLabel?: string
  evidenceDetails?: EvidenceDetail[]
}

interface RecordedFutureResponse {
  risk?: RiskInfo
  entity?: { id?: string; name?: string; type?: string }
  intelCard?: string
  timestamps?: { firstSeen?: string; lastSeen?: string }
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: RecordedFutureResponse | null
}

const CRITICALITY_STYLES: Record<string, string> = {
  None: 'text-green-400 bg-green-500/10 border-green-500/30',
  Unusual: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  Suspicious: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  Malicious: 'text-red-400 bg-red-500/10 border-red-500/30',
  Critical: 'text-red-400 bg-red-500/10 border-red-500/30',
}

function RiskBadge({ risk }: { risk: RiskInfo }) {
  const label = risk.criticalityLabel ?? 'None'
  const style = CRITICALITY_STYLES[label] ?? CRITICALITY_STYLES.None
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold ${style}`}>
      Risk {risk.score ?? 0}/99 · {label}
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

function EvidenceRow({ evidence }: { evidence: EvidenceDetail }) {
  const label = evidence.criticalityLabel ?? 'None'
  const style = CRITICALITY_STYLES[label] ?? CRITICALITY_STYLES.None
  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-1.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium text-foreground">{evidence.rule}</span>
        <span className={`px-1.5 py-0.5 rounded-full border text-xs font-medium shrink-0 ${style}`}>{label}</span>
      </div>
      {evidence.evidenceString && (
        <p className="text-xs text-muted-foreground">{evidence.evidenceString}</p>
      )}
    </div>
  )
}

export default function RecordedFutureCard({ loading, error, data }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const risk = !apiError ? data?.risk : undefined
  const evidence = risk?.evidenceDetails ?? []

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">Recorded Future</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          {!loading && isRealError && <AlertCircle className="h-4 w-4 text-red-400" />}
          {!loading && isNotFound && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-medium text-muted-foreground bg-muted/40 border-border">
              <SearchX className="h-3 w-3" />
              Not Found
            </span>
          )}
          {!loading && risk && <RiskBadge risk={risk} />}
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
        <div className="px-4 py-4 flex flex-col gap-4">
          {loading && (
            <p className="text-sm text-muted-foreground">Querying Recorded Future...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiError?.message}</p>
          )}

          {!loading && risk && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label="Risk Score" value={<RiskBadge risk={risk} />} />
                <Field label="Rules Triggered" value={risk.riskString} />
                <Field label="First Seen" value={data?.timestamps?.firstSeen ? new Date(data.timestamps.firstSeen).toLocaleString() : undefined} />
                <Field label="Last Seen" value={data?.timestamps?.lastSeen ? new Date(data.timestamps.lastSeen).toLocaleString() : undefined} />
              </div>

              {risk.riskSummary && (
                <p className="text-sm text-muted-foreground">{risk.riskSummary}</p>
              )}

              {evidence.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    Risk Rules ({evidence.length})
                  </span>
                  {evidence.map((e, i) => (
                    <EvidenceRow key={e.rule ?? i} evidence={e} />
                  ))}
                </div>
              )}

              {data?.intelCard && (
                <a
                  href={data.intelCard}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> View Intelligence Card
                </a>
              )}
            </>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="Recorded Future" />
    </div>
  )
}
