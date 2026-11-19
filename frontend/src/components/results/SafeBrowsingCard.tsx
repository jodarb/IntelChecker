import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink, ShieldAlert } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'

interface ThreatMatch {
  threatType: string
  platformType: string
  threatEntryType: string
  cacheDuration?: string
}

interface SafeBrowsingResponse {
  matches?: ThreatMatch[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: SafeBrowsingResponse | null
  score?: number | null
  weight?: CardWeight | null
  indicator?: string
}

function MatchRow({ match }: { match: ThreatMatch }) {
  return (
    <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 flex items-center gap-2">
      <ShieldAlert className="h-3.5 w-3.5 text-red-400 shrink-0" />
      <span className="text-xs font-medium text-red-400 capitalize">
        {match.threatType.replace(/_/g, ' ').toLowerCase()}
      </span>
      <span className="text-xs text-muted-foreground">· {match.platformType}</span>
    </div>
  )
}

export default function SafeBrowsingCard({ loading, error, data, score = null, weight = null, indicator }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const matches = !apiError ? (data?.matches ?? []) : []
  const hasChecked = !isRealError && !!data

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">Google Safe Browsing</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={hasChecked} />}
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
        <div className="px-4 py-4 flex flex-col gap-3">
          {loading && (
            <p className="text-sm text-muted-foreground">Querying Google Safe Browsing...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && hasChecked && matches.length === 0 && (
            <p className="text-sm text-muted-foreground">Not found on any Google Safe Browsing threat list.</p>
          )}

          {!loading && matches.length > 0 && (
            <div className="flex flex-col gap-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wide">
                Threat Matches ({matches.length})
              </span>
              {matches.map((m, i) => <MatchRow key={i} match={m} />)}
            </div>
          )}

          {!loading && hasChecked && indicator && (
            <a
              href={`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(indicator)}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
            >
              <ExternalLink className="h-3 w-3" /> View on Google Transparency Report
            </a>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="Google Safe Browsing" />
    </div>
  )
}
