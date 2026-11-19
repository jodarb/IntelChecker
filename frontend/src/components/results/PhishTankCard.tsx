import { useState } from 'react'
import { Loader2, ShieldCheck, ShieldAlert, ShieldQuestion, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'

interface PhishTankResponse {
  url?: string
  in_database?: boolean
  phish_id?: number
  phish_detail_page?: string
  verified?: boolean
  verified_at?: string | null
  valid?: boolean
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: PhishTankResponse | null
  score?: number | null
  weight?: CardWeight | null
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

function VerdictBadge({ data }: { data: PhishTankResponse }) {
  if (!data.in_database) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
        <ShieldCheck className="h-3 w-3" />
        Not Listed
      </span>
    )
  }
  if (data.valid && data.verified) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
        <ShieldAlert className="h-3 w-3" />
        Confirmed Phishing
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-amber-400 bg-amber-500/10 border-amber-500/30">
      <ShieldQuestion className="h-3 w-3" />
      Submitted, Not Confirmed
    </span>
  )
}

export default function PhishTankCard({ loading, error, data, score = null, weight = null }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const isKnown = !apiError && data?.in_database != null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">PhishTank</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} />}
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
            <p className="text-sm text-muted-foreground">Checking PhishTank...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isKnown && !data?.in_database && (
            <p className="text-sm text-muted-foreground">This URL is not in PhishTank's database.</p>
          )}

          {!loading && isKnown && data?.in_database && (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label="Status" value={<VerdictBadge data={data!} />} />
                <Field label="Verified" value={data?.verified ? 'Yes' : 'No'} />
                <Field
                  label="Verified At"
                  value={data?.verified_at ? new Date(data.verified_at).toLocaleString() : undefined}
                />
                <Field label="Phish ID" value={data?.phish_id} />
              </div>
              {data?.phish_detail_page && (
                <a
                  href={data.phish_detail_page}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> View on PhishTank
                </a>
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="PhishTank" />
    </div>
  )
}
