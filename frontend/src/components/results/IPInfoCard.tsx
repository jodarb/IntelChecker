import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge from './WeightBadge'

interface IPInfoResponse {
  ip?: string
  hostname?: string
  city?: string
  region?: string
  country?: string
  loc?: string
  org?: string
  postal?: string
  timezone?: string
  bogon?: boolean
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: IPInfoResponse | null
  score?: number | null
  weight?: number | null
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

export default function IPInfoCard({ loading, error, data, score = null, weight = null }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const info = (!apiError && data?.ip) ? data : null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">IPinfo</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={!!info} />}
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
            <p className="text-sm text-muted-foreground">Querying IPinfo...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiError?.message}</p>
          )}

          {!loading && info && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
              <Field label="Organization" value={info.org} />
              <Field label="Country" value={info.country} />
              <Field label="Region" value={info.region} />
              <Field label="City" value={info.city} />
              <Field label="Postal" value={info.postal} />
              <Field label="Timezone" value={info.timezone} />
              <Field label="Hostname" value={info.hostname} />
              <Field label="Coordinates" value={info.loc} />
            </div>
          )}

          {!loading && info?.ip && (
            <a
              href={`https://ipinfo.io/${info.ip}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit mt-3"
            >
              <ExternalLink className="h-3 w-3" /> View on IPinfo
            </a>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="IPinfo" />
    </div>
  )
}
