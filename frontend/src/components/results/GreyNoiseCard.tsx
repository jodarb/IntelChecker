import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink, ShieldX, ShieldCheck, ShieldQuestion } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'

interface GreyNoiseResponse {
  ip?: string
  noise?: boolean
  riot?: boolean
  classification?: 'malicious' | 'benign' | 'unknown'
  name?: string
  link?: string
  last_seen?: string
  message?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: GreyNoiseResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const CLASSIFICATION_STYLES: Record<string, string> = {
  malicious: 'text-red-400 bg-red-500/10 border-red-500/30',
  benign: 'text-green-400 bg-green-500/10 border-green-500/30',
  unknown: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
}
const CLASSIFICATION_ICONS: Record<string, typeof ShieldX> = {
  malicious: ShieldX,
  benign: ShieldCheck,
  unknown: ShieldQuestion,
}

function ClassificationBadge({ classification }: { classification: string }) {
  const style = CLASSIFICATION_STYLES[classification] ?? CLASSIFICATION_STYLES.unknown
  const Icon = CLASSIFICATION_ICONS[classification] ?? ShieldQuestion
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold capitalize ${style}`}>
      <Icon className="h-3 w-3" />
      {classification}
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

export default function GreyNoiseCard({ loading, error, data, score = null, weight = null }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const observed = !apiError && !!(data?.noise || data?.riot)

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">GreyNoise</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={observed} />}
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
            <p className="text-sm text-muted-foreground">Querying GreyNoise...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && !isRealError && !observed && (
            <p className="text-sm text-muted-foreground">{data?.message ?? 'IP not observed scanning the internet or contained in RIOT data set.'}</p>
          )}

          {!loading && observed && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field
                  label="Classification"
                  value={data?.classification ? <ClassificationBadge classification={data.classification} /> : undefined}
                />
                <Field label="Internet Scanner" value={data?.noise ? 'Yes' : 'No'} />
                <Field label="Known Business Service (RIOT)" value={data?.riot ? 'Yes' : 'No'} />
                <Field label="Actor / Service Name" value={data?.name} />
                <Field label="Last Seen" value={data?.last_seen} />
              </div>

              {data?.link && (
                <a
                  href={data.link}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> View on GreyNoise
                </a>
              )}
            </>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="GreyNoise" />
    </div>
  )
}
