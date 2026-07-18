import { useState } from 'react'
import { Loader2, AlertCircle, CheckCircle2, ShieldX, SearchX, ChevronDown, FileCode2 } from 'lucide-react'
import RawJsonModal from './RawJsonModal'

interface Pulse {
  id: string
  name: string
  description: string
  tags: string[]
  created: string
  author_name: string
  references: string[]
}

interface PulseInfo {
  count: number
  pulses: Pulse[]
}

interface OTXResponse {
  indicator?: string
  reputation?: number
  country_name?: string | null
  city?: string | null
  asn?: string | null
  pulse_info?: PulseInfo
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: OTXResponse | null
}

function PulseBadge({ count }: { count: number }) {
  if (count === 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
        <CheckCircle2 className="h-3 w-3" />
        No Pulses
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
      <ShieldX className="h-3 w-3" />
      {count} Pulse{count > 1 ? 's' : ''}
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

function PulseRow({ pulse }: { pulse: Pulse }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <span className="text-sm text-foreground font-medium">{pulse.name}</span>
        <span className="text-xs text-muted-foreground shrink-0">
          {new Date(pulse.created).toLocaleDateString()}
        </span>
      </div>
      {pulse.description && (
        <p className="text-xs text-muted-foreground line-clamp-2">{pulse.description}</p>
      )}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <span className="text-muted-foreground">
          by <span className="text-foreground">{pulse.author_name}</span>
        </span>
        {pulse.tags && pulse.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {pulse.tags.slice(0, 6).map(tag => (
              <span key={tag} className="px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">
                {tag}
              </span>
            ))}
            {pulse.tags.length > 6 && (
              <span className="px-1.5 py-0.5 text-muted-foreground">+{pulse.tags.length - 6}</span>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default function AlienVaultCard({ loading, error, data }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const pulseInfo = data?.pulse_info ?? null
  const pulseCount = pulseInfo?.count ?? 0

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">AlienVault OTX</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          {!loading && isRealError && <AlertCircle className="h-4 w-4 text-red-400" />}
          {!loading && isNotFound && (
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-medium text-muted-foreground bg-muted/40 border-border">
              <SearchX className="h-3 w-3" />
              Not Found
            </span>
          )}
          {!loading && pulseInfo && <PulseBadge count={pulseCount} />}
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
            <p className="text-sm text-muted-foreground">Querying AlienVault OTX...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiError?.message}</p>
          )}

          {!loading && data && !apiError && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label="Pulses" value={pulseInfo ? <PulseBadge count={pulseCount} /> : '—'} />
                <Field label="Reputation" value={data.reputation ?? '—'} />
                <Field label="Country" value={data.country_name} />
                <Field label="City" value={data.city} />
                <Field label="ASN" value={data.asn} />
              </div>

              {pulseInfo && pulseInfo.pulses.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    Threat Pulses ({pulseCount})
                  </span>
                  {pulseInfo.pulses.map(pulse => (
                    <PulseRow key={pulse.id} pulse={pulse} />
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="AlienVault OTX" />
    </div>
  )
}
