import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge from './WeightBadge'

interface RIPEstatResponse {
  // type=ip
  network_info?: { asns?: string[]; prefix?: string }
  // type=asn
  as_overview?: { resource?: string; holder?: string; announced?: boolean }
  abuse_contacts?: { abuse_contacts?: string[] } | null
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: RIPEstatResponse | null
  score?: number | null
  weight?: number | null
  indicator?: string
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

export default function RIPEstatCard({ loading, error, data, score = null, weight = null, indicator }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError

  const isIp = !apiError && !!data?.network_info
  const isAsn = !apiError && !!data?.as_overview
  const hasRoute = isIp && (data?.network_info?.asns?.length ?? 0) > 0

  const abuseContacts = data?.abuse_contacts?.abuse_contacts ?? []

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">RIPEstat</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && (
            <ScoreBadge score={score} isError={isRealError} hasResult={isIp ? hasRoute : isAsn} />
          )}
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
            <p className="text-sm text-muted-foreground">Querying RIPEstat...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && isIp && (
            <div className="flex flex-col gap-4">
              {hasRoute ? (
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                  <Field label="ASN" value={data?.network_info?.asns?.map(a => `AS${a}`).join(', ')} />
                  <Field label="Prefix" value={data?.network_info?.prefix} />
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No announced route found for this IP in the RIPE routing registry.</p>
              )}
              {abuseContacts.length > 0 && (
                <Field label="Abuse Contacts" value={abuseContacts.join(', ')} />
              )}
              {indicator && (
                <a
                  href={`https://stat.ripe.net/${indicator}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> View on RIPEstat
                </a>
              )}
            </div>
          )}

          {!loading && isAsn && (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label="Resource" value={data?.as_overview?.resource ? `AS${data.as_overview.resource}` : undefined} />
                <Field label="Holder" value={data?.as_overview?.holder} />
                <Field label="Announced" value={data?.as_overview?.announced ? 'Yes' : 'No'} />
              </div>
              {abuseContacts.length > 0 && (
                <Field label="Abuse Contacts" value={abuseContacts.join(', ')} />
              )}
              {indicator && (
                <a
                  href={`https://stat.ripe.net/${indicator}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> View on RIPEstat
                </a>
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="RIPEstat" />
    </div>
  )
}
