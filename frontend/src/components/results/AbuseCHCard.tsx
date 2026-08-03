import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge from './WeightBadge'

interface ThreatFoxIOC {
  id: string
  ioc: string
  ioc_type: string
  threat_type: string
  threat_type_desc: string
  malware_printable: string
  malware_alias: string | null
  confidence_level: number
  first_seen: string
  last_seen: string | null
  reporter: string
  tags: string[] | null
  reference: string | null
}

interface ThreatFoxResponse {
  query_status?: string
  data?: ThreatFoxIOC[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: ThreatFoxResponse | null
  score?: number | null
  weight?: number | null
}

function ConfidenceBadge({ level }: { level: number }) {
  const color =
    level >= 75 ? 'text-red-400 bg-red-500/10 border-red-500/30' :
    level >= 50 ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' :
                  'text-muted-foreground bg-muted/40 border-border'
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full border text-xs font-semibold ${color}`}>
      {level}% confidence
    </span>
  )
}

function IOCRow({ ioc }: { ioc: ThreatFoxIOC }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-sm text-foreground font-medium">{ioc.ioc}</span>
        <ConfidenceBadge level={ioc.confidence_level} />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-1.5 text-xs">
        <div>
          <span className="text-muted-foreground uppercase tracking-wide">Threat</span>
          <p className="text-foreground font-medium mt-0.5">{ioc.threat_type_desc}</p>
        </div>
        <div>
          <span className="text-muted-foreground uppercase tracking-wide">Malware</span>
          <p className="text-foreground font-medium mt-0.5">
            {ioc.malware_printable}
            {ioc.malware_alias ? ` (${ioc.malware_alias})` : ''}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground uppercase tracking-wide">Reporter</span>
          <p className="text-foreground font-medium mt-0.5">{ioc.reporter}</p>
        </div>
        <div>
          <span className="text-muted-foreground uppercase tracking-wide">First Seen</span>
          <p className="text-foreground font-medium mt-0.5">
            {new Date(ioc.first_seen).toLocaleString()}
          </p>
        </div>
        {ioc.last_seen && (
          <div>
            <span className="text-muted-foreground uppercase tracking-wide">Last Seen</span>
            <p className="text-foreground font-medium mt-0.5">
              {new Date(ioc.last_seen).toLocaleString()}
            </p>
          </div>
        )}
        {ioc.tags && ioc.tags.length > 0 && (
          <div className="col-span-2 sm:col-span-3">
            <span className="text-muted-foreground uppercase tracking-wide">Tags</span>
            <div className="flex flex-wrap gap-1 mt-0.5">
              {ioc.tags.map(tag => (
                <span key={tag} className="px-1.5 py-0.5 rounded bg-muted border border-border text-xs text-muted-foreground">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
      <a
        href={`https://threatfox.abuse.ch/ioc/${ioc.id}/`}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
      >
        <ExternalLink className="h-3 w-3" /> View on ThreatFox
      </a>
    </div>
  )
}

export default function AbuseCHCard({ loading, error, data, score = null, weight = null }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const iocs = data?.data ?? null
  const hasData = iocs !== null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">ThreatFox · abuse.ch</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={!!(error || apiError)} />}
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
            <p className="text-sm text-muted-foreground">Querying ThreatFox...</p>
          )}

          {!loading && (error || apiError) && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && hasData && iocs.length === 0 && (
            <p className="text-sm text-muted-foreground">No IOCs found for this indicator.</p>
          )}

          {!loading && hasData && iocs.map(ioc => (
            <IOCRow key={ioc.id} ioc={ioc} />
          ))}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="ThreatFox · abuse.ch" />
    </div>
  )
}
