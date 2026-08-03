import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge from './WeightBadge'

interface MispTag {
  name: string
}

interface MispEvent {
  id?: string
  info?: string
  date?: string
}

interface MispAttribute {
  id?: string
  event_id?: string
  category?: string
  type?: string
  value?: string
  to_ids?: boolean
  timestamp?: string
  Event?: MispEvent
  Tag?: MispTag[] | null
  event_url?: string
}

interface MispResponse {
  Attribute?: MispAttribute[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: MispResponse | null
  label?: string
  score?: number | null
  weight?: number | null
}

function AttributeRow({ attr }: { attr: MispAttribute }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <span className="text-sm text-foreground font-medium">{attr.Event?.info ?? 'Untitled event'}</span>
        {attr.Event?.date && (
          <span className="text-xs text-muted-foreground shrink-0">{attr.Event.date}</span>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        {attr.category && (
          <span className="text-muted-foreground">
            category: <span className="text-foreground">{attr.category}</span>
          </span>
        )}
        {attr.type && (
          <span className="text-muted-foreground">
            type: <span className="text-foreground">{attr.type}</span>
          </span>
        )}
        {attr.to_ids && (
          <span className="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 font-medium">
            IDS
          </span>
        )}
      </div>
      {attr.Tag && attr.Tag.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {attr.Tag.map(tag => (
            <span key={tag.name} className="px-1.5 py-0.5 rounded bg-muted border border-border text-xs text-muted-foreground">
              {tag.name}
            </span>
          ))}
        </div>
      )}
      {attr.event_url && (
        <a
          href={attr.event_url}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
        >
          <ExternalLink className="h-3 w-3" /> View event
        </a>
      )}
    </div>
  )
}

export default function MISPCard({ loading, error, data, label, score = null, weight = null }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const attributes = !apiError ? data?.Attribute ?? [] : []
  const hasResolved = !apiError && data?.Attribute != null
  const title = label ?? 'MISP'

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">{title}</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && (
            <ScoreBadge score={score} isError={isRealError} hasResult={attributes.length > 0} />
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
        <div className="px-4 py-4 flex flex-col gap-3">
          {loading && <p className="text-sm text-muted-foreground">Querying {title}...</p>}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && hasResolved && attributes.length === 0 && (
            <p className="text-sm text-muted-foreground">No matching attributes found in {title}.</p>
          )}

          {!loading && attributes.length > 0 && (
            <div className="flex flex-col gap-2">
              {attributes.slice(0, 15).map((attr, i) => (
                <AttributeRow key={attr.id ?? i} attr={attr} />
              ))}
              {attributes.length > 15 && (
                <p className="text-xs text-muted-foreground">+{attributes.length - 15} more, view raw JSON for the full list.</p>
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title={title} />
    </div>
  )
}
