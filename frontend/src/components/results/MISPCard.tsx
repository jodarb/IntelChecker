import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'

interface MispTag {
  name: string
  colour?: string
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

interface MispEventDetail {
  id?: string
  info?: string
  date?: string
  threat_level_id?: string | number
  analysis?: string | number
  published?: boolean
  org?: string
  Tag?: MispTag[]
}

interface MispResponse {
  Attribute?: MispAttribute[]
  Events?: Record<string, MispEventDetail>
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: MispResponse | null
  label?: string
  score?: number | null
  weight?: CardWeight | null
}

const THREAT_LEVEL: Record<string, { label: string; style: string }> = {
  '1': { label: 'High', style: 'text-red-400 bg-red-500/10 border-red-500/30' },
  '2': { label: 'Medium', style: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  '3': { label: 'Low', style: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  '4': { label: 'Undefined', style: 'text-muted-foreground bg-muted/30 border-border' },
}
const ANALYSIS_LABEL: Record<string, string> = { '0': 'Initial', '1': 'Ongoing', '2': 'Completed' }

function TagChip({ tag }: { tag: MispTag }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-muted border border-border text-xs text-muted-foreground">
      {tag.colour && <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: tag.colour }} />}
      {tag.name}
    </span>
  )
}

function AttributeRow({ attr }: { attr: MispAttribute }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs px-2.5 py-2 rounded bg-background/40">
      {attr.value && <span className="font-mono text-foreground break-all">{attr.value}</span>}
      {attr.category && (
        <span className="text-muted-foreground">category: <span className="text-foreground">{attr.category}</span></span>
      )}
      {attr.type && (
        <span className="text-muted-foreground">type: <span className="text-foreground">{attr.type}</span></span>
      )}
      {attr.to_ids && (
        <span className="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 font-medium">
          IDS
        </span>
      )}
      {attr.Tag && attr.Tag.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {attr.Tag.map(tag => <TagChip key={tag.name} tag={tag} />)}
        </div>
      )}
    </div>
  )
}

function EventGroup({ event, attrs }: { event?: MispEventDetail; attrs: MispAttribute[] }) {
  const fallback = attrs[0]?.Event
  const title = event?.info ?? fallback?.info ?? 'Untitled event'
  const date = event?.date ?? fallback?.date
  const eventUrl = attrs.find(a => a.event_url)?.event_url
  const threatLevel = event?.threat_level_id != null ? THREAT_LEVEL[String(event.threat_level_id)] : undefined
  const analysisLabel = event?.analysis != null ? ANALYSIS_LABEL[String(event.analysis)] : undefined

  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <span className="text-sm text-foreground font-medium">{title}</span>
        {date && <span className="text-xs text-muted-foreground shrink-0">{date}</span>}
      </div>

      {(threatLevel || analysisLabel || event?.published != null || event?.org) && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
          {threatLevel && (
            <span className={`px-1.5 py-0.5 rounded border font-medium ${threatLevel.style}`}>
              Threat: {threatLevel.label}
            </span>
          )}
          {analysisLabel && (
            <span className="text-muted-foreground">Analysis: <span className="text-foreground">{analysisLabel}</span></span>
          )}
          {event?.published != null && (
            <span className="text-muted-foreground">Published: <span className="text-foreground">{event.published ? 'Yes' : 'No'}</span></span>
          )}
          {event?.org && (
            <span className="text-muted-foreground">Org: <span className="text-foreground">{event.org}</span></span>
          )}
        </div>
      )}

      {event?.Tag && event.Tag.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {event.Tag.map(tag => <TagChip key={tag.name} tag={tag} />)}
        </div>
      )}

      <div className="flex flex-col gap-1.5 border-t border-border pt-2">
        {attrs.map((attr, i) => <AttributeRow key={attr.id ?? i} attr={attr} />)}
      </div>

      {eventUrl && (
        <a
          href={eventUrl}
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
  const events = !apiError ? data?.Events ?? {} : {}
  const hasResolved = !apiError && data?.Attribute != null
  const title = label ?? 'MISP'

  // Group matching attributes by their parent event so its info/tags are shown
  // once per event, not repeated on every single matching attribute.
  const eventGroups: { eventId: string; attrs: MispAttribute[] }[] = []
  const groupIndex = new Map<string, number>()
  const unlinked: MispAttribute[] = []
  for (const attr of attributes) {
    const eid = attr.event_id
    if (!eid) { unlinked.push(attr); continue }
    if (!groupIndex.has(eid)) {
      groupIndex.set(eid, eventGroups.length)
      eventGroups.push({ eventId: eid, attrs: [] })
    }
    eventGroups[groupIndex.get(eid)!].attrs.push(attr)
  }
  const visibleGroups = eventGroups.slice(0, 10)
  const hiddenGroups = eventGroups.length - visibleGroups.length

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
              {visibleGroups.map(g => (
                <EventGroup key={g.eventId} event={events[g.eventId]} attrs={g.attrs} />
              ))}
              {unlinked.length > 0 && (
                <div className="flex flex-col gap-1.5">
                  {unlinked.map((attr, i) => <AttributeRow key={attr.id ?? i} attr={attr} />)}
                </div>
              )}
              {hiddenGroups > 0 && (
                <p className="text-xs text-muted-foreground">+{hiddenGroups} more event{hiddenGroups === 1 ? '' : 's'}, view raw JSON for the full list.</p>
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title={title} />
    </div>
  )
}
