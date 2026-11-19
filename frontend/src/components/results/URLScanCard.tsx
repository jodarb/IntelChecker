import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, Tag, ExternalLink, Camera } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'

interface URLScanResult {
  task?: { time?: string; tags?: string[]; uuid?: string; url?: string }
  page?: { url?: string; domain?: string; ip?: string; country?: string; asnname?: string; server?: string }
  result?: string
  screenshot?: string
}

interface URLScanResponse {
  results?: URLScanResult[]
  total?: number
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: URLScanResponse | null
  score?: number | null
  weight?: CardWeight | null
}

function TagChip({ tag }: { tag: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-amber-500/30 bg-amber-500/10 text-amber-400 text-xs font-medium">
      <Tag className="h-3 w-3" />
      {tag}
    </span>
  )
}

export default function URLScanCard({ loading, error, data, score = null, weight = null }: Props) {
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError

  const results = data?.results ?? []
  const total = data?.total ?? 0
  const hasResults = !apiError && total > 0

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">urlscan.io</span>
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
            <p className="text-sm text-muted-foreground">Searching urlscan.io...</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiError?.message}</p>
          )}

          {!loading && !apiError && !hasResults && (
            <p className="text-sm text-muted-foreground">No prior urlscan.io scans were found for this indicator.</p>
          )}

          {!loading && hasResults && (
            <div className="flex flex-col gap-3">
              {results.map((r, i) => (
                <div key={r.task?.uuid ?? i} className="flex flex-col gap-2 rounded-md border border-border/60 bg-muted/20 px-3 py-2.5">
                  <div className="flex items-start justify-between gap-3">
                    <span className="text-sm font-medium text-foreground break-all">{r.page?.url ?? r.task?.url}</span>
                    <span className="text-xs text-muted-foreground shrink-0">
                      {r.task?.time ? new Date(r.task.time).toLocaleString() : ''}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    {r.page?.ip && <span>IP: <span className="text-foreground">{r.page.ip}</span></span>}
                    {r.page?.country && <span>Country: <span className="text-foreground">{r.page.country}</span></span>}
                    {r.page?.asnname && <span>ASN: <span className="text-foreground">{r.page.asnname}</span></span>}
                    {r.page?.server && <span>Server: <span className="text-foreground">{r.page.server}</span></span>}
                  </div>
                  {(r.task?.tags?.length ?? 0) > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {r.task!.tags!.map(tag => <TagChip key={tag} tag={tag} />)}
                    </div>
                  )}
                  <div className="flex items-center gap-3 pt-0.5">
                    {r.result && (
                      <a href={r.result} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                        <ExternalLink className="h-3 w-3" /> Result
                      </a>
                    )}
                    {r.screenshot && (
                      <a href={r.screenshot} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                        <Camera className="h-3 w-3" /> Screenshot
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="urlscan.io" />
    </div>
  )
}
