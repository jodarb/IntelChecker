import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

/**
 * Shared frame of a source card: collapsible header with weight, score and RAW
 * buttons, plus the loading / error states. The body (`children`) is rendered only
 * once the source answered without an error.
 */
export function SourceCard({ title, loading, error, data, score, weight, hasResult, children }: {
  title: string
  loading: boolean
  error: string | null
  data: unknown
  score: number | null
  weight: CardWeight | null
  /** The source has a record of the indicator (drives the "no results" chip) */
  hasResult: boolean
  children: React.ReactNode
}) {
  const i18n = useI18n()
  const { t } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = (data as { error?: { code: string; message: string } } | null)?.error ?? null
  const isError = !!error || !!apiError

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">{title}</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isError} hasResult={hasResult} />}
          {!loading && !!data && (
            <button
              onClick={e => { e.stopPropagation(); setRawOpen(true) }}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
              title={t('raw.buttonTitle')}
            >
              <FileCode2 className="h-3 w-3" />
              RAW
            </button>
          )}
          <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </div>

      {open && (
        <div className="px-4 py-4 flex flex-col gap-3">
          {loading && <p className="text-sm text-muted-foreground">{t('card.querying', { source: title })}</p>}
          {!loading && isError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, title)}</p>
          )}
          {!loading && !isError && !!data && children}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title={title} />
    </div>
  )
}

export function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

export function FieldGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">{children}</div>
}

export function Note({ children, tone = 'muted' }: { children: React.ReactNode; tone?: 'muted' | 'warn' | 'good' }) {
  const cls = tone === 'warn' ? 'text-amber-400' : tone === 'good' ? 'text-green-400' : 'text-muted-foreground'
  return <p className={`text-sm ${cls}`}>{children}</p>
}

export function Chips({ items, max = 12 }: { items: string[]; max?: number }) {
  const { t } = useI18n()
  if (items.length === 0) return <>—</>
  return (
    <span className="flex flex-wrap gap-1">
      {items.slice(0, max).map(item => (
        <span key={item} className="px-1.5 py-0.5 rounded bg-muted border border-border text-xs text-muted-foreground font-normal">
          {item}
        </span>
      ))}
      {items.length > max && (
        <span className="px-1.5 py-0.5 text-xs text-muted-foreground font-normal">{t('common.more', { n: items.length - max })}</span>
      )}
    </span>
  )
}

export function SourceLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit">
      <ExternalLink className="h-3 w-3" /> {children}
    </a>
  )
}
