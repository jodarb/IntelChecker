import { useState } from 'react'
import { Loader2, CheckCircle2, ShieldX, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

interface URLHausPayload {
  filename?: string | null
  file_type?: string
  signature?: string | null
}

interface URLHausUrlRecord {
  id?: string
  url: string
  url_status?: string
  date_added?: string
  threat?: string
  tags?: string[] | null
}

interface URLHausResponse {
  query_status?: string
  // /url/ lookup shape
  url?: string
  url_status?: string
  host?: string
  date_added?: string
  threat?: string
  tags?: string[] | null
  urlhaus_reference?: string
  payloads?: URLHausPayload[]
  // /host/ and /payload/ lookup shape
  urls?: URLHausUrlRecord[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: URLHausResponse | null
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

function StatusBadge({ found, count }: { found: boolean; count?: number }) {
  const { t } = useI18n()
  if (!found) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
        <CheckCircle2 className="h-3 w-3" />
        {t('card.clean')}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
      <ShieldX className="h-3 w-3" />
      {count && count > 1 ? t('urlhaus.urlsFound', { n: count }) : t('urlhaus.listed')}
    </span>
  )
}

function TagList({ tags }: { tags: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map(tag => (
        <span key={tag} className="px-1.5 py-0.5 rounded bg-muted border border-border text-xs text-muted-foreground">
          {tag}
        </span>
      ))}
    </div>
  )
}

function UrlRow({ record }: { record: URLHausUrlRecord }) {
  const { t, locale } = useI18n()
  return (
    <div className="rounded-md border border-border bg-muted/20 px-4 py-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-sm text-foreground font-medium break-all">{record.url}</span>
        {record.url_status && (
          <span className={`px-2 py-0.5 rounded-full border text-xs font-semibold shrink-0 ${
            record.url_status === 'online'
              ? 'text-red-400 bg-red-500/10 border-red-500/30'
              : 'text-muted-foreground bg-muted/40 border-border'
          }`}>
            {record.url_status}
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-1.5 text-xs">
        <div>
          <span className="text-muted-foreground uppercase tracking-wide">{t('f.threat')}</span>
          <p className="text-foreground font-medium mt-0.5">{record.threat ?? '—'}</p>
        </div>
        <div>
          <span className="text-muted-foreground uppercase tracking-wide">{t('f.dateAdded')}</span>
          <p className="text-foreground font-medium mt-0.5">
            {record.date_added ? new Date(record.date_added).toLocaleString(locale) : '—'}
          </p>
        </div>
        {record.tags && record.tags.length > 0 && (
          <div className="col-span-2 sm:col-span-3">
            <span className="text-muted-foreground uppercase tracking-wide">{t('f.tags')}</span>
            <div className="mt-0.5"><TagList tags={record.tags} /></div>
          </div>
        )}
      </div>
      {record.id && (
        <a
          href={`https://urlhaus.abuse.ch/url/${record.id}/`}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
        >
          <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'URLhaus' })}
        </a>
      )}
    </div>
  )
}

export default function URLHausCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const noResults = data?.query_status === 'no_results'
  const isSingleUrl = !apiError && !noResults && !!data?.url
  const urlList = !apiError && !noResults && !isSingleUrl ? (data?.urls ?? []) : null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">URLhaus · abuse.ch</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={!!(error || apiError)} />}
          {!loading && data && (
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
          {loading && <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'URLhaus' })}</p>}

          {!loading && (error || apiError) && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'URLhaus')}</p>
          )}

          {!loading && noResults && (
            <p className="text-sm text-muted-foreground">{t('card.noMatches', { source: 'URLhaus' })}</p>
          )}

          {!loading && isSingleUrl && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label={t('f.status')} value={<StatusBadge found={true} />} />
                <Field label={t('f.urlStatus')} value={data?.url_status} />
                <Field label={t('f.threat')} value={data?.threat} />
                <Field label={t('f.host')} value={data?.host} />
                <Field
                  label={t('f.dateAdded')}
                  value={data?.date_added ? new Date(data.date_added).toLocaleString(locale) : undefined}
                />
                <Field
                  label={t('f.reference')}
                  value={data?.urlhaus_reference && (
                    <a href={data.urlhaus_reference} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">
                      {data.urlhaus_reference}
                    </a>
                  )}
                />
              </div>
              {data?.tags && data.tags.length > 0 && <TagList tags={data.tags} />}
              {data?.payloads && data.payloads.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('urlhaus.payloads', { n: data.payloads.length })}
                  </span>
                  {data.payloads.map((p, i) => (
                    <div
                      key={i}
                      className="rounded-md border border-border bg-muted/20 px-4 py-3 grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-2"
                    >
                      <Field label={t('f.fileName')} value={p.filename} />
                      <Field label={t('f.fileType')} value={p.file_type} />
                      <Field label={t('f.signature')} value={p.signature} />
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {!loading && urlList && urlList.length > 0 && (
            <div className="flex flex-col gap-2">
              {urlList.map(record => (
                <UrlRow key={record.id ?? record.url} record={record} />
              ))}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="URLhaus" />
    </div>
  )
}
