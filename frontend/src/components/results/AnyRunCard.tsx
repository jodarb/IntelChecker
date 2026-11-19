import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import type { IndicatorType } from '@/registry'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'

interface RelatedIP {
  destinationIP: string
  date: string
  threatLevel: number
  threatName: string[]
}

interface RelatedDNS {
  domainName: string
  date: string
  threatLevel: number
  threatName: string[]
}

interface RelatedURL {
  url: string
  date: string
  threatLevel: number
  threatName: string[]
}

interface RelatedFile {
  fileName: string
  fileExtension?: string
  hashes: { md5: string; sha1: string; sha256: string }
}

interface SourceTask {
  related: string
}

interface AnyRunResponse {
  summary?: { threatLevel: number | null; lastSeen: string | null; tags: string[] | null }
  destinationIPgeo?: string[]
  destinationIpAsn?: { asn: string; date: string }[]
  destinationIP?: RelatedIP[]
  relatedDNS?: RelatedDNS[]
  relatedURLs?: RelatedURL[]
  relatedFiles?: RelatedFile[]
  sourceTasks?: SourceTask[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: AnyRunResponse | null
  score?: number | null
  weight?: CardWeight | null
  indicator?: string
  type?: IndicatorType
}

const VERDICT_STYLES: Record<number, string> = {
  0: 'text-muted-foreground bg-muted/30 border-border',
  1: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  2: 'text-red-400 bg-red-500/10 border-red-500/30',
}
const VERDICT_LABELS = { 0: 'anyrun.noInfo', 1: 'card.suspicious', 2: 'card.malicious' } as const

function VerdictBadge({ threatLevel }: { threatLevel: number }) {
  const { t } = useI18n()
  const style = VERDICT_STYLES[threatLevel] ?? VERDICT_STYLES[0]
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full border text-xs font-semibold ${style}`}>
      {t(VERDICT_LABELS[threatLevel as 0 | 1 | 2] ?? 'anyrun.noInfo')}
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

function isEmpty(data: AnyRunResponse): boolean {
  return (
    !data.destinationIP?.length &&
    !data.relatedDNS?.length &&
    !data.relatedURLs?.length &&
    !data.relatedFiles?.length &&
    !data.sourceTasks?.length
  )
}

function hashField(value: string): string {
  if (value.length === 64) return 'sha256'
  if (value.length === 40) return 'sha1'
  return 'md5'
}

function buildDeepLink(indicator?: string, type?: IndicatorType): string | null {
  if (!indicator) return null
  const field = type === 'ip' ? 'destinationIP'
    : type === 'domain' ? 'domainName'
    : type === 'url' ? 'url'
    : type === 'hash' ? hashField(indicator)
    : null
  if (!field) return null
  const fragment = JSON.stringify({ query: `${field}:"${indicator}"`, dateRange: 180 })
  return `https://intelligence.any.run/analysis/lookup#${encodeURIComponent(fragment)}`
}

export default function AnyRunCard({ loading, error, data, score = null, weight = null, indicator, type }: Props) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const notFound = !apiError && !!data && isEmpty(data)
  const summary = !apiError ? data?.summary : undefined
  const deepLink = buildDeepLink(indicator, type)

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">ANY.RUN</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={!notFound} />}
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
      </button>

      {open && (
        <div className="px-4 py-4 flex flex-col gap-4">
          {loading && (
            <p className="text-sm text-muted-foreground">{t('anyrun.querying')}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'ANY.RUN')}</p>
          )}

          {!loading && notFound && (
            <p className="text-sm text-muted-foreground">{t('anyrun.none', { days: 180 })}</p>
          )}

          {!loading && summary && !notFound && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field
                  label={t('f.verdict')}
                  value={summary.threatLevel != null ? <VerdictBadge threatLevel={summary.threatLevel} /> : undefined}
                />
                <Field
                  label={t('f.lastSeen')}
                  value={summary.lastSeen ? new Date(summary.lastSeen).toLocaleString(locale) : undefined}
                />
                <Field label={t('f.country')} value={data?.destinationIPgeo?.[0]?.toUpperCase()} />
                <Field label={t('f.asn')} value={data?.destinationIpAsn?.[0]?.asn} />
              </div>

              {summary.tags && summary.tags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {summary.tags.map(tag => (
                    <span key={tag} className="px-2 py-0.5 rounded-full border border-border bg-muted/30 text-xs text-muted-foreground">
                      {tag}
                    </span>
                  ))}
                </div>
              )}

              {data?.relatedURLs && data.relatedURLs.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('anyrun.relatedUrls', { n: data.relatedURLs.length })}
                  </span>
                  {data.relatedURLs.slice(0, 5).map((u, i) => (
                    <div key={i} className="rounded-md border border-border bg-muted/20 px-3 py-2 flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-foreground break-all">{u.url}</span>
                      <VerdictBadge threatLevel={u.threatLevel} />
                    </div>
                  ))}
                </div>
              )}

              {data?.relatedDNS && data.relatedDNS.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('anyrun.relatedDomains', { n: data.relatedDNS.length })}
                  </span>
                  {data.relatedDNS.slice(0, 5).map((d, i) => (
                    <div key={i} className="rounded-md border border-border bg-muted/20 px-3 py-2 flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-foreground break-all">{d.domainName}</span>
                      <VerdictBadge threatLevel={d.threatLevel} />
                    </div>
                  ))}
                </div>
              )}

              {data?.destinationIP && data.destinationIP.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('anyrun.relatedIps', { n: data.destinationIP.length })}
                  </span>
                  {data.destinationIP.slice(0, 5).map((ip, i) => (
                    <div key={i} className="rounded-md border border-border bg-muted/20 px-3 py-2 flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-foreground break-all">{ip.destinationIP}</span>
                      <VerdictBadge threatLevel={ip.threatLevel} />
                    </div>
                  ))}
                </div>
              )}

              {data?.relatedFiles && data.relatedFiles.length > 0 && (
                <div className="flex flex-col gap-2">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('anyrun.relatedFiles', { n: data.relatedFiles.length })}
                  </span>
                  {data.relatedFiles.slice(0, 5).map((f, i) => (
                    <div key={i} className="rounded-md border border-border bg-muted/20 px-3 py-2 flex flex-col gap-0.5">
                      <span className="text-xs font-mono text-foreground break-all">{f.fileName}</span>
                      <span className="text-xs text-muted-foreground font-mono break-all">{f.hashes?.sha256}</span>
                    </div>
                  ))}
                </div>
              )}

              {deepLink && (
                <a
                  href={deepLink}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'ANY.RUN TI Lookup' })}
                </a>
              )}
            </>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="ANY.RUN" />
    </div>
  )
}
