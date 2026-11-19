import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'

interface ShodanFacetEntry {
  value: string
  count: number
}

interface ShodanResponse {
  // host lookup (type=ip)
  ip_str?: string
  org?: string | null
  isp?: string | null
  asn?: string | null
  city?: string | null
  country_name?: string | null
  country_code?: string | null
  hostnames?: string[]
  ports?: number[]
  vulns?: string[]
  os?: string | null
  last_update?: string
  // host count (type=asn)
  total?: number
  facets?: {
    port?: ShodanFacetEntry[]
    org?: ShodanFacetEntry[]
    country?: ShodanFacetEntry[]
  }
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: ShodanResponse | null
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

function formatFacets(entries?: ShodanFacetEntry[]) {
  if (!entries || entries.length === 0) return null
  return entries.map(f => `${f.value} (${f.count})`).join(', ')
}

export default function ShodanCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)

  const isHost = !apiError && !!data?.ip_str
  const isAsnSummary = !apiError && !isHost && data?.total !== undefined

  const vulnCount = data?.vulns?.length ?? 0
  const portCount = data?.ports?.length ?? 0

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">Shodan</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={isHost || isAsnSummary} />}
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
        <div className="px-4 py-4">
          {loading && (
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'Shodan' })}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'Shodan')}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiErrorText(i18n, apiError, 'Shodan')}</p>
          )}

          {!loading && isHost && (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label={t('f.organization')} value={data?.org} />
                <Field label={t('f.isp')} value={data?.isp} />
                <Field label={t('f.asn')} value={data?.asn} />
                <Field label={t('f.country')} value={data?.country_name} />
                <Field label={t('f.city')} value={data?.city} />
                <Field label={t('f.os')} value={data?.os} />
                <Field
                  label={t('f.lastUpdate')}
                  value={data?.last_update ? new Date(data.last_update).toLocaleString(locale) : undefined}
                />
              </div>
              {portCount > 0 && <Field label={t('f.openPorts')} value={data!.ports!.join(', ')} />}
              {vulnCount > 0 && <Field label={t('f.vulns')} value={data!.vulns!.join(', ')} />}
              {(data?.hostnames?.length ?? 0) > 0 && (
                <Field label={t('f.hostnames')} value={data!.hostnames!.join(', ')} />
              )}
              {data?.ip_str && (
                <a
                  href={`https://www.shodan.io/host/${data.ip_str}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                >
                  <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'Shodan' })}
                </a>
              )}
            </div>
          )}

          {!loading && isAsnSummary && (
            <div className="flex flex-col gap-4">
              <Field label={t('f.totalHosts')} value={data?.total} />
              {formatFacets(data?.facets?.org) && (
                <Field label={t('f.topOrgs')} value={formatFacets(data?.facets?.org)} />
              )}
              {formatFacets(data?.facets?.port) && (
                <Field label={t('f.topPorts')} value={formatFacets(data?.facets?.port)} />
              )}
              {formatFacets(data?.facets?.country) && (
                <Field label={t('f.topCountries')} value={formatFacets(data?.facets?.country)} />
              )}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="Shodan" />
    </div>
  )
}
