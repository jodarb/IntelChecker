import { useState } from 'react'
import { Loader2, AlertCircle, CheckCircle2, ShieldX, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import EngineScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

interface AbuseData {
  ipAddress: string
  isPublic: boolean
  ipVersion: number
  isWhitelisted: boolean
  abuseConfidenceScore: number
  countryCode: string | null
  usageType: string | null
  isp: string | null
  domain: string | null
  hostnames: string[]
  isTor: boolean
  totalReports: number
  numDistinctUsers: number
  lastReportedAt: string | null
}

interface AbuseIPDBResponse {
  data?: AbuseData
  errors?: { detail: string; status: number }[]
}

interface Props {
  loading: boolean
  error: string | null
  data: AbuseIPDBResponse | null
  score?: number | null
  weight?: CardWeight | null
}

function ScoreBadge({ score }: { score: number }) {
  const { t } = useI18n()
  if (score >= 76) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
        <ShieldX className="h-3 w-3" />
        {score}/100 · {t('card.malicious')}
      </span>
    )
  }
  if (score >= 26) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-yellow-400 bg-yellow-500/10 border-yellow-500/30">
        <AlertCircle className="h-3 w-3" />
        {score}/100 · {t('card.suspicious')}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
      <CheckCircle2 className="h-3 w-3" />
      {score}/100 · {t('card.clean')}
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

export default function AbuseIPDBCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.errors?.[0]?.detail ?? null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">AbuseIPDB</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <EngineScoreBadge score={score} isError={!!(error || apiError)} />}
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
        <div className="px-4 py-4">
          {loading && (
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'AbuseIPDB' })}</p>
          )}

          {!loading && (error || apiError) && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'AbuseIPDB')}</p>
          )}

          {!loading && data?.data && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
              <Field label={t('f.confidenceScore')} value={<ScoreBadge score={data.data.abuseConfidenceScore} />} />
              <Field label={t('f.totalReports')} value={data.data.totalReports} />
              <Field label={t('f.distinctReporters')} value={data.data.numDistinctUsers} />
              <Field label={t('f.country')} value={data.data.countryCode} />
              <Field label={t('f.isp')} value={data.data.isp} />
              <Field label={t('f.domain')} value={data.data.domain} />
              <Field label={t('f.usageType')} value={data.data.usageType} />
              <Field label={t('f.torExitNode')} value={data.data.isTor ? t('common.yes') : t('common.no')} />
              <Field
                label={t('f.lastReported')}
                value={
                  data.data.lastReportedAt
                    ? new Date(data.data.lastReportedAt).toLocaleString(locale)
                    : t('common.never')
                }
              />
              {data.data.hostnames.length > 0 && (
                <div className="col-span-2 sm:col-span-3">
                  <Field label={t('f.hostnames')} value={data.data.hostnames.join(', ')} />
                </div>
              )}
            </div>
          )}

          {!loading && data?.data?.ipAddress && (
            <a
              href={`https://www.abuseipdb.com/check/${data.data.ipAddress}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit mt-3"
            >
              <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'AbuseIPDB' })}
            </a>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="AbuseIPDB" />
    </div>
  )
}
