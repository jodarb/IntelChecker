import { useState } from 'react'
import { Loader2, CheckCircle2, ShieldX, ShieldAlert, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

interface AnalysisStats {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  timeout: number
}

interface VTAttributes {
  last_analysis_stats: AnalysisStats
  country: string | null
  asn: number | null
  as_owner: string | null
  network: string | null
  reputation: number
  last_analysis_date: number | null
  total_votes: { harmless: number; malicious: number }
}

interface VTData {
  id: string
  attributes: VTAttributes
}

interface VTResponse {
  data?: VTData
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: VTResponse | null
  score?: number | null
  weight?: CardWeight | null
  type?: string
}

const VT_TYPE_SLUG: Record<string, string> = { ip: 'ip-address', domain: 'domain', url: 'url', hash: 'file' }

function DetectionBadge({ stats }: { stats: AnalysisStats }) {
  const { t } = useI18n()
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected + stats.timeout
  const flagged = stats.malicious + stats.suspicious

  if (stats.malicious >= 4) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
        <ShieldX className="h-3 w-3" />
        {stats.malicious}/{total} · {t('card.malicious')}
      </span>
    )
  }
  if (flagged > 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-yellow-400 bg-yellow-500/10 border-yellow-500/30">
        <ShieldAlert className="h-3 w-3" />
        {flagged}/{total} · {t('card.suspicious')}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-green-400 bg-green-500/10 border-green-500/30">
      <CheckCircle2 className="h-3 w-3" />
      0/{total} · {t('card.clean')}
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

export default function VirusTotalCard({ loading, error, data, score = null, weight = null, type }: Props) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const attrs = data?.data?.attributes ?? null
  const vtUrl = data?.data?.id && type && VT_TYPE_SLUG[type]
    ? `https://www.virustotal.com/gui/${VT_TYPE_SLUG[type]}/${data.data.id}`
    : null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">VirusTotal</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} />}
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
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'VirusTotal' })}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'VirusTotal')}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiErrorText(i18n, apiError, 'VirusTotal')}</p>
          )}

          {!loading && attrs && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
              <Field
                label={t('f.detection')}
                value={<DetectionBadge stats={attrs.last_analysis_stats} />}
              />
              <Field label={t('f.maliciousEngines')} value={attrs.last_analysis_stats.malicious} />
              <Field label={t('f.suspiciousEngines')} value={attrs.last_analysis_stats.suspicious} />
              <Field label={t('f.communityReputation')} value={attrs.reputation} />
              <Field label={t('f.country')} value={attrs.country} />
              <Field label={t('f.asOwner')} value={attrs.as_owner} />
              <Field label={t('f.asn')} value={attrs.asn ? `AS${attrs.asn}` : null} />
              <Field label={t('f.network')} value={attrs.network} />
              <Field
                label={t('f.lastAnalysis')}
                value={
                  attrs.last_analysis_date
                    ? new Date(attrs.last_analysis_date * 1000).toLocaleString(locale)
                    : '—'
                }
              />
            </div>
          )}

          {!loading && vtUrl && (
            <a
              href={vtUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit mt-3"
            >
              <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'VirusTotal' })}
            </a>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="VirusTotal" />
    </div>
  )
}
