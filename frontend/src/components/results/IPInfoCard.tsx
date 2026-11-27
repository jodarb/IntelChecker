import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

interface IPInfoResponse {
  ip?: string
  hostname?: string
  city?: string
  region?: string
  country?: string
  loc?: string
  org?: string
  postal?: string
  timezone?: string
  bogon?: boolean
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: IPInfoResponse | null
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

export default function IPInfoCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const info = (!apiError && data?.ip) ? data : null

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">IPinfo</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={!!info} />}
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
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'IPinfo' })}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'IPinfo')}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiErrorText(i18n, apiError, 'IPinfo')}</p>
          )}

          {!loading && info && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
              <Field label={t('f.organization')} value={info.org} />
              <Field label={t('f.country')} value={info.country} />
              <Field label={t('f.region')} value={info.region} />
              <Field label={t('f.city')} value={info.city} />
              <Field label={t('f.postal')} value={info.postal} />
              <Field label={t('f.timezone')} value={info.timezone} />
              <Field label={t('f.hostname')} value={info.hostname} />
              <Field label={t('f.coordinates')} value={info.loc} />
            </div>
          )}

          {!loading && info?.ip && (
            <a
              href={`https://ipinfo.io/${info.ip}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit mt-3"
            >
              <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'IPinfo' })}
            </a>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="IPinfo" />
    </div>
  )
}
