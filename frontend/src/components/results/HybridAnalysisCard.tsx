import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

interface SampleResult {
  sha256?: string
  submit_name?: string
  verdict?: string
  threat_score?: number | null
  vx_family?: string | null
  av_detect?: number | null
  environment_description?: string
  analysis_start_time?: string
}

interface HybridAnalysisResponse {
  count?: number
  result?: SampleResult[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: HybridAnalysisResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const VERDICT_STYLES: Record<string, string> = {
  malicious: 'text-red-400 bg-red-500/10 border-red-500/30',
  suspicious: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  whitelisted: 'text-green-400 bg-green-500/10 border-green-500/30',
  'no specific threat': 'text-green-400 bg-green-500/10 border-green-500/30',
  'no verdict': 'text-muted-foreground bg-muted/30 border-border',
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const { t } = useI18n()
  const key = verdict.toLowerCase()
  const style = VERDICT_STYLES[key] ?? VERDICT_STYLES['no verdict']
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border text-xs font-medium capitalize shrink-0 ${style}`}>
      {key in VERDICT_STYLES ? t(`hybrid.verdict.${key as 'malicious' | 'suspicious' | 'whitelisted' | 'no specific threat' | 'no verdict'}`) : verdict}
    </span>
  )
}

export default function HybridAnalysisCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const results = !apiError ? (data?.result ?? []) : []
  const hasResults = results.length > 0

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">Hybrid Analysis</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={hasResults} />}
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
          {loading && (
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'Hybrid Analysis' })}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'Hybrid Analysis')}</p>
          )}

          {!loading && !isRealError && !hasResults && (
            <p className="text-sm text-muted-foreground">{t('hybrid.none')}</p>
          )}

          {!loading && hasResults && (
            <div className="flex flex-col gap-2">
              <span className="text-xs text-muted-foreground uppercase tracking-wide">
                {t('hybrid.reports', { n: results.length })}
              </span>
              {results.slice(0, 8).map((r, i) => (
                <div key={r.sha256 ?? i} className="rounded-md border border-border bg-muted/20 px-3 py-2.5 flex flex-col gap-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-foreground break-all">{r.submit_name ?? r.sha256}</span>
                    {r.verdict && <VerdictBadge verdict={r.verdict} />}
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    {r.threat_score != null && <span>{t('hybrid.threatScore', { n: r.threat_score })}</span>}
                    {r.vx_family && <span>{t('hybrid.family', { name: r.vx_family })}</span>}
                    {r.environment_description && <span>{r.environment_description}</span>}
                  </div>
                  {r.sha256 && (
                    <a
                      href={`https://hybrid-analysis.com/sample/${r.sha256}`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
                    >
                      <ExternalLink className="h-3 w-3" /> {t('hybrid.viewReport')}
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="Hybrid Analysis" />
    </div>
  )
}
