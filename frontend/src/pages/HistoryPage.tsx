import { useFetchJson } from '@/hooks/useFetchJson'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ChevronRight, X, Crosshair, Building2, VenetianMask, RotateCw, UserRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import ScoreBadge from '@/components/results/ScoreBadge'
import { QUADRANT_META, quadrantLabel } from '@/quadrants'
import type { Quadrant } from '@/verdictEngine'
import { useI18n } from '@/i18n/useI18n'
import type { IndicatorType } from '@/registry'
import { useAuth } from '@/auth/context'
import { rerunUrl } from '@/lib/rerun'

interface HistoryListEntry {
  id: number
  indicator: string
  type: string
  timestamp: string
  score: number | null
  knowledge_score: number | null
  quadrant: Quadrant | null
  username: string | null
  via: 'ui' | 'api' | null
}

const BACKEND = '/api'

function formatTimestamp(ts: string, locale: string): string {
  // Backend stores UTC as "YYYY-MM-DD HH:MM:SS" (SQLite datetime('now')) — mark it
  // explicitly as UTC so the browser converts it to the analyst's local time.
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString(locale)
}

export default function HistoryPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('indicator') ?? ''
  const { t, tn, locale } = useI18n()
  const { can } = useAuth()
  const query = indicator ? `?indicator=${encodeURIComponent(indicator)}` : ''
  const { data: entries, failed } = useFetchJson<HistoryListEntry[]>(`${BACKEND}/history${query}`)
  const error = failed ? t('common.backendDown') : null

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="sm" asChild className="shrink-0">
            <Link to="/">
              <ArrowLeft className="h-4 w-4 mr-1" />
              {t('common.back')}
            </Link>
          </Button>
          <h2 className="text-xl font-semibold text-foreground">{t('history.title')}</h2>
        </div>

        {indicator && (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-muted/20 text-sm">
            <span className="text-muted-foreground">{t('history.filteredTo')}</span>
            <span className="font-mono text-foreground font-medium break-all">{indicator}</span>
            {entries && (
              <span className="text-muted-foreground">
                {tn('history.total', entries.length)}
              </span>
            )}
            <Link
              to="/history"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground ml-auto shrink-0"
            >
              <X className="h-3 w-3" /> {t('history.clearFilter')}
            </Link>
          </div>
        )}

        {error && <p className="text-sm text-red-400">{error}</p>}

        {!error && entries === null && (
          <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
        )}

        {entries && entries.length === 0 && (
          <p className="text-sm text-muted-foreground">
            {indicator ? t('history.emptyFor', { indicator }) : t('history.empty')}
          </p>
        )}

        {entries && entries.length > 0 && (
          <div className="flex flex-col gap-2">
            {entries.map(entry => (
              // The row opens the entry; "run again" sits next to it (a link can't hold another link).
              <div key={entry.id} className="flex items-stretch rounded-lg border border-border bg-muted/20 overflow-hidden">
              <Link
                to={`/history/${entry.id}`}
                className="flex-1 min-w-0 flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 px-4 py-3 hover:bg-muted/40 transition-colors"
              >
                {/* When, what, who — then the scores on the right. On narrow screens the
                    scores wrap below instead of covering the indicator. */}
                <div className="flex flex-wrap sm:flex-nowrap items-center gap-x-4 gap-y-1 min-w-0 flex-1 basis-72">
                  {/* Phones: the time on its own line, so the indicator keeps its width */}
                  <span className="basis-full sm:basis-auto text-xs text-muted-foreground tabular-nums shrink-0">{formatTimestamp(entry.timestamp, locale)}</span>
                  <span className="flex items-center gap-2 min-w-0 flex-1 sm:flex-initial">
                    {/* Same icons as the search tabs: companies, actors, artifacts */}
                    {entry.type === 'company'
                      ? <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" aria-label={t('tabs.companies')}><title>{t('tabs.companies')}</title></Building2>
                      : entry.type === 'threat-actor'
                      ? <VenetianMask className="h-4 w-4 shrink-0 text-muted-foreground" aria-label={t('tabs.actors')}><title>{t('tabs.actors')}</title></VenetianMask>
                      : <Crosshair className="h-4 w-4 shrink-0 text-muted-foreground" aria-label={t('tabs.artifacts')}><title>{t('tabs.artifacts')}</title></Crosshair>}
                    <span className="font-mono text-sm text-foreground font-medium truncate" title={entry.indicator}>
                      {entry.indicator}
                    </span>
                    {/* Short of room, the type label gives way before the indicator */}
                    <span className="hidden sm:inline text-xs text-muted-foreground uppercase tracking-wide min-w-0 truncate shrink-[6]">
                      {t(`type.${entry.type as IndicatorType}`)}
                    </span>
                  </span>
                  {(entry.username || entry.via === 'api') && (
                    <span className="flex items-center gap-1.5 shrink-0">
                      {entry.username && (
                        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('history.ranBy', { username: entry.username })}>
                          <UserRound className="h-3.5 w-3.5 shrink-0" aria-hidden />
                          {entry.username}
                        </span>
                      )}
                      {entry.via === 'api' && (
                        <span className="inline-flex px-1.5 py-0.5 rounded border border-border text-[0.65rem] font-semibold uppercase tracking-wide text-muted-foreground" title={t('history.viaApiTitle')}>
                          API
                        </span>
                      )}
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 ml-auto justify-end">
                  {/* No risk/knowledge scoring shown for companies for now; actors have no
                      risk (activity replaces it), so only their Knowledge is listed */}
                  {entry.type !== 'company' && (<>
                  {entry.type !== 'threat-actor' && entry.quadrant && (
                    <span className={`hidden md:inline-flex px-2 py-0.5 rounded-full border text-xs font-medium ${QUADRANT_META[entry.quadrant].className}`}>
                      {quadrantLabel(entry.quadrant, t, entry.type as IndicatorType)}
                    </span>
                  )}
                  <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('history.knowledgeTitle')}>
                    K
                    <span className="inline-flex px-2 py-0.5 rounded-full border border-border bg-muted/30 font-semibold text-foreground">
                      {entry.knowledge_score ?? '—'}
                    </span>
                  </span>
                  {entry.type !== 'threat-actor' && (
                    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('history.riskTitle')}>
                      R <ScoreBadge score={entry.score} />
                    </span>
                  )}
                  </>)}
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </Link>
              {can('analyze') && (
                <Link
                  to={rerunUrl(entry.type, entry.indicator)}
                  title={t('history.rerunTitle', { indicator: entry.indicator })}
                  aria-label={t('history.rerunTitle', { indicator: entry.indicator })}
                  className="shrink-0 flex items-center px-3 border-l border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-colors"
                >
                  <RotateCw className="h-4 w-4" />
                </Link>
              )}
              </div>
            ))}
          </div>
        )}
      </main>
    </Layout>
  )
}
