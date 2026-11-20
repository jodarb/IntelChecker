import { useFetchJson } from '@/hooks/useFetchJson'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ChevronRight, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import ScoreBadge from '@/components/results/ScoreBadge'
import { QUADRANT_META, quadrantLabel } from '@/quadrants'
import type { Quadrant } from '@/verdictEngine'
import { useI18n } from '@/i18n/useI18n'
import type { IndicatorType } from '@/registry'

interface HistoryListEntry {
  id: number
  indicator: string
  type: string
  timestamp: string
  score: number | null
  knowledge_score: number | null
  quadrant: Quadrant | null
  username: string | null
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
  const query = indicator ? `?indicator=${encodeURIComponent(indicator)}` : ''
  const { data: entries, failed } = useFetchJson<HistoryListEntry[]>(`${BACKEND}/history${query}`)
  const error = failed ? t('common.backendDown') : null

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-4xl mx-auto flex flex-col gap-6">
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
              <Link
                key={entry.id}
                to={`/history/${entry.id}`}
                className="flex items-center justify-between gap-4 px-4 py-3 rounded-lg border border-border bg-muted/20 hover:bg-muted/40 transition-colors"
              >
                <div className="flex items-center gap-4 min-w-0">
                  <span className="font-mono text-sm text-foreground font-medium truncate">
                    {entry.indicator}
                  </span>
                  <span className="text-xs text-muted-foreground uppercase tracking-wide shrink-0">
                    {t(`type.${entry.type as IndicatorType}`)}
                  </span>
                </div>
                <div className="flex items-center gap-4 shrink-0">
                  {entry.username && (
                    <span className="hidden sm:inline text-xs text-muted-foreground" title={t('history.ranBy', { username: entry.username })}>
                      {entry.username}
                    </span>
                  )}
                  <span className="text-xs text-muted-foreground">{formatTimestamp(entry.timestamp, locale)}</span>
                  {entry.quadrant && (
                    <span className={`hidden md:inline-flex px-2 py-0.5 rounded-full border text-xs font-medium ${QUADRANT_META[entry.quadrant].className}`}>
                      {quadrantLabel(entry.quadrant, t)}
                    </span>
                  )}
                  <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('history.knowledgeTitle')}>
                    K
                    <span className="inline-flex px-2 py-0.5 rounded-full border border-border bg-muted/30 font-semibold text-foreground">
                      {entry.knowledge_score ?? '—'}
                    </span>
                  </span>
                  <span className="inline-flex items-center gap-1 text-xs text-muted-foreground" title={t('history.riskTitle')}>
                    R <ScoreBadge score={entry.score} />
                  </span>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </main>
    </Layout>
  )
}
