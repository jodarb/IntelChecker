import { useState } from 'react'
import { useFetchJson } from '@/hooks/useFetchJson'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, History } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import SummarySection from '@/components/results/SummarySection'
import SearchFrequencyCard from '@/components/results/SearchFrequencyCard'
import RawJsonModal from '@/components/results/RawJsonModal'
import { useEngines } from '@/EnginesContext'
import {
  getEngineAssessment, type Quadrant, type VerdictContributions, type VerdictResult,
} from '@/verdictEngine'
import { useVerdictWeights } from '@/hooks/useVerdictWeights'
import type { IndicatorType, QueryResult } from '@/registry'
import { useI18n } from '@/i18n/useI18n'
import { BACKEND_DOWN } from '@/i18n/errors'
import DisconnectedCard from '@/components/results/DisconnectedCard'

interface StoredEngineResult {
  label: string
  data: unknown
  error: string | null
}

interface HistoryDetail {
  id: number
  indicator: string
  type: IndicatorType
  timestamp: string
  score: number | null            // Risk Score
  knowledge_score: number | null  // null for entries saved before the two-score model
  quadrant: Quadrant | null
  results: Record<string, StoredEngineResult>
  contributions: VerdictContributions
}

const BACKEND = '/api'

function formatTimestamp(ts: string, locale: string): string {
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString(locale)
}

function UnknownEngineCard({ label, data }: { label: string; data: unknown }) {
  const [rawOpen, setRawOpen] = useState(false)
  const { t } = useI18n()
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40">
        <span className="font-semibold text-sm text-foreground">{label}</span>
        <button
          onClick={() => setRawOpen(true)}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
        >
          {t('raw.button')}
        </button>
      </div>
      <div className="px-4 py-4">
        <p className="text-sm text-muted-foreground">
          {t('history.unknownEngine')}
        </p>
      </div>
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title={label} />
    </div>
  )
}

export default function HistoryDetailPage() {
  const { id } = useParams()
  const { engines } = useEngines()
  const { t, locale } = useI18n()
  const config = useVerdictWeights()
  const { data: entry, failed } = useFetchJson<HistoryDetail>(`${BACKEND}/history/${id}`)
  const error = failed ? t('history.loadError') : null

  if (error) {
    return (
      <Layout>
        <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">
          <Button variant="ghost" size="sm" asChild className="w-fit">
            <Link to="/history"><ArrowLeft className="h-4 w-4 mr-1" /> {t('history.backToHistory')}</Link>
          </Button>
          <p className="text-sm text-red-400">{error}</p>
        </main>
      </Layout>
    )
  }

  if (!entry) {
    return (
      <Layout>
        <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">
          <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
        </main>
      </Layout>
    )
  }

  const resultsForSummary: Record<string, QueryResult> = Object.fromEntries(
    Object.entries(entry.results).map(([id, r]) => [id, { loading: false, data: r.data, error: r.error }]),
  )
  const enginesForSummary = engines.filter(e => e.id in entry.results)
  const assessments = Object.fromEntries(
    Object.keys(entry.results).map(id => [id, getEngineAssessment(id, entry.type, resultsForSummary[id])]),
  )
  // Scores are the ones computed at query time (with the weights in force then),
  // not recomputed with today's weights.
  const verdict: VerdictResult = {
    risk: entry.score,
    knowledge: entry.knowledge_score,
    quadrant: entry.quadrant,
    contributions: entry.contributions,
    responded: Object.values(assessments).filter(a => a.outcome !== 'excluded').length,
    queried: Object.values(entry.results)
      .filter(r => (r.data as { error?: { code?: string } })?.error?.code !== 'MissingApiKey').length,
  }
  const isLegacy = entry.knowledge_score == null && entry.contributions.knowledge.length === 0

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">

        <div className="flex items-start gap-4">
          <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
            <Link to="/history">
              <ArrowLeft className="h-4 w-4 mr-1" />
              {t('history.backToHistory')}
            </Link>
          </Button>
          <div>
            <h2 className="text-xl font-semibold text-foreground font-mono break-all">{entry.indicator}</h2>
            <span className="text-xs text-muted-foreground uppercase tracking-wide">
              {t(`type.${entry.type}`)}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-muted/20 text-xs text-muted-foreground">
          <History className="h-3.5 w-3.5 shrink-0" />
          {t('history.archived', { date: formatTimestamp(entry.timestamp, locale) })}
        </div>

        <SearchFrequencyCard indicator={entry.indicator} excludeSelf />

        <SummarySection
          indicator={entry.indicator}
          type={entry.type}
          engines={enginesForSummary}
          results={resultsForSummary}
          verdict={verdict}
          thresholds={config?.thresholds ?? null}
          unconfigured={Object.values(entry.results)
            .filter(r => (r.data as { error?: { code?: string } } | null)?.error?.code === 'MissingApiKey').length}
        />

        {isLegacy && (
          <p className="text-xs text-muted-foreground -mt-3">
            {t('history.legacy')}
          </p>
        )}

        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('results.byEngine')}</p>
          <div className="grid grid-cols-1 gap-4">
            {Object.entries(entry.results).map(([engineId, stored]) => {
              const engine = engines.find(e => e.id === engineId)
              if (!engine) {
                return <UnknownEngineCard key={engineId} label={stored.label} data={stored.data} />
              }
              if ((stored.data as { error?: { code?: string } } | null)?.error?.code === 'MissingApiKey') {
                return <DisconnectedCard key={engineId} label={stored.label} reason="missing-key" />
              }
              const Component = engine.component
              const assessment = assessments[engineId]
              const score = assessment.subscore
              const weight = {
                risk: entry.contributions.risk.find(c => c.engineId === engineId)?.weight ?? 0,
                knowledge: entry.contributions.knowledge.find(c => c.engineId === engineId)?.weight ?? 0,
                depth: assessment.depth,
              }
              return (
                <Component
                  key={engineId}
                  loading={false}
                  error={stored.error === BACKEND_DOWN ? t('common.backendDown') : stored.error}
                  data={stored.data}
                  label={stored.label}
                  score={score}
                  weight={weight}
                  indicator={entry.indicator}
                  type={entry.type}
                />
              )
            })}
          </div>
        </div>

      </main>
    </Layout>
  )
}
