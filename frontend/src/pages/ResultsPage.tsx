import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import SummarySection from '@/components/results/SummarySection'
import SearchFrequencyCard from '@/components/results/SearchFrequencyCard'
import { getEnginesForType, type EngineConfig, type IndicatorType, type QueryResult } from '@/registry'
import DisconnectedCard from '@/components/results/DisconnectedCard'
import {
  computeVerdict, getEngineAssessment, knowledgeWeightOf, riskWeightOf, EMPTY_VERDICT,
  type VerdictConfig,
} from '@/verdictEngine'
import type { CardWeight } from '@/components/results/WeightBadge'
import { useVerdictWeights } from '@/hooks/useVerdictWeights'
import { useEngineToggles } from '@/hooks/useEngineToggles'
import { useEngines } from '@/EnginesContext'
import { useI18n } from '@/i18n/useI18n'
import { BACKEND_DOWN } from '@/i18n/errors'

const BACKEND = '/api'

type ResultMap = Record<string, QueryResult>

const loadingMap = (engines: EngineConfig[]): ResultMap =>
  Object.fromEntries(engines.map(e => [e.id, { loading: true, data: null, error: null }]))

// One POST /analyze/{engine} per source, fired in parallel. Responses are stored
// under the key of the lookup that produced them (indicator + type + engine set),
// so when the analyst moves to another indicator mid-lookup the old requests are
// aborted and any late answer is discarded instead of overwriting the new cards.
function useAllEngineQueries(
  engines: EngineConfig[],
  indicator: string,
  type: string,
  ready: boolean,
): ResultMap {
  const runKey = `${indicator}|${type}|${engines.map(e => e.id).join(',')}`
  const [stored, setStored] = useState<{ key: string; results: ResultMap }>({ key: '', results: {} })

  useEffect(() => {
    if (!indicator || !ready) return
    const ctrl = new AbortController()
    const put = (id: string, r: QueryResult) =>
      setStored(prev => ({
        key: runKey,
        results: { ...(prev.key === runKey ? prev.results : {}), [id]: r },
      }))

    engines.forEach(engine => {
      fetch(`${BACKEND}/analyze/${engine.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator, type }),
        signal: ctrl.signal,
      })
        .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json() })
        .then(data => put(engine.id, { loading: false, data, error: null }))
        .catch(() => {
          if (ctrl.signal.aborted) return
          put(engine.id, { loading: false, data: null, error: BACKEND_DOWN })
        })
    })
    return () => ctrl.abort()
  }, [indicator, type, ready, engines, runKey])

  // Engines that haven't answered for *this* lookup yet show as loading.
  return useMemo(
    () => ({ ...loadingMap(engines), ...(stored.key === runKey ? stored.results : {}) }),
    [engines, stored, runKey],
  )
}

function cardWeight(
  config: VerdictConfig | null, engineId: string, type: IndicatorType, depth: number | null,
): CardWeight | null {
  if (!config) return null
  return { risk: riskWeightOf(config, engineId), knowledge: knowledgeWeightOf(config, engineId, type), depth }
}

function EngineCard({
  engine, result, type, config, indicator,
}: {
  engine: EngineConfig
  result: QueryResult | undefined
  type: IndicatorType
  config: VerdictConfig | null
  indicator: string
}) {
  const Component = engine.component
  const { t } = useI18n()
  const assessment = getEngineAssessment(engine.id, type, result)
  const weight = cardWeight(config, engine.id, type, assessment.depth)
  if (!result) {
    return (
      <Component
        loading data={null} error={null} label={engine.label} score={null} weight={weight}
        indicator={indicator} type={type}
      />
    )
  }
  const apiErrorCode = (result.data as { error?: { code?: string } } | null)?.error?.code
  if (!result.loading && apiErrorCode === 'MissingApiKey') {
    return <DisconnectedCard label={engine.label} />
  }
  const score = result.loading ? null : assessment.subscore
  return (
    <Component
      loading={result.loading}
      error={result.error === BACKEND_DOWN ? t('common.backendDown') : result.error}
      data={result.data}
      label={engine.label}
      score={score}
      weight={weight}
      indicator={indicator}
      type={type}
    />
  )
}

export default function ResultsPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('indicator') ?? ''
  const type = (searchParams.get('type') ?? 'auto') as IndicatorType
  const { t } = useI18n()

  const { engines: allEngines, status, loading: enginesLoading } = useEngines()
  const engines = useMemo(() => getEnginesForType(allEngines, type), [allEngines, type])
  const { disabled } = useEngineToggles()
  // Sources without their API key are shown as switched off and never queried.
  const isUnconfigured = (id: string) => status?.[id]?.connected === false
  const activeEngines = useMemo(
    () => engines.filter(e => !disabled.has(e.id) && status?.[e.id]?.connected !== false),
    [engines, disabled, status],
  )
  const results = useAllEngineQueries(activeEngines, indicator, type, !enginesLoading)
  const config = useVerdictWeights()

  const verdict = useMemo(() => {
    if (!config) return EMPTY_VERDICT
    return computeVerdict(config, activeEngines, results, type)
  }, [config, activeEngines, results, type])

  // Highest-weighted engines float to the top (risk weight first, knowledge weight
  // as tie-breaker) — Array#sort is stable, so ties keep their original order.
  const sortedEngines = useMemo(() => {
    if (!config) return engines
    return [...engines].sort((a, b) =>
      riskWeightOf(config, b.id) - riskWeightOf(config, a.id)
      || knowledgeWeightOf(config, b.id, type) - knowledgeWeightOf(config, a.id, type))
  }, [engines, config, type])

  // Once every active engine has settled, log this query to the history DB —
  // once per indicator+type, not on every re-render (e.g. toggling an engine
  // shouldn't spawn a new history entry for the same search).
  const savedKeyRef = useRef<string | null>(null)
  useEffect(() => {
    if (!indicator || !config || activeEngines.length === 0) return
    const allSettled = activeEngines.every(e => results[e.id] && !results[e.id].loading)
    if (!allSettled) return

    const key = `${indicator}|${type}`
    if (savedKeyRef.current === key) return
    savedKeyRef.current = key

    const snapshot = Object.fromEntries(
      activeEngines.map(e => [
        e.id,
        { label: e.label, data: results[e.id]?.data ?? null, error: results[e.id]?.error ?? null },
      ]),
    )

    fetch(`${BACKEND}/history`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicator,
        type,
        score: verdict.risk,
        knowledge_score: verdict.knowledge,
        quadrant: verdict.quadrant,
        results: snapshot,
        contributions: verdict.contributions,
      }),
    }).catch(() => {
      // History logging is best-effort — a failure here shouldn't disrupt the lookup itself.
    })
  }, [indicator, type, config, activeEngines, results, verdict])

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">

        {/* Header */}
        <div className="flex items-start gap-4">
          <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
            <Link to="/">
              <ArrowLeft className="h-4 w-4 mr-1" />
              {t('common.back')}
            </Link>
          </Button>
          <div>
            <h2 className="text-xl font-semibold text-foreground font-mono break-all">{indicator}</h2>
            <span className="text-xs text-muted-foreground uppercase tracking-wide">
              {t(`type.${type}`)}
            </span>
          </div>
        </div>

        <SearchFrequencyCard indicator={indicator} />

        {/* Summary */}
        <SummarySection
          indicator={indicator}
          type={type}
          engines={activeEngines}
          results={results}
          verdict={verdict}
          thresholds={config?.thresholds ?? null}
        />

        {/* Engine results */}
        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('results.byEngine')}</p>
          <div className="grid grid-cols-1 gap-4">
            {sortedEngines.map(engine => (
              isUnconfigured(engine.id)
                ? <DisconnectedCard key={engine.id} label={engine.label} reason="missing-key" />
                : disabled.has(engine.id)
                ? <DisconnectedCard key={engine.id} label={engine.label} reason="disabled" />
                : (
                  <EngineCard
                    key={engine.id}
                    engine={engine}
                    result={results[engine.id]}
                    type={type}
                    config={config}
                    indicator={indicator}
                  />
                )
            ))}
          </div>
        </div>

      </main>
    </Layout>
  )
}
