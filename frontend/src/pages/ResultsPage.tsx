import { useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import SummarySection from '@/components/results/SummarySection'
import { getEnginesForType, type EngineConfig, type IndicatorType, type QueryResult } from '@/registry'
import DisconnectedCard from '@/components/results/DisconnectedCard'
import { computeVerdict, getEngineSubscore } from '@/verdictEngine'
import { useVerdictWeights } from '@/hooks/useVerdictWeights'
import { useEngineToggles } from '@/hooks/useEngineToggles'
import { useEngines } from '@/EnginesContext'

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'File Hash',
  asn: 'ASN',
  'threat-actor': 'Threat Actor',
}

const BACKEND = '/api'

function useAllEngineQueries(
  engines: EngineConfig[],
  indicator: string,
  type: string,
  ready: boolean,
): Record<string, QueryResult> {
  const [results, setResults] = useState<Record<string, QueryResult>>(() =>
    Object.fromEntries(engines.map(e => [e.id, { loading: true, data: null, error: null }])),
  )

  useEffect(() => {
    if (!indicator || !ready) return
    setResults(Object.fromEntries(engines.map(e => [e.id, { loading: true, data: null, error: null }])))

    engines.forEach(engine => {
      fetch(`${BACKEND}/analyze/${engine.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator, type }),
      })
        .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json() })
        .then(data => setResults(prev => ({ ...prev, [engine.id]: { loading: false, data, error: null } })))
        .catch(() => setResults(prev => ({
          ...prev,
          [engine.id]: { loading: false, data: null, error: 'Could not reach the backend. Is it running?' },
        })))
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [indicator, type, ready, engines])

  return results
}

function EngineCard({
  engine, result, type, weight, indicator,
}: {
  engine: EngineConfig
  result: QueryResult | undefined
  type: IndicatorType
  weight: number | null
  indicator: string
}) {
  const Component = engine.component
  if (!result) {
    return (
      <Component
        loading data={null} error={null} label={engine.label} score={null} weight={weight}
        indicator={indicator} type={type}
      />
    )
  }
  const apiErrorCode = (result.data as any)?.error?.code
  if (!result.loading && apiErrorCode === 'MissingApiKey') {
    return <DisconnectedCard label={engine.label} />
  }
  const score = result.loading ? null : getEngineSubscore(engine.id, type, result.data)
  return (
    <Component
      loading={result.loading}
      error={result.error}
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

  const { engines: allEngines, loading: enginesLoading } = useEngines()
  const engines = useMemo(() => getEnginesForType(allEngines, type), [allEngines, type])
  const { disabled } = useEngineToggles()
  const activeEngines = useMemo(
    () => engines.filter(e => !disabled.has(e.id)),
    [engines, disabled],
  )
  const results = useAllEngineQueries(activeEngines, indicator, type, !enginesLoading)
  const weights = useVerdictWeights()

  const verdict = useMemo(() => {
    if (!weights) return { score: null, contributions: [] }
    return computeVerdict(weights, activeEngines, results, type)
  }, [weights, activeEngines, results, type])

  // Highest-weighted engines float to the top — Array#sort is stable, so engines
  // sharing a weight (including ones absent from weights.json, treated as 0) keep
  // their original relative order.
  const sortedEngines = useMemo(() => {
    if (!weights) return engines
    return [...engines].sort((a, b) => (weights[b.id] ?? 0) - (weights[a.id] ?? 0))
  }, [engines, weights])

  // Once every active engine has settled, log this query to the history DB —
  // once per indicator+type, not on every re-render (e.g. toggling an engine
  // shouldn't spawn a new history entry for the same search).
  const savedKeyRef = useRef<string | null>(null)
  useEffect(() => {
    if (!indicator || !weights || activeEngines.length === 0) return
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
        indicator, type, score: verdict.score, results: snapshot, contributions: verdict.contributions,
      }),
    }).catch(() => {
      // History logging is best-effort — a failure here shouldn't disrupt the lookup itself.
    })
  }, [indicator, type, weights, activeEngines, results, verdict])

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">

        {/* Header */}
        <div className="flex items-start gap-4">
          <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
            <Link to="/">
              <ArrowLeft className="h-4 w-4 mr-1" />
              Back
            </Link>
          </Button>
          <div>
            <h2 className="text-xl font-semibold text-foreground font-mono break-all">{indicator}</h2>
            <span className="text-xs text-muted-foreground uppercase tracking-wide">
              {TYPE_LABELS[type] ?? type}
            </span>
          </div>
        </div>

        {/* Summary */}
        <SummarySection
          type={type}
          engines={activeEngines}
          results={results}
          score={verdict.score}
          contributions={verdict.contributions}
        />

        {/* Engine results */}
        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">Results by engine</p>
          <div className="grid grid-cols-1 gap-4">
            {sortedEngines.map(engine => (
              disabled.has(engine.id)
                ? <DisconnectedCard key={engine.id} label={engine.label} reason="disabled" />
                : (
                  <EngineCard
                    key={engine.id}
                    engine={engine}
                    result={results[engine.id]}
                    type={type}
                    weight={weights?.[engine.id] ?? null}
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
