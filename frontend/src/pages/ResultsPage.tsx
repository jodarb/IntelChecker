import { useEffect, useMemo, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import SummarySection from '@/components/results/SummarySection'
import { getEnginesForType, type EngineConfig, type IndicatorType, type QueryResult } from '@/registry'
import DisconnectedCard from '@/components/results/DisconnectedCard'
import { computeVerdict } from '@/verdictEngine'
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

function EngineCard({ engine, result }: { engine: EngineConfig; result: QueryResult | undefined }) {
  const Component = engine.component
  if (!result) {
    return <Component loading data={null} error={null} label={engine.label} />
  }
  const apiErrorCode = (result.data as any)?.error?.code
  if (!result.loading && apiErrorCode === 'MissingApiKey') {
    return <DisconnectedCard label={engine.label} />
  }
  return <Component loading={result.loading} error={result.error} data={result.data} label={engine.label} />
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
            {engines.map(engine => (
              disabled.has(engine.id)
                ? <DisconnectedCard key={engine.id} label={engine.label} reason="disabled" />
                : <EngineCard key={engine.id} engine={engine} result={results[engine.id]} />
            ))}
          </div>
        </div>

      </main>
    </Layout>
  )
}
