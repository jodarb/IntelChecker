import { useEffect, useMemo, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import SummarySection from '@/components/results/SummarySection'
import { getEnginesForType, type EngineConfig, type IndicatorType, type QueryResult } from '@/registry'

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'File Hash',
  asn: 'ASN',
  'threat-actor': 'Threat Actor',
}

const BACKEND = 'http://localhost:8000'

function useAllEngineQueries(
  engines: EngineConfig[],
  indicator: string,
  type: string,
): Record<string, QueryResult> {
  const [results, setResults] = useState<Record<string, QueryResult>>(() =>
    Object.fromEntries(engines.map(e => [e.id, { loading: true, data: null, error: null }])),
  )

  useEffect(() => {
    if (!indicator) return
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
  }, [indicator, type])

  return results
}

function EngineCard({ engine, result }: { engine: EngineConfig; result: QueryResult }) {
  const Component = engine.component
  return <Component loading={result.loading} error={result.error} data={result.data} />
}

export default function ResultsPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('indicator') ?? ''
  const type = (searchParams.get('type') ?? 'auto') as IndicatorType

  const engines = useMemo(() => getEnginesForType(type), [type])
  const results = useAllEngineQueries(engines, indicator, type)

  // Random score per search — placeholder until VerdictEngine is implemented
  const score = useMemo(() => Math.floor(Math.random() * 11), [indicator])

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
        <SummarySection type={type} engines={engines} results={results} score={score} />

        {/* Engine results */}
        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">Results by engine</p>
          <div className="grid grid-cols-1 gap-4">
            {engines.map(engine => (
              <EngineCard key={engine.id} engine={engine} result={results[engine.id]} />
            ))}
          </div>
        </div>

      </main>
    </Layout>
  )
}
