import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, History } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import SummarySection from '@/components/results/SummarySection'
import SearchFrequencyCard from '@/components/results/SearchFrequencyCard'
import RawJsonModal from '@/components/results/RawJsonModal'
import { useEngines } from '@/EnginesContext'
import { getEngineSubscore, type VerdictContribution } from '@/verdictEngine'
import type { IndicatorType, QueryResult } from '@/registry'

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
  score: number | null
  results: Record<string, StoredEngineResult>
  contributions: VerdictContribution[]
}

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  hash: 'File Hash',
  asn: 'ASN',
  'threat-actor': 'Threat Actor',
}

const BACKEND = '/api'

function formatTimestamp(ts: string): string {
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString()
}

function UnknownEngineCard({ label, data }: { label: string; data: unknown }) {
  const [rawOpen, setRawOpen] = useState(false)
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40">
        <span className="font-semibold text-sm text-foreground">{label}</span>
        <button
          onClick={() => setRawOpen(true)}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
        >
          RAW
        </button>
      </div>
      <div className="px-4 py-4">
        <p className="text-sm text-muted-foreground">
          This source is no longer configured — showing the raw stored response.
        </p>
      </div>
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title={label} />
    </div>
  )
}

export default function HistoryDetailPage() {
  const { id } = useParams()
  const { engines } = useEngines()
  const [entry, setEntry] = useState<HistoryDetail | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setEntry(null)
    setError(null)
    fetch(`${BACKEND}/history/${id}`)
      .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json() })
      .then(setEntry)
      .catch(() => setError('Could not load this history entry. It may have been removed.'))
  }, [id])

  if (error) {
    return (
      <Layout>
        <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">
          <Button variant="ghost" size="sm" asChild className="w-fit">
            <Link to="/history"><ArrowLeft className="h-4 w-4 mr-1" /> Back to history</Link>
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
          <p className="text-sm text-muted-foreground">Loading...</p>
        </main>
      </Layout>
    )
  }

  const resultsForSummary: Record<string, QueryResult> = Object.fromEntries(
    Object.entries(entry.results).map(([id, r]) => [id, { loading: false, data: r.data, error: r.error }]),
  )
  const enginesForSummary = engines.filter(e => e.id in entry.results)

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">

        <div className="flex items-start gap-4">
          <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
            <Link to="/history">
              <ArrowLeft className="h-4 w-4 mr-1" />
              Back to history
            </Link>
          </Button>
          <div>
            <h2 className="text-xl font-semibold text-foreground font-mono break-all">{entry.indicator}</h2>
            <span className="text-xs text-muted-foreground uppercase tracking-wide">
              {TYPE_LABELS[entry.type] ?? entry.type}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-muted/20 text-xs text-muted-foreground">
          <History className="h-3.5 w-3.5 shrink-0" />
          Archived result from {formatTimestamp(entry.timestamp)} — showing what each source returned at that time, not a live lookup.
        </div>

        <SearchFrequencyCard indicator={entry.indicator} />

        <SummarySection
          type={entry.type}
          engines={enginesForSummary}
          results={resultsForSummary}
          score={entry.score}
          contributions={entry.contributions}
        />

        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">Results by engine</p>
          <div className="grid grid-cols-1 gap-4">
            {Object.entries(entry.results).map(([engineId, stored]) => {
              const engine = engines.find(e => e.id === engineId)
              if (!engine) {
                return <UnknownEngineCard key={engineId} label={stored.label} data={stored.data} />
              }
              const Component = engine.component
              const score = getEngineSubscore(engineId, entry.type, stored.data)
              const weight = entry.contributions.find(c => c.engineId === engineId)?.weight ?? 0
              return (
                <Component
                  key={engineId}
                  loading={false}
                  error={stored.error}
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
