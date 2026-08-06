import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ChevronRight, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import ScoreBadge from '@/components/results/ScoreBadge'

interface HistoryListEntry {
  id: number
  indicator: string
  type: string
  timestamp: string
  score: number | null
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
  // Backend stores UTC as "YYYY-MM-DD HH:MM:SS" (SQLite datetime('now')) — mark it
  // explicitly as UTC so the browser converts it to the analyst's local time.
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString()
}

export default function HistoryPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('indicator') ?? ''
  const [entries, setEntries] = useState<HistoryListEntry[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setEntries(null)
    setError(null)
    const query = indicator ? `?indicator=${encodeURIComponent(indicator)}` : ''
    fetch(`${BACKEND}/history${query}`)
      .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json() })
      .then(setEntries)
      .catch(() => setError('Could not reach the backend. Is it running?'))
  }, [indicator])

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-4xl mx-auto flex flex-col gap-6">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="sm" asChild className="shrink-0">
            <Link to="/">
              <ArrowLeft className="h-4 w-4 mr-1" />
              Back
            </Link>
          </Button>
          <h2 className="text-xl font-semibold text-foreground">Query History</h2>
        </div>

        {indicator && (
          <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-muted/20 text-sm">
            <span className="text-muted-foreground">Filtered to</span>
            <span className="font-mono text-foreground font-medium break-all">{indicator}</span>
            {entries && (
              <span className="text-muted-foreground">
                — {entries.length} search{entries.length === 1 ? '' : 'es'} total
              </span>
            )}
            <Link
              to="/history"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground ml-auto shrink-0"
            >
              <X className="h-3 w-3" /> Clear filter
            </Link>
          </div>
        )}

        {error && <p className="text-sm text-red-400">{error}</p>}

        {!error && entries === null && (
          <p className="text-sm text-muted-foreground">Loading...</p>
        )}

        {entries && entries.length === 0 && (
          <p className="text-sm text-muted-foreground">
            {indicator ? `No queries logged yet for ${indicator}.` : 'No queries have been logged yet.'}
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
                    {TYPE_LABELS[entry.type] ?? entry.type}
                  </span>
                </div>
                <div className="flex items-center gap-4 shrink-0">
                  <span className="text-xs text-muted-foreground">{formatTimestamp(entry.timestamp)}</span>
                  <ScoreBadge score={entry.score} />
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
