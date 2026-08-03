import { useEffect, useState } from 'react'
import { History } from 'lucide-react'

interface Frequency {
  last_24h: number
  last_72h: number
  last_30d: number
}

const BACKEND = '/api'

function useSearchFrequency(indicator: string): Frequency | null {
  const [freq, setFreq] = useState<Frequency | null>(null)

  useEffect(() => {
    setFreq(null)
    if (!indicator) return
    fetch(`${BACKEND}/history/frequency?indicator=${encodeURIComponent(indicator)}`)
      .then(r => r.json())
      .then(setFreq)
      .catch(() => setFreq(null))
  }, [indicator])

  return freq
}

// 0 = never seen, 1 = green, 2 = yellow, 3 = orange, 4 = red. Each window has its
// own breakpoints since the same raw count means very different things depending
// on the timeframe it happened in — 5 hits in the last 24h is a hot indicator,
// but 5 hits spread across 30 days is unremarkable background noise. The overall
// level is whichever window reads most severe, so a recent burst always wins.
const THRESHOLDS: Record<keyof Frequency, { yellow: number; orange: number; red: number }> = {
  last_24h: { yellow: 2, orange: 3, red: 5 },
  last_72h: { yellow: 3, orange: 5, red: 8 },
  last_30d: { yellow: 4, orange: 9, red: 16 },
}

function levelForCount(count: number, t: { yellow: number; orange: number; red: number }): number {
  if (count <= 0) return 0
  if (count < t.yellow) return 1
  if (count < t.orange) return 2
  if (count < t.red) return 3
  return 4
}

function overallLevel(freq: Frequency): number {
  return Math.max(
    levelForCount(freq.last_24h, THRESHOLDS.last_24h),
    levelForCount(freq.last_72h, THRESHOLDS.last_72h),
    levelForCount(freq.last_30d, THRESHOLDS.last_30d),
  )
}

const LEVEL_STYLES = [
  { border: 'border-border', bg: 'bg-muted/20', text: 'text-muted-foreground' },
  { border: 'border-green-500/40', bg: 'bg-green-500/10', text: 'text-green-400' },
  { border: 'border-yellow-500/40', bg: 'bg-yellow-500/10', text: 'text-yellow-400' },
  { border: 'border-orange-500/40', bg: 'bg-orange-500/10', text: 'text-orange-400' },
  { border: 'border-red-500/40', bg: 'bg-red-500/10', text: 'text-red-400' },
]

export default function SearchFrequencyCard({ indicator }: { indicator: string }) {
  const freq = useSearchFrequency(indicator)
  if (!freq) return null

  const style = LEVEL_STYLES[overallLevel(freq)]

  return (
    <div className={`rounded-lg border p-4 flex items-center gap-4 ${style.border} ${style.bg}`}>
      <History className={`h-4 w-4 shrink-0 ${style.text}`} />
      <span className={`text-xs uppercase tracking-wide font-medium shrink-0 ${style.text}`}>
        Search Frequency
      </span>
      <div className="flex items-center gap-4 text-sm ml-auto">
        <span>
          <span className={`font-semibold ${style.text}`}>{freq.last_24h}</span>
          <span className="text-muted-foreground"> / 24h</span>
        </span>
        <span>
          <span className={`font-semibold ${style.text}`}>{freq.last_72h}</span>
          <span className="text-muted-foreground"> / 72h</span>
        </span>
        <span>
          <span className={`font-semibold ${style.text}`}>{freq.last_30d}</span>
          <span className="text-muted-foreground"> / 30d</span>
        </span>
      </div>
    </div>
  )
}
