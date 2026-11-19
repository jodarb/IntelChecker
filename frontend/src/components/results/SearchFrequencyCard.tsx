import { useFetchJson } from '@/hooks/useFetchJson'
import { Link } from 'react-router-dom'
import { History, ExternalLink } from 'lucide-react'
import { useI18n } from '@/i18n/useI18n'

interface Frequency {
  last_24h: number
  last_72h: number
  last_30d: number
}

interface Props {
  indicator: string
  // Set on HistoryDetailPage: the entry being viewed is itself already a saved
  // row, so the backend's raw count already includes it — subtract 1 so the
  // number reflects *other* occurrences, not this one. On a live ResultsPage
  // lookup the current search hasn't been saved yet, so the raw count already
  // excludes it and no adjustment is needed.
  excludeSelf?: boolean
}

const BACKEND = '/api'

function useSearchFrequency(indicator: string): Frequency | null {
  const { data } = useFetchJson<Frequency>(
    indicator ? `${BACKEND}/history/frequency?indicator=${encodeURIComponent(indicator)}` : null,
  )
  return data
}

// 0 = never seen, 1 = green, 2 = yellow, 3 = orange, 4 = red. Green only shows up
// for stale hits — something seen in the 30d window but nothing in the last 72h.
// The moment there's any hit within 72h (which includes any hit within 24h), it's
// at least yellow — recent activity is never "cooler" than that, no matter how
// small the count. From that yellow floor, higher counts in the tighter windows
// escalate to orange/red, since a burst in the last 24h is far more significant
// than the same count over 30 days.
const THRESHOLDS: Record<keyof Frequency, { yellow: number; orange: number; red: number }> = {
  last_24h: { yellow: 1, orange: 3, red: 5 },
  last_72h: { yellow: 1, orange: 5, red: 8 },
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

export default function SearchFrequencyCard({ indicator, excludeSelf = false }: Props) {
  const raw = useSearchFrequency(indicator)
  const { t } = useI18n()
  if (!raw) return null

  const freq: Frequency = excludeSelf
    ? {
        last_24h: Math.max(0, raw.last_24h - 1),
        last_72h: Math.max(0, raw.last_72h - 1),
        last_30d: Math.max(0, raw.last_30d - 1),
      }
    : raw

  const style = LEVEL_STYLES[overallLevel(freq)]

  return (
    <div className={`rounded-lg border p-4 flex items-center gap-4 ${style.border} ${style.bg}`}>
      <History className={`h-4 w-4 shrink-0 ${style.text}`} />
      <span className={`text-xs uppercase tracking-wide font-medium shrink-0 ${style.text}`}>
        {t('results.frequency')}
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
        <Link
          to={`/history?indicator=${encodeURIComponent(indicator)}`}
          className={`inline-flex items-center gap-1 text-xs hover:underline ${style.text}`}
        >
          <ExternalLink className="h-3 w-3" /> {t('results.viewAll')}
        </Link>
      </div>
    </div>
  )
}
