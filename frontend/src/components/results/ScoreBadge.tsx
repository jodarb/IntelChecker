import { Gauge, CheckCircle2, AlertTriangle, ShieldX, AlertCircle, SearchX } from 'lucide-react'
import { useI18n } from '@/i18n/useI18n'
import { useScoresHidden } from './scoreVisibility'

interface Props {
  score: number | null
  isError?: boolean
  hasResult?: boolean
}

// Two visually distinct kinds of chip share this component, deliberately styled so
// they're never confused at a glance: the *status* chip (error / no results / no
// score) is a soft, pastel pill — it's metadata about the lookup itself. The
// *score* chip is a solid, high-contrast pill — it's the actual 0-10 verdict, and
// needs to read as categorically more important than a status note, especially
// since a high score and an error both lean red. `0` is a genuine "checked, found
// clean" score — distinct from `null`, which means there was nothing to score.
// Normalizers can yield fractional subscores (e.g. Recorded Future's 0-99 → 0-10).
const fmt = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1))

export default function ScoreBadge({ score, isError = false, hasResult = false }: Props) {
  const { t } = useI18n()
  const hidden = useScoresHidden()
  if (isError) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold text-red-400 bg-red-500/10 border-red-500/30">
        <AlertCircle className="h-3 w-3" />
        {t('badge.error')}
      </span>
    )
  }
  // Scores hidden (company lookups): only the status chips remain
  if (hidden && (score != null || hasResult)) return null
  if (score == null) {
    if (hasResult) {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-medium text-yellow-400 bg-yellow-500/10 border-yellow-500/30">
          <Gauge className="h-3 w-3" />
          {t('badge.noScore')}
        </span>
      )
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-medium text-yellow-400 bg-yellow-500/10 border-yellow-500/30">
        <SearchX className="h-3 w-3" />
        {t('badge.noResults')}
      </span>
    )
  }
  if (score === 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold text-white bg-green-600">
        <CheckCircle2 className="h-3 w-3" />
        {fmt(score)}/10
      </span>
    )
  }
  if (score <= 3) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold text-white bg-yellow-600">
        <AlertTriangle className="h-3 w-3" />
        {fmt(score)}/10
      </span>
    )
  }
  if (score <= 6) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold text-white bg-orange-600">
        <AlertTriangle className="h-3 w-3" />
        {fmt(score)}/10
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-bold text-white bg-red-600">
      <ShieldX className="h-3 w-3" />
      {fmt(score)}/10
    </span>
  )
}
