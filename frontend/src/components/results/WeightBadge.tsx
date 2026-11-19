import { Scale, BookOpen } from 'lucide-react'
import { depthLabel } from '@/quadrants'

export interface CardWeight {
  /** Weight in the Risk Score */
  risk: number
  /** Weight in the Knowledge Score (already resolved for the indicator type) */
  knowledge: number
  /** This engine's knowledge depth for the current result (0 / 0.5 / 1), if settled */
  depth?: number | null
}

interface Props {
  weight: CardWeight | null
}

// Always-visible weights for this engine (editable from the Admin page): R = how
// much it moves the Risk Score, K = how much it moves the Knowledge Score. When
// the result has settled, the K chip also shows how much this source knows.
export default function WeightBadge({ weight }: Props) {
  const risk = weight?.risk ?? 0
  const knowledge = weight?.knowledge ?? 0
  const depth = weight?.depth
  return (
    <span className="inline-flex items-center gap-1">
      <span
        title="Risk weight — how much this source moves the Risk Score"
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30"
      >
        <Scale className="h-3 w-3" />
        R {risk}
      </span>
      <span
        title={`Knowledge weight — how much this source moves the Knowledge Score${depth != null ? ` · depth of record: ${depthLabel(depth)}` : ''}`}
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30"
      >
        <BookOpen className="h-3 w-3" />
        K {knowledge}
        {depth != null && (
          <span className={depth >= 1 ? 'text-foreground' : depth > 0 ? 'text-foreground/70' : 'opacity-60'}>
            · {depthLabel(depth)}
          </span>
        )}
      </span>
    </span>
  )
}
