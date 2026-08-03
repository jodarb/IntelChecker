import { Scale } from 'lucide-react'

interface Props {
  weight: number | null
}

// Shows the engine's configured contribution weight (see weights.json) next to
// its result — engines are also sorted by this same weight, highest first.
export default function WeightBadge({ weight }: Props) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30">
      <Scale className="h-3 w-3" />
      {weight ?? 0}
    </span>
  )
}
