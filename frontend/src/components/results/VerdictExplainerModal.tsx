import { useEffect } from 'react'
import { X } from 'lucide-react'
import type { VerdictContribution } from '@/verdictEngine'

interface Props {
  open: boolean
  onClose: () => void
  score: number | null
  contributions: VerdictContribution[]
}

export default function VerdictExplainerModal({ open, onClose, score, contributions }: Props) {
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  const totalWeight = contributions.reduce((sum, c) => sum + c.weight, 0)
  const weightedSum = contributions.reduce((sum, c) => sum + c.weight * c.subscore, 0)

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-lg mx-4 rounded-lg border border-border bg-background shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 shrink-0">
          <span className="text-sm font-semibold text-foreground">Threat Score · How it's calculated</span>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-auto flex-1 px-4 py-4 flex flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            Weighted average of the sources that responded successfully for this indicator.
            Sources that are disconnected, errored, or don't provide a maliciousness signal
            (e.g. Shodan, IPinfo) are excluded from the calculation.
          </p>

          {contributions.length === 0 ? (
            <p className="text-sm text-foreground font-medium">
              No source with a maliciousness signal responded successfully for this indicator — showing N/A.
            </p>
          ) : (
            <>
              <div className="flex flex-col gap-2">
                <div className="grid grid-cols-4 gap-2 text-xs text-muted-foreground uppercase tracking-wide font-medium px-1">
                  <span>Source</span>
                  <span className="text-right">Weight</span>
                  <span className="text-right">Subscore</span>
                  <span className="text-right">Share</span>
                </div>
                {contributions.map(c => (
                  <div
                    key={c.engineId}
                    className="grid grid-cols-4 gap-2 items-center rounded-md border border-border bg-muted/20 px-3 py-2 text-sm"
                  >
                    <span className="text-foreground font-medium truncate">{c.label}</span>
                    <span className="text-right text-muted-foreground">{c.weight}</span>
                    <span className="text-right text-foreground font-medium">{c.subscore.toFixed(1)}/10</span>
                    <span className="text-right text-muted-foreground">
                      {((c.weight / totalWeight) * 100).toFixed(0)}%
                    </span>
                  </div>
                ))}
              </div>

              <div className="rounded-md border border-border bg-muted/10 px-3 py-2 text-xs font-mono text-muted-foreground">
                score = round(Σ(weight × subscore) / Σ(weight)) = round({weightedSum.toFixed(1)} / {totalWeight}) ={' '}
                <span className="text-foreground font-semibold">{score}/10</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
