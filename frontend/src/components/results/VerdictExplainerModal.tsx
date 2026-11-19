import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import type { VerdictResult, VerdictThresholds } from '@/verdictEngine'
import { OUTCOME_META, QUADRANT_META, depthLabel } from '@/quadrants'

interface Props {
  open: boolean
  onClose: () => void
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
}

type Tab = 'knowledge' | 'risk'

function Formula({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-muted/10 px-3 py-2 text-xs font-mono text-muted-foreground">
      {children}
    </div>
  )
}

function KnowledgeTab({ verdict }: { verdict: VerdictResult }) {
  const rows = verdict.contributions.knowledge
  const totalWeight = rows.reduce((s, c) => s + c.weight, 0)
  const sum = rows.reduce((s, c) => s + c.weight * c.depth, 0)
  return (
    <>
      <p className="text-sm text-muted-foreground">
        How much of the available intel coverage has information on this indicator, good or bad.
        Every configured and enabled source for this indicator type counts in the total; each one adds
        its weight × depth of record (None = 0, Basic = 0.5, Rich = 1). Sources with no record — or that
        failed to answer — add nothing, so knowledge only grows as sources contribute and no single
        source can reach 10 on its own. Sources without an API key or disabled are left out.
      </p>
      {rows.length === 0 ? (
        <p className="text-sm text-foreground font-medium">No configured source has a knowledge weight for this indicator type — showing N/A.</p>
      ) : (
        <>
          <div className="flex flex-col gap-2">
            <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 text-xs text-muted-foreground uppercase tracking-wide font-medium px-1">
              <span>Source</span>
              <span className="text-right w-14">Weight</span>
              <span className="text-right w-14">Depth</span>
              <span className="text-right w-24">Outcome</span>
            </div>
            {rows.map(c => (
              <div
                key={c.engineId}
                className="grid grid-cols-[1fr_auto_auto_auto] gap-3 items-center rounded-md border border-border bg-muted/20 px-3 py-2 text-sm"
              >
                <span className="text-foreground font-medium truncate">{c.label}</span>
                <span className="text-right text-muted-foreground w-14">{c.weight}</span>
                <span className="text-right text-foreground font-medium w-14">{depthLabel(c.depth)}</span>
                <span className={`text-right text-xs w-24 ${OUTCOME_META[c.outcome].className}`}>
                  {OUTCOME_META[c.outcome].label}
                </span>
              </div>
            ))}
          </div>
          <Formula>
            knowledge = round(10 × Σ(weight × depth) / Σ(weight)) = round(10 × {sum.toFixed(1)} / {totalWeight}) ={' '}
            <span className="text-foreground font-semibold">{verdict.knowledge}/10</span>
          </Formula>
        </>
      )}
    </>
  )
}

function RiskTab({ verdict }: { verdict: VerdictResult }) {
  const rows = verdict.contributions.risk
  const totalWeight = rows.reduce((s, c) => s + c.weight, 0)
  const sum = rows.reduce((s, c) => s + c.weight * c.subscore, 0)
  return (
    <>
      <p className="text-sm text-muted-foreground">
        Weighted average of the sources that issued an actual verdict — a risk signal or an explicit
        clean evaluation. Sources with no record, or with only context (e.g. Shodan, IPinfo), are left
        out: not knowing an indicator is not the same as confirming it's benign.
      </p>
      {verdict.risk == null ? (
        <p className="text-sm text-foreground font-medium">
          No source issued a risk verdict for this indicator — showing "No data", not a clean 0.
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
            {rows.map(c => (
              <div
                key={c.engineId}
                className="grid grid-cols-4 gap-2 items-center rounded-md border border-border bg-muted/20 px-3 py-2 text-sm"
              >
                <span className="text-foreground font-medium truncate">{c.label}</span>
                <span className="text-right text-muted-foreground">{c.weight}</span>
                <span className="text-right text-foreground font-medium">{c.subscore.toFixed(1)}/10</span>
                <span className="text-right text-muted-foreground">{((c.weight / totalWeight) * 100).toFixed(0)}%</span>
              </div>
            ))}
          </div>
          <Formula>
            risk = round(Σ(weight × subscore) / Σ(weight)) = round({sum.toFixed(1)} / {totalWeight}) ={' '}
            <span className="text-foreground font-semibold">{verdict.risk}/10</span>
          </Formula>
        </>
      )}
    </>
  )
}

export default function VerdictExplainerModal({ open, onClose, verdict, thresholds }: Props) {
  const [tab, setTab] = useState<Tab>('knowledge')

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  const quadrant = verdict.quadrant ? QUADRANT_META[verdict.quadrant] : null

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-xl mx-4 rounded-lg border border-border bg-background shadow-2xl overflow-hidden flex flex-col max-h-[85vh]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 shrink-0">
          <span className="text-sm font-semibold text-foreground">Verdict · How it's calculated</span>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex border-b border-border shrink-0">
          {(['knowledge', 'risk'] as Tab[]).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
                tab === t ? 'text-foreground border-b-2 border-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {t === 'knowledge' ? `Knowledge · ${verdict.knowledge ?? 'N/A'}` : `Risk · ${verdict.risk ?? 'No data'}`}
            </button>
          ))}
        </div>

        <div className="overflow-auto flex-1 px-4 py-4 flex flex-col gap-4">
          {tab === 'knowledge' ? <KnowledgeTab verdict={verdict} /> : <RiskTab verdict={verdict} />}

          {quadrant && (
            <div className="rounded-md border border-border bg-muted/10 px-3 py-2 text-xs text-muted-foreground">
              <span className="text-foreground font-semibold">{quadrant.label}</span> — {quadrant.hint}
              {thresholds && (
                <span className="block mt-1">
                  Thresholds: knowledge ≥ {thresholds.knowledge} is "known", risk ≥ {thresholds.risk} is "high risk" (editable in Admin).
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
