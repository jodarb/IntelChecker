import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, ChevronDown, RotateCcw, Save, Undo2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import { useEngines } from '@/EnginesContext'
import { useVerdictConfigEditor } from '@/hooks/useVerdictWeights'
import type { EngineWeight, VerdictConfig } from '@/verdictEngine'
import type { IndicatorType } from '@/registry'

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP',
  domain: 'Domain',
  url: 'URL',
  hash: 'Hash',
  asn: 'ASN',
  'threat-actor': 'Actor',
}

function NumberInput({
  value, onChange, min = 0, max = 100, step = 1, placeholder, className = '',
}: {
  value: number | '' | undefined
  onChange: (v: number | '') => void
  min?: number
  max?: number
  step?: number
  placeholder?: string
  className?: string
}) {
  return (
    <input
      type="number"
      inputMode="decimal"
      min={min}
      max={max}
      step={step}
      value={value ?? ''}
      placeholder={placeholder}
      onChange={e => onChange(e.target.value === '' ? '' : Number(e.target.value))}
      className={`h-8 w-20 rounded-md border border-input bg-background px-2 text-sm text-right text-foreground focus:outline-none focus:ring-2 focus:ring-ring ${className}`}
    />
  )
}

function EngineRow({
  id, label, logo, supports, weight, onChange,
}: {
  id: string
  label: string
  logo?: string
  supports: IndicatorType[]
  weight: EngineWeight
  onChange: (w: EngineWeight) => void
}) {
  const overrides = weight.knowledge_by_type ?? {}
  const overrideCount = Object.keys(overrides).length
  const [open, setOpen] = useState(overrideCount > 0)

  const setOverride = (type: IndicatorType, v: number | '') => {
    const next = { ...overrides }
    if (v === '') delete next[type]
    else next[type] = v
    onChange({ ...weight, knowledge_by_type: next })
  }

  return (
    <div className="rounded-lg border border-border bg-muted/20">
      <div className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-3 px-3 py-2">
        <div className="flex items-center gap-2 min-w-0">
          {logo && (
            <span className="h-6 w-6 shrink-0 rounded-md bg-white border border-border/50 flex items-center justify-center overflow-hidden">
              <img src={logo} alt="" className="h-4 w-4 object-contain" />
            </span>
          )}
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium text-foreground truncate">{label}</span>
            <span className="text-xs text-muted-foreground truncate">
              {id} · {supports.map(t => TYPE_LABELS[t] ?? t).join(', ')}
            </span>
          </div>
        </div>
        <NumberInput value={weight.risk} onChange={v => onChange({ ...weight, risk: v === '' ? 0 : v })} />
        <NumberInput value={weight.knowledge} onChange={v => onChange({ ...weight, knowledge: v === '' ? 0 : v })} />
        <button
          type="button"
          onClick={() => setOpen(o => !o)}
          title="Knowledge weight overrides per indicator type"
          className="inline-flex items-center gap-1 h-8 px-2 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-muted/60 w-24 justify-end"
        >
          {overrideCount > 0 ? `${overrideCount} override${overrideCount > 1 ? 's' : ''}` : 'Per type'}
          <ChevronDown className={`h-3 w-3 transition-transform ${open ? 'rotate-180' : ''}`} />
        </button>
      </div>
      {open && (
        <div className="flex flex-wrap gap-3 px-3 pb-3 pt-1 border-t border-border/60">
          <span className="w-full text-xs text-muted-foreground">
            Knowledge weight for a specific indicator type. Leave blank to use the general value ({weight.knowledge}).
          </span>
          {supports.map(t => (
            <label key={t} className="flex items-center gap-2 text-xs text-muted-foreground">
              {TYPE_LABELS[t] ?? t}
              <NumberInput
                value={overrides[t]}
                placeholder={String(weight.knowledge)}
                onChange={v => setOverride(t, v)}
              />
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AdminPage() {
  const { engines } = useEngines()
  const { config, error: loadError, save, reset, reload } = useVerdictConfigEditor()
  // null = no local edits; the form shows the saved config.
  const [edits, setEdits] = useState<VerdictConfig | null>(null)
  const draft = edits ?? config
  const setDraft = setEdits
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)

  const dirty = useMemo(
    () => !!config && !!draft && JSON.stringify(config) !== JSON.stringify(draft),
    [config, draft],
  )

  const rows = useMemo(() => {
    if (!draft) return []
    return Object.keys(draft.engines)
      .map(id => {
        const engine = engines.find(e => e.id === id)
        return { id, label: engine?.label ?? id, logo: engine?.logo, supports: engine?.supports ?? [] }
      })
      .sort((a, b) =>
        (draft.engines[b.id].risk - draft.engines[a.id].risk)
        || (draft.engines[b.id].knowledge - draft.engines[a.id].knowledge)
        || a.label.localeCompare(b.label))
  // Sort only on load/save, not on every keystroke (rows would jump while typing).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [config, engines])

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    setMessage(null)
    try {
      await fn()
      setEdits(null)
      setMessage({ kind: 'ok', text: ok })
    } catch (e) {
      setMessage({ kind: 'error', text: e instanceof Error ? e.message : 'Unexpected error' })
    } finally {
      setBusy(false)
    }
  }

  const onReset = () => {
    if (!window.confirm('Reset every weight and threshold to the built-in defaults? This discards all admin changes.')) return
    run(reset, 'Weights reset to defaults.')
  }

  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-4xl mx-auto flex flex-col gap-6">
        <div className="flex items-start gap-4">
          <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
            <Link to="/"><ArrowLeft className="h-4 w-4 mr-1" /> Back</Link>
          </Button>
          <div>
            <h2 className="text-xl font-semibold text-foreground">Admin · Verdict weights</h2>
            <p className="text-sm text-muted-foreground mt-1">
              Changes apply to every new lookup. Archived history entries keep the scores computed when they were run.
            </p>
          </div>
        </div>

        {loadError && (
          <div className="flex items-center gap-3">
            <p className="text-sm text-red-400">{loadError}</p>
            <Button size="sm" variant="ghost" onClick={() => reload()}>Retry</Button>
          </div>
        )}

        {draft && (
          <>
            <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">How the weights work</p>
              <ul className="text-sm text-muted-foreground list-disc pl-5 flex flex-col gap-1">
                <li><span className="text-foreground font-medium">Risk weight</span> — how much the source's 0–10 maliciousness subscore counts in the Risk Score. Only sources that issued a verdict (risk signal or explicit clean) take part.</li>
                <li><span className="text-foreground font-medium">Knowledge weight</span> — how much the source's depth of record (None 0 · Basic 0.5 · Rich 1) adds to the Knowledge Score, out of the total weight of every configured source for that indicator type. Knowledge only grows: sources with no record, or that fail, add nothing.</li>
                <li>A weight of <span className="text-foreground font-medium">0</span> keeps the source visible but out of that score.</li>
              </ul>
            </section>

            <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">Quadrant thresholds (0–10)</p>
              <div className="flex flex-wrap gap-6">
                <label className="flex items-center gap-2 text-sm text-foreground">
                  Knowledge ≥
                  <NumberInput
                    value={draft.thresholds.knowledge}
                    max={10}
                    onChange={v => setDraft({ ...draft, thresholds: { ...draft.thresholds, knowledge: v === '' ? 0 : v } })}
                  />
                  <span className="text-xs text-muted-foreground">is "known"</span>
                </label>
                <label className="flex items-center gap-2 text-sm text-foreground">
                  Risk ≥
                  <NumberInput
                    value={draft.thresholds.risk}
                    max={10}
                    onChange={v => setDraft({ ...draft, thresholds: { ...draft.thresholds, risk: v === '' ? 0 : v } })}
                  />
                  <span className="text-xs text-muted-foreground">is "high risk"</span>
                </label>
              </div>
            </section>

            <section className="flex flex-col gap-2">
              <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 px-3 text-xs text-muted-foreground uppercase tracking-wide font-medium">
                <span>Source</span>
                <span className="w-20 text-right">Risk</span>
                <span className="w-20 text-right">Knowledge</span>
                <span className="w-24" />
              </div>
              {rows.map(r => (
                <EngineRow
                  key={r.id}
                  {...r}
                  weight={draft.engines[r.id]}
                  onChange={w => setDraft({ ...draft, engines: { ...draft.engines, [r.id]: w } })}
                />
              ))}
            </section>

            <div className="sticky bottom-0 -mx-6 px-6 py-3 border-t border-border bg-background/95 backdrop-blur flex flex-wrap items-center gap-2">
              <Button onClick={() => run(() => save(draft), 'Weights saved.')} disabled={!dirty || busy} className="gap-1.5">
                <Save className="h-4 w-4" /> Save
              </Button>
              <Button
                variant="ghost"
                onClick={() => { setEdits(null); setMessage(null) }}
                disabled={!dirty || busy}
                className="gap-1.5"
              >
                <Undo2 className="h-4 w-4" /> Discard changes
              </Button>
              <Button variant="ghost" onClick={onReset} disabled={busy} className="gap-1.5 ml-auto">
                <RotateCcw className="h-4 w-4" /> Reset to defaults
              </Button>
              {message && (
                <span className={`w-full text-sm ${message.kind === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
                  {message.text}
                </span>
              )}
              {dirty && !message && <span className="w-full text-xs text-muted-foreground">Unsaved changes</span>}
            </div>
          </>
        )}
      </main>
    </Layout>
  )
}
