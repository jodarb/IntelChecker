import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, ChevronDown, RotateCcw, Save, Undo2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import { useEngines } from '@/EnginesContext'
import { useVerdictConfigEditor } from '@/hooks/useVerdictWeights'
import { DEFAULT_SCORING, type EngineWeight, type VerdictConfig } from '@/verdictEngine'
import type { IndicatorType } from '@/registry'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'

/** Every weight (and both thresholds) lives on a 0–10 scale; the backend rejects anything else. */
const WEIGHT_MIN = 0
const WEIGHT_MAX = 10

const clampWeight = (v: number) => Math.min(WEIGHT_MAX, Math.max(WEIGHT_MIN, v))

function NumberInput({
  value, onChange, min = WEIGHT_MIN, max = WEIGHT_MAX, step = 1, placeholder, className = '', ariaLabel,
}: {
  value: number | '' | undefined
  onChange: (v: number | '') => void
  min?: number
  max?: number
  step?: number
  placeholder?: string
  className?: string
  ariaLabel?: string
}) {
  const { t } = useI18n()
  return (
    <input
      type="number"
      inputMode="decimal"
      min={min}
      max={max}
      step={step}
      value={value ?? ''}
      placeholder={placeholder}
      aria-label={ariaLabel}
      title={t('admin.valueBetween', { min, max })}
      // Block characters that could produce out-of-range values (negative sign, exponent).
      onKeyDown={e => { if (['-', '+', 'e', 'E'].includes(e.key)) e.preventDefault() }}
      onChange={e => {
        const raw = e.target.value
        if (raw === '') return onChange('')
        const n = Number(raw)
        if (Number.isNaN(n)) return
        onChange(Math.min(max, Math.max(min, n)))
      }}
      className={`h-8 w-14 rounded-md border border-input bg-background px-2 text-sm text-right text-foreground focus:outline-none focus:ring-2 focus:ring-ring ${className}`}
    />
  )
}

/** Slider + numeric input bound to the same 0–10 weight. */
function WeightControl({
  value, onChange, label,
}: {
  value: number
  onChange: (v: number) => void
  label: string
}) {
  const { t } = useI18n()
  return (
    <div className="flex items-center gap-2 w-44">
      <input
        type="range"
        min={WEIGHT_MIN}
        max={WEIGHT_MAX}
        step={1}
        value={value}
        aria-label={t('admin.sliderAria', { label })}
        onChange={e => onChange(clampWeight(Number(e.target.value)))}
        className="flex-1 min-w-0 h-1.5 cursor-pointer accent-primary"
      />
      <NumberInput
        value={value}
        ariaLabel={t('admin.inputAria', { label })}
        onChange={v => onChange(v === '' ? 0 : clampWeight(v))}
      />
    </div>
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
  const { t, tn } = useI18n()
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
              {id} · {supports.map(type => t(`typeShort.${type}`)).join(', ')}
            </span>
          </div>
        </div>
        <WeightControl label={t('admin.riskOf', { label })} value={weight.risk} onChange={v => onChange({ ...weight, risk: v })} />
        <WeightControl label={t('admin.knowledgeOf', { label })} value={weight.knowledge} onChange={v => onChange({ ...weight, knowledge: v })} />
        <button
          type="button"
          onClick={() => setOpen(o => !o)}
          title={t('admin.overridesTitle')}
          className="inline-flex items-center gap-1 h-8 px-2 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-muted/60 w-24 justify-end"
        >
          {overrideCount > 0 ? tn('admin.overrides', overrideCount) : t('admin.perType')}
          <ChevronDown className={`h-3 w-3 transition-transform ${open ? 'rotate-180' : ''}`} />
        </button>
      </div>
      {open && (
        <div className="flex flex-wrap gap-3 px-3 pb-3 pt-1 border-t border-border/60">
          <span className="w-full text-xs text-muted-foreground">
            {t('admin.overrideHelp', { value: weight.knowledge })}
          </span>
          {supports.map(type => (
            <label key={type} className="flex items-center gap-2 text-xs text-muted-foreground">
              {t(`typeShort.${type}`)}
              <NumberInput
                value={overrides[type]}
                placeholder={String(weight.knowledge)}
                onChange={v => setOverride(type, v)}
              />
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AdminPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-4xl mx-auto flex flex-col gap-6">
        <div className="flex items-start gap-4">
          <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
            <Link to="/"><ArrowLeft className="h-4 w-4 mr-1" /> {t('common.back')}</Link>
          </Button>
          <div>
            <h2 className="text-xl font-semibold text-foreground">{t('admin.title')}</h2>
            <p className="text-sm text-muted-foreground mt-1">
              {t('admin.subtitle')}
            </p>
          </div>
        </div>
        <WeightsEditor />
      </main>
    </Layout>
  )
}

function WeightsEditor() {
  const { engines } = useEngines()
  const { config, error: loadError, save, reset, reload } = useVerdictConfigEditor()
  // null = no local edits; the form shows the saved config.
  const [edits, setEdits] = useState<VerdictConfig | null>(null)
  const draft = edits ?? config
  const setDraft = setEdits
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const { t } = useI18n()

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
      setMessage({ kind: 'error', text: e instanceof Error ? e.message : t('admin.unexpected') })
    } finally {
      setBusy(false)
    }
  }

  const fullAt = draft?.scoring?.knowledge_full_at ?? DEFAULT_SCORING.knowledge_full_at

  const onReset = () => {
    if (!window.confirm(t('admin.resetConfirm'))) return
    run(reset, t('admin.resetDone'))
  }

  return (
    <>
        {loadError && (
          <div className="flex items-center gap-3">
            <p className="text-sm text-red-400">{t('admin.loadError')}</p>
            <Button size="sm" variant="ghost" onClick={() => reload()}>{t('common.retry')}</Button>
          </div>
        )}

        {draft && (
          <>
            <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('admin.howTitle')}</p>
              <ul className="text-sm text-muted-foreground list-disc pl-5 flex flex-col gap-1">
                <li>{rich(t('admin.howRisk'))}</li>
                <li>{rich(t('admin.howKnowledge'))}</li>
                <li>{rich(t('admin.howRange'))}</li>
                <li>{rich(t('admin.howZero'))}</li>
              </ul>
            </section>

            <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('admin.thresholds')}</p>
              <div className="flex flex-wrap gap-6">
                <label className="flex items-center gap-2 text-sm text-foreground">
                  {t('admin.knowledgeGte')}
                  <NumberInput
                    value={draft.thresholds.knowledge}
                    onChange={v => setDraft({ ...draft, thresholds: { ...draft.thresholds, knowledge: v === '' ? 0 : v } })}
                  />
                  <span className="text-xs text-muted-foreground">{t('admin.isKnown')}</span>
                </label>
                <label className="flex items-center gap-2 text-sm text-foreground">
                  {t('admin.riskGte')}
                  <NumberInput
                    value={draft.thresholds.risk}
                    onChange={v => setDraft({ ...draft, thresholds: { ...draft.thresholds, risk: v === '' ? 0 : v } })}
                  />
                  <span className="text-xs text-muted-foreground">{t('admin.isHighRisk')}</span>
                </label>
              </div>
            </section>

            <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('admin.saturation')}</p>
              <div className="flex flex-wrap items-center gap-3 text-sm text-foreground">
                {t('admin.fullAt')}
                <input
                  type="range"
                  min={10}
                  max={100}
                  step={5}
                  value={fullAt}
                  aria-label={t('admin.fullAtSlider')}
                  onChange={e => setDraft({ ...draft, scoring: { knowledge_full_at: Number(e.target.value) } })}
                  className="w-48 h-1.5 cursor-pointer accent-primary"
                />
                <NumberInput
                  value={fullAt}
                  min={10}
                  max={100}
                  onChange={v => setDraft({ ...draft, scoring: { knowledge_full_at: v === '' ? 10 : v } })}
                />
                <span className="text-xs text-muted-foreground">{t('admin.fullAtSuffix')}</span>
              </div>
              <p className="text-xs text-muted-foreground">{t('admin.fullAtHelp')}</p>
            </section>

            <section className="flex flex-col gap-2">
              <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 px-3 text-xs text-muted-foreground uppercase tracking-wide font-medium">
                <span>{t('admin.colSource')}</span>
                <span className="w-44 text-right">{t('admin.colRisk')}</span>
                <span className="w-44 text-right">{t('admin.colKnowledge')}</span>
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
              <Button onClick={() => run(() => save(draft), t('admin.saved'))} disabled={!dirty || busy} className="gap-1.5">
                <Save className="h-4 w-4" /> {t('admin.save')}
              </Button>
              <Button
                variant="ghost"
                onClick={() => { setEdits(null); setMessage(null) }}
                disabled={!dirty || busy}
                className="gap-1.5"
              >
                <Undo2 className="h-4 w-4" /> {t('admin.discard')}
              </Button>
              <Button variant="ghost" onClick={onReset} disabled={busy} className="gap-1.5 ml-auto">
                <RotateCcw className="h-4 w-4" /> {t('admin.reset')}
              </Button>
              {message && (
                <span className={`w-full text-sm ${message.kind === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
                  {message.text}
                </span>
              )}
              {dirty && !message && <span className="w-full text-xs text-muted-foreground">{t('admin.unsaved')}</span>}
            </div>
          </>
        )}
    </>
  )
}
