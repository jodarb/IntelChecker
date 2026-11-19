import { useEngines } from '@/EnginesContext'
import { useEngineToggles } from '@/hooks/useEngineToggles'
import { useVerdictWeights } from '@/hooks/useVerdictWeights'
import WeightBadge, { type CardWeight } from '@/components/results/WeightBadge'
import { knowledgeWeightOf, riskWeightOf } from '@/verdictEngine'
import type { IndicatorType } from '@/registry'
import { useI18n } from '@/i18n/useI18n'

interface Props {
  selectedType: string
}

function ToggleSwitch({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      title={enabled ? t('home.disableSource') : t('home.enableSource')}
      onClick={onToggle}
      className={`relative inline-flex h-4 w-7 shrink-0 items-center rounded-full transition-colors ${
        enabled ? 'bg-primary' : 'bg-muted-foreground/30'
      }`}
    >
      <span
        className={`inline-block h-3 w-3 transform rounded-full bg-background transition-transform ${
          enabled ? 'translate-x-3.5' : 'translate-x-0.5'
        }`}
      />
    </button>
  )
}

function EngineCard({
  engine, connected, supports, relevant, enabled, selectedType, weight, onToggle,
}: {
  engine: { id: string; label: string; logo: string }
  connected: boolean
  supports: string[]
  relevant: boolean
  enabled: boolean
  selectedType: string
  weight: CardWeight | null
  onToggle: () => void
}) {
  const { t } = useI18n()
  return (
    <div
      className={`flex flex-col gap-1.5 px-3 py-2 rounded-lg border transition-all duration-200 ${
        relevant
          ? connected
            ? enabled
              ? 'border-border bg-muted/30 shadow-sm'
              : 'border-border/50 bg-muted/10 opacity-60'
            : 'border-border/50 bg-muted/10 opacity-50'
          : 'border-border/30 bg-muted/5 opacity-25'
      }`}
    >
      {/* Top row: logo (with status dot badge) + name + on/off */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <span className="relative shrink-0 inline-flex">
            <span className="h-6 w-6 rounded-md bg-white border border-border/50 flex items-center justify-center overflow-hidden">
              <img src={engine.logo} alt="" className="h-4 w-4 object-contain" />
            </span>
            <span
              className={`absolute -bottom-0.5 -right-0.5 h-2 w-2 rounded-full ring-2 ring-background ${
                connected ? (enabled ? 'bg-green-500' : 'bg-amber-500') : 'bg-muted-foreground'
              }`}
            />
          </span>
          <span className={`text-sm font-medium truncate ${
            relevant ? 'text-foreground' : 'text-muted-foreground'
          }`}>
            {engine.label}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {connected && <WeightBadge weight={weight} />}
          {connected && (
            <ToggleSwitch enabled={enabled} onToggle={onToggle} />
          )}
        </div>
      </div>

      {/* Bottom row: type chips */}
      <div className="flex flex-wrap items-center gap-1 pl-4">
        {supports.map(type => (
          <span
            key={type}
            className={`px-1.5 py-0.5 rounded text-xs border transition-colors ${
              type === selectedType
                ? 'bg-primary/15 border-primary/40 text-primary font-medium'
                : 'bg-muted border-border text-muted-foreground'
            }`}
          >
            {t(`typeShort.${type as IndicatorType}`)}
          </span>
        ))}
      </div>
    </div>
  )
}

export default function EngineStatusPanel({ selectedType }: Props) {
  const { engines, status } = useEngines()
  const { disabled, toggle } = useEngineToggles()
  const config = useVerdictWeights()
  const { t } = useI18n()

  if (!status) return null

  const enriched = engines.map(engine => {
    const s = status[engine.id]
    const connected = s?.connected ?? false
    const supports: string[] = s?.supports ?? engine.supports
    return {
      engine,
      connected,
      supports,
      relevant: supports.includes(selectedType),
      enabled: !disabled.has(engine.id),
      weight: config
        ? {
            risk: riskWeightOf(config, engine.id),
            knowledge: knowledgeWeightOf(config, engine.id, selectedType as IndicatorType),
          }
        : null,
    }
  })

  // Within each group, engines supporting the selected indicator type float to
  // the top, and within that, higher-weighted engines come first — Array#sort is
  // stable, so anything still tied keeps its original relative order.
  const configured = enriched
    .filter(e => e.connected)
    .sort((a, b) =>
      Number(b.relevant) - Number(a.relevant)
      || (b.weight?.risk ?? 0) - (a.weight?.risk ?? 0)
      || (b.weight?.knowledge ?? 0) - (a.weight?.knowledge ?? 0))
  const notConfigured = enriched.filter(e => !e.connected)

  return (
    <div className="w-full max-w-2xl flex flex-col gap-5">
      <div className="flex flex-col gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">
          {t('home.connected', { n: configured.length })}
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {configured.map(({ engine, connected, supports, relevant, enabled, weight }) => (
            <EngineCard
              key={engine.id}
              engine={engine}
              connected={connected}
              supports={supports}
              relevant={relevant}
              enabled={enabled}
              selectedType={selectedType}
              weight={weight}
              onToggle={() => toggle(engine.id)}
            />
          ))}
        </div>
      </div>

      {notConfigured.length > 0 && (
        <div className="flex flex-col gap-2">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">
            {t('home.notConfigured', { n: notConfigured.length })}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {notConfigured.map(({ engine, connected, supports, relevant, enabled, weight }) => (
              <EngineCard
                key={engine.id}
                engine={engine}
                connected={connected}
                supports={supports}
                relevant={relevant}
                enabled={enabled}
                selectedType={selectedType}
                weight={weight}
                onToggle={() => toggle(engine.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
