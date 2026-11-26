import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'
import { getEngineAssessment, knowledgeWeightOf, riskWeightOf, type VerdictConfig } from '@/verdictEngine'
import type { CardWeight } from './WeightBadge'
import DisconnectedCard from './DisconnectedCard'
import { useI18n } from '@/i18n/useI18n'
import { BACKEND_DOWN } from '@/i18n/errors'

function cardWeight(
  config: VerdictConfig | null, engineId: string, type: IndicatorType, depth: number | null,
): CardWeight | null {
  if (!config) return null
  return { risk: riskWeightOf(config, engineId), knowledge: knowledgeWeightOf(config, engineId, type), depth }
}

/** A live source card: loading / error / result, with its weights and subscore. */
export default function EngineCard({
  engine, result, type, config, indicator, disabled = false,
}: {
  engine: EngineConfig
  result: QueryResult | undefined
  type: IndicatorType
  config: VerdictConfig | null
  indicator: string
  disabled?: boolean
}) {
  const Component = engine.component
  const { t } = useI18n()
  if (disabled) return <DisconnectedCard label={engine.label} reason="disabled" />
  const assessment = getEngineAssessment(engine.id, type, result)
  const weight = cardWeight(config, engine.id, type, assessment.depth)
  if (!result) {
    return (
      <Component
        loading data={null} error={null} label={engine.label} score={null} weight={weight}
        indicator={indicator} type={type}
      />
    )
  }
  const apiErrorCode = (result.data as { error?: { code?: string } } | null)?.error?.code
  if (!result.loading && apiErrorCode === 'MissingApiKey') {
    return <DisconnectedCard label={engine.label} />
  }
  return (
    <Component
      loading={result.loading}
      error={result.error === BACKEND_DOWN ? t('common.backendDown') : result.error}
      data={result.data}
      label={engine.label}
      score={result.loading ? null : assessment.subscore}
      weight={weight}
      indicator={indicator}
      type={type}
    />
  )
}
