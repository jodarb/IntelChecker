import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import type { VerdictResult, VerdictThresholds } from '@/verdictEngine'
import type { IndicatorType } from '@/registry'
import { OUTCOME_META, depthLabel, outcomeLabel, quadrantHint, quadrantLabel } from '@/quadrants'
import { useI18n } from '@/i18n/useI18n'

interface Props {
  open: boolean
  onClose: () => void
  verdict: VerdictResult
  thresholds: VerdictThresholds | null
  /** Indicator type: CVEs word the quadrants differently */
  type?: IndicatorType
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
  const counted = rows.filter(c => c.inTotal !== false)
  const totalWeight = counted.reduce((s, c) => s + c.weight, 0)
  const sum = counted.reduce((s, c) => s + c.weight * c.depth, 0)
  const fullAt = verdict.contributions.knowledgeFullAt ?? 100
  const { t } = useI18n()
  return (
    <>
      <p className="text-sm text-muted-foreground">
        {t('explainer.knowledgeIntro')}
      </p>
      {rows.length === 0 ? (
        <p className="text-sm text-foreground font-medium">{t('explainer.knowledgeEmpty')}</p>
      ) : (
        <>
          <div className="flex flex-col gap-2">
            <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 text-xs text-muted-foreground uppercase tracking-wide font-medium px-1">
              <span>{t('explainer.source')}</span>
              <span className="text-right w-14">{t('explainer.weight')}</span>
              <span className="text-right w-24">{t('explainer.depth')}</span>
              <span className="text-right w-24">{t('explainer.outcome')}</span>
            </div>
            {rows.map(c => (
              <div
                key={c.engineId}
                className="grid grid-cols-[1fr_auto_auto_auto] gap-3 items-center rounded-md border border-border bg-muted/20 px-3 py-2 text-sm"
              >
                <span className="text-foreground font-medium truncate">{c.label}</span>
                <span className={`text-right text-muted-foreground w-14 ${c.inTotal === false ? 'line-through opacity-60' : ''}`}>{c.weight}</span>
                <span className="text-right text-foreground font-medium w-24">{depthLabel(c.depth, t)}</span>
                <span className={`text-right text-xs w-24 ${OUTCOME_META[c.outcome].className}`}>
                  {c.inTotal === false ? t('explainer.notInTotal') : outcomeLabel(c.outcome, t)}
                </span>
              </div>
            ))}
          </div>
          <Formula>
            {fullAt < 100
              ? <>knowledge = round(10 × min(1, Σ(weight × depth) / Σ(weight) ÷ {fullAt}%)) = round(10 × min(1, {sum.toFixed(1)} / {totalWeight} ÷ {(fullAt / 100).toFixed(2)})) ={' '}</>
              : <>knowledge = round(10 × Σ(weight × depth) / Σ(weight)) = round(10 × {sum.toFixed(1)} / {totalWeight}) ={' '}</>}
            <span className="text-foreground font-semibold">{verdict.knowledge}/10</span>
          </Formula>
          {fullAt < 100 && <p className="text-xs text-muted-foreground">{t('explainer.saturation', { pct: fullAt })}</p>}
        </>
      )}
    </>
  )
}

function RiskTab({ verdict }: { verdict: VerdictResult }) {
  const rows = verdict.contributions.risk
  const totalWeight = rows.reduce((s, c) => s + c.weight, 0)
  const sum = rows.reduce((s, c) => s + c.weight * c.subscore, 0)
  const { t } = useI18n()
  return (
    <>
      <p className="text-sm text-muted-foreground">
        {t('explainer.riskIntro')}
      </p>
      {verdict.risk == null ? (
        <p className="text-sm text-foreground font-medium">
          {t('explainer.riskEmpty')}
        </p>
      ) : (
        <>
          <div className="flex flex-col gap-2">
            <div className="grid grid-cols-4 gap-2 text-xs text-muted-foreground uppercase tracking-wide font-medium px-1">
              <span>{t('explainer.source')}</span>
              <span className="text-right">{t('explainer.weight')}</span>
              <span className="text-right">{t('explainer.subscore')}</span>
              <span className="text-right">{t('explainer.share')}</span>
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

export default function VerdictExplainerModal({ open, onClose, verdict, thresholds, type }: Props) {
  const [tab, setTab] = useState<Tab>('knowledge')
  const { t } = useI18n()

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  // Threat actors show neither Risk nor a quadrant: only the Knowledge part applies.
  const knowledgeOnly = type === 'threat-actor'
  const q = knowledgeOnly ? null : verdict.quadrant
  const shownTab: Tab = knowledgeOnly ? 'knowledge' : tab

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
          <span className="text-sm font-semibold text-foreground">{t(knowledgeOnly ? 'explainer.titleKnowledge' : 'explainer.title')}</span>
          <button
            onClick={onClose}
            aria-label={t('common.close')}
            className="p-1 rounded hover:bg-muted/60 transition-colors text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {!knowledgeOnly && <div className="flex border-b border-border shrink-0">
          {(['knowledge', 'risk'] as Tab[]).map(id => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex-1 px-4 py-2 text-sm font-medium transition-colors ${
                tab === id ? 'text-foreground border-b-2 border-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {id === 'knowledge'
                ? `${t('score.knowledge')} · ${verdict.knowledge ?? t('score.na')}`
                : `${t('score.risk')} · ${verdict.risk ?? t('score.noData')}`}
            </button>
          ))}
        </div>}

        <div className="overflow-auto flex-1 px-4 py-4 flex flex-col gap-4">
          {shownTab === 'knowledge' ? <KnowledgeTab verdict={verdict} /> : <RiskTab verdict={verdict} />}

          {q && (
            <div className="rounded-md border border-border bg-muted/10 px-3 py-2 text-xs text-muted-foreground">
              <span className="text-foreground font-semibold">{quadrantLabel(q, t, type)}</span> — {quadrantHint(q, t, type)}
              {thresholds && (
                <span className="block mt-1">
                  {t('explainer.thresholds', { k: thresholds.knowledge, r: thresholds.risk })}
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
