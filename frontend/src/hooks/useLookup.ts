import { useEffect, useMemo, useRef, useState } from 'react'
import type { EngineConfig, IndicatorType, QueryResult } from '@/registry'
import {
  computeVerdict, getEngineAssessment, knowledgeWeightOf, riskWeightOf, EMPTY_VERDICT,
  type VerdictConfig, type VerdictResult,
} from '@/verdictEngine'
import { cardState, compareCards } from '@/resultOrder'
import { useVerdictWeights } from '@/hooks/useVerdictWeights'
import { useEngineToggles } from '@/hooks/useEngineToggles'
import { useEngines } from '@/EnginesContext'
import { BACKEND_DOWN } from '@/i18n/errors'
import { apiFetch } from '@/lib/api'

// A live lookup, shared by the artifact results page and the company report: one
// POST /analyze/{engine} per source in parallel, the verdict, the card order and
// the history entry once every source has answered.

const BACKEND = '/api'

export type ResultMap = Record<string, QueryResult>

const loadingMap = (engines: EngineConfig[]): ResultMap =>
  Object.fromEntries(engines.map(e => [e.id, { loading: true, data: null, error: null }]))

// Responses are stored under the key of the lookup that produced them (indicator +
// type + engine set), so when the analyst moves to another indicator mid-lookup the
// old requests are aborted and any late answer is discarded instead of overwriting
// the new cards.
function useAllEngineQueries(engines: EngineConfig[], indicator: string, type: string, ready: boolean): ResultMap {
  const runKey = `${indicator}|${type}|${engines.map(e => e.id).join(',')}`
  const [stored, setStored] = useState<{ key: string; results: ResultMap }>({ key: '', results: {} })

  useEffect(() => {
    if (!indicator || !ready) return
    const ctrl = new AbortController()
    const put = (id: string, r: QueryResult) =>
      setStored(prev => ({
        key: runKey,
        results: { ...(prev.key === runKey ? prev.results : {}), [id]: r },
      }))

    engines.forEach(engine => {
      apiFetch(`${BACKEND}/analyze/${engine.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator, type }),
        signal: ctrl.signal,
      })
        .then(res => { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json() })
        .then(data => put(engine.id, { loading: false, data, error: null }))
        .catch(() => {
          if (ctrl.signal.aborted) return
          put(engine.id, { loading: false, data: null, error: BACKEND_DOWN })
        })
    })
    return () => ctrl.abort()
  }, [indicator, type, ready, engines, runKey])

  // Engines that haven't answered for *this* lookup yet show as loading.
  return useMemo(
    () => ({ ...loadingMap(engines), ...(stored.key === runKey ? stored.results : {}) }),
    [engines, stored, runKey],
  )
}

// Once every active engine has settled, log the query to the history — once per
// indicator+type, not on every re-render (toggling an engine shouldn't spawn a new
// history entry for the same search).
function useSaveToHistory(
  indicator: string, type: IndicatorType, config: VerdictConfig | null,
  activeEngines: EngineConfig[], results: ResultMap, verdict: VerdictResult,
) {
  const savedKeyRef = useRef<string | null>(null)
  useEffect(() => {
    if (!indicator || !config || activeEngines.length === 0) return
    if (!activeEngines.every(e => results[e.id] && !results[e.id].loading)) return
    const key = `${indicator}|${type}`
    if (savedKeyRef.current === key) return
    savedKeyRef.current = key

    const snapshot = Object.fromEntries(
      activeEngines.map(e => [
        e.id,
        { label: e.label, data: results[e.id]?.data ?? null, error: results[e.id]?.error ?? null },
      ]),
    )
    apiFetch(`${BACKEND}/history`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        indicator,
        type,
        score: verdict.risk,
        knowledge_score: verdict.knowledge,
        quadrant: verdict.quadrant,
        results: snapshot,
        contributions: verdict.contributions,
      }),
    }).catch(() => {
      // History logging is best-effort — a failure here shouldn't disrupt the lookup itself.
    })
  }, [indicator, type, config, activeEngines, results, verdict])
}

export interface Lookup {
  /** Every source for the type, configured or not */
  engines: EngineConfig[]
  /** Configured and switched on: the ones queried */
  activeEngines: EngineConfig[]
  /** Configured sources in display order (results first — see resultOrder.ts) */
  sortedEngines: EngineConfig[]
  results: ResultMap
  verdict: VerdictResult
  config: VerdictConfig | null
  disabled: Set<string>
  /** Sources for the type without their API key */
  unconfigured: number
}

export function useLookup(indicator: string, type: IndicatorType, engineFilter?: (e: EngineConfig) => boolean): Lookup {
  const { engines: allEngines, status, loading: enginesLoading } = useEngines()
  const engines = useMemo(
    () => allEngines.filter(e => e.supports.includes(type) && (!engineFilter || engineFilter(e))),
    [allEngines, type, engineFilter],
  )
  const { disabled } = useEngineToggles()
  // Sources without their API key are shown as switched off and never queried.
  const activeEngines = useMemo(
    () => engines.filter(e => !disabled.has(e.id) && status?.[e.id]?.connected !== false),
    [engines, disabled, status],
  )
  const results = useAllEngineQueries(activeEngines, indicator, type, !enginesLoading)
  const config = useVerdictWeights()

  const verdict = useMemo(
    () => (config ? computeVerdict(config, activeEngines, results, type) : EMPTY_VERDICT),
    [config, activeEngines, results, type],
  )

  const sortedEngines = useMemo(() => {
    const ranked = engines
      .filter(e => status?.[e.id]?.connected !== false)
      .map(e => {
        const result = results[e.id]
        const a = getEngineAssessment(e.id, type, result)
        return {
          engine: e,
          rank: {
            state: disabled.has(e.id) ? 'off' as const : cardState(result, a),
            subscore: a.subscore,
            depth: a.depth,
            riskWeight: config ? riskWeightOf(config, e.id) : 0,
            knowledgeWeight: config ? knowledgeWeightOf(config, e.id, type) : 0,
          },
        }
      })
    return ranked.sort((x, y) => compareCards(x.rank, y.rank)).map(x => x.engine)
  }, [engines, status, disabled, results, config, type])

  useSaveToHistory(indicator, type, config, activeEngines, results, verdict)

  return {
    engines, activeEngines, sortedEngines, results, verdict, config, disabled,
    unconfigured: engines.filter(e => status?.[e.id]?.connected === false).length,
  }
}
