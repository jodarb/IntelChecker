import { useCallback, useEffect, useState } from 'react'
import type { VerdictConfig } from '@/verdictEngine'
import { apiFetch } from '@/lib/api'

const FALLBACK: VerdictConfig = { engines: {}, thresholds: { knowledge: 4, risk: 5 } }

// Weights (risk + knowledge per engine, MISP instances included) and quadrant
// thresholds are owned by the backend — editable from the Admin page and
// persisted in backend/data/weights.json.
export function useVerdictWeights() {
  const [config, setConfig] = useState<VerdictConfig | null>(null)

  useEffect(() => {
    apiFetch('/api/weights')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
      .then((c: VerdictConfig) => setConfig(c))
      .catch(() => setConfig(FALLBACK))
  }, [])

  return config
}

export function useVerdictConfigEditor() {
  const [config, setConfig] = useState<VerdictConfig | null>(null)
  const [error, setError] = useState<string | null>(null)

  const fetchConfig = useCallback(() => apiFetch('/api/weights')
    .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json() })
    .then((c: VerdictConfig) => { setError(null); setConfig(c) })
    .catch(() => setError('Could not load weights from the backend. Is it running?')), [])

  useEffect(() => { fetchConfig() }, [fetchConfig])

  const send = useCallback(async (url: string, init: RequestInit) => {
    const r = await apiFetch(url, init)
    const body = await r.json().catch(() => ({}))
    const detail = typeof body?.detail === 'string' ? body.detail : body?.detail?.message
    if (!r.ok) throw new Error(detail ?? `Backend returned HTTP ${r.status}`)
    setConfig(body)
    return body as VerdictConfig
  }, [])

  const save = useCallback((next: VerdictConfig) => send('/api/weights', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(next),
  }), [send])

  const reset = useCallback(() => send('/api/weights/reset', { method: 'POST' }), [send])

  return { config, error, save, reset, reload: fetchConfig }
}
