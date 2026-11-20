import { createContext, useContext, useEffect, useMemo, useState, type ReactNode, type ComponentType } from 'react'
import { STATIC_ENGINES, type EngineConfig, type IndicatorType, type CardProps } from '@/registry'
import MISPCard from '@/components/results/MISPCard'
import { apiFetch } from '@/lib/api'

const BACKEND = '/api'

export interface EngineStatus {
  connected: boolean
  supports: IndicatorType[]
  label?: string
}

export type StatusMap = Record<string, EngineStatus>

interface EnginesContextValue {
  engines: EngineConfig[]
  status: StatusMap | null
  loading: boolean
}

const EnginesContext = createContext<EnginesContextValue>({
  engines: STATIC_ENGINES,
  status: null,
  loading: true,
})

export function EnginesProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<StatusMap | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    apiFetch(`${BACKEND}/engines/status`)
      .then(r => r.json())
      .then((s: StatusMap) => setStatus(s))
      .catch(() => setStatus(null))
      .finally(() => setLoading(false))
  }, [])

  const engines = useMemo(() => {
    const staticIds = new Set(STATIC_ENGINES.map(e => e.id))
    const dynamicEngines: EngineConfig[] = status
      ? Object.entries(status)
          .filter(([id]) => !staticIds.has(id))
          .map(([id, meta]) => ({
            id,
            label: meta.label ?? id,
            supports: meta.supports,
            component: MISPCard as ComponentType<CardProps>,
            logo: '/logos/misp.png',
          }))
      : []
    return [...STATIC_ENGINES, ...dynamicEngines]
  }, [status])

  return (
    <EnginesContext.Provider value={{ engines, status, loading }}>
      {children}
    </EnginesContext.Provider>
  )
}

export function useEngines() {
  return useContext(EnginesContext)
}
