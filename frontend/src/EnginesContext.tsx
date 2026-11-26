import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode, type ComponentType } from 'react'
import { STATIC_ENGINES, type EngineConfig, type IndicatorType, type CardProps } from '@/registry'
import MISPCard from '@/components/results/MISPCard'
import OpenCTICard from '@/components/results/OpenCTICard'
import { apiFetch } from '@/lib/api'

const BACKEND = '/api'

export interface EngineStatus {
  connected: boolean
  supports: IndicatorType[]
  label?: string
  /** Multi-instance platforms: which card renders the instance */
  kind?: 'misp' | 'opencti'
}

const INSTANCE_CARDS: Record<'misp' | 'opencti', { component: ComponentType<CardProps>; logo: string }> = {
  misp: { component: MISPCard as ComponentType<CardProps>, logo: '/logos/misp.png' },
  opencti: { component: OpenCTICard as ComponentType<CardProps>, logo: '/logos/opencti.png' },
}

export type StatusMap = Record<string, EngineStatus>

interface EnginesContextValue {
  engines: EngineConfig[]
  status: StatusMap | null
  loading: boolean
  /** Re-fetch the status (after a change on the Connectors page). */
  reload: () => void
}

const EnginesContext = createContext<EnginesContextValue>({
  engines: STATIC_ENGINES,
  status: null,
  loading: true,
  reload: () => {},
})

export function EnginesProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<StatusMap | null>(null)
  const [loading, setLoading] = useState(true)

  const reload = useCallback(() => {
    apiFetch(`${BACKEND}/engines/status`)
      .then(r => r.json())
      .then((s: StatusMap) => setStatus(s))
      .catch(() => setStatus(null))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { reload() }, [reload])

  const engines = useMemo(() => {
    const staticIds = new Set(STATIC_ENGINES.map(e => e.id))
    const dynamicEngines: EngineConfig[] = status
      ? Object.entries(status)
          .filter(([id]) => !staticIds.has(id))
          .map(([id, meta]) => ({
            id,
            label: meta.label ?? id,
            supports: meta.supports,
            ...INSTANCE_CARDS[meta.kind ?? (id.startsWith('opencti_') ? 'opencti' : 'misp')],
          }))
      : []
    return [...STATIC_ENGINES, ...dynamicEngines]
  }, [status])

  return (
    <EnginesContext.Provider value={{ engines, status, loading, reload }}>
      {children}
    </EnginesContext.Provider>
  )
}

export function useEngines() {
  return useContext(EnginesContext)
}
