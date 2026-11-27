import { createContext, useContext } from 'react'
import { STATIC_ENGINES, type EngineConfig, type IndicatorType } from '@/registry'

// The engines context and its hook, apart from EnginesProvider (src/EnginesContext.tsx)
// so that file only exports a component (React fast refresh).

export interface EngineStatus {
  connected: boolean
  supports: IndicatorType[]
  label?: string
  /** Multi-instance platforms: which card renders the instance */
  kind?: 'misp' | 'opencti'
}

export type StatusMap = Record<string, EngineStatus>

export interface EnginesContextValue {
  engines: EngineConfig[]
  status: StatusMap | null
  loading: boolean
  /** Re-fetch the status (after a change on the Connectors page). */
  reload: () => void
}

export const EnginesContext = createContext<EnginesContextValue>({
  engines: STATIC_ENGINES,
  status: null,
  loading: true,
  reload: () => {},
})

export function useEngines() {
  return useContext(EnginesContext)
}
