import { useState } from 'react'

const STORAGE_KEY = 'intelchecker:disabledEngines'

function readDisabled(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return new Set(raw ? JSON.parse(raw) : [])
  } catch {
    return new Set()
  }
}

export function useEngineToggles() {
  const [disabled, setDisabled] = useState<Set<string>>(() => readDisabled())

  const toggle = (engineId: string) => {
    setDisabled(prev => {
      const next = new Set(prev)
      if (next.has(engineId)) next.delete(engineId)
      else next.add(engineId)
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...next]))
      return next
    })
  }

  return { disabled, toggle }
}
