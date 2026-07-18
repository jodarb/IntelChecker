import { useState, useEffect } from 'react'
import type { VerdictWeights } from '@/verdictEngine'

export function useVerdictWeights() {
  const [weights, setWeights] = useState<VerdictWeights | null>(null)

  useEffect(() => {
    fetch('/verdict.config.json')
      .then(r => r.json())
      .then(cfg => setWeights(cfg.weights ?? {}))
      .catch(() => setWeights({}))
  }, [])

  return weights
}
