import { useState, useEffect } from 'react'
import type { VerdictWeights } from '@/verdictEngine'

// weights.json only covers statically-known engines. MISP instances are only
// known at deploy time, so their weight travels alongside their name/URL in
// backend/.env (MISP_<N>_WEIGHT) and is surfaced via /engines/status instead —
// merge it in here so the rest of the app can treat weights as one flat object.
export function useVerdictWeights() {
  const [weights, setWeights] = useState<VerdictWeights | null>(null)

  useEffect(() => {
    Promise.all([
      fetch('/weights.json').then(r => r.json()).catch(() => ({})),
      fetch('/api/engines/status').then(r => r.json()).catch(() => ({})),
    ]).then(([staticWeights, status]) => {
      const dynamicWeights: VerdictWeights = {}
      for (const [id, meta] of Object.entries(status ?? {})) {
        const weight = (meta as any)?.weight
        if (typeof weight === 'number') dynamicWeights[id] = weight
      }
      setWeights({ ...(staticWeights ?? {}), ...dynamicWeights })
    }).catch(() => setWeights({}))
  }, [])

  return weights
}
