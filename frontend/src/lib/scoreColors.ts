/** Risk colour: green ≤ 3, amber ≤ 6, red above. */
export function riskColor(score: number) {
  return score <= 3 ? '#4ade80' : score <= 6 ? '#fbbf24' : '#f87171'
}

/** Knowledge isn't good or bad, just more or less — a single-hue scale. */
export function knowledgeColor(score: number) {
  return score <= 3 ? '#94a3b8' : score <= 6 ? '#60a5fa' : '#3b82f6'
}
