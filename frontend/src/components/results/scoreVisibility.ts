import { createContext, useContext } from 'react'

// Company lookups don't show any risk/knowledge scoring for now: the company report
// wraps its source cards in `<HideScores value>`, and WeightBadge / ScoreBadge read
// it to drop the weight chips and the subscore (status chips — error, no results —
// stay). The verdict is still computed and saved to history; it is only not shown.
const HideScoresContext = createContext(false)
export const HideScores = HideScoresContext.Provider
export const useScoresHidden = () => useContext(HideScoresContext)
