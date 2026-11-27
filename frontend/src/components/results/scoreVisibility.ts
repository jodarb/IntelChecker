import { createContext, useContext } from 'react'

// Companies are not scored: a company lookup only gathers information (no Risk, no
// Knowledge, no quadrant — computeVerdict returns an empty verdict for them). The
// company report and the Companies search page wrap their source cards in
// `<HideScores value>`, and WeightBadge / ScoreBadge read it to drop the weight chips
// and the subscore (status chips — error, no results — stay).
// Threat actors have Knowledge but no Risk: the actor report uses `value="risk"`, which
// drops the subscore chip ("No score") and the R weight, and keeps the K weight.
export type HiddenScores = boolean | 'risk'
const HideScoresContext = createContext<HiddenScores>(false)
export const HideScores = HideScoresContext.Provider
export const useScoresHidden = () => useContext(HideScoresContext)
