import { createContext, useContext } from 'react'

// Companies are not scored: a company lookup only gathers information (no Risk, no
// Knowledge, no quadrant — computeVerdict returns an empty verdict for them). The
// company report and the Companies search page wrap their source cards in
// `<HideScores value>`, and WeightBadge / ScoreBadge read it to drop the weight chips
// and the subscore (status chips — error, no results — stay).
const HideScoresContext = createContext(false)
export const HideScores = HideScoresContext.Provider
export const useScoresHidden = () => useContext(HideScoresContext)
