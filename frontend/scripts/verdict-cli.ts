// Runs the frontend verdict engine on cases read from stdin, for the backend parity
// test (backend/tests/verdict_parity.py). Node ≥ 23 runs this .ts file directly
// (type stripping): `node frontend/scripts/verdict-cli.ts < cases.json`.
//
// Input:  [{ config, engines: [{ id, label }], results: { id: { data, error } }, type }]
// Output: [{ verdict, assessments: { id: EngineAssessment } }]
import { readFileSync } from 'node:fs'
import { computeVerdict, getEngineAssessment } from '../src/verdictEngine.ts'

type Case = {
  config: Parameters<typeof computeVerdict>[0]
  engines: { id: string; label: string }[]
  results: Record<string, { data: unknown; error: string | null }>
  type: Parameters<typeof computeVerdict>[3]
}

const cases = JSON.parse(readFileSync(0, 'utf8')) as Case[]
const out = cases.map(c => {
  const engines = c.engines.map(e => ({ ...e, supports: [c.type], component: null, logo: '' }))
  const results = Object.fromEntries(
    Object.entries(c.results).map(([id, r]) => [id, { loading: false, data: r.data, error: r.error }]),
  )
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    verdict: computeVerdict(c.config, engines as any, results, c.type),
    assessments: Object.fromEntries(c.engines.map(e => [e.id, getEngineAssessment(e.id, c.type, results[e.id])])),
  }
})
process.stdout.write(JSON.stringify(out))
