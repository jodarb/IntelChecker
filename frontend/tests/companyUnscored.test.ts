import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { DEFAULT_SCORING, EMPTY_VERDICT, computeVerdict, type VerdictConfig } from '@/verdictEngine'
import { engines, ok } from './helpers.ts'

// Companies are not scored: the lookup only gathers information.
describe('computeVerdict · companies', () => {
  const config = {
    engines: { hudsonrock: { risk: 7, knowledge: 5 }, ransomwarelive: { risk: 10, knowledge: 6 } },
    thresholds: { knowledge: 4, risk: 5 },
    scoring: DEFAULT_SCORING,
  } as unknown as VerdictConfig

  it('returns no Risk, no Knowledge and no quadrant, even with exposure signals', () => {
    const v = computeVerdict(config, engines('hudsonrock', 'ransomwarelive'), {
      hudsonrock: ok({ found: true, employees: 12, last_employee_compromised: '2026-11-01' }),
      ransomwarelive: ok({ kind: 'company', found: true, match_count: 1, last_claim: '2026-11-20' }),
    }, 'company')
    assert.deepEqual(v, EMPTY_VERDICT)
  })
})
