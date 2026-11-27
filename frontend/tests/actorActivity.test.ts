import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { ACTIVE_DAYS, RECENT_DAYS, computeActorActivity } from '@/actorActivity'
import { computeActorProfile } from '@/actorProfile'
import { engines, failed, historyFixture, loading, ok } from './helpers.ts'

const AS_OF = new Date('2026-11-27T12:00:00Z')
const daysAgo = (n: number) => new Date(AS_OF.getTime() - n * 86_400_000).toISOString().slice(0, 10)

const opencti = (lastSeen: string | null, reports: { name: string; published: string }[] = []) =>
  ok({ kind: 'actor', found: true, actor: { last_seen: lastSeen }, reports })

describe('computeActorActivity · history #10 (The Gentlemen)', () => {
  it('is active as of the day the lookup ran, from its last claimed victim', () => {
    const f = historyFixture(10)
    const p = computeActorProfile(engines(...f.engineIds), f.results, f.indicator)
    const a = computeActorActivity(engines(...p.engineIds), f.results, f.asOf, p.allNames)
    assert.equal(a.level, 'active')
    assert.equal(a.daysSince, 2)
    assert.equal(a.lastOperation?.date, '2026-11-24')
    assert.equal(a.lastOperation?.source, 'ransomware.live')
    // The 90-day count comes from the full dump, not from the `recent` sample.
    assert.deepEqual(a.recent, [{ engineId: 'ransomwarelive', source: 'ransomware.live', kind: 'operation', count: 349 }])
  })

  it('replayed a year later, the same entry reads as recent', () => {
    const f = historyFixture(10)
    const p = computeActorProfile(engines(...f.engineIds), f.results, f.indicator)
    const later = new Date(f.asOf.getTime() + 200 * 86_400_000)
    assert.equal(computeActorActivity(engines(...p.engineIds), f.results, later, p.allNames).level, 'recent')
  })
})

describe('computeActorActivity · levels', () => {
  const level = (days: number) =>
    computeActorActivity(engines('opencti_1'), { opencti_1: opencti(daysAgo(days)) }, AS_OF).level

  it(`active ≤ ${ACTIVE_DAYS} d, recent ≤ ${RECENT_DAYS} d, dormant after`, () => {
    assert.equal(level(0), 'active')
    assert.equal(level(ACTIVE_DAYS), 'active')
    assert.equal(level(ACTIVE_DAYS + 1), 'recent')
    assert.equal(level(RECENT_DAYS), 'recent')
    assert.equal(level(RECENT_DAYS + 1), 'dormant')
  })

  it('unknown when no source has dated evidence', () => {
    const a = computeActorActivity(engines('opencti_1', 'mitreattack'), {
      opencti_1: opencti(null), mitreattack: ok({ name: 'X', modified: '2026-11-01' }),
    }, AS_OF)
    assert.equal(a.level, 'unknown')
    assert.equal(a.daysSince, null)
    assert.equal(a.sources, 0)
  })
})

describe('computeActorActivity · signals', () => {
  it('separates operations (last_seen) from reports and counts the last 90 days per source', () => {
    const a = computeActorActivity(engines('opencti_1'), {
      opencti_1: opencti(daysAgo(200), [
        { name: 'New campaign', published: daysAgo(10) },
        { name: 'Older write-up', published: daysAgo(30) },
        { name: 'Ancient', published: daysAgo(400) },
      ]),
    }, AS_OF)
    assert.equal(a.level, 'active')
    assert.equal(a.daysSince, 10)
    assert.equal(a.lastOperation?.date, daysAgo(200))
    assert.equal(a.lastReport?.detail, 'New campaign')
    assert.deepEqual(a.recent, [{ engineId: 'opencti_1', source: 'OpenCTI', kind: 'report', count: 2 }])
  })

  it('ignores future dates (clock skew, typos)', () => {
    const a = computeActorActivity(engines('opencti_1'), { opencti_1: opencti('2030-01-01', [{ name: 'r', published: daysAgo(500) }]) }, AS_OF)
    assert.equal(a.level, 'dormant')
    assert.equal(a.lastOperation, null)
  })

  it('only OTX pulses that name the actor count', () => {
    const a = computeActorActivity(engines('alienvault'), {
      alienvault: ok({
        results: [
          { name: 'Phishing feed', created: daysAgo(1) },
          { name: 'Zorblax intrusion', created: daysAgo(120) },
        ],
      }),
    }, AS_OF, ['Zorblax'])
    assert.equal(a.level, 'recent')
    assert.equal(a.lastReport?.detail, 'Zorblax intrusion')
  })

  it('Recorded Future Threat Map changes are reports', () => {
    const a = computeActorActivity(engines('recordedfuture'), {
      recordedfuture: ok({ kind: 'actor', found: true, threat_map: { log: [{ date: daysAgo(5), axis: 'intent' }] } }),
    }, AS_OF)
    assert.equal(a.lastReport?.detail, 'Threat Map · intent')
  })

  it('skips sources still loading, failed or with an error payload', () => {
    const a = computeActorActivity(engines('opencti_1', 'ransomwarelive', 'alienvault'), {
      opencti_1: loading(),
      ransomwarelive: failed('RateLimitExceeded'),
      alienvault: { loading: false, data: null, error: 'BACKEND_DOWN' },
    }, AS_OF, ['Zorblax'])
    assert.equal(a.level, 'unknown')
    assert.equal(a.sources, 0)
  })
})
