import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { computeActorProfile, relevantPulses } from '@/actorProfile'
import type { QueryResult } from '@/registry'
import { engines, failed, historyFixture, loading, ok } from './helpers.ts'

const values = (items: { value: string }[]) => items.map(i => i.value)

// Real lookups saved in history (frontend/tests/fixtures).
describe('computeActorProfile · history #10 (The Gentlemen)', () => {
  const f = historyFixture(10)
  const p = computeActorProfile(engines(...f.engineIds), f.results, f.indicator)

  it('confirms the actor: four sources agree, MITRE names it', () => {
    assert.equal(p.status, 'confirmed')
    assert.equal(p.name, 'The Gentlemen')
    assert.equal(p.mitreId, 'G1058')
    assert.equal(p.prov.mitreId, 'MITRE ATT&CK')
    assert.deepEqual(p.others, [])
    assert.deepEqual(
      p.identities.map(i => i.engineId).sort(),
      ['malpedia', 'mitreattack', 'ransomwarelive', 'recordedfuture'],
    )
  })

  it('lists real aliases apart from spellings of the name', () => {
    assert.deepEqual(values(p.aliases).sort(), ['GOLD SHERWOOD', 'Storm-2697'])
    assert.deepEqual(p.nameVariants.sort(), ['The Gentlemen Ransomware', 'The Gentlemen Ransomware Group'])
  })

  it('attributes its own ransomware and tools; other families are only mentioned', () => {
    const own = p.arsenal.find(a => a.value === 'The Gentlemen Ransomware')
    assert.ok(own)
    assert.deepEqual(own.sources.sort(), ['MITRE ATT&CK', 'Malpedia', 'Recorded Future'])
    assert.ok(values(p.arsenal).includes('PsExec'))
    // RF co-mentions other groups' ransomware: never attributed on a single mention.
    assert.ok(values(p.arsenalMentioned).includes('Akira Ransomware'))
    assert.ok(!values(p.arsenal).includes('Akira Ransomware'))
  })

  it('takes the ransomware.live group data and RF categories', () => {
    assert.ok(p.ransomware)
    assert.equal(p.ransomware.victims, 1139)
    assert.equal(p.ransomware.d90, 349)
    assert.equal(p.ransomware.raas, true)
    assert.equal(p.ransomwareCategory, true)
    assert.equal(p.countries[0].country, 'US')
    assert.equal(p.sectors[0].value, 'Manufacturing')
    assert.ok(p.ttps.length > 0)
  })

  it('shows an entry saved before leak sites existed with an empty leak sites tab', () => {
    assert.deepEqual(p.leakSites, [])
  })

  it('without Recorded Future the report still stands on the curated sources', () => {
    const noRf = f.engineIds.filter(id => id !== 'recordedfuture')
    const q = computeActorProfile(engines(...noRf), f.results, f.indicator)
    assert.equal(q.status, 'confirmed')
    assert.equal(q.name, 'The Gentlemen')
    assert.deepEqual(q.categories, [])
    assert.equal(q.ransomwareCategory, false)
    assert.deepEqual(q.arsenalMentioned, [])
    const own = q.arsenal.find(a => a.value === 'The Gentlemen Ransomware')
    assert.deepEqual(own?.sources.sort(), ['MITRE ATT&CK', 'Malpedia'])
    assert.ok(!q.engineIds.has('recordedfuture'))
  })
})

describe('computeActorProfile · history #8 (RF persona "Gentleman")', () => {
  const f = historyFixture(8)
  const p = computeActorProfile(engines(...f.engineIds), f.results, f.indicator)

  it('flags a forum member as a persona, not a group', () => {
    assert.equal(p.status, 'persona')
    assert.equal(p.name, 'Gentleman')
    assert.equal(p.identities.length, 1)
    assert.equal(p.identities[0].persona, true)
    assert.deepEqual([...p.engineIds], ['recordedfuture'])
    assert.equal(p.ransomware, null)
  })
})

// Synthetic source payloads, shaped like the backend services return them.
const mitre = (name: string, aliases: string[] = [], extra: object = {}) =>
  ok({ attack_id: 'G0001', name, aliases, description: `${name} (MITRE)`, techniques: [], software: [], ...extra })
const rf = (name: string, opts: { exact?: boolean; persona?: boolean; aliases?: string[]; categories?: string[] } = {}) =>
  ok({
    kind: 'actor', found: true, exact: opts.exact ?? true, name, common_names: [], aliases: opts.aliases ?? [],
    categories: opts.categories ?? [], persona: opts.persona ?? false, insikt_links: {},
  })
const malpedia = (name: string, synonyms: string[] = [], exact = true) =>
  ok({ found: true, exact, name, synonyms, victims: [], target_category: [], families: [] })
const notFound = ok({ found: false })

describe('computeActorProfile · identity', () => {
  it('conflict: sources that share no name are different actors; the curated one leads', () => {
    const p = computeActorProfile(engines('mitreattack', 'recordedfuture'), {
      mitreattack: mitre('Play', ['PlayCrypt']),
      recordedfuture: rf('Play Ransomware Gang', { exact: false, aliases: ['Balloonfly'] }),
    }, 'Play')
    assert.equal(p.status, 'conflict')
    assert.equal(p.name, 'Play')
    assert.deepEqual(p.others, [{ name: 'Play Ransomware Gang', sources: ['Recorded Future'] }])
    assert.deepEqual([...p.engineIds], ['mitreattack'])
  })

  it('sources that share an alias are one actor', () => {
    const p = computeActorProfile(engines('mitreattack', 'malpedia'), {
      mitreattack: mitre('APT28', ['Fancy Bear', 'Sofacy']),
      malpedia: malpedia('Sofacy', ['APT28', 'Fancy Bear']),
    }, 'fancy bear')
    assert.equal(p.status, 'confirmed')
    assert.equal(p.name, 'APT28')
    assert.equal(p.identities.length, 2)
  })

  it('single: only one non-curated source knows it', () => {
    const p = computeActorProfile(engines('mitreattack', 'recordedfuture', 'malpedia'), {
      mitreattack: failed('NotFound'),
      recordedfuture: rf('Storm-9999'),
      malpedia: notFound,
    }, 'Storm-9999')
    assert.equal(p.status, 'single')
    assert.equal(p.name, 'Storm-9999')
  })

  it('a curated catalogue matching exactly is enough to confirm', () => {
    const p = computeActorProfile(engines('malpedia'), { malpedia: malpedia('APT5') }, 'APT5')
    assert.equal(p.status, 'confirmed')
  })

  it('a curated closest match on its own stays single', () => {
    const p = computeActorProfile(engines('malpedia'), { malpedia: malpedia('APT5', [], false) }, 'APT55')
    assert.equal(p.status, 'single')
  })

  it('a persona never joins a group that shares its name', () => {
    const p = computeActorProfile(engines('mitreattack', 'recordedfuture'), {
      mitreattack: mitre('The Gentlemen'),
      recordedfuture: rf('The Gentlemen', { persona: true, categories: ['Underground Forum Member'] }),
    }, 'The Gentlemen')
    assert.equal(p.status, 'conflict')
    assert.deepEqual([...p.engineIds], ['mitreattack'])
  })

  it('RF categories alone mark a persona (older entries without `persona`)', () => {
    const p = computeActorProfile(engines('recordedfuture'), {
      recordedfuture: ok({ kind: 'actor', found: true, name: 'h4x', categories: ['Underground Forum Member'], insikt_links: {} }),
    }, 'h4x')
    assert.equal(p.status, 'persona')
  })

  it('older entries without `exact`: an alias equal to the query is an exact match', () => {
    const p = computeActorProfile(engines('malpedia'), {
      malpedia: ok({ found: true, name: 'Sofacy', synonyms: ['APT28'] }),
    }, 'apt-28')
    assert.equal(p.identities[0].exact, true)
    assert.equal(p.status, 'confirmed')
  })
})

describe('computeActorProfile · no profile', () => {
  const pulses = {
    results: [
      { id: 'a1', name: 'Zorblax campaign targets banks', created: '2026-10-01T00:00:00' },
      { id: 'a2', name: 'Weekly phishing feed', created: '2026-10-02T00:00:00' },
    ],
  }

  it('no source identified an actor: status none, OTX pulses are unverified mentions', () => {
    const p = computeActorProfile(engines('mitreattack', 'recordedfuture', 'malpedia', 'alienvault'), {
      mitreattack: failed('NotFound'),
      recordedfuture: ok({ kind: 'actor', found: false }),
      malpedia: notFound,
      alienvault: ok(pulses),
    }, 'Zorblax')
    assert.equal(p.status, 'none')
    assert.equal(p.name, 'Zorblax')
    assert.deepEqual(p.identities, [])
    assert.deepEqual(p.mentions.map(m => m.title), ['Zorblax campaign targets banks'])
    assert.deepEqual(p.incidents, [])
    assert.ok(!p.engineIds.has('alienvault'))
    assert.deepEqual(p.consulted, ['MITRE ATT&CK', 'Recorded Future', 'Malpedia', 'AlienVault OTX'])
  })

  it('with an actor, matching pulses are incidents and OTX joins the report', () => {
    const p = computeActorProfile(engines('mitreattack', 'alienvault'), {
      mitreattack: mitre('Zorblax'),
      alienvault: ok(pulses),
    }, 'Zorblax')
    assert.deepEqual(p.incidents.map(i => i.title), ['Zorblax campaign targets banks'])
    assert.equal(p.incidents[0].link, 'https://otx.alienvault.com/pulse/a1')
    assert.ok(p.engineIds.has('alienvault'))
  })

  it('reports loading while a source is still running', () => {
    const results: Record<string, QueryResult> = { mitreattack: mitre('Zorblax'), malpedia: loading() }
    const p = computeActorProfile(engines('mitreattack', 'malpedia'), results, 'Zorblax')
    assert.equal(p.loading, true)
  })
})

describe('relevantPulses', () => {
  const pulse = (name: string, extra: object = {}) => ({ name, ...extra })

  it('matches whole words in the title, description or adversary', () => {
    const pulses = [
      pulse('Akira ransomware hits schools'),
      pulse('IOCs', { description: 'Linked to akira affiliates' }),
      pulse('Report', { adversary: 'Akira' }),
      pulse('makira-nft.com domain list'),
      pulse('Akiradomains phishing'),
    ]
    assert.deepEqual(relevantPulses(pulses, ['Akira']).map(p => p.name), ['Akira ransomware hits schools', 'IOCs', 'Report'])
  })

  it('ignores names shorter than 4 characters', () => {
    assert.deepEqual(relevantPulses([pulse('Play store malware')], ['Play', 'TA5']).map(p => p.name), ['Play store malware'])
    assert.deepEqual(relevantPulses([pulse('TA5 report')], ['TA5']), [])
  })

  it('escapes regex characters in the names', () => {
    assert.equal(relevantPulses([pulse('LockBit 3.0 builder leak')], ['LockBit 3.0']).length, 1)
    assert.equal(relevantPulses([pulse('LockBit 310 builder leak')], ['LockBit 3.0']).length, 0)
  })

  it('accepts anything as input', () => {
    assert.deepEqual(relevantPulses(null, ['Akira']), [])
    assert.deepEqual(relevantPulses([null, 3, pulse('Akira')], ['Akira']).length, 1)
  })
})

describe('computeActorProfile · country of origin', () => {
  const apt28 = 'APT28 is a threat group that has been attributed to Russia\'s General Staff Main Intelligence Directorate (GRU).'

  it('normalises each source and counts how many give each country', () => {
    const p = computeActorProfile(engines('mitreattack', 'malpedia', 'recordedfuture'), {
      mitreattack: mitre('APT28', ['Fancy Bear'], { description: apt28 }),
      malpedia: ok({ found: true, exact: true, name: 'APT28', synonyms: ['Fancy Bear'], country: 'RU', state_sponsor: 'Russian Federation', victims: [], target_category: [], families: [] }),
      recordedfuture: rf('APT28', { aliases: ['Fancy Bear'], categories: ['Russia Nation State Sponsored', 'Nation State Sponsored'] }),
    }, 'APT28')
    assert.equal(p.country, 'RU')
    assert.deepEqual(p.origins, [{ country: 'RU', sources: ['MITRE ATT&CK', 'Malpedia', 'Recorded Future'] }])
  })

  it('lists every country when the sources disagree, most sources first', () => {
    const p = computeActorProfile(engines('mitreattack', 'malpedia', 'recordedfuture'), {
      mitreattack: mitre('APT5', [], { description: 'APT5 is a China-based espionage actor.' }),
      malpedia: ok({ found: true, exact: true, name: 'APT5', synonyms: [], country: 'CN', victims: [], target_category: [], families: [] }),
      recordedfuture: rf('APT5', { categories: ['Iran Nation State Sponsored'] }),
    }, 'APT5')
    assert.deepEqual(p.origins.map(o => [o.country, o.sources.length]), [['CN', 2], ['IR', 1]])
    assert.equal(p.country, 'CN')
  })

  it('OpenCTI originates-from is the origin, not a targeted country', () => {
    const p = computeActorProfile(engines('opencti_1'), {
      opencti_1: ok({
        kind: 'actor', found: true, exact: true, entity: { value: 'Kimsuky' }, actor: { aliases: [] },
        relations: [
          { type: 'originates-from', direction: 'out', entity_type: 'Country', name: 'North Korea' },
          { type: 'targets', direction: 'out', entity_type: 'Country', name: 'South Korea' },
        ],
        reports: [],
      }),
    }, 'Kimsuky')
    assert.deepEqual(p.origins, [{ country: 'KP', sources: ['OpenCTI'] }])
    assert.deepEqual(values(p.countries), ['South Korea'])
  })

  it('no origin when no source gives one (history #10, The Gentlemen)', () => {
    const f = historyFixture(10)
    const p = computeActorProfile(engines(...f.engineIds), f.results, f.indicator)
    assert.deepEqual(p.origins, [])
    assert.equal(p.country, null)
  })
})

describe('computeActorProfile · ransomware.live found by alias', () => {
  it('a group found under a MITRE alias is not an exact match, but joins the MITRE actor', () => {
    const p = computeActorProfile(engines('mitreattack', 'ransomwarelive'), {
      mitreattack: mitre('Akira', ['GOLD SAHARA']),
      ransomwarelive: ok({
        kind: 'group', found: true, query: 'GOLD SAHARA', groups: [{ name: 'akira' }],
        matched_alias: { alias: 'Akira', source: 'MITRE ATT&CK' },
      }),
    }, 'GOLD SAHARA')
    const rl = p.identities.find(i => i.engineId === 'ransomwarelive')
    assert.equal(rl?.exact, false)
    assert.equal(p.status, 'confirmed')
    assert.equal(p.name, 'Akira')
    assert.ok(p.engineIds.has('ransomwarelive'))
  })
})
