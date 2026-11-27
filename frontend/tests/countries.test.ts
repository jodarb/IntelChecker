import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { originCountriesInText, toCountryCode } from '@/lib/countries'

describe('toCountryCode', () => {
  it('normalises codes, official names, Spanish names and demonyms', () => {
    const cases: [string, string | null][] = [
      ['RU', 'RU'], ['ru', 'RU'], ['UK', 'GB'], ['Russian Federation', 'RU'], ['Russia', 'RU'],
      ["Korea, Democratic People's Republic of", 'KP'], ['DPRK', 'KP'], ['North Korean', 'KP'],
      ['Iran, Islamic Republic of', 'IR'], ['Irán', 'IR'], ['Viet Nam', 'VN'], ['Türkiye', 'TR'],
      ['Chinese', 'CN'], ['XX', null], ['Narnia', null], ['', null],
    ]
    for (const [v, cc] of cases) assert.equal(toCountryCode(v), cc, v)
  })
  it('ignores anything that is not a string', () => {
    assert.equal(toCountryCode(null), null)
    assert.equal(toCountryCode(3), null)
  })
})

describe('originCountriesInText (ATT&CK descriptions)', () => {
  const cases: [string, string[]][] = [
    ["APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU).", ['RU']],
    ['APT5 is a China-based espionage actor that has been active since at least 2007.', ['CN']],
    ['Lazarus Group is a North Korean state-sponsored cyber threat group.', ['KP']],
    ['Kimsuky is a North Korea-based cyber espionage group.', ['KP']],
    ["MuddyWater is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence.", ['IR']],
    ['Akira is a ransomware variant and ransomware deployment entity active since at least March 2023.', []],
    ['Scattered Spider is a native English-speaking cybercriminal group.', []],
  ]
  for (const [text, want] of cases) {
    it(text.slice(0, 40), () => assert.deepEqual(originCountriesInText(text), want))
  }
  it('only reads the first two sentences', () => {
    assert.deepEqual(originCountriesInText('A group. It is busy. Later reports tied it to China-based operators.'), [])
  })
})
