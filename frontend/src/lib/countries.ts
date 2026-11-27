/** ISO 3166 alpha-2 code ("ES", "US-CA" → region part ignored) → localised country name. */
export function countryName(code: string, locale: string): string {
  const cc = code.split('-')[0].toUpperCase()
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(cc) ?? code
  } catch {
    return code
  }
}

const key = (v: string) => v.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '')

// Spellings the sources use that Intl doesn't give: official / short names and
// demonyms ("Russian", "North Korean"), as threat intel writes about state actors.
const EXTRA: Record<string, string> = {
  russianfederation: 'RU', russian: 'RU', ussr: 'RU',
  china: 'CN', prc: 'CN', peoplesrepublicofchina: 'CN', chinese: 'CN',
  northkorea: 'KP', dprk: 'KP', democraticpeoplesrepublicofkorea: 'KP', koreademocraticpeoplesrepublicof: 'KP', northkorean: 'KP',
  southkorea: 'KR', republicofkorea: 'KR', korearepublicof: 'KR', southkorean: 'KR',
  iran: 'IR', iranislamicrepublicof: 'IR', islamicrepublicofiran: 'IR', iranian: 'IR',
  syria: 'SY', syrianarabrepublic: 'SY', syrian: 'SY',
  vietnam: 'VN', vietnamese: 'VN',
  turkey: 'TR', turkiye: 'TR', turkish: 'TR',
  usa: 'US', us: 'US', unitedstatesofamerica: 'US', american: 'US',
  uk: 'GB', greatbritain: 'GB', british: 'GB',
  uae: 'AE', emirati: 'AE',
  palestine: 'PS', palestinian: 'PS',
  taiwan: 'TW', taiwanese: 'TW',
  pakistani: 'PK', indian: 'IN', israeli: 'IL', lebanese: 'LB', belarusian: 'BY', ukrainian: 'UA',
  kazakh: 'KZ', nigerian: 'NG', brazilian: 'BR', spanish: 'ES', french: 'FR', german: 'DE', italian: 'IT',
  egyptian: 'EG', saudi: 'SA', qatari: 'QA', indonesian: 'ID', malaysian: 'MY', thai: 'TH', filipino: 'PH',
}

let byName: Map<string, string> | null = null
function names(): Map<string, string> {
  if (byName) return byName
  byName = new Map(Object.entries(EXTRA))
  for (const locale of ['en', 'es']) {
    try {
      const dn = new Intl.DisplayNames([locale], { type: 'region' })
      for (let a = 65; a <= 90; a++) for (let b = 65; b <= 90; b++) {
        const code = String.fromCharCode(a, b)
        const name = dn.of(code)
        if (name && name !== code && !byName.has(key(name))) byName.set(key(name), code)
      }
    } catch { /* no Intl: only the extra spellings */ }
  }
  return byName
}

const isCode = (v: string) => {
  try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(v) !== v } catch { return true }
}

/**
 * A country as the sources give it — ISO code ("RU"), name ("Russian Federation",
 * "Korea, Democratic People's Republic of", "Irán") or demonym ("North Korean") —
 * as its ISO 3166 alpha-2 code, or null if it isn't one.
 */
export function toCountryCode(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null
  const v = value.trim()
  if (/^[A-Za-z]{2}$/.test(v)) {
    const cc = v.toUpperCase()
    if (cc === 'UK') return 'GB'
    return isCode(cc) ? cc : null
  }
  return names().get(key(v)) ?? null
}

// "China-based", "Russian state-sponsored", "attributed to Iran's…", "North Korean
// government": how ATT&CK descriptions name the state behind a group.
const ORIGIN_CONTEXT = String.raw`(?:-based|-nexus|-linked|-sponsored|-backed|-affiliated|\s+state(?:-|\s)sponsored|\s+state|\s+government|\s+military|\s+intelligence|\s+nation(?:-|\s)state|\s+cyber\s+espionage|\s+espionage|\s+threat|\s+advanced|\s+APT|'s)`
const PLACE = String.raw`((?:North |South )?[A-Z][a-z]+(?: [A-Z][a-z]+)?)`
const ORIGIN_RES = [
  new RegExp(`${PLACE}${ORIGIN_CONTEXT}`, 'g'),
  new RegExp(String.raw`(?:attributed to|operating (?:out of|from)|based in|on behalf of|sponsored by) (?:the )?${PLACE}`, 'g'),
]

/** Countries a free-text description says the actor works for or from (first two sentences only). */
export function originCountriesInText(text: unknown): string[] {
  if (typeof text !== 'string') return []
  const head = text.split(/(?<=\.)\s+/).slice(0, 2).join(' ')
  const out = new Set<string>()
  for (const re of ORIGIN_RES) {
    for (const m of head.matchAll(re)) {
      // "Russia's General Staff" → Russia; "People's Liberation Army" → no country.
      const words = m[1].split(' ')
      const code = toCountryCode(m[1]) ?? (words.length > 1 ? toCountryCode(words[words.length - 1]) : null)
      if (code) out.add(code)
    }
  }
  return [...out]
}
