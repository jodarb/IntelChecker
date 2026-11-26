/** ISO 3166 alpha-2 code ("ES", "US-CA" → region part ignored) → localised country name. */
export function countryName(code: string, locale: string): string {
  const cc = code.split('-')[0].toUpperCase()
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(cc) ?? code
  } catch {
    return code
  }
}
