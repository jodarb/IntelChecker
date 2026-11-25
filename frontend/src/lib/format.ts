/** Localised date (day precision) of an ISO string; the raw value if it doesn't parse. */
export function fmtDate(v: string | null | undefined, locale: string): string | undefined {
  if (!v) return undefined
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? v : d.toLocaleDateString(locale, { year: 'numeric', month: 'short', day: 'numeric' })
}
