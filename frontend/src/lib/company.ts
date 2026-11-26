/**
 * A company indicator that already names its entity ("Acme (acme.com, Q123)", with a
 * domain, Wikidata id or LEI in a trailing parenthesis) needs no picking in the
 * search box. Same format as backend/app/core/company.py.
 */
export const isPinnedCompany = (q: string) =>
  /\(([^()]*\b(Q\d+|[A-Z0-9]{18}\d{2}|[a-z0-9-]+\.[a-z]{2,}))[^()]*\)\s*$/i.test(q)

/** The company report for an indicator. */
export const companyReportUrl = (indicator: string) => `/companies/report?q=${encodeURIComponent(indicator)}`

/** Name and domains of a company indicator (the identifiers are only read by the backend). */
export function parseCompany(indicator: string): { name: string; domains: string[] } {
  const m = indicator.trim().match(/^(.*?)\s*\(([^()]*)\)\s*$/)
  const tokens = m ? m[2].split(/[,;·\s]+/).filter(Boolean) : []
  const domains = tokens.filter(t => /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i.test(t)).map(t => t.toLowerCase())
  const name = m ? m[1].trim() : indicator.trim()
  if (!m && /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i.test(name)) return { name: '', domains: [name.toLowerCase()] }
  return { name, domains }
}
