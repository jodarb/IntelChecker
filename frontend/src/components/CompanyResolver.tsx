import { useEffect, useState } from 'react'
import { Building2, Loader2, Search } from 'lucide-react'
import { apiJson } from '@/lib/api'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'

export interface CompanyCandidate {
  qid: string
  name: string | null
  description: string | null
  countries: string[]
  types: string[]
  domain: string | null
  lei: string | null
  organization: boolean
  domain_match: boolean
  /** "Name (domain, QID[, LEI])": what gets searched when this one is picked */
  indicator: string
}

interface ResolveResponse {
  candidates: CompanyCandidate[]
  error?: { code: string; message: string }
}

function CandidateRow({ c, onPick }: { c: CompanyCandidate; onPick: (indicator: string) => void }) {
  const { t } = useI18n()
  return (
    <button
      type="button"
      onClick={() => onPick(c.indicator)}
      className="w-full text-left flex items-start gap-3 rounded-md border border-border bg-muted/20 hover:bg-muted/60 px-3 py-2 transition-colors"
    >
      <Building2 className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
      <span className="flex flex-col gap-0.5 min-w-0">
        <span className="text-sm text-foreground font-medium">
          {c.name ?? c.qid}
          {c.domain_match && (
            <span className="ml-2 px-1.5 py-0.5 rounded border border-green-500/30 bg-green-500/10 text-xs text-green-400 font-normal">
              {t('company.domainMatch')}
            </span>
          )}
        </span>
        {c.description && <span className="text-xs text-muted-foreground">{c.description}</span>}
        <span className="text-xs text-muted-foreground font-mono break-all">
          {[c.countries.slice(0, 3).join(', '), c.domain, c.qid, c.lei].filter(Boolean).join(' · ')}
        </span>
      </span>
    </button>
  )
}

/**
 * Wikidata candidates for a company name or domain. Picking one searches its pinned
 * indicator, so every source (and the history) refers to the same entity.
 */
export default function CompanyResolver({ query, onPick }: { query: string; onPick: (indicator: string) => void }) {
  const { t } = useI18n()
  const [state, setState] = useState<{ q: string; data: ResolveResponse | null; failed: boolean }>({ q: '', data: null, failed: false })

  useEffect(() => {
    let cancelled = false
    apiJson<ResolveResponse>(`/company/resolve?q=${encodeURIComponent(query)}`)
      .then(data => { if (!cancelled) setState({ q: query, data, failed: !!data.error }) })
      .catch(() => { if (!cancelled) setState({ q: query, data: null, failed: true }) })
    return () => { cancelled = true }
  }, [query])

  const loading = state.q !== query
  const cands = state.data?.candidates ?? []
  const orgs = cands.filter(c => c.organization)
  const others = cands.filter(c => !c.organization)

  return (
    <div className="w-full max-w-2xl flex flex-col gap-2">
      {loading && (
        <p className="text-sm text-muted-foreground inline-flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('company.searching')}
        </p>
      )}
      {!loading && (
        <>
          {state.failed && <p className="text-sm text-amber-400">{t('company.resolveError')}</p>}
          {!state.failed && cands.length === 0 && <p className="text-sm text-muted-foreground">{t('company.noCandidates', { q: query })}</p>}
          {orgs.length > 0 && <p className="text-xs text-muted-foreground">{t('company.pick')}</p>}
          {orgs.map(c => <CandidateRow key={c.qid} c={c} onPick={onPick} />)}
          {others.length > 0 && (
            <details className="text-sm">
              <summary className="cursor-pointer text-xs text-muted-foreground">{t('company.notOrg')}</summary>
              <div className="flex flex-col gap-2 mt-2">{others.map(c => <CandidateRow key={c.qid} c={c} onPick={onPick} />)}</div>
            </details>
          )}
          <button
            type="button"
            onClick={() => onPick(query)}
            className="w-full text-left flex items-start gap-3 rounded-md border border-dashed border-border hover:bg-muted/40 px-3 py-2 transition-colors"
          >
            <Search className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
            <span className="flex flex-col gap-0.5">
              <span className="text-sm text-foreground">{t('company.asTyped', { q: query })}</span>
              <span className="text-xs text-muted-foreground">{t('company.asTypedHint')}</span>
            </span>
          </button>
          <p className="text-xs text-muted-foreground">{rich(t('company.format'))}</p>
        </>
      )}
    </div>
  )
}
