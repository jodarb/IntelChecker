import { useEffect, useState } from 'react'
import { Loader2, Search, VenetianMask } from 'lucide-react'
import { apiJson } from '@/lib/api'
import { useI18n } from '@/i18n/useI18n'

export interface ActorCandidate {
  /** The name to look it up by: the one most sources know it by */
  name: string
  aliases: string[]
  aliases_total: number
  sources: string[]
  score: number
  description: string | null
  mitre_id: string | null
  ransomware: boolean
  victims: number | null
  categories: string[]
  /** RF-only names without a group category: forum handles, people… */
  minor: boolean
}

interface ResolveResponse {
  candidates: ActorCandidate[]
  error?: { code: string; message: string }
}

function CandidateRow({ c, onPick }: { c: ActorCandidate; onPick: (name: string) => void }) {
  const { t, locale } = useI18n()
  const more = c.aliases_total - c.aliases.length
  return (
    <button
      type="button"
      onClick={() => onPick(c.name)}
      className="w-full text-left flex items-start gap-3 rounded-md border border-border bg-muted/20 hover:bg-muted/60 px-3 py-2 transition-colors"
    >
      <VenetianMask className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
      <span className="flex flex-col gap-0.5 min-w-0">
        <span className="text-sm text-foreground font-medium flex flex-wrap items-center gap-2">
          {c.name}
          {c.mitre_id && <span className="text-xs text-muted-foreground font-mono font-normal">{c.mitre_id}</span>}
          {c.ransomware && (
            <span className="px-1.5 py-0.5 rounded border border-red-500/30 bg-red-500/10 text-xs text-red-400 font-normal">
              {c.victims != null ? t('actorPick.ransomwareVictims', { n: c.victims.toLocaleString(locale) }) : t('actorPick.ransomware')}
            </span>
          )}
          {c.score === 100 && (
            <span className="px-1.5 py-0.5 rounded border border-green-500/30 bg-green-500/10 text-xs text-green-400 font-normal">
              {t('actorPick.exact')}
            </span>
          )}
        </span>
        {c.aliases.length > 0 && (
          <span className="text-xs text-muted-foreground">
            {t('actorPick.aka')} {c.aliases.join(', ')}{more > 0 ? ` +${more}` : ''}
          </span>
        )}
        {c.description && <span className="text-xs text-muted-foreground line-clamp-2">{c.description}</span>}
        <span className="text-xs text-muted-foreground">
          {[c.sources.join(' · '), c.categories.slice(0, 3).join(', ')].filter(Boolean).join(' — ')}
        </span>
      </span>
    </button>
  )
}

/**
 * Candidate actors for what the analyst typed ("Gentleman" → The Gentlemen), from
 * MITRE ATT&CK, ransomware.live, Malpedia and Recorded Future. Picking one searches
 * it by the name most sources know it by.
 */
export default function ActorResolver({ query, onPick }: { query: string; onPick: (name: string) => void }) {
  const { t } = useI18n()
  const [state, setState] = useState<{ q: string; data: ResolveResponse | null; failed: boolean }>({ q: '', data: null, failed: false })

  useEffect(() => {
    let cancelled = false
    apiJson<ResolveResponse>(`/actor/resolve?q=${encodeURIComponent(query)}`)
      .then(data => { if (!cancelled) setState({ q: query, data, failed: !!data.error }) })
      .catch(() => { if (!cancelled) setState({ q: query, data: null, failed: true }) })
    return () => { cancelled = true }
  }, [query])

  const loading = state.q !== query
  const cands = state.data?.candidates ?? []
  const actors = cands.filter(c => !c.minor)
  const minor = cands.filter(c => c.minor)

  return (
    <div className="w-full max-w-2xl flex flex-col gap-2">
      {loading && (
        <p className="text-sm text-muted-foreground inline-flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin" /> {t('actorPick.searching')}
        </p>
      )}
      {!loading && (
        <>
          {state.failed && <p className="text-sm text-amber-400">{t('actorPick.error')}</p>}
          {!state.failed && cands.length === 0 && <p className="text-sm text-muted-foreground">{t('actorPick.none', { q: query })}</p>}
          {actors.length > 0 && <p className="text-xs text-muted-foreground">{t('actorPick.pick')}</p>}
          {actors.map((c, i) => <CandidateRow key={`${c.name}-${i}`} c={c} onPick={onPick} />)}
          {minor.length > 0 && (
            <details className="text-sm" open={actors.length === 0}>
              <summary className="cursor-pointer text-xs text-muted-foreground">{t('actorPick.minor', { n: minor.length })}</summary>
              <div className="flex flex-col gap-2 mt-2">{minor.map((c, i) => <CandidateRow key={`${c.name}-${i}`} c={c} onPick={onPick} />)}</div>
            </details>
          )}
          <button
            type="button"
            onClick={() => onPick(query)}
            className="w-full text-left flex items-start gap-3 rounded-md border border-dashed border-border hover:bg-muted/40 px-3 py-2 transition-colors"
          >
            <Search className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
            <span className="flex flex-col gap-0.5">
              <span className="text-sm text-foreground">{t('actorPick.asTyped', { q: query })}</span>
              <span className="text-xs text-muted-foreground">{t('actorPick.asTypedHint')}</span>
            </span>
          </button>
        </>
      )}
    </div>
  )
}
