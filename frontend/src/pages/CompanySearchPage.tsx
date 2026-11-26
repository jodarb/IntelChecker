import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Building2, Skull, KeyRound, DatabaseZap, Newspaper } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import Layout from '@/components/Layout'
import EngineStatusPanel from '@/components/EngineStatusPanel'
import CompanyResolver from '@/components/CompanyResolver'
import { companyReportUrl, isPinnedCompany } from '@/lib/company'
import { useI18n } from '@/i18n/useI18n'

/**
 * Company search: a name or a domain. Names are ambiguous, so the analyst first picks
 * the organisation among the Wikidata candidates; the report then runs the company
 * sources on the pinned entity ("Name (domain, Q-id[, LEI])").
 */
export default function CompanySearchPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [resolving, setResolving] = useState<string | null>(null)

  const go = (indicator: string) => navigate(companyReportUrl(indicator))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const q = query.trim()
    if (!q) return
    if (isPinnedCompany(q)) go(q)
    else setResolving(q)
  }

  const covers = [
    { icon: <Building2 className="h-4 w-4" />, label: t('companies.covers.profile') },
    { icon: <Skull className="h-4 w-4" />, label: t('companies.covers.darkweb') },
    { icon: <KeyRound className="h-4 w-4" />, label: t('companies.covers.stealers') },
    { icon: <DatabaseZap className="h-4 w-4" />, label: t('companies.covers.breaches') },
    { icon: <Newspaper className="h-4 w-4" />, label: t('companies.covers.news') },
  ]

  return (
    <Layout tab="companies">
      <main className="flex-1 flex flex-col items-center justify-center px-4 py-10 gap-8">
        <div className="text-center space-y-3">
          <h1 className="text-3xl font-bold tracking-tight text-foreground">{t('companies.title')}</h1>
          <p className="text-muted-foreground text-sm">{t('companies.subtitle')}</p>
          <div className="flex flex-wrap justify-center gap-2 pt-1">
            {covers.map(c => (
              <span key={c.label} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-border bg-muted/20 text-xs text-muted-foreground">
                {c.icon}{c.label}
              </span>
            ))}
          </div>
        </div>

        <form onSubmit={handleSubmit} className="w-full max-w-2xl flex flex-col gap-3">
          <Input
            value={query}
            onChange={e => { setQuery(e.target.value); setResolving(null) }}
            placeholder={t('companies.placeholder')}
            autoFocus
          />
          <Button type="submit" className="w-full gap-2" disabled={!query.trim()}>
            <Search className="h-4 w-4" />
            {t('companies.search')}
          </Button>
        </form>

        {resolving && <CompanyResolver query={resolving} onPick={go} />}

        <EngineStatusPanel selectedType="company" scope="companies" />
      </main>
    </Layout>
  )
}
