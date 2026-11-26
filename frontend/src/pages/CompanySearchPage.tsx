import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import Layout from '@/components/Layout'
import EngineStatusPanel from '@/components/EngineStatusPanel'
import { HideScores } from '@/components/results/scoreVisibility'
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

  return (
    <Layout tab="companies">
      <main className="flex-1 flex flex-col items-center justify-start px-4 pt-16 pb-10 gap-8">
        <div className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight text-foreground">{t('companies.title')}</h1>
          <p className="text-muted-foreground text-sm">{t('companies.subtitle')}</p>
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

        <HideScores value><EngineStatusPanel selectedType="company" scope="companies" /></HideScores>
      </main>
    </Layout>
  )
}
