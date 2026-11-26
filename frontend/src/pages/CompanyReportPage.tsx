import { useSearchParams, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import CompanyReport from '@/components/company/CompanyReport'
import SearchFrequencyCard from '@/components/results/SearchFrequencyCard'
import EngineCard from '@/components/results/EngineCard'
import { useLookup } from '@/hooks/useLookup'
import { useI18n } from '@/i18n/useI18n'

/** Live company report: the company sources on the pinned entity, then the report. */
export default function CompanyReportPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('q') ?? ''
  const { t } = useI18n()
  const { sortedEngines, results, verdict, config, disabled } = useLookup(indicator, 'company')

  return (
    <Layout tab="companies">
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">
        <Button variant="ghost" size="sm" asChild className="w-fit">
          <Link to="/companies"><ArrowLeft className="h-4 w-4 mr-1" />{t('report.newSearch')}</Link>
        </Button>
        <SearchFrequencyCard indicator={indicator} />
        <CompanyReport indicator={indicator} results={results} verdict={verdict} thresholds={config?.thresholds ?? null}>
          {sortedEngines.map(engine => (
            <EngineCard
              key={engine.id}
              engine={engine}
              result={results[engine.id]}
              type="company"
              config={config}
              indicator={indicator}
              disabled={disabled.has(engine.id)}
            />
          ))}
        </CompanyReport>
      </main>
    </Layout>
  )
}
