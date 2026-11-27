import { useSearchParams } from 'react-router-dom'
import Layout from '@/components/Layout'
import CompanyReport from '@/components/company/CompanyReport'
import SearchFrequencyCard from '@/components/results/SearchFrequencyCard'
import EngineCard from '@/components/results/EngineCard'
import { useLookup } from '@/hooks/useLookup'
import BackButton from '@/components/BackButton'

/** Live company report: the company sources on the pinned entity, then the report. */
export default function CompanyReportPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('q') ?? ''
  const { sortedEngines, results, config, disabled } = useLookup(indicator, 'company')

  return (
    <Layout tab="companies">
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <BackButton fallback="/companies" />
          <SearchFrequencyCard indicator={indicator} />
        </div>
        <CompanyReport indicator={indicator} results={results}>
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
