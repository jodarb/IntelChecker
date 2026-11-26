import { useSearchParams, Link, Navigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import Layout from '@/components/Layout'
import ActorReport from '@/components/actor/ActorReport'
import SummarySection from '@/components/results/SummarySection'
import SearchFrequencyCard from '@/components/results/SearchFrequencyCard'
import EngineCard from '@/components/results/EngineCard'
import type { IndicatorType } from '@/registry'
import { useLookup } from '@/hooks/useLookup'
import { companyReportUrl } from '@/lib/company'
import { useI18n } from '@/i18n/useI18n'

/** Artifact results (IP, domain, URL, hash, ASN, actor, CVE). Companies have their own report. */
export default function ResultsPage() {
  const [searchParams] = useSearchParams()
  const indicator = searchParams.get('indicator') ?? ''
  const type = (searchParams.get('type') ?? 'auto') as IndicatorType
  if (type === 'company') {
    return <Navigate to={companyReportUrl(indicator)} replace />
  }
  return <ArtifactResults indicator={indicator} type={type} />
}

function ArtifactResults({ indicator, type }: { indicator: string; type: IndicatorType }) {
  const { t } = useI18n()
  const { activeEngines, sortedEngines, results, verdict, config, disabled, unconfigured } = useLookup(indicator, type)

  const isActor = type === 'threat-actor'
  return (
    <Layout tab={isActor ? 'actors' : 'artifacts'}>
      <main className="flex-1 px-6 py-6 w-full max-w-5xl mx-auto flex flex-col gap-6">

        {/* Header */}
        {/* Title first, flush left; frequency and "back" on the right so they never push it */}
        <div className="flex flex-wrap items-start gap-x-4 gap-y-2">
          <div className="min-w-0 flex-1">
            <h2 className="text-xl font-semibold text-foreground font-mono break-all">{indicator}</h2>
            <span className="text-xs text-muted-foreground uppercase tracking-wide">
              {t(`type.${type}`)}
            </span>
          </div>
          {/* Right column: "back" on top, the search frequency right below it */}
          <div className="flex flex-col items-end gap-1.5">
            <Button variant="ghost" size="sm" asChild className="h-7 px-2 text-xs text-muted-foreground">
              <Link to={isActor ? '/actors' : '/'}>
                <ArrowLeft className="h-3.5 w-3.5 mr-1" />
                {t('common.back')}
              </Link>
            </Button>
            <SearchFrequencyCard indicator={indicator} />
          </div>
        </div>

        {isActor ? (
          <ActorReport indicator={indicator} engines={activeEngines} results={results} verdict={verdict}
            thresholds={config?.thresholds ?? null}>
            {sortedEngines.map(engine => (
              <EngineCard key={engine.id} engine={engine} result={results[engine.id]} type={type}
                config={config} indicator={indicator} disabled={disabled.has(engine.id)} />
            ))}
          </ActorReport>
        ) : (<>
        {/* Summary */}
        <SummarySection
          indicator={indicator}
          type={type}
          engines={activeEngines}
          results={results}
          verdict={verdict}
          thresholds={config?.thresholds ?? null}
          unconfigured={unconfigured}
        />

        {/* Engine results — unconfigured sources aren't shown; the rest: results
            first, then loading, then no result / errors / switched off (resultOrder.ts). */}
        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('results.byEngine')}</p>
          <div className="grid grid-cols-1 gap-4">
            {sortedEngines.map(engine => (
              <EngineCard
                key={engine.id}
                engine={engine}
                result={results[engine.id]}
                type={type}
                config={config}
                indicator={indicator}
                disabled={disabled.has(engine.id)}
              />
            ))}
          </div>
        </div>
        </>)}

      </main>
    </Layout>
  )
}
