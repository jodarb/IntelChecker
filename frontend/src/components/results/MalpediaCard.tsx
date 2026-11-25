import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'

interface MalpediaFamily { id: string; common_name: string; alt_names?: string[]; link?: string }

interface MalpediaResponse {
  found?: boolean
  query?: string
  name?: string
  description?: string
  synonyms?: string[]
  country?: string | null
  state_sponsor?: string | null
  victims?: string[] | string
  target_category?: string[] | string
  incident_type?: string | null
  attribution_confidence?: string | number | null
  families?: MalpediaFamily[]
  refs?: string[]
  refs_total?: number
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: MalpediaResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const list = (v: string[] | string | undefined | null): string[] =>
  Array.isArray(v) ? v.filter(Boolean) : v ? [v] : []

export default function MalpediaCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t } = useI18n()
  const found = !!data?.found
  const families = data?.families ?? []

  return (
    <SourceCard title="Malpedia" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && <Note>{t('malpedia.notFound')}</Note>}
      {found && (
        <>
          {data?.description && <p className="text-sm text-foreground/90 leading-relaxed">{data.description}</p>}
          <FieldGrid>
            <Field label={t('f.name')} value={data?.name} />
            <Field label={t('f.country')} value={data?.country || undefined} />
            <Field label={t('f.stateSponsor')} value={data?.state_sponsor || undefined} />
            <Field label={t('f.incidentType')} value={data?.incident_type || undefined} />
            <Field label={t('f.attributionConfidence')} value={data?.attribution_confidence != null ? String(data.attribution_confidence) : undefined} />
          </FieldGrid>
          <Field label={t('f.synonyms')} value={<Chips items={data?.synonyms ?? []} max={20} />} />
          <Field label={t('f.targetCategory')} value={<Chips items={list(data?.target_category)} />} />
          <Field label={t('f.victims')} value={<Chips items={list(data?.victims)} max={15} />} />
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('malpedia.families', { n: families.length })}</span>
            {families.length === 0 ? <span className="text-sm">—</span> : (
              <span className="flex flex-wrap gap-1">
                {families.map(f => (
                  <a key={f.id} href={f.link} target="_blank" rel="noreferrer" title={f.id}
                    className="px-1.5 py-0.5 rounded bg-muted border border-border text-xs text-foreground hover:border-primary">
                    {f.common_name}
                  </a>
                ))}
              </span>
            )}
          </div>
          {(data?.refs_total ?? 0) > 0 && (
            <Field label={t('malpedia.refs', { n: data!.refs_total! })} value={
              <span className="flex flex-col gap-0.5 font-normal">
                {(data?.refs ?? []).slice(0, 5).map(r => (
                  <a key={r} href={r} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline truncate">{r}</a>
                ))}
              </span>
            } />
          )}
        </>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'Malpedia' })}</SourceLink>}
    </SourceCard>
  )
}
