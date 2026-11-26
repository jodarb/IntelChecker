import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Ref { name: string; qid?: string | null; country?: string }
interface Presence { country: string; code: string | null; via: ('company' | 'headquarters' | 'subsidiary')[] }

interface WikidataResponse {
  found?: boolean
  exact?: boolean
  qid?: string
  name?: string | null
  description?: string | null
  official_names?: string[]
  sectors?: string[]
  types?: Ref[]
  countries?: string[]
  presence?: Presence[]
  headquarters?: Ref[]
  parents?: Ref[]
  owners?: Ref[]
  subsidiaries?: Ref[]
  subsidiaries_total?: number
  exchanges?: Ref[]
  tickers?: string[]
  domain?: string | null
  websites?: string[]
  inception?: string | null
  employees?: number | null
  lei?: string | null
  link?: string
  query?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: WikidataResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const names = (refs?: Ref[]) => (refs ?? []).map(r => r.name)

export default function WikidataCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = data?.found === true
  const hq = data?.headquarters?.[0]
  const presence = data?.presence ?? []
  const subsidiaryCountries = presence.filter(p => p.via.includes('subsidiary') && !p.via.includes('company'))

  return (
    <SourceCard title="Wikidata" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && <Note>{t('wikidata.notFound', { q: data?.query ?? '' })}</Note>}
      {found && (
        <>
          {data?.exact === false && <Note tone="warn">{t('wikidata.guess')}</Note>}
          <div className="flex flex-col gap-0.5">
            <p className="text-sm font-medium text-foreground">{data?.name ?? data?.qid}</p>
            {data?.description && <p className="text-sm text-muted-foreground">{data.description}</p>}
          </div>
          <FieldGrid>
            <Field label={t('f.sector')} value={<Chips items={data?.sectors ?? []} max={6} />} />
            <Field label={t('f.country')} value={(data?.countries ?? []).join(', ') || undefined} />
            <Field label={t('f.headquarters')} value={hq ? `${hq.name}${hq.country ? `, ${hq.country}` : ''}` : undefined} />
            <Field label={t('f.parent')} value={names(data?.parents).join(', ') || undefined} />
            <Field label={t('f.owners')} value={names(data?.owners).slice(0, 4).join(', ') || undefined} />
            <Field label={t('f.founded')} value={data?.inception && data.inception.length > 7 ? fmtDate(data.inception, locale) : data?.inception ?? undefined} />
            <Field label={t('f.employees')} value={data?.employees != null ? data.employees.toLocaleString(locale) : undefined} />
            <Field label={t('f.website')} value={data?.domain ?? undefined} />
            <Field label={t('f.tickers')} value={(data?.tickers ?? []).join(', ') || undefined} />
            <Field label="LEI" value={data?.lei ?? undefined} />
          </FieldGrid>
          {subsidiaryCountries.length > 0 && (
            <Field
              label={t('wikidata.presence', { n: data?.subsidiaries_total ?? 0 })}
              value={<Chips items={subsidiaryCountries.map(p => p.country)} max={20} />}
            />
          )}
          {(data?.subsidiaries ?? []).length > 0 && (
            <Field
              label={t('f.subsidiaries')}
              value={<Chips items={(data?.subsidiaries ?? []).map(s => (s.country ? `${s.name} · ${s.country}` : s.name))} max={15} />}
            />
          )}
          {(data?.official_names ?? []).length > 0 && (
            <Field label={t('f.legalName')} value={<span className="font-normal">{data!.official_names!.join(' · ')}</span>} />
          )}
        </>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'Wikidata' })}</SourceLink>}
    </SourceCard>
  )
}
