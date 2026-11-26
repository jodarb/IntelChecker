import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'
import { countryName } from '@/lib/countries'

interface Brief { lei: string; legal_name: string | null; country: string | null; status: string | null }
interface Address { city?: string | null; region?: string | null; country?: string | null; lines?: string[] }

interface GleifResponse {
  found?: boolean
  exact?: boolean
  lei?: string
  legal_name?: string | null
  other_names?: string[]
  jurisdiction?: string | null
  legal_address?: Address | null
  hq_address?: Address | null
  entity_status?: string | null
  category?: string | null
  registered_as?: string | null
  creation_date?: string | null
  registration_status?: string | null
  initial_registration?: string | null
  last_update?: string | null
  direct_parent?: Brief | null
  ultimate_parent?: Brief | null
  children_total?: number
  children?: Brief[]
  children_countries?: Record<string, number>
  candidates?: Brief[]
  same_name?: Brief[]
  query?: string
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: GleifResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const brief = (b: Brief | null | undefined, locale: string) =>
  b ? `${b.legal_name ?? b.lei}${b.country ? ` · ${countryName(b.country, locale)}` : ''}` : undefined

const addr = (a: Address | null | undefined, locale: string) =>
  a ? [a.city, a.country ? countryName(a.country, locale) : null].filter(Boolean).join(', ') || undefined : undefined

export default function GleifCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = data?.found === true
  const countries = Object.entries(data?.children_countries ?? {})

  return (
    <SourceCard title="GLEIF (LEI)" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && (
        <>
          <Note>{t('gleif.notFound', { q: data?.query ?? '' })}</Note>
          {(data?.candidates ?? []).length > 0 && (
            <Field label={t('gleif.candidates')} value={<Chips items={(data?.candidates ?? []).map(c => brief(c, locale)!)} />} />
          )}
        </>
      )}
      {found && (
        <>
          {data?.exact === false && <Note tone="warn">{t('gleif.byName')}</Note>}
          <p className="text-sm font-medium text-foreground">{data?.legal_name}</p>
          <FieldGrid>
            <Field label="LEI" value={data?.lei} />
            <Field label={t('f.jurisdiction')} value={data?.jurisdiction ?? undefined} />
            <Field label={t('f.status')} value={[data?.entity_status, data?.registration_status].filter(Boolean).join(' · ') || undefined} />
            <Field label={t('f.legalAddress')} value={addr(data?.legal_address, locale)} />
            <Field label={t('f.headquarters')} value={addr(data?.hq_address, locale)} />
            <Field label={t('f.registeredAs')} value={data?.registered_as ?? undefined} />
            <Field label={t('f.parent')} value={brief(data?.direct_parent, locale)} />
            <Field label={t('f.ultimateParent')} value={brief(data?.ultimate_parent, locale)} />
            <Field label={t('f.lastUpdate')} value={fmtDate(data?.last_update, locale)} />
          </FieldGrid>
          {(data?.children_total ?? 0) > 0 && (
            <Field
              label={t('gleif.children', { n: data?.children_total ?? 0 })}
              value={<Chips items={countries.map(([c, n]) => `${countryName(c, locale)} (${n})`)} max={20} />}
            />
          )}
          {(data?.same_name ?? []).length > 0 && (
            <Field label={t('gleif.sameName')} value={<Chips items={(data?.same_name ?? []).map(c => brief(c, locale)!)} />} />
          )}
        </>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'GLEIF' })}</SourceLink>}
    </SourceCard>
  )
}
