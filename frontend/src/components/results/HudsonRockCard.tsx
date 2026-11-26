import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Count { name: string; count: number }
interface UrlCount { url: string; occurrence: number }

interface HudsonRockResponse {
  domains?: string[]
  total?: number
  employees?: number
  users?: number
  third_parties?: number
  last_employee_compromised?: string | null
  last_user_compromised?: string | null
  days_since_employee?: number | null
  stealer_families?: Count[]
  per_domain?: { domain: string; employee_urls?: UrlCount[]; user_urls?: UrlCount[]; third_party_domains?: string[] }[]
  database_size?: number | null
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: HudsonRockResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function HudsonRockCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const total = data?.total ?? 0
  const employees = data?.employees ?? 0
  const n = (v?: number | null) => (v ?? 0).toLocaleString(locale)
  const employeeUrls = (data?.per_domain ?? []).flatMap(p => p.employee_urls ?? []).slice(0, 8)
  const userUrls = (data?.per_domain ?? []).flatMap(p => p.user_urls ?? []).slice(0, 8)

  return (
    <SourceCard title="Hudson Rock (infostealers)" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={total > 0}>
      {total === 0 && <Note tone="good">{t('hrock.clean', { domains: (data?.domains ?? []).join(', ') })}</Note>}
      {total > 0 && (
        <>
          {employees > 0
            ? <Note tone="warn">{t('hrock.employees', { n: n(employees) })}</Note>
            : <Note>{t('hrock.usersOnly')}</Note>}
          <FieldGrid>
            <Field label={t('hrock.f.employees')} value={n(employees)} />
            <Field label={t('hrock.f.users')} value={n(data?.users)} />
            <Field label={t('hrock.f.thirdParties')} value={n(data?.third_parties)} />
            <Field label={t('hrock.f.lastEmployee')} value={fmtDate(data?.last_employee_compromised, locale)} />
            <Field label={t('hrock.f.lastUser')} value={fmtDate(data?.last_user_compromised, locale)} />
            <Field label={t('f.domain')} value={(data?.domains ?? []).join(', ')} />
          </FieldGrid>
          <Field label={t('hrock.f.families')} value={<Chips items={(data?.stealer_families ?? []).map(f => `${f.name} (${n(f.count)})`)} />} />
          {employeeUrls.length > 0 && (
            <Field label={t('hrock.f.employeeUrls')} value={<Chips items={employeeUrls.map(u => `${u.url} (${n(u.occurrence)})`)} />} />
          )}
          {userUrls.length > 0 && (
            <Field label={t('hrock.f.userUrls')} value={<Chips items={userUrls.map(u => `${u.url} (${n(u.occurrence)})`)} />} />
          )}
        </>
      )}
      <p className="text-xs text-muted-foreground">{t('hrock.note')}</p>
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'Hudson Rock' })}</SourceLink>}
    </SourceCard>
  )
}
