import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface RdapResponse {
  found?: boolean
  domain?: string
  registered?: string | null
  expires?: string | null
  last_changed?: string | null
  age_days?: number | null
  registrar?: string | null
  abuse_email?: string | null
  status?: string[]
  nameservers?: string[]
  dnssec?: boolean
  rdap_url?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: RdapResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function RdapCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, tn, locale } = useI18n()
  const found = !!data?.found
  const age = typeof data?.age_days === 'number' ? data.age_days : null

  return (
    <SourceCard title="RDAP" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && <Note>{t('rdap.notRegistered', { domain: data?.domain ?? '' })}</Note>}
      {found && (
        <>
          {age != null && age < 30 && <Note tone="warn">{tn('rdap.young', age)}</Note>}
          <FieldGrid>
            <Field label={t('f.domain')} value={data?.domain} />
            <Field label={t('f.registered')} value={fmtDate(data?.registered, locale)} />
            <Field label={t('f.age')} value={age != null ? tn('rdap.age', age) : undefined} />
            <Field label={t('f.expires')} value={fmtDate(data?.expires, locale)} />
            <Field label={t('f.lastUpdate')} value={fmtDate(data?.last_changed, locale)} />
            <Field label={t('f.registrar')} value={data?.registrar} />
            <Field label={t('f.abuseContacts')} value={data?.abuse_email} />
            <Field label="DNSSEC" value={data?.dnssec ? t('common.yes') : t('common.no')} />
          </FieldGrid>
          <Field label={t('f.status')} value={<Chips items={data?.status ?? []} />} />
          <Field label={t('f.nameservers')} value={<Chips items={data?.nameservers ?? []} />} />
        </>
      )}
      {data?.rdap_url && <SourceLink href={data.rdap_url}>{t('rdap.viewRecord')}</SourceLink>}
    </SourceCard>
  )
}
