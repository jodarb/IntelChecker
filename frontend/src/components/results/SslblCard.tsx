import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface SslblResponse {
  applicable?: boolean
  listed?: boolean
  sha1?: string
  listing_date?: string | null
  reason?: string | null
  list_size?: number
  list_updated?: string | null
  link?: string | null
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: SslblResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function SslblCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()

  return (
    <SourceCard title="SSLBL · abuse.ch" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={!!data?.listed}>
      {data?.applicable === false && <Note>{t('sslbl.notSha1')}</Note>}
      {data?.applicable && !data.listed && <Note>{t('sslbl.notListed')}</Note>}
      {data?.listed && <Note tone="warn">{t('sslbl.listed')}</Note>}
      {data?.applicable && (
        <FieldGrid>
          {data.listed && <Field label={t('f.reason')} value={data.reason} />}
          {data.listed && <Field label={t('f.dateAdded')} value={data.listing_date ? fmtDate(`${data.listing_date.replace(' ', 'T')}Z`, locale) : undefined} />}
          <Field label={t('f.listSize')} value={data.list_size?.toLocaleString(locale)} />
          <Field label={t('f.listUpdated')} value={fmtDate(data.list_updated, locale)} />
        </FieldGrid>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'SSLBL' })}</SourceLink>}
    </SourceCard>
  )
}
