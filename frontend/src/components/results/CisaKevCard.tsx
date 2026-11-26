import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface KevResponse {
  cve?: string
  listed?: boolean
  vendor?: string
  product?: string
  name?: string
  description?: string
  date_added?: string
  due_date?: string
  required_action?: string
  ransomware?: string
  cwes?: string[]
  catalog_version?: string
  catalog_size?: number
  list_updated?: string | null
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: KevResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function CisaKevCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const listed = data?.listed === true

  return (
    <SourceCard title="CISA KEV" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={listed}>
      {!listed && <Note>{t('kev.notListed')}</Note>}
      {listed && (
        <>
          <Note tone="warn">{t('kev.listed')}</Note>
          {data?.ransomware === 'Known' && <Note tone="warn">{t('kev.ransomware')}</Note>}
          {data?.name && <p className="text-sm font-medium text-foreground">{data.name}</p>}
          {data?.description && <p className="text-sm text-foreground/90 leading-relaxed">{data.description}</p>}
          <FieldGrid>
            <Field label={t('f.vendor')} value={data?.vendor} />
            <Field label={t('f.product')} value={data?.product} />
            <Field label={t('f.dateAdded')} value={fmtDate(data?.date_added, locale)} />
            <Field label={t('f.dueDate')} value={fmtDate(data?.due_date, locale)} />
            <Field label={t('f.ransomware')} value={data?.ransomware === 'Known' ? t('kev.ransomKnown') : t('kev.ransomUnknown')} />
          </FieldGrid>
          <Field label={t('f.cwe')} value={<Chips items={data?.cwes ?? []} />} />
          {data?.required_action && <Field label={t('f.requiredAction')} value={<span className="font-normal">{data.required_action}</span>} />}
        </>
      )}
      <p className="text-xs text-muted-foreground">
        {t('kev.catalog', {
          n: (data?.catalog_size ?? 0).toLocaleString(locale),
          version: data?.catalog_version ?? '—',
          date: fmtDate(data?.list_updated, locale) ?? '—',
        })}
      </p>
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'CISA' })}</SourceLink>}
    </SourceCard>
  )
}
