import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface OpenPhishResponse {
  kind?: 'url' | 'host'
  host?: string
  exact?: boolean
  listed?: boolean
  matches?: string[]
  matches_total?: number
  feed_size?: number
  feed_updated?: string | null
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: OpenPhishResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function OpenPhishCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const matches = data?.matches ?? []

  return (
    <SourceCard title="OpenPhish" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={!!data?.listed}>
      {!data?.listed && <Note>{t('openphish.notListed')}</Note>}
      {data?.exact && data.kind === 'url' && <Note tone="warn">{t('openphish.urlListed')}</Note>}
      {data?.exact && data.kind === 'host' && <Note tone="warn">{t('openphish.hostListed', { host: data.host ?? '' })}</Note>}
      {!data?.exact && matches.length > 0 && <Note tone="warn">{t('openphish.sameHost', { host: data?.host ?? '' })}</Note>}
      {matches.length > 0 && (
        <Field label={t('openphish.matches', { n: data?.matches_total ?? matches.length })} value={
          <span className="flex flex-col gap-0.5 font-mono text-xs font-normal">
            {matches.map(u => <span key={u} className="break-all">{u}</span>)}
          </span>
        } />
      )}
      <FieldGrid>
        <Field label={t('f.listSize')} value={data?.feed_size} />
        <Field label={t('f.listUpdated')} value={fmtDate(data?.feed_updated, locale)} />
      </FieldGrid>
    </SourceCard>
  )
}
