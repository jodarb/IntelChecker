import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'
import { TRANCO_CLEAN_MAX_RANK } from '@/verdictEngine'

interface TrancoResponse {
  host?: string
  domain?: string
  exact?: boolean
  found?: boolean
  rank?: number | null
  date?: string | null
  best_rank?: number | null
  days_listed?: number
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: TrancoResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function TrancoCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = !!data?.found
  const rank = data?.rank ?? null

  return (
    <SourceCard title="Tranco" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={found && !!data?.exact}>
      {!found && <Note>{t('tranco.notListed', { domain: data?.domain ?? '' })}</Note>}
      {found && !data?.exact && <Note tone="warn">{t('tranco.parentOnly', { domain: data?.domain ?? '', host: data?.host ?? '' })}</Note>}
      {found && data?.exact && rank != null && (
        rank <= TRANCO_CLEAN_MAX_RANK
          ? <Note tone="good">{t('tranco.top', { max: TRANCO_CLEAN_MAX_RANK.toLocaleString(locale) })}</Note>
          : <Note>{t('tranco.lowRank', { max: TRANCO_CLEAN_MAX_RANK.toLocaleString(locale) })}</Note>
      )}
      {found && (
        <>
          <FieldGrid>
            <Field label={t('f.domain')} value={data?.domain} />
            <Field label={t('f.rank')} value={rank != null ? `#${rank.toLocaleString(locale)}` : undefined} />
            <Field label={t('f.bestRank')} value={data?.best_rank != null ? `#${data.best_rank.toLocaleString(locale)}` : undefined} />
            <Field label={t('f.daysListed')} value={data?.days_listed} />
            <Field label={t('f.listUpdated')} value={fmtDate(data?.date, locale)} />
          </FieldGrid>
          <Note>{t('tranco.caveat')}</Note>
        </>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'Tranco' })}</SourceLink>}
    </SourceCard>
  )
}
