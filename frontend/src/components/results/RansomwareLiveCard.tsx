import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'
import { countryName } from '@/lib/countries'

interface Victim {
  victim: string
  group?: string | null
  domain?: string | null
  country?: string | null
  sector?: string | null
  attack_date?: string | null
  discovered?: string | null
  description?: string | null
  data_size?: string | null
  link?: string | null
  claim_url?: string | null
}

interface RansomwareLiveResponse {
  query?: string
  listed?: boolean
  matches?: Victim[]
  match_count?: number
  groups?: string[]
  last_claim?: string | null
  days_since_last?: number | null
  claims_365d?: number
  similar?: Victim[]
  similar_count?: number
  via?: 'dump' | 'api'
  list_size?: number | null
  list_updated?: string | null
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: RansomwareLiveResponse | null
  score?: number | null
  weight?: CardWeight | null
}

function VictimRow({ v, locale }: { v: Victim; locale: string }) {
  const { t } = useI18n()
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2 flex flex-col gap-1">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-sm">
        <span className="font-medium text-foreground">{v.victim}</span>
        {v.group && <span className="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-xs text-red-400">{v.group}</span>}
        <span className="text-xs text-muted-foreground">
          {[fmtDate(v.discovered ?? v.attack_date, locale), v.country ? countryName(v.country, locale) : null, v.sector, v.domain]
            .filter(Boolean).join(' · ')}
        </span>
      </div>
      {v.description && <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">{v.description}</p>}
      <div className="flex flex-wrap gap-3">
        {v.link && <SourceLink href={v.link}>{t('card.viewOn', { source: 'ransomware.live' })}</SourceLink>}
        {/* Leak-site address: shown as text, never linked (.onion, attacker-controlled). */}
        {v.claim_url && <span className="text-xs text-muted-foreground font-mono break-all" title={t('rlive.claimUrl')}>{v.claim_url}</span>}
      </div>
    </div>
  )
}

export default function RansomwareLiveCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, tn, locale } = useI18n()
  const listed = data?.listed === true
  const similar = data?.similar ?? []

  return (
    <SourceCard title="ransomware.live" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={listed}>
      {!listed && <Note>{t('rlive.notListed')}</Note>}
      {listed && (
        <>
          <Note tone="warn">{tn('rlive.listed', data?.match_count ?? 0)}</Note>
          <FieldGrid>
            <Field label={t('rlive.groups')} value={<Chips items={data?.groups ?? []} />} />
            <Field label={t('rlive.lastClaim')} value={fmtDate(data?.last_claim, locale)} />
            <Field label={t('rlive.last365')} value={data?.claims_365d ?? 0} />
          </FieldGrid>
          <div className="flex flex-col gap-2">
            {(data?.matches ?? []).slice(0, 10).map((v, i) => <VictimRow key={`${v.victim}-${i}`} v={v} locale={locale} />)}
          </div>
        </>
      )}
      {similar.length > 0 && (
        <Field
          label={t('rlive.similar', { n: data?.similar_count ?? similar.length })}
          value={<Chips items={similar.map(v => `${v.victim}${v.group ? ` · ${v.group}` : ''}`)} max={10} />}
        />
      )}
      <p className="text-xs text-muted-foreground">
        {data?.via === 'api'
          ? t('rlive.viaApi')
          : t('rlive.list', { n: (data?.list_size ?? 0).toLocaleString(locale), date: fmtDate(data?.list_updated, locale) ?? '—' })}
      </p>
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'ransomware.live' })}</SourceLink>}
    </SourceCard>
  )
}
