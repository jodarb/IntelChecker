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

interface GroupProfile {
  name: string
  altname?: string | null
  lineage?: string | null
  first_seen?: string | null
  raas?: boolean | null
  description?: string | null
  leak_sites?: number
  leak_sites_up?: number
  link?: string
}

interface RansomwareLiveResponse {
  // Threat actor (ransomware group) lookups
  kind?: 'group'
  found?: boolean
  victim_count?: number
  first_claim?: string | null
  claims_30d?: number
  claims_90d?: number
  top_sectors?: { name: string; count: number }[]
  top_countries?: { name: string; count: number }[]
  recent?: Victim[]
  victims_error?: { code: string; message: string }
  // Company lookups
  query?: string
  listed?: boolean
  matches?: Victim[]
  match_count?: number
  groups?: string[] | GroupProfile[]
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

/** Threat actor: the ransomware group's profile and its leak-site activity. */
function GroupView({ data }: { data: RansomwareLiveResponse }) {
  const { t, locale } = useI18n()
  const groups = (data.groups ?? []) as GroupProfile[]
  const main = groups[0]
  if (!data.found || !main) return <Note>{t('rlive.groupNotFound')}</Note>
  const leakTotal = groups.reduce((n, g) => n + (g.leak_sites ?? 0), 0)
  const leakUp = groups.reduce((n, g) => n + (g.leak_sites_up ?? 0), 0)
  const counts = (xs?: { name: string; count: number }[], country = false) =>
    (xs ?? []).map(x => `${country ? countryName(x.name, locale) : x.name} · ${x.count}`)
  return (
    <>
      <Field label={t('rlive.groupVariants')} value={<Chips items={groups.map(g => g.altname ? `${g.name} (${g.altname})` : g.name)} />} />
      {main.description && <p className="text-sm text-muted-foreground leading-relaxed line-clamp-5">{main.description}</p>}
      <FieldGrid>
        <Field label={t('rlive.victims')} value={(data.victim_count ?? 0).toLocaleString(locale)} />
        <Field label={t('rlive.lastClaim')} value={fmtDate(data.last_claim, locale)} />
        <Field label={t('rlive.last30')} value={data.claims_30d ?? 0} />
        <Field label={t('rlive.last90')} value={data.claims_90d ?? 0} />
        <Field label={t('rlive.last365')} value={data.claims_365d ?? 0} />
        <Field label={t('rlive.firstSeen')} value={fmtDate(main.first_seen ?? data.first_claim, locale)} />
        <Field label={t('rlive.leakSites')} value={`${leakTotal} (${leakUp})`} />
        {main.raas != null && <Field label={t('rlive.raas')} value={main.raas ? t('common.yes') : t('common.no')} />}
        {main.lineage && <Field label={t('rlive.lineage')} value={main.lineage} />}
      </FieldGrid>
      {(data.top_sectors ?? []).length > 0 && <Field label={t('rlive.topSectors')} value={<Chips items={counts(data.top_sectors)} />} />}
      {(data.top_countries ?? []).length > 0 && <Field label={t('rlive.topCountries')} value={<Chips items={counts(data.top_countries, true)} />} />}
      {data.victims_error && <Note>{t('rlive.victimsUnavailable', { reason: data.victims_error.message })}</Note>}
      {(data.recent ?? []).length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('rlive.recent')}</span>
          {data.recent!.slice(0, 8).map((v, i) => <VictimRow key={`${v.victim}-${i}`} v={v} locale={locale} />)}
        </div>
      )}
      {data.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'ransomware.live' })}</SourceLink>}
    </>
  )
}

export default function RansomwareLiveCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, tn, locale } = useI18n()
  if (data?.kind === 'group') {
    return (
      <SourceCard title="ransomware.live" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={data.found === true}>
        <GroupView data={data} />
      </SourceCard>
    )
  }
  const listed = data?.listed === true
  const similar = data?.similar ?? []

  return (
    <SourceCard title="ransomware.live" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={listed}>
      {!listed && <Note>{t('rlive.notListed')}</Note>}
      {listed && (
        <>
          <Note tone="warn">{tn('rlive.listed', data?.match_count ?? 0)}</Note>
          <FieldGrid>
            <Field label={t('rlive.groups')} value={<Chips items={(data?.groups ?? []) as string[]} />} />
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
