import { ShieldX, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Labelled { name?: string; label?: string }

interface CrowdSecResponse {
  found?: boolean
  ip?: string
  reputation?: string
  confidence?: string
  background_noise?: string
  as_name?: string
  as_num?: number
  reverse_dns?: string | null
  location?: { country?: string | null; city?: string | null }
  history?: { first_seen?: string; last_seen?: string }
  behaviors?: Labelled[]
  classifications?: { false_positives?: Labelled[]; classifications?: Labelled[] }
  mitre_techniques?: Labelled[]
  cves?: string[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: CrowdSecResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const REPUTATIONS = ['malicious', 'suspicious', 'known', 'safe', 'benign', 'unknown'] as const
type Reputation = typeof REPUTATIONS[number]

const STYLE: Record<Reputation, { cls: string; Icon: typeof ShieldX }> = {
  malicious: { cls: 'text-red-400 bg-red-500/10 border-red-500/30', Icon: ShieldX },
  suspicious: { cls: 'text-orange-400 bg-orange-500/10 border-orange-500/30', Icon: ShieldAlert },
  known: { cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30', Icon: ShieldQuestion },
  safe: { cls: 'text-green-400 bg-green-500/10 border-green-500/30', Icon: ShieldCheck },
  benign: { cls: 'text-green-400 bg-green-500/10 border-green-500/30', Icon: ShieldCheck },
  unknown: { cls: 'text-muted-foreground bg-muted/40 border-border', Icon: ShieldQuestion },
}

const labels = (xs: Labelled[] | undefined) => (xs ?? []).map(x => x.label || x.name || '').filter(Boolean)

function ReputationBadge({ reputation }: { reputation: string }) {
  const { t } = useI18n()
  const known = (REPUTATIONS as readonly string[]).includes(reputation)
  const { cls, Icon } = STYLE[(known ? reputation : 'unknown') as Reputation]
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border text-xs font-semibold ${cls}`}>
      <Icon className="h-3 w-3" />
      {known ? t(`crowdsec.rep.${reputation as Reputation}`) : reputation}
    </span>
  )
}

export default function CrowdSecCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = !!data?.found
  const falsePositives = labels(data?.classifications?.false_positives)
  const asn = data?.as_num != null ? `AS${data.as_num}${data.as_name ? ` · ${data.as_name}` : ''}` : data?.as_name

  return (
    <SourceCard title="CrowdSec CTI" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={found}>
      {!found && <Note>{t('crowdsec.notReported')}</Note>}
      {found && (
        <>
          {falsePositives.length > 0 && <Note tone="good">{t('crowdsec.falsePositive', { list: falsePositives.join(', ') })}</Note>}
          <FieldGrid>
            <Field label={t('f.reputation')} value={data?.reputation ? <ReputationBadge reputation={data.reputation} /> : undefined} />
            <Field label={t('f.confidence')} value={data?.confidence} />
            <Field label={t('f.backgroundNoise')} value={data?.background_noise} />
            <Field label={t('f.asn')} value={asn} />
            <Field label={t('f.country')} value={[data?.location?.city, data?.location?.country].filter(Boolean).join(', ') || undefined} />
            <Field label={t('f.hostname')} value={data?.reverse_dns || undefined} />
            <Field label={t('f.firstSeen')} value={fmtDate(data?.history?.first_seen, locale)} />
            <Field label={t('f.lastSeen')} value={fmtDate(data?.history?.last_seen, locale)} />
          </FieldGrid>
          <Field label={t('f.behaviors')} value={<Chips items={labels(data?.behaviors)} />} />
          <Field label={t('f.classification')} value={<Chips items={labels(data?.classifications?.classifications)} />} />
          {labels(data?.mitre_techniques).length > 0 && (
            <Field label={t('f.techniques')} value={<Chips items={(data?.mitre_techniques ?? []).map(m => [m.name, m.label].filter(Boolean).join(' '))} />} />
          )}
          {(data?.cves?.length ?? 0) > 0 && <Field label={t('f.vulns')} value={<Chips items={data!.cves!} />} />}
        </>
      )}
      {data?.ip && (
        <SourceLink href={`https://app.crowdsec.net/cti/${data.ip}`}>{t('card.viewOn', { source: 'CrowdSec' })}</SourceLink>
      )}
    </SourceCard>
  )
}
