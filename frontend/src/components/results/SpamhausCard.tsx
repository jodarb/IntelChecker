import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import type { MessageKey } from '@/i18n/types'
import { messages } from '@/i18n/messages'
import { fmtDate } from '@/lib/format'
import { SPAMHAUS_SCORES } from '@/verdictEngine'

interface Listing { code: string; list: string; category: string; query: string; zone: string }

interface SpamhausResponse {
  indicator?: string
  checks?: { zone: string; query: string; codes: string[] }[]
  listings?: Listing[]
  listed?: boolean
  dqs?: boolean
  asn_record?: { asn?: number; asname?: string; cc?: string; domain?: string; rir?: string } | null
  list_size?: number
  list_updated?: string | null
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: SpamhausResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const ZONE_NAMES: Record<string, string> = { zen: 'ZEN', dbl: 'DBL', asndrop: 'ASN-DROP' }

export default function SpamhausCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const listings = data?.listings ?? []
  const zones = [...new Set((data?.checks ?? []).map(c => ZONE_NAMES[c.zone] ?? c.zone))]
  const category = (c: string) => {
    const key = `spamhaus.cat.${c}` as MessageKey
    return key in messages.en ? t(key) : c
  }

  return (
    <SourceCard title="Spamhaus" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={listings.length > 0}>
      {listings.length === 0 && <Note>{t('spamhaus.notListed', { zones: zones.join(', ') || '—' })}</Note>}
      {listings.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {listings.map((l, i) => {
            const scored = Object.prototype.hasOwnProperty.call(SPAMHAUS_SCORES, l.code)
            return (
              <div key={`${l.code}-${l.query}-${i}`} className="flex flex-wrap items-center gap-2 text-sm">
                <span className={`px-2 py-0.5 rounded-full border text-xs font-semibold ${scored
                  ? 'text-red-400 bg-red-500/10 border-red-500/30'
                  : 'text-muted-foreground bg-muted/40 border-border'}`}>
                  {l.list}
                </span>
                <span className="text-foreground">{category(l.category)}</span>
                <span className="text-xs text-muted-foreground font-mono">{l.query} · {l.code}</span>
              </div>
            )
          })}
          {listings.every(l => !Object.prototype.hasOwnProperty.call(SPAMHAUS_SCORES, l.code)) && (
            <Note>{t('spamhaus.policyOnly')}</Note>
          )}
        </div>
      )}
      <FieldGrid>
        <Field label={t('f.zones')} value={zones.join(', ') || undefined} />
        <Field label="DQS" value={data?.dqs ? t('common.yes') : t('common.no')} />
        {data?.asn_record && (
          <>
            <Field label={t('f.asOwner')} value={data.asn_record.asname} />
            <Field label={t('f.country')} value={data.asn_record.cc} />
            <Field label={t('f.domain')} value={data.asn_record.domain} />
          </>
        )}
        {data?.list_updated && <Field label={t('f.listUpdated')} value={fmtDate(data.list_updated, locale)} />}
      </FieldGrid>
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'Spamhaus' })}</SourceLink>}
    </SourceCard>
  )
}
