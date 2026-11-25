import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface PdnsRecord {
  rrname?: string
  rrtype?: string
  rdata?: string | string[]
  count?: number
  time_first?: number
  time_last?: number
}

interface PdnsResponse {
  found?: boolean
  query?: string
  total?: number
  distinct_rdata?: number
  rrtypes?: Record<string, number>
  first_seen?: number | null
  last_seen?: number | null
  records?: PdnsRecord[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: PdnsResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const unix = (v: number | null | undefined, locale: string) =>
  typeof v === 'number' ? fmtDate(new Date(v * 1000).toISOString(), locale) : undefined

export default function CirclPdnsCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = !!data?.found
  const records = data?.records ?? []

  return (
    <SourceCard title="CIRCL Passive DNS" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={found}>
      {!found && <Note>{t('pdns.none')}</Note>}
      {found && (
        <>
          <FieldGrid>
            <Field label={t('f.records')} value={data?.total} />
            <Field label={t('f.distinctAnswers')} value={data?.distinct_rdata} />
            <Field label={t('f.firstSeen')} value={unix(data?.first_seen, locale)} />
            <Field label={t('f.lastSeen')} value={unix(data?.last_seen, locale)} />
          </FieldGrid>
          <Field label={t('f.recordTypes')} value={
            <Chips items={Object.entries(data?.rrtypes ?? {}).map(([k, n]) => `${k} × ${n}`)} />
          } />
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-muted-foreground">
                <tr className="text-left">
                  <th className="py-1 pr-3 font-medium">{t('pdns.type')}</th>
                  <th className="py-1 pr-3 font-medium">{t('pdns.name')}</th>
                  <th className="py-1 pr-3 font-medium">{t('pdns.answer')}</th>
                  <th className="py-1 pr-3 font-medium">{t('f.firstSeen')}</th>
                  <th className="py-1 font-medium">{t('f.lastSeen')}</th>
                </tr>
              </thead>
              <tbody>
                {records.slice(0, 25).map((r, i) => (
                  <tr key={i} className="border-t border-border align-top">
                    <td className="py-1 pr-3 font-mono">{r.rrtype}</td>
                    <td className="py-1 pr-3 font-mono break-all">{r.rrname}</td>
                    <td className="py-1 pr-3 font-mono break-all">{Array.isArray(r.rdata) ? r.rdata.join(', ') : r.rdata}</td>
                    <td className="py-1 pr-3 whitespace-nowrap">{unix(r.time_first, locale)}</td>
                    <td className="py-1 whitespace-nowrap">{unix(r.time_last, locale)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {records.length > 25 && <p className="text-xs text-muted-foreground mt-1">{t('common.more', { n: (data?.total ?? records.length) - 25 })}</p>}
          </div>
        </>
      )}
    </SourceCard>
  )
}
