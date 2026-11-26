import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Breach {
  name: string
  title?: string
  domain?: string
  breach_date?: string
  added_date?: string | null
  pwn_count?: number | null
  data_classes?: string[]
  verified?: boolean
  sensitive?: boolean
  description?: string | null
  link?: string
}

interface HibpResponse {
  domains?: string[]
  count?: number
  breaches?: Breach[]
  flagged?: Breach[]
  latest_breach?: string | null
  accounts?: number
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: HibpResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function HibpCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, tn, locale } = useI18n()
  const count = data?.count ?? 0

  return (
    <SourceCard title="Have I Been Pwned" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={count > 0}>
      {count === 0 && <Note>{t('hibp.none', { domains: (data?.domains ?? []).join(', ') })}</Note>}
      {count > 0 && (
        <>
          <Note tone="warn">
            {tn('hibp.breaches', count)} · {t('hibp.accounts', { n: (data?.accounts ?? 0).toLocaleString(locale) })}
          </Note>
          <div className="flex flex-col gap-2">
            {(data?.breaches ?? []).slice(0, 8).map(b => (
              <div key={b.name} className="rounded-md border border-border bg-muted/20 px-3 py-2 flex flex-col gap-1">
                <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
                  <span className="font-medium text-foreground">{b.title ?? b.name}</span>
                  <span className="text-xs text-muted-foreground">
                    {[fmtDate(b.breach_date, locale), b.pwn_count != null ? t('hibp.accounts', { n: b.pwn_count.toLocaleString(locale) }) : null,
                      b.verified ? t('hibp.verified') : t('hibp.unverified')].filter(Boolean).join(' · ')}
                  </span>
                </div>
                {b.description && <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">{b.description}</p>}
                <Chips items={b.data_classes ?? []} max={8} />
              </div>
            ))}
          </div>
        </>
      )}
      {(data?.flagged ?? []).length > 0 && (
        <Field label={t('hibp.flagged')} value={<Chips items={(data?.flagged ?? []).map(b => b.title ?? b.name)} />} />
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'Have I Been Pwned' })}</SourceLink>}
    </SourceCard>
  )
}
