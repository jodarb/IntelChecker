import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface YaraRule { rule_name: string; author?: string | null; description?: string | null }

interface YaraifyResponse {
  found?: boolean
  metadata?: {
    file_size?: number
    file_type_mime?: string
    first_seen?: string | null
    last_seen?: string | null
    sightings?: number
    sha256_hash?: string
  }
  rules?: YaraRule[]
  clamav?: string[]
  file_names?: string[]
  tasks_total?: number
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: YaraifyResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function YaraifyCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = !!data?.found
  const m = data?.metadata
  const rules = data?.rules ?? []
  const date = (v?: string | null) => fmtDate(v?.replace(' UTC', 'Z').replace(' ', 'T'), locale)

  return (
    <SourceCard title="YARAify · abuse.ch" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={found}>
      {!found && <Note>{t('yaraify.notFound')}</Note>}
      {found && (
        <>
          <FieldGrid>
            <Field label={t('f.fileType')} value={m?.file_type_mime} />
            <Field label={t('f.fileSize')} value={m?.file_size != null ? `${m.file_size.toLocaleString(locale)} B` : undefined} />
            <Field label={t('f.sightings')} value={m?.sightings} />
            <Field label={t('f.firstSeen')} value={date(m?.first_seen)} />
            <Field label={t('f.lastSeen')} value={date(m?.last_seen)} />
          </FieldGrid>
          <Field label={t('f.clamav')} value={<Chips items={data?.clamav ?? []} />} />
          <Field label={t('yaraify.rules', { n: rules.length })} value={
            rules.length === 0 ? '—' : (
              <span className="flex flex-col gap-1 font-normal">
                {rules.slice(0, 15).map(r => (
                  <span key={r.rule_name} className="text-xs">
                    <span className="font-mono text-foreground">{r.rule_name}</span>
                    {r.author && <span className="text-muted-foreground"> · {r.author}</span>}
                    {r.description && <span className="block text-muted-foreground">{r.description}</span>}
                  </span>
                ))}
                {rules.length > 15 && <span className="text-xs text-muted-foreground">{t('common.more', { n: rules.length - 15 })}</span>}
              </span>
            )
          } />
          {rules.length > 0 && <Note>{t('yaraify.rulesCaveat')}</Note>}
          <Field label={t('f.fileName')} value={<Chips items={data?.file_names ?? []} max={6} />} />
        </>
      )}
      {found && m?.sha256_hash && (
        <SourceLink href={`https://yaraify.abuse.ch/sample/${m.sha256_hash}/`}>{t('card.viewOn', { source: 'YARAify' })}</SourceLink>
      )}
    </SourceCard>
  )
}
