import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'

interface HashlookupParent { FileName?: string; PackageName?: string; 'snap-name'?: string; 'SHA-1'?: string }

interface HashlookupResponse {
  found?: boolean
  algorithm?: string
  hash?: string
  FileName?: string
  FileSize?: string
  MD5?: string
  'SHA-1'?: string
  'SHA-256'?: string
  mimetype?: string
  source?: string
  db?: string
  KnownMalicious?: string
  ProductCode?: { ProductName?: string; ProductVersion?: string; ApplicationType?: string }
  'hashlookup:trust'?: number
  'hashlookup:parent-total'?: number
  parents?: HashlookupParent[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: HashlookupResponse | null
  score?: number | null
  weight?: CardWeight | null
  indicator?: string
}

/** Package or file a parent record stands for, without the mirror URL around it. */
function parentName(p: HashlookupParent): string | null {
  const raw = p.PackageName || p['snap-name'] || p.FileName
  if (!raw) return null
  return raw.split('/').filter(Boolean).pop() ?? raw
}

export default function HashlookupCard({ loading, error, data, score = null, weight = null, indicator }: Props) {
  const { t } = useI18n()
  const found = !!data?.found
  const product = data?.ProductCode?.ProductName
    ? [data.ProductCode.ProductName, data.ProductCode.ProductVersion].filter(Boolean).join(' ')
    : undefined
  const parents = [...new Set((data?.parents ?? []).map(parentName).filter((x): x is string => !!x))]
  const size = data?.FileSize ? Number(data.FileSize) : NaN
  const hash = indicator?.trim()

  return (
    <SourceCard title="CIRCL hashlookup" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={found}>
      {!found && <Note>{t('hashlookup.unknown')}</Note>}
      {found && (
        <>
          {data?.KnownMalicious
            ? <Note tone="warn">{t('hashlookup.knownMalicious', { source: data.KnownMalicious })}</Note>
            : <Note tone="good">{t('hashlookup.known')}</Note>}
          <FieldGrid>
            <Field label={t('f.fileName')} value={data?.FileName} />
            <Field label={t('f.fileSize')} value={Number.isFinite(size) ? `${size.toLocaleString()} B` : data?.FileSize} />
            <Field label={t('f.fileType')} value={data?.mimetype} />
            <Field label={t('f.product')} value={product} />
            <Field label={t('f.source')} value={[data?.source, data?.db].filter(Boolean).join(' · ') || undefined} />
            <Field label={t('f.trust')} value={data?.['hashlookup:trust'] != null ? `${data['hashlookup:trust']}/100` : undefined} />
          </FieldGrid>
          {parents.length > 0 && (
            <Field
              label={t('hashlookup.parents', { n: data?.['hashlookup:parent-total'] ?? parents.length })}
              value={<Chips items={parents} max={10} />}
            />
          )}
        </>
      )}
      {found && hash && data?.algorithm && (
        <SourceLink href={`https://hashlookup.circl.lu/lookup/${data.algorithm}/${hash}`}>{t('card.viewOn', { source: 'hashlookup' })}</SourceLink>
      )}
    </SourceCard>
  )
}
