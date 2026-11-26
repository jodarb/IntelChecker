import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Label { value: string; color?: string | null }
interface Marking { definition: string; color?: string | null }

interface OpenCTIIndicator {
  id: string
  name?: string
  pattern?: string
  score?: number | null
  valid_until?: string | null
  revoked?: boolean
  active?: boolean
  types?: string[]
  author?: string | null
  link?: string
}

interface OpenCTIResponse {
  found?: boolean
  kind?: 'observable' | 'indicator' | 'vulnerability' | 'actor'
  exact?: boolean
  entity?: {
    id: string; type?: string; value?: string; description?: string; score?: number | null
    created_at?: string; updated_at?: string; author?: string | null
    labels?: Label[]; markings?: Marking[]; link?: string
  } | null
  indicators?: OpenCTIIndicator[]
  indicators_active?: number
  relations?: { type: string; direction: 'in' | 'out'; entity_type?: string; name?: string; link?: string }[]
  relations_total?: number
  reports?: { name: string; published?: string; author?: string | null; link?: string }[]
  reports_total?: number
  vulnerability?: {
    cvss_score?: number | null; cvss_severity?: string | null; cvss_version?: string; cvss_vector?: string | null
    kev?: boolean | null; epss?: number | null; epss_percentile?: number | null; cwe?: string[]; ssvc_exploitation?: string | null
  }
  actor?: {
    aliases?: string[]; first_seen?: string | null; last_seen?: string | null; motivation?: string | null
    resource_level?: string | null; goals?: string[]; types?: string[]; sophistication?: string | null
  }
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: OpenCTIResponse | null
  label?: string
  score?: number | null
  weight?: CardWeight | null
}

function ColorChips({ items }: { items: { text: string; color?: string | null }[] }) {
  if (items.length === 0) return <>—</>
  return (
    <span className="flex flex-wrap gap-1">
      {items.map(i => (
        <span key={i.text} className="px-1.5 py-0.5 rounded border text-xs font-normal text-foreground"
          style={i.color ? { borderColor: i.color } : undefined}>
          {i.text}
        </span>
      ))}
    </span>
  )
}

function IndicatorRow({ ind }: { ind: OpenCTIIndicator }) {
  const { t, locale } = useI18n()
  const state = ind.revoked ? 'revoked' : ind.active ? 'active' : 'expired'
  const cls = state === 'active' ? 'text-red-400 border-red-500/40 bg-red-500/10' : 'text-muted-foreground border-border bg-muted/30'
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2 flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`px-1.5 py-0.5 rounded border text-xs font-semibold ${cls}`}>{t(`opencti.ind.${state}`)}</span>
        {typeof ind.score === 'number' && <span className="text-xs text-muted-foreground">{t('opencti.score', { n: ind.score })}</span>}
        {ind.valid_until && <span className="text-xs text-muted-foreground">{t('opencti.validUntil', { date: fmtDate(ind.valid_until, locale) ?? ind.valid_until })}</span>}
        {ind.author && <span className="text-xs text-muted-foreground">· {ind.author}</span>}
      </div>
      <code className="text-xs font-mono text-foreground break-all">{ind.pattern || ind.name}</code>
      {ind.link && <SourceLink href={ind.link}>{t('opencti.open')}</SourceLink>}
    </div>
  )
}

export default function OpenCTICard({ loading, error, data, label, score = null, weight = null }: Props) {
  const { t, tn, locale } = useI18n()
  const title = label ?? 'OpenCTI'
  const found = !!data?.found
  const e = data?.entity
  const indicators = data?.indicators ?? []
  const relations = data?.relations ?? []
  const reports = data?.reports ?? []
  const v = data?.vulnerability
  const a = data?.actor

  return (
    <SourceCard title={title} loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && <Note>{t('opencti.notFound', { source: title })}</Note>}
      {found && (
        <>
          {data?.kind === 'indicator' && <Note>{t('opencti.indicatorOnly')}</Note>}
          {data?.kind === 'actor' && data.exact === false && <Note tone="warn">{t('opencti.closestActor', { name: e?.value ?? '' })}</Note>}
          {(data?.indicators_active ?? 0) > 0 && <Note tone="warn">{tn('opencti.activeIndicators', data!.indicators_active!)}</Note>}
          {indicators.length > 0 && (data?.indicators_active ?? 0) === 0 && <Note>{t('opencti.noActive')}</Note>}
          {e?.description && <p className="text-sm text-foreground/90 leading-relaxed line-clamp-4">{e.description}</p>}
          <FieldGrid>
            {e && <Field label={t('f.name')} value={e.value} />}
            {e?.type && <Field label={t('pdns.type')} value={e.type} />}
            {e?.author && <Field label={t('opencti.author')} value={e.author} />}
            {e && <Field label={t('f.firstSeen')} value={fmtDate(e.created_at, locale)} />}
            {e && <Field label={t('f.lastModified')} value={fmtDate(e.updated_at, locale)} />}
            {v?.cvss_score != null && <Field label={t('f.cvss')} value={`${v.cvss_score.toFixed(1)}${v.cvss_severity ? ` ${v.cvss_severity}` : ''} · v${v.cvss_version}`} />}
            {v?.kev != null && <Field label={t('summaryField.kev')} value={v.kev ? t('common.yes') : t('common.no')} />}
            {v?.epss != null && <Field label={t('f.epss')} value={`${(v.epss * 100).toFixed(2)} %`} />}
            {a?.motivation && <Field label={t('opencti.motivation')} value={a.motivation} />}
            {a?.resource_level && <Field label={t('opencti.resources')} value={a.resource_level} />}
            {a?.first_seen && <Field label={t('f.firstSeen')} value={fmtDate(a.first_seen, locale)} />}
          </FieldGrid>
          {a && <Field label={t('f.synonyms')} value={<Chips items={a.aliases ?? []} max={20} />} />}
          {v && (v.cwe ?? []).length > 0 && <Field label={t('f.cwe')} value={<Chips items={v.cwe!} />} />}
          {e && (e.markings ?? []).length > 0 && <Field label={t('opencti.markings')} value={<ColorChips items={e.markings!.map(m => ({ text: m.definition, color: m.color }))} />} />}
          {e && (e.labels ?? []).length > 0 && <Field label={t('opencti.labels')} value={<ColorChips items={e.labels!.map(l => ({ text: l.value, color: l.color }))} />} />}
          {indicators.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('opencti.indicators', { n: indicators.length })}</span>
              {indicators.slice(0, 8).map(i => <IndicatorRow key={i.id} ind={i} />)}
            </div>
          )}
          {relations.length > 0 && (
            <Field label={t('opencti.relations', { n: data?.relations_total ?? relations.length })} value={
              <span className="flex flex-col gap-0.5 font-normal">
                {relations.slice(0, 15).map((r, i) => (
                  <span key={i} className="text-xs">
                    <span className="text-muted-foreground">{r.direction === 'out' ? `${r.type} →` : `← ${r.type}`}</span>{' '}
                    {r.link ? <a href={r.link} target="_blank" rel="noreferrer" className="text-primary hover:underline">{r.name || r.entity_type}</a> : r.name}
                    {r.entity_type && <span className="text-muted-foreground"> ({r.entity_type})</span>}
                  </span>
                ))}
              </span>
            } />
          )}
          {(data?.reports_total ?? 0) > 0 && (
            <Field label={t('opencti.reports', { n: data!.reports_total! })} value={
              <span className="flex flex-col gap-0.5 font-normal">
                {reports.slice(0, 5).map((r, i) => (
                  <a key={r.link ?? i} href={r.link} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline truncate">
                    {r.name}{r.published && <span className="text-muted-foreground"> · {fmtDate(r.published, locale)}</span>}
                  </a>
                ))}
              </span>
            } />
          )}
          {e?.link && <SourceLink href={e.link}>{t('card.viewOn', { source: title })}</SourceLink>}
        </>
      )}
    </SourceCard>
  )
}
