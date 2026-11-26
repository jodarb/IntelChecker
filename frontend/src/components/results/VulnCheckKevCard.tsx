import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface VulnCheckKevResponse {
  cve?: string
  listed?: boolean
  vendor?: string
  product?: string
  name?: string
  description?: string
  required_action?: string
  ransomware?: string
  cwes?: string[]
  date_added?: string | null
  cisa_date_added?: string | null
  due_date?: string | null
  canaries?: boolean
  exploits_total?: number
  exploits?: { id?: string; url?: string; type?: string; date?: string | null }[]
  reports_total?: number
  reports?: { url: string; date?: string | null }[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: VulnCheckKevResponse | null
  score?: number | null
  weight?: CardWeight | null
}

export default function VulnCheckKevCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const listed = data?.listed === true
  const exploits = data?.exploits ?? []
  const reports = data?.reports ?? []

  return (
    <SourceCard title="VulnCheck KEV" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={listed}>
      {!listed && <Note>{t('vckev.notListed')}</Note>}
      {listed && (
        <>
          <Note tone="warn">{t('vckev.listed')}</Note>
          {data?.ransomware === 'Known' && <Note tone="warn">{t('kev.ransomware')}</Note>}
          {data?.canaries && <Note tone="warn">{t('vckev.canaries')}</Note>}
          {!data?.cisa_date_added && <Note>{t('vckev.notInCisa')}</Note>}
          {data?.name && <p className="text-sm font-medium text-foreground">{data.name}</p>}
          {data?.description && <p className="text-sm text-foreground/90 leading-relaxed">{data.description}</p>}
          <FieldGrid>
            <Field label={t('f.vendor')} value={data?.vendor} />
            <Field label={t('f.product')} value={data?.product} />
            <Field label={t('vckev.dateAdded')} value={fmtDate(data?.date_added, locale)} />
            <Field label={t('vckev.cisaDateAdded')} value={fmtDate(data?.cisa_date_added, locale) ?? t('common.no')} />
            <Field label={t('f.publicExploits')} value={(data?.exploits_total ?? 0).toLocaleString(locale)} />
            <Field label={t('f.ransomware')} value={data?.ransomware === 'Known' ? t('kev.ransomKnown') : t('kev.ransomUnknown')} />
          </FieldGrid>
          <Field label={t('f.cwe')} value={<Chips items={data?.cwes ?? []} />} />
          {reports.length > 0 && (
            <Field label={t('vckev.reports', { n: data?.reports_total ?? reports.length })} value={
              <span className="flex flex-col gap-0.5 font-normal">
                {reports.slice(0, 6).map(r => (
                  <a key={r.url} href={r.url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline truncate">
                    {r.date && <span className="text-muted-foreground mr-1">{fmtDate(r.date, locale)}</span>}{r.url}
                  </a>
                ))}
              </span>
            } />
          )}
          {exploits.length > 0 && (
            <Field label={t('vckev.exploits', { n: data?.exploits_total ?? exploits.length })} value={
              <span className="flex flex-col gap-0.5 font-normal">
                {exploits.slice(0, 6).map((e, i) => (
                  <a key={e.id ?? i} href={e.url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline truncate">
                    <span className="text-muted-foreground mr-1">[{e.type ?? 'exploit'}{e.date ? ` · ${fmtDate(e.date, locale)}` : ''}]</span>{e.id}
                  </a>
                ))}
              </span>
            } />
          )}
          {data?.required_action && <Field label={t('f.requiredAction')} value={<span className="font-normal">{data.required_action}</span>} />}
        </>
      )}
    </SourceCard>
  )
}
