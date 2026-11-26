import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Cvss { version: string; score: number; severity?: string | null; vector?: string | null; source?: string | null; type?: string | null }

interface NvdResponse {
  found?: boolean
  id?: string
  status?: string
  rejected?: boolean
  published?: string
  last_modified?: string
  description?: string
  cvss?: Cvss | null
  cvss_all?: Cvss[]
  cwes?: string[]
  ssvc?: { exploitation?: string | null; automatable?: string | null; technical_impact?: string | null } | null
  kev?: { date_added?: string | null; due_date?: string | null; name?: string | null } | null
  products?: string[]
  products_total?: number
  references?: { url: string; tags: string[] }[]
  references_total?: number
  exploit_refs?: number
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: NvdResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as const
type Severity = typeof SEVERITIES[number]
const SSVC_EXPLOITATION = ['none', 'poc', 'active'] as const
type Exploitation = typeof SSVC_EXPLOITATION[number]
const isSeverity = (v: string): v is Severity => (SEVERITIES as readonly string[]).includes(v)
const isExploitation = (v: string): v is Exploitation => (SSVC_EXPLOITATION as readonly string[]).includes(v)

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500/40 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  MEDIUM: 'text-amber-400 border-amber-500/40 bg-amber-500/10',
  LOW: 'text-sky-400 border-sky-500/40 bg-sky-500/10',
}

export default function NvdCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = !!data?.found
  const cvss = data?.cvss
  const sev = cvss?.severity?.toUpperCase() ?? ''

  return (
    <SourceCard title="NVD (NIST)" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && <Note>{t('nvd.notFound', { id: data?.id ?? '' })}</Note>}
      {found && (
        <>
          {data?.rejected && <Note tone="warn">{t('nvd.rejected')}</Note>}
          {!data?.rejected && !cvss && <Note>{t('nvd.noCvss', { status: data?.status ?? '—' })}</Note>}
          {data?.kev?.date_added && (
            <Note tone="warn">{t('nvd.inKev', { date: fmtDate(data.kev.date_added, locale) ?? data.kev.date_added })}</Note>
          )}
          {data?.description && <p className="text-sm text-foreground/90 leading-relaxed">{data.description}</p>}
          <FieldGrid>
            <Field label={t('f.cvss')} value={cvss ? (
              <span className="inline-flex items-center gap-2">
                <span>{cvss.score.toFixed(1)}</span>
                {sev && (
                  <span className={`px-1.5 py-0.5 rounded border text-xs font-semibold ${SEVERITY_CLASS[sev] ?? 'text-muted-foreground border-border'}`}>
                    {isSeverity(sev) ? t(`nvd.sev.${sev}`) : sev}
                  </span>
                )}
                <span className="text-xs text-muted-foreground font-normal">v{cvss.version}</span>
              </span>
            ) : undefined} />
            <Field label={t('f.status')} value={data?.status} />
            <Field label={t('f.published')} value={fmtDate(data?.published, locale)} />
            <Field label={t('f.lastModified')} value={fmtDate(data?.last_modified, locale)} />
            {data?.ssvc?.exploitation && <Field label={t('f.ssvcExploitation')} value={isExploitation(data.ssvc.exploitation) ? t(`nvd.ssvc.${data.ssvc.exploitation}`) : data.ssvc.exploitation} />}
            {data?.ssvc?.automatable && <Field label={t('f.ssvcAutomatable')} value={data.ssvc.automatable === 'yes' ? t('common.yes') : t('common.no')} />}
          </FieldGrid>
          {cvss?.vector && <Field label={t('f.vector')} value={<code className="text-xs font-mono font-normal">{cvss.vector}</code>} />}
          <Field label={t('f.cwe')} value={<Chips items={data?.cwes ?? []} />} />
          <Field label={t('nvd.products', { n: data?.products_total ?? 0 })} value={<Chips items={data?.products ?? []} max={10} />} />
          {(data?.references_total ?? 0) > 0 && (
            <Field label={t('nvd.refs', { n: data!.references_total!, exploits: data?.exploit_refs ?? 0 })} value={
              <span className="flex flex-col gap-0.5 font-normal">
                {(data?.references ?? []).slice(0, 6).map(r => (
                  <a key={r.url} href={r.url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline truncate">
                    {r.tags.includes('Exploit') && <span className="text-red-400 mr-1">[{t('nvd.exploitTag')}]</span>}
                    {r.url}
                  </a>
                ))}
              </span>
            } />
          )}
        </>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'NVD' })}</SourceLink>}
    </SourceCard>
  )
}
