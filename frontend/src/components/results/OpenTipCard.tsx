import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, Chips, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

// OpenTIP's answer is rendered generically: the verdict is `Zone`, and every other
// block (IpGeneralInfo, DomainGeneralInfo, UrlGeneralInfo, FileGeneralInfo, WHOIS,
// detections…) is shown as it comes, so a field Kaspersky adds or renames still shows.

type Json = string | number | boolean | null | Json[] | { [k: string]: Json }

interface Props {
  loading: boolean
  error: string | null
  data: ({ Zone?: string; applicable?: boolean; link?: string; error?: { code: string; message: string } } & Record<string, unknown>) | null
  score?: number | null
  weight?: CardWeight | null
}

const ZONES = ['Red', 'Orange', 'Yellow', 'Green', 'Grey'] as const
type Zone = typeof ZONES[number]
const isZone = (z: unknown): z is Zone => typeof z === 'string' && (ZONES as readonly string[]).includes(z)

const ZONE_CLASS: Record<Zone, string> = {
  Red: 'text-red-400 border-red-500/40 bg-red-500/10',
  Orange: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  Yellow: 'text-amber-400 border-amber-500/40 bg-amber-500/10',
  Green: 'text-green-400 border-green-500/40 bg-green-500/10',
  Grey: 'text-muted-foreground border-border bg-muted/30',
}

const SKIP = new Set(['Zone', 'applicable', 'link', 'error'])
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$/

/** "IpGeneralInfo" → "Ip general info", "HitsCount" → "Hits count" */
const humanize = (k: string) =>
  k.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
    .replace(/(?<= )([A-Z])(?=[a-z])/g, c => c.toLowerCase())

function scalar(v: Json, locale: string): string {
  if (typeof v === 'string') return ISO_DATE.test(v) ? fmtDate(v, locale) ?? v : v
  if (typeof v === 'boolean') return v ? '✓' : '✗'
  return v == null ? '—' : String(v)
}

/** One object (a category with its zone, a detection, an ASN…) as a single line. */
function line(o: Json, locale: string): string {
  if (o && typeof o === 'object' && !Array.isArray(o)) {
    return Object.entries(o)
      .filter(([, v]) => v != null && v !== '' && typeof v !== 'object')
      .map(([k, v]) => `${humanize(k)}: ${scalar(v, locale)}`).join(' · ')
  }
  return scalar(o, locale)
}

function Block({ name, value }: { name: string; value: Json }) {
  const { locale } = useI18n()
  if (Array.isArray(value)) {
    if (value.length === 0) return null
    return (
      <Field label={humanize(name)} value={
        value.every(v => typeof v !== 'object' || v === null)
          ? <Chips items={value.map(v => scalar(v, locale))} max={20} />
          : <span className="flex flex-col gap-0.5 font-normal">{value.slice(0, 10).map((v, i) => <span key={i} className="text-xs">{line(v, locale)}</span>)}</span>
      } />
    )
  }
  if (!value || typeof value !== 'object') return <Field label={humanize(name)} value={scalar(value, locale)} />
  const entries = Object.entries(value).filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && v.length === 0))
  if (entries.length === 0) return null
  const flat = entries.filter(([, v]) => typeof v !== 'object')
  const nested = entries.filter(([, v]) => typeof v === 'object')
  return (
    <div className="flex flex-col gap-2">
      <span className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{humanize(name)}</span>
      {flat.length > 0 && (
        <FieldGrid>{flat.map(([k, v]) => <Field key={k} label={humanize(k)} value={scalar(v as Json, locale)} />)}</FieldGrid>
      )}
      {nested.map(([k, v]) => <Block key={k} name={k} value={v as Json} />)}
    </div>
  )
}

export default function OpenTipCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t } = useI18n()
  const zone = data?.Zone
  const blocks = Object.entries(data ?? {}).filter(([k]) => !SKIP.has(k)) as [string, Json][]

  return (
    <SourceCard title="Kaspersky OpenTIP" loading={loading} error={error} data={data} score={score} weight={weight}
      hasResult={isZone(zone) && zone !== 'Grey'}>
      {data?.applicable === false && <Note>{t('opentip.notApplicable')}</Note>}
      {isZone(zone) && (
        <div className="flex flex-wrap items-center gap-2">
          <span className={`px-2 py-0.5 rounded-full border text-xs font-semibold ${ZONE_CLASS[zone]}`}>{t(`opentip.zone.${zone}`)}</span>
          <span className="text-sm text-muted-foreground">{t(`opentip.zoneHint.${zone}`)}</span>
        </div>
      )}
      {blocks.map(([k, v]) => <Block key={k} name={k} value={v} />)}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'OpenTIP' })}</SourceLink>}
    </SourceCard>
  )
}
