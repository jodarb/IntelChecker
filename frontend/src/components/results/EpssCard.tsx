import { useState } from 'react'
import type { CardWeight } from './WeightBadge'
import { SourceCard, Field, FieldGrid, Note, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface EpssPoint { date: string; epss: number; percentile: number | null }

interface EpssResponse {
  found?: boolean
  cve?: string
  epss?: number
  percentile?: number | null
  date?: string
  change_30d?: number | null
  series?: EpssPoint[]
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: EpssResponse | null
  score?: number | null
  weight?: CardWeight | null
}

const pct = (v: number, locale: string, digits = 2) =>
  (v * 100).toLocaleString(locale, { minimumFractionDigits: digits, maximumFractionDigits: digits }) + ' %'

// 30-day probability trend: one 2px line, hover shows the day's value.
function Sparkline({ points, locale }: { points: EpssPoint[]; locale: string }) {
  const [hover, setHover] = useState<number | null>(null)
  const W = 300, H = 56, PAD = 4
  const max = Math.max(...points.map(p => p.epss))
  const min = Math.min(...points.map(p => p.epss))
  const span = max - min || max || 1
  const x = (i: number) => PAD + (i * (W - 2 * PAD)) / Math.max(1, points.length - 1)
  const y = (v: number) => H - PAD - ((v - (max === min ? 0 : min)) / span) * (H - 2 * PAD)
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p.epss).toFixed(1)}`).join(' ')
  const h = hover != null ? points[hover] : null

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const rel = ((e.clientX - rect.left) / rect.width) * W
    const i = Math.round(((rel - PAD) / (W - 2 * PAD)) * (points.length - 1))
    setHover(Math.max(0, Math.min(points.length - 1, i)))
  }

  return (
    <div className="flex flex-col gap-1">
      <div className="flex justify-between text-xs text-muted-foreground h-4">
        {h ? <span className="text-foreground">{fmtDate(h.date, locale)} · {pct(h.epss, locale)}</span>
          : <span>{fmtDate(points[0].date, locale)}</span>}
        {!h && <span>{fmtDate(points[points.length - 1].date, locale)}</span>}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-14 text-primary" preserveAspectRatio="none"
        onMouseMove={onMove} onMouseLeave={() => setHover(null)} role="img">
        <line x1={PAD} x2={W - PAD} y1={H - PAD} y2={H - PAD} className="stroke-border" strokeWidth={1} vectorEffect="non-scaling-stroke" />
        <path d={path} fill="none" stroke="currentColor" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        {h && hover != null && (
          <>
            <line x1={x(hover)} x2={x(hover)} y1={PAD} y2={H - PAD} className="stroke-muted-foreground/50" strokeWidth={1} vectorEffect="non-scaling-stroke" />
            <circle cx={x(hover)} cy={y(h.epss)} r={4} fill="currentColor" className="stroke-background" strokeWidth={2} vectorEffect="non-scaling-stroke" />
          </>
        )}
      </svg>
    </div>
  )
}

export default function EpssCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, locale } = useI18n()
  const found = !!data?.found && typeof data?.epss === 'number'
  const series = data?.series ?? []
  const change = data?.change_30d

  return (
    <SourceCard title="EPSS · FIRST" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={found}>
      {!found && <Note>{t('epss.notFound')}</Note>}
      {found && (
        <>
          <FieldGrid>
            <Field label={t('f.epss')} value={pct(data!.epss!, locale)} />
            <Field label={t('f.percentile')} value={data?.percentile != null ? t('epss.percentile', { p: pct(data.percentile, locale, 1) }) : undefined} />
            <Field label={t('f.change30d')} value={change != null ? (
              <span className={change > 0.001 ? 'text-red-400' : change < -0.001 ? 'text-green-400' : ''}>
                {(change > 0 ? '+' : '') + pct(change, locale)}
              </span>
            ) : undefined} />
            <Field label={t('f.scoreDate')} value={fmtDate(data?.date, locale)} />
          </FieldGrid>
          {series.length > 1 && <Sparkline points={series} locale={locale} />}
          <Note>{t('epss.meaning')}</Note>
        </>
      )}
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'FIRST' })}</SourceLink>}
    </SourceCard>
  )
}
