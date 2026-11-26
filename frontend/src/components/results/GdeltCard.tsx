import { ExternalLink } from 'lucide-react'
import type { CardWeight } from './WeightBadge'
import { SourceCard, Note, SourceLink } from './SourceCard'
import { useI18n } from '@/i18n/useI18n'
import { fmtDate } from '@/lib/format'

interface Article {
  title: string
  url: string
  source?: string | null
  language?: string | null
  source_country?: string | null
  seen?: string | null
  in_title?: boolean
}

interface GdeltResponse {
  query?: string
  count?: number
  in_title?: number
  latest?: string | null
  articles?: Article[]
  link?: string
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: GdeltResponse | null
  score?: number | null
  weight?: CardWeight | null
}

function ArticleRow({ a, locale }: { a: Article; locale: string }) {
  return (
    <li className="flex flex-col gap-0.5">
      <a href={a.url} target="_blank" rel="noreferrer noopener" className="text-sm text-foreground hover:underline inline-flex items-start gap-1">
        <ExternalLink className="h-3 w-3 mt-1 shrink-0 text-muted-foreground" />
        <span>{a.title || a.url}</span>
      </a>
      <span className="text-xs text-muted-foreground pl-4">
        {[fmtDate(a.seen, locale), a.source, a.language].filter(Boolean).join(' · ')}
      </span>
    </li>
  )
}

export default function GdeltCard({ loading, error, data, score = null, weight = null }: Props) {
  const { t, tn, locale } = useI18n()
  const articles = data?.articles ?? []
  const inTitle = articles.filter(a => a.in_title)
  const rest = articles.filter(a => !a.in_title)

  return (
    <SourceCard title="GDELT (news)" loading={loading} error={error} data={data} score={score} weight={weight} hasResult={(data?.in_title ?? 0) > 0}>
      {articles.length === 0 && <Note>{t('gdelt.none', { q: data?.query ?? '' })}</Note>}
      {inTitle.length > 0 && (
        <>
          <Note tone="warn">{tn('gdelt.inTitle', inTitle.length)}</Note>
          <ul className="flex flex-col gap-2">{inTitle.slice(0, 10).map(a => <ArticleRow key={a.url} a={a} locale={locale} />)}</ul>
        </>
      )}
      {rest.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-xs text-muted-foreground">{tn('gdelt.mentions', rest.length)}</summary>
          <ul className="flex flex-col gap-2 mt-2">{rest.slice(0, 15).map(a => <ArticleRow key={a.url} a={a} locale={locale} />)}</ul>
        </details>
      )}
      <p className="text-xs text-muted-foreground">{t('gdelt.note')}</p>
      {data?.link && <SourceLink href={data.link}>{t('card.viewOn', { source: 'GDELT' })}</SourceLink>}
    </SourceCard>
  )
}
