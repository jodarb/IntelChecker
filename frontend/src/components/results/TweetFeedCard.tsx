import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2, ExternalLink, AlertTriangle } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'

interface TweetFeedRecord {
  type: string
  value: string
  first_seen?: string
  last_seen?: string
  count?: number
  users?: string[]
  tags?: string[]
  tweets?: string[]
  related?: [string, string][]
}

interface TweetFeedCampaign {
  id: string
  name: string
  confidence?: string
  threat_types?: string[]
  ioc_count?: number
  last_seen?: string
}

export interface TweetFeedResponse {
  found?: boolean
  query?: string
  records?: TweetFeedRecord[]
  campaigns?: TweetFeedCampaign[]
  ai?: { summary?: string; family?: string; threat_type?: string; confidence?: number }
  net?: { city?: string; country?: string; org?: string }
  reg?: { apex?: string; asn?: string; org?: string; registrar?: string | null; created?: string | null; status?: string }
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: TweetFeedResponse | null
  score?: number | null
  weight?: CardWeight | null
  indicator?: string
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

function Chips({ items, mono = false }: { items: string[]; mono?: boolean }) {
  return (
    <div className="flex flex-wrap gap-1">
      {items.map(t => (
        <span
          key={t}
          className={`px-1.5 py-0.5 rounded text-xs border bg-muted border-border text-muted-foreground ${mono ? 'font-mono' : ''}`}
        >
          {t}
        </span>
      ))}
    </div>
  )
}

const unique = (xs: (string | undefined)[]) => [...new Set(xs.filter((x): x is string => !!x))]

function tweetFeedStats(d: TweetFeedResponse | null | undefined) {
  const records = d?.records ?? []
  const users = unique(records.flatMap(r => r.users ?? []))
  const tweets = unique(records.flatMap(r => r.tweets ?? []))
  const tags = unique(records.flatMap(r => r.tags ?? []))
  const firstSeen = records.map(r => r.first_seen).filter(Boolean).sort()[0]
  const lastSeen = records.map(r => r.last_seen).filter(Boolean).sort().at(-1)
  return { records, users, tweets, tags, firstSeen, lastSeen }
}

export default function TweetFeedCard({ loading, error, data, score = null, weight = null, indicator }: Props) {
  const i18n = useI18n()
  const { t } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isRealError = !!error || !!apiError
  const found = !apiError && !!data?.found
  const { users, tweets, tags, firstSeen, lastSeen } = tweetFeedStats(data)
  const campaigns = data?.campaigns ?? []
  const related = unique((data?.records ?? []).flatMap(r => (r.related ?? []).map(([, v]) => v)))
    .filter(v => v !== data?.query)
  const query = indicator ?? data?.query ?? ''

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div
        role="button"
        tabIndex={0}
        onClick={() => setOpen(o => !o)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(o => !o) } }}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left cursor-pointer"
      >
        <span className="font-semibold text-sm text-foreground">TweetFeed</span>
        <div className="flex items-center gap-2">
          {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
          <WeightBadge weight={weight} />
          {!loading && <ScoreBadge score={score} isError={isRealError} hasResult={found} />}
          {!loading && data && (
            <button
              onClick={e => { e.stopPropagation(); setRawOpen(true) }}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30 hover:bg-muted/70 hover:text-foreground transition-colors"
              title={t('raw.buttonTitle')}
            >
              <FileCode2 className="h-3 w-3" />
              RAW
            </button>
          )}
          <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </div>

      {open && (
        <div className="px-4 py-4 flex flex-col gap-4">
          {loading && <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'TweetFeed' })}</p>}

          {!loading && isRealError && <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'TweetFeed')}</p>}

          {!loading && !isRealError && !found && (
            <p className="text-sm text-muted-foreground">
              {t('tweetfeed.notReported')}
            </p>
          )}

          {!loading && found && (
            <>
              <p className="flex items-start gap-1.5 text-xs text-amber-400">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-px" />
                {t('tweetfeed.unvetted')}
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-4">
                <Field label={t('f.reporters')} value={users.length} />
                <Field label={t('f.tweets')} value={tweets.length} />
                <Field label={t('f.firstSeen')} value={firstSeen} />
                <Field label={t('f.lastSeen')} value={lastSeen} />
                {data?.net && (
                  <>
                    <Field label={t('f.country')} value={data.net.country} />
                    <Field label={t('f.network')} value={data.net.org} />
                  </>
                )}
                {data?.reg && (
                  <>
                    <Field label={t('f.registrar')} value={data.reg.registrar} />
                    <Field label={t('f.hosting')} value={[data.reg.asn, data.reg.org].filter(Boolean).join(' · ') || undefined} />
                  </>
                )}
              </div>

              {users.length > 0 && <Field label={t('f.reportedBy')} value={<Chips items={users.map(u => `@${u}`)} />} />}
              {tags.length > 0 && <Field label={t('f.tags')} value={<Chips items={tags} />} />}

              {data?.ai?.summary && (
                <Field
                  label={t('f.aiSummary')}
                  value={<span className="font-normal text-muted-foreground">{data.ai.summary}</span>}
                />
              )}

              {campaigns.length > 0 && (
                <Field
                  label={t('f.campaigns')}
                  value={
                    <div className="flex flex-col gap-1">
                      {campaigns.map(c => (
                        <span key={c.id} className="font-normal">
                          {c.name}
                          <span className="text-muted-foreground">{t('tweetfeed.campaignMeta', { confidence: c.confidence ?? '?', iocs: c.ioc_count ?? '?' })}</span>
                        </span>
                      ))}
                    </div>
                  }
                />
              )}

              {related.length > 0 && (
                <Field label={t('tweetfeed.related', { n: related.length })} value={<Chips items={related.slice(0, 12)} mono />} />
              )}

              {tweets.length > 0 && (
                <div className="flex flex-col gap-1">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">{t('tweetfeed.sourceTweets')}</span>
                  {tweets.slice(0, 5).map(t => (
                    <a key={t} href={t} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit break-all">
                      <ExternalLink className="h-3 w-3 shrink-0" /> {t}
                    </a>
                  ))}
                </div>
              )}
            </>
          )}

          {!loading && !isRealError && query && (
            <a
              href={`https://tweetfeed.live/search/?q=${encodeURIComponent(query)}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline w-fit"
            >
              <ExternalLink className="h-3 w-3" /> {t('card.viewOn', { source: 'TweetFeed' })}
            </a>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="TweetFeed" />
    </div>
  )
}
