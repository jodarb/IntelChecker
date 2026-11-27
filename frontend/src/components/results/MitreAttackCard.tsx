import { useState } from 'react'
import { Loader2, ChevronDown, FileCode2 } from 'lucide-react'
import RawJsonModal from './RawJsonModal'
import ScoreBadge from './ScoreBadge'
import WeightBadge, { type CardWeight } from './WeightBadge'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'
import { clickOnEnterOrSpace } from '@/lib/a11y'

interface MitreItem {
  attack_id: string
  name: string
}

interface MitreAttackResponse {
  attack_id?: string
  name?: string
  aliases?: string[]
  description?: string
  url?: string
  techniques?: MitreItem[]
  software?: MitreItem[]
  error?: { code: string; message: string }
}

interface Props {
  loading: boolean
  error: string | null
  data: MitreAttackResponse | null
  score?: number | null
  weight?: CardWeight | null
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      <span className="text-sm text-foreground font-medium break-all">{value ?? '—'}</span>
    </div>
  )
}

function TagList({ items, max = 10 }: { items: string[]; max?: number }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-wrap gap-1">
      {items.slice(0, max).map(item => (
        <span key={item} className="px-1.5 py-0.5 rounded bg-muted border border-border text-xs text-muted-foreground">
          {item}
        </span>
      ))}
      {items.length > max && (
        <span className="px-1.5 py-0.5 text-xs text-muted-foreground">{t('common.more', { n: items.length - max })}</span>
      )}
    </div>
  )
}

export default function MitreAttackCard({ loading, error, data, score = null, weight = null }: Props) {
  const i18n = useI18n()
  const { t } = i18n
  const [open, setOpen] = useState(false)
  const [rawOpen, setRawOpen] = useState(false)
  const apiError = data?.error ?? null
  const isNotFound = apiError?.code === 'NotFound'
  const isRealError = !!error || (!!apiError && !isNotFound)
  const found = !apiError && !!data?.name

  const techCount = data?.techniques?.length ?? 0
  const softCount = data?.software?.length ?? 0
  const otherAliases = (data?.aliases ?? []).filter(a => a !== data?.name)

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div role="button" tabIndex={0} onKeyDown={clickOnEnterOrSpace} aria-expanded={open}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/40 hover:bg-muted/60 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-foreground">MITRE ATT&CK</span>
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
          {loading && (
            <p className="text-sm text-muted-foreground">{t('card.querying', { source: 'MITRE ATT&CK' })}</p>
          )}

          {!loading && isRealError && (
            <p className="text-sm text-red-400">{error ?? apiErrorText(i18n, apiError, 'MITRE ATT&CK')}</p>
          )}

          {!loading && isNotFound && (
            <p className="text-sm text-muted-foreground">{apiErrorText(i18n, apiError, 'MITRE ATT&CK')}</p>
          )}

          {!loading && found && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4">
                <Field label={t('f.attackId')} value={data?.attack_id} />
                <Field label={t('f.name')} value={data?.name} />
                <Field label={t('f.techniques')} value={techCount} />
                <Field label={t('f.software')} value={softCount} />
                {data?.url && (
                  <Field
                    label={t('f.reference')}
                    value={
                      <a href={data.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                        attack.mitre.org
                      </a>
                    }
                  />
                )}
              </div>

              {data?.description && (
                <p className="text-sm text-muted-foreground leading-relaxed">{data.description}</p>
              )}

              {otherAliases.length > 0 && (
                <div className="flex flex-col gap-1">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('mitre.aliases', { n: otherAliases.length })}
                  </span>
                  <TagList items={otherAliases} />
                </div>
              )}

              {techCount > 0 && (
                <div className="flex flex-col gap-1">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('mitre.techniques', { n: techCount })}
                  </span>
                  <TagList items={data!.techniques!.map(t => `${t.attack_id} ${t.name}`)} max={12} />
                </div>
              )}

              {softCount > 0 && (
                <div className="flex flex-col gap-1">
                  <span className="text-xs text-muted-foreground uppercase tracking-wide">
                    {t('mitre.software', { n: softCount })}
                  </span>
                  <TagList items={data!.software!.map(s => s.name)} max={12} />
                </div>
              )}
            </>
          )}
        </div>
      )}
      <RawJsonModal open={rawOpen} onClose={() => setRawOpen(false)} data={data} title="MITRE ATT&CK" />
    </div>
  )
}
