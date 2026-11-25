import { useEffect, useState } from 'react'
import { CheckCircle2, ChevronDown, ChevronRight, ChevronUp, CircleDashed, Loader2, X, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { IndicatorType } from '@/registry'
import { useI18n } from '@/i18n/useI18n'
import { apiErrorText } from '@/i18n/errors'

/** Answer of POST /connectors/test/{engine}. */
export interface EngineTestResult {
  engine: string
  label: string
  indicator: string | null
  type: IndicatorType | null
  ok: boolean
  /** ok = data returned · not_found = answered, no record (still OK) · error */
  outcome: 'ok' | 'not_found' | 'error'
  duration_ms: number | null
  error: { code?: string; message?: string } | null
  /** Raw source response (a string when truncated). */
  response: unknown
  truncated: boolean
}

/** One run of the Test button of a row: one or more sources tested in parallel. */
export interface RowTest {
  startedAt: number
  finishedAt: number | null
  engineIds: string[]
  results: Record<string, EngineTestResult>
}

function formatMs(ms: number, locale: string) {
  return ms < 1000
    ? `${Math.round(ms)} ms`
    : `${(ms / 1000).toLocaleString(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 })} s`
}

function Elapsed({ since, locale }: { since: number; locale: string }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 100)
    return () => window.clearInterval(id)
  }, [])
  return <span className="tabular-nums">{formatMs(now - since, locale)}</span>
}

function ProgressBar({ done, total, running, failed }: { done: number; total: number; running: boolean; failed: boolean }) {
  const pct = total ? (done / total) * 100 : 0
  const fill = running ? 'bg-primary' : failed ? 'bg-red-500' : 'bg-green-500'
  return (
    <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-muted" role="progressbar"
      aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
      <div className={`absolute inset-y-0 left-0 rounded-full transition-[width] duration-300 ${fill}`}
        style={{ width: `${running ? pct : 100}%` }} />
      {running && <div className="progress-indeterminate absolute inset-y-0 w-2/5 rounded-full bg-primary/60" />}
    </div>
  )
}

function EngineResult({ id, result, label }: { id: string; result?: EngineTestResult; label: string }) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [open, setOpen] = useState(false)

  if (!result) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground" data-engine={id}>
        <Loader2 className="h-3.5 w-3.5 animate-spin shrink-0" />
        {t('connectors.test.querying', { label })}
      </div>
    )
  }

  const styles = {
    ok: { icon: CheckCircle2, color: 'text-green-500', badge: 'border-green-500/40 bg-green-500/10 text-green-600 dark:text-green-400' },
    not_found: { icon: CircleDashed, color: 'text-green-500', badge: 'border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-400' },
    error: { icon: XCircle, color: 'text-red-400', badge: 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400' },
  }[result.outcome]
  const Icon = styles.icon
  const json = result.response === null || result.response === undefined
    ? null
    : typeof result.response === 'string' ? result.response : JSON.stringify(result.response, null, 2)

  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border/70 bg-background/50 px-2.5 py-2">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
        <Icon className={`h-4 w-4 shrink-0 ${styles.color}`} />
        <span className="font-medium text-foreground">{result.label}</span>
        <span className={`rounded-full border px-1.5 py-px ${styles.badge}`}>{t(`connectors.test.outcome.${result.outcome}`)}</span>
        {result.duration_ms !== null && (
          <span className="text-muted-foreground tabular-nums">· {formatMs(result.duration_ms, locale)}</span>
        )}
      </div>
      {result.indicator && (
        <p className="text-xs text-muted-foreground">
          {t('connectors.test.artifact')}{' '}
          <code className="font-mono text-foreground bg-muted rounded px-1 py-px break-all">{result.indicator}</code>
          {result.type && <> · {t(`type.${result.type}`)}</>}
        </p>
      )}
      <p className={`text-xs ${result.outcome === 'error' ? 'text-red-400' : 'text-muted-foreground'}`}>
        {result.outcome === 'error'
          ? apiErrorText(i18n, result.error, result.label)
          : t(`connectors.test.explain.${result.outcome}`)}
      </p>
      {json !== null && (
        <div className="flex flex-col gap-1">
          <button type="button" onClick={() => setOpen(o => !o)} aria-expanded={open}
            className="self-start inline-flex items-center gap-1 text-xs text-primary hover:underline">
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            {open ? t('connectors.test.hideResponse') : t('connectors.test.showResponse')}
          </button>
          {open && (
            <>
              <pre className="max-h-72 overflow-auto rounded-md border border-border bg-muted/40 p-2 text-[0.7rem] leading-relaxed font-mono text-foreground whitespace-pre-wrap break-all">
                {json}
              </pre>
              {result.truncated && <p className="text-xs text-muted-foreground">{t('connectors.test.truncated')}</p>}
            </>
          )}
        </div>
      )}
    </div>
  )
}

/** Progress and result of the last test of one Connectors row. */
export default function ConnectorTestPanel({ test, labelOf, onClose }: {
  test: RowTest
  labelOf: (id: string) => string
  onClose: () => void
}) {
  const { t, locale } = useI18n()
  const total = test.engineIds.length
  const results = test.engineIds.map(id => test.results[id]).filter(Boolean)
  const done = results.length
  const running = test.finishedAt === null
  const failed = results.filter(r => !r.ok).length
  const [hidden, setHidden] = useState(false)
  const collapsed = hidden && !running
  // A new run of the same row starts expanded again.
  const [runStart, setRunStart] = useState(test.startedAt)
  if (runStart !== test.startedAt) { setRunStart(test.startedAt); setHidden(false) }

  return (
    <div className={`flex flex-col gap-2 rounded-md border border-border bg-muted/30 ${collapsed ? 'px-2.5 py-1.5' : 'p-2.5'}`}
      aria-live="polite">
      <div className="flex items-center gap-2 text-xs">
        {!running && (failed
          ? <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
          : <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />)}
        <span className={`font-medium ${running ? 'text-foreground' : failed ? 'text-red-400' : 'text-green-500'}`}>
          {running
            ? (total > 1 ? t('connectors.test.runningMany', { done, total }) : t('connectors.test.running'))
            : failed
              ? t('connectors.test.failed', { failed, total })
              : t('connectors.test.passed', { total })}
        </span>
        <span className="text-muted-foreground">
          · {running
            ? <Elapsed since={test.startedAt} locale={locale} />
            : <span className="tabular-nums">{formatMs(test.finishedAt! - test.startedAt, locale)}</span>}
        </span>
        {!running && (
          <div className="ml-auto flex items-center gap-0.5">
            <Button variant="ghost" size="sm" onClick={() => setHidden(h => !h)} aria-expanded={!collapsed}
              className="h-6 gap-1 px-1.5 text-xs">
              {collapsed ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronUp className="h-3.5 w-3.5" />}
              {collapsed ? t('connectors.test.show') : t('connectors.test.hide')}
            </Button>
            <Button variant="ghost" size="icon" onClick={onClose} aria-label={t('connectors.test.dismiss')}
              title={t('connectors.test.dismiss')} className="h-6 w-6">
              <X className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}
      </div>
      {!collapsed && (
        <>
          <ProgressBar done={done} total={total} running={running} failed={failed > 0} />
          <div className="flex flex-col gap-1.5">
            {test.engineIds.map(id => <EngineResult key={id} id={id} result={test.results[id]} label={labelOf(id)} />)}
          </div>
        </>
      )}
    </div>
  )
}
