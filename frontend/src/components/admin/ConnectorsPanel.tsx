import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { ExternalLink, Eye, EyeOff, FlaskConical, Loader2, Plus, ShieldOff, Trash2, KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { apiJson } from '@/lib/api'
import { useEngines } from '@/EnginesContext'
import type { IndicatorType } from '@/registry'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'
import { authErrorText } from '@/i18n/errors'
import ConnectorTestPanel, { type EngineTestResult, type RowTest } from './ConnectorTest'

interface KeyConnector {
  key: string
  label: string
  engines: string[]
  optional: boolean
  signup: string
  configured: boolean
  source: 'ui' | 'env' | null
  env_available: boolean
  hint: string
}

interface PlatformInstance {
  id: string
  name: string
  url: string
  verify_ssl: boolean
  client_cert: string
  client_key: string
  has_key: boolean
  hint: string
  connected: boolean
}

type Kind = 'misp' | 'opencti'

interface ConnectorsData {
  keys: KeyConnector[]
  misp: PlatformInstance[]
  misp_from_env: boolean
  opencti: PlatformInstance[]
  opencti_from_env: boolean
  cert_files: string[]
  keyless: { id: string; label: string }[]
}

type Message = { kind: 'ok' | 'error'; text: string }

/** Per-platform wording, logo and URL hint of a multi-instance section. */
const KIND_UI = {
  misp: {
    logo: '/logos/misp.png', placeholder: 'https://misp.example.org',
    title: 'connectors.misp', subtitle: 'connectors.mispSubtitle', fromEnv: 'connectors.mispFromEnv',
    empty: 'connectors.mispEmpty', keyLabel: 'connectors.mispKey', deleteConfirm: 'connectors.mispDeleteConfirm',
    created: 'connectors.mispCreated', updated: 'connectors.mispUpdated', deleted: 'connectors.mispDeleted',
  },
  opencti: {
    logo: '/logos/opencti.png', placeholder: 'https://opencti.example.org',
    title: 'connectors.opencti', subtitle: 'connectors.openctiSubtitle', fromEnv: 'connectors.openctiFromEnv',
    empty: 'connectors.openctiEmpty', keyLabel: 'connectors.openctiKey', deleteConfirm: 'connectors.openctiDeleteConfirm',
    created: 'connectors.openctiCreated', updated: 'connectors.openctiUpdated', deleted: 'connectors.openctiDeleted',
  },
} as const
const KINDS: Kind[] = ['misp', 'opencti']
type Filter = 'all' | 'configured' | 'pending' | 'keyless'
type Status = 'ui' | 'env' | 'none' | 'incomplete'

/** Columns shared by the header and every row of a table (stacked below md). */
/** Action slots: key (Set / Replace, or Complete / Edit for MISP) · Test — fixed so buttons line up across rows. */
const ACTION_GRID = 'grid grid-cols-[8rem_6.5rem] gap-1.5 items-center'
const ROW_GRID = 'grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_9.5rem_7.5rem_15rem] gap-x-3 gap-y-2 md:items-center'

const selectClass =
  'h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

function Logo({ src }: { src?: string }) {
  return (
    <span className="h-7 w-7 shrink-0 rounded-md bg-white border border-border/50 flex items-center justify-center overflow-hidden">
      {src ? <img src={src} alt="" className="h-5 w-5 object-contain" /> : <KeyRound className="h-4 w-4 text-slate-500" />}
    </span>
  )
}

function StatusCell({ status }: { status: Status }) {
  const { t } = useI18n()
  const look = {
    ui: { dot: 'bg-green-500', text: 'text-green-600 dark:text-green-400', label: t('connectors.status.ui') },
    env: { dot: 'bg-sky-500', text: 'text-sky-600 dark:text-sky-400', label: t('connectors.status.env') },
    none: { dot: 'border-2 border-amber-500', text: 'text-amber-600 dark:text-amber-400', label: t('connectors.status.none') },
    incomplete: { dot: 'border-2 border-amber-500', text: 'text-amber-600 dark:text-amber-400', label: t('connectors.mispIncomplete') },
  }[status]
  return (
    <span className={`flex items-center gap-2 text-sm ${look.text}`}>
      <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full box-border ${look.dot}`} />
      {look.label}
    </span>
  )
}

function KeyCell({ hint, has }: { hint: string; has: boolean }) {
  return (
    <span className="font-mono text-xs text-muted-foreground">
      {has ? `•••• ${hint || '••••'}` : '—'}
    </span>
  )
}

function TestButton({ testing, disabled, title, onClick, className = '' }: {
  testing: boolean; disabled: boolean; title: string; onClick: () => void; className?: string
}) {
  const { t } = useI18n()
  return (
    <Button variant="outline" size="sm" disabled={disabled} onClick={onClick} title={title} className={`h-8 w-full gap-1.5 px-2.5 text-xs ${className}`}>
      {testing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />}
      {testing ? t('connectors.testing') : t('connectors.test')}
    </Button>
  )
}

/** The stored key, masked; the eye fetches it from the backend (admin, browser
 *  session only, logged) and toggles it. Nothing is loaded until asked. */
function CurrentSecret({ hint, revealPath, label }: { hint: string; revealPath: string; label: string }) {
  const { t } = useI18n()
  const [value, setValue] = useState<string | null>(null)
  const [visible, setVisible] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(false)

  const toggle = async () => {
    if (visible) { setVisible(false); return }
    if (value === null) {
      setLoading(true)
      setError(false)
      try {
        const r = await apiJson<{ value: string }>(revealPath)
        setValue(r.value)
      } catch {
        setError(true)
        return
      } finally {
        setLoading(false)
      }
    }
    setVisible(true)
  }

  return (
    <div className="flex flex-col gap-1">
      <div className="relative">
        <Input readOnly value={visible && value !== null ? value : `•••• •••• ${hint || '••••'}`} aria-label={label}
          className="h-9 w-full pr-10 font-mono text-muted-foreground read-only:bg-muted/40" />
        <button type="button" onClick={toggle} disabled={loading} aria-pressed={visible}
          aria-label={visible ? t('connectors.hideKey') : t('connectors.showKey')} title={visible ? t('connectors.hideKey') : t('connectors.showKey')}
          className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted disabled:opacity-50">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
      {error && <span role="alert" className="text-xs text-red-400">{t('connectors.revealError')}</span>}
    </div>
  )
}

function TableHeader({ title, action }: { title: string; action?: ReactNode }) {
  const { t } = useI18n()
  return (
    <div className={`${ROW_GRID} px-4 py-2.5 border-b border-border text-xs uppercase tracking-wide text-muted-foreground font-medium`}>
      <span className="flex items-center justify-between gap-3">{title}<span className="md:hidden">{action}</span></span>
      <span className="hidden md:block">{t('connectors.col.status')}</span>
      <span className="hidden md:block">{t('connectors.col.key')}</span>
      <span className="hidden md:flex justify-end normal-case tracking-normal">{action}</span>
    </div>
  )
}

/** One table row plus whatever it expands into (key form, MISP form, test result). */
function Row({ logo, title, subtitle, status, keyCell, setup, testButton, children }: {
  logo?: string
  title: ReactNode
  subtitle: ReactNode
  status: Status
  keyCell: ReactNode
  /** Set / Replace key (Complete / Edit for MISP) */
  setup?: ReactNode
  testButton?: ReactNode
  children?: ReactNode
}) {
  return (
    <div className="border-b border-border/60 last:border-b-0">
      <div className={`${ROW_GRID} px-4 py-2.5 min-h-[3.25rem]`}>
        <div className="flex items-center gap-3 min-w-0">
          <Logo src={logo} />
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium text-foreground truncate">{title}</span>
            <span className="text-xs text-muted-foreground truncate">{subtitle}</span>
          </div>
        </div>
        <div className="pl-10 md:pl-0"><StatusCell status={status} /></div>
        <div className="pl-10 md:pl-0">{keyCell}</div>
        <div className={`${ACTION_GRID} pl-10 md:pl-0 md:justify-end`}>
          <div>{setup}</div>
          <div>{testButton}</div>
        </div>
      </div>
      {children && <div className="flex flex-col gap-2 px-4 pb-3 md:pl-14">{children}</div>}
    </div>
  )
}

export default function ConnectorsPanel() {
  const i18n = useI18n()
  const { t } = i18n
  const { engines, reload: reloadEngines } = useEngines()
  const [data, setData] = useState<ConnectorsData | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [tests, setTests] = useState<Record<string, RowTest>>({})   // last test of each row
  const [message, setMessage] = useState<Message | null>(null)
  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [keyValue, setKeyValue] = useState('')
  const [editing, setEditing] = useState<string | null>(null)   // "<kind>:<id>", or "<kind>:new"
  const [filter, setFilter] = useState<Filter>('all')

  const engineOf = (id: string) => engines.find(e => e.id === id)
  const labelOf = (id: string) => engineOf(id)?.label ?? id
  const typesOf = (id: string) =>
    (engineOf(id)?.supports ?? []).map(ty => t(`typeShort.${ty as IndicatorType}`)).join(' · ')

  const load = useCallback(() => {
    apiJson<ConnectorsData>('/connectors')
      .then(d => { setData(d); setLoadFailed(false) })
      .catch(() => setLoadFailed(true))
  }, [])

  useEffect(() => { load() }, [load])

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    setMessage(null)
    try {
      await fn()
      setMessage({ kind: 'ok', text: ok })
      load()
      reloadEngines()
      return true
    } catch (err) {
      setMessage({ kind: 'error', text: authErrorText(i18n, err) })
      return false
    } finally {
      setBusy(false)
    }
  }

  const isTesting = (rowId: string) => tests[rowId] !== undefined && tests[rowId].finishedAt === null

  /** Tests every source a row powers in parallel (the abuse.ch key serves three
   *  different APIs); each result shows up as soon as its source answers. */
  const test = async (rowId: string, engineIds: string[]) => {
    setTests(ts => ({ ...ts, [rowId]: { startedAt: Date.now(), finishedAt: null, engineIds, results: {} } }))
    const setResult = (id: string, result: EngineTestResult) =>
      setTests(ts => ts[rowId] ? { ...ts, [rowId]: { ...ts[rowId], results: { ...ts[rowId].results, [id]: result } } } : ts)
    await Promise.all(engineIds.map(async id => {
      try {
        setResult(id, await apiJson<EngineTestResult>(`/connectors/test/${encodeURIComponent(id)}`, 'POST'))
      } catch (err) {
        setResult(id, {
          engine: id, label: labelOf(id), indicator: null, type: null, ok: false, outcome: 'error',
          duration_ms: null, error: { message: authErrorText(i18n, err) }, response: null, truncated: false,
        })
      }
    }))
    setTests(ts => ts[rowId] ? { ...ts, [rowId]: { ...ts[rowId], finishedAt: Date.now() } } : ts)
  }

  const closeTest = (rowId: string) => setTests(ts => { const rest = { ...ts }; delete rest[rowId]; return rest })

  const testPanel = (rowId: string) =>
    tests[rowId] && <ConnectorTestPanel test={tests[rowId]} labelOf={labelOf} onClose={() => closeTest(rowId)} />

  const toggleKeyEditor = (c: KeyConnector) => { setEditingKey(k => (k === c.key ? null : c.key)); setKeyValue('') }

  const saveKey = async (c: KeyConnector) => {
    const ok = await run(
      () => apiJson(`/connectors/keys/${c.key}`, 'PUT', { value: keyValue.trim() }),
      t('connectors.saved', { label: c.label }),
    )
    if (ok) { setEditingKey(null); setKeyValue('') }
  }

  const removeKey = (c: KeyConnector) => {
    const confirmText = c.env_available
      ? t('connectors.removeConfirmEnv', { label: c.label })
      : t('connectors.removeConfirm', { label: c.label })
    if (!window.confirm(confirmText)) return
    run(() => apiJson(`/connectors/keys/${c.key}`, 'DELETE'), t('connectors.removed', { label: c.label }))
  }

  const removeInstance = (kind: Kind, m: PlatformInstance) => {
    if (!window.confirm(t(KIND_UI[kind].deleteConfirm, { name: m.name }))) return
    run(() => apiJson(`/connectors/${kind}/${m.id}`, 'DELETE'), t(KIND_UI[kind].deleted, { name: m.name }))
  }

  if (loadFailed) {
    return (
      <div className="flex items-center gap-3">
        <p className="text-sm text-red-400">{t('connectors.loadError')}</p>
        <Button size="sm" variant="ghost" onClick={load}>{t('common.retry')}</Button>
      </div>
    )
  }
  if (!data) return <p className="text-sm text-muted-foreground">{t('common.loading')}</p>

  const keyStatus = (c: KeyConnector): Status => c.source ?? 'none'
  const fromEnv = (kind: Kind) => (kind === 'misp' ? data.misp_from_env : data.opencti_from_env)
  const instancesOf = (kind: Kind) => (kind === 'misp' ? data.misp : data.opencti ?? [])
  const instanceStatus = (kind: Kind, m: PlatformInstance): Status => (!m.connected ? 'incomplete' : fromEnv(kind) ? 'env' : 'ui')
  const isPending = (s: Status) => s === 'none' || s === 'incomplete'
  const allInstances = KINDS.flatMap(k => instancesOf(k))

  const counts = {
    all: data.keys.length + allInstances.length + data.keyless.length,
    configured: data.keys.filter(c => !isPending(keyStatus(c))).length + allInstances.filter(m => m.connected).length,
    pending: data.keys.filter(c => isPending(keyStatus(c))).length + allInstances.filter(m => !m.connected).length,
    keyless: data.keyless.length,
  }
  const shows = (s: Status | 'keyless') =>
    filter === 'all'
    || (filter === 'keyless' && s === 'keyless')
    || (filter === 'pending' && s !== 'keyless' && isPending(s))
    || (filter === 'configured' && s !== 'keyless' && !isPending(s))

  const keys = data.keys.filter(c => shows(keyStatus(c)))
  const visible = (kind: Kind) => instancesOf(kind).filter(m => shows(instanceStatus(kind, m)))
  const showKeyless = shows('keyless')
  const showSection = (kind: Kind) => filter === 'all' || visible(kind).length > 0 || (filter === 'pending' && editing === `${kind}:new`)

  // Every testable row in view: configured keys (and optional ones), complete MISP instances, keyless sources.
  const testable: [string, string[]][] = [
    ...keys.filter(c => c.configured || c.optional).map(c => [c.key, c.engines] as [string, string[]]),
    ...KINDS.flatMap(k => visible(k)).filter(m => m.connected).map(m => [m.id, [m.id]] as [string, string[]]),
    ...(showKeyless ? data.keyless.map(k => [k.id, [k.id]] as [string, string[]]) : []),
  ]
  const testableRequests = testable.reduce((n, [, ids]) => n + ids.length, 0)
  const testAll = () => {
    if (!window.confirm(t('connectors.testAllConfirm', { n: testableRequests }))) return
    testable.forEach(([row, ids]) => { if (!isTesting(row)) test(row, ids) })
  }

  const tabs: Filter[] = ['all', 'configured', 'pending', 'keyless']

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div role="tablist" aria-label={t('connectors.filter.label')}
          className="flex flex-wrap gap-1 rounded-lg border border-border bg-muted/30 p-1">
          {tabs.map(f => (
            <button key={f} type="button" role="tab" aria-selected={filter === f} onClick={() => setFilter(f)}
              className={`rounded-md px-3 py-1.5 text-sm transition-colors ${
                filter === f ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'
              } ${f === 'pending' && counts.pending > 0 && filter !== f ? 'text-amber-600 dark:text-amber-400' : ''}`}>
              {t(`connectors.filter.${f}`)} <span className="tabular-nums opacity-70">{counts[f]}</span>
            </button>
          ))}
        </div>
        <Button variant="outline" size="sm" disabled={busy || testable.length === 0} onClick={testAll}
          title={t('connectors.testTitle')} className="gap-1.5">
          <FlaskConical className="h-4 w-4" /> {t('connectors.testAll')}
        </Button>
      </div>

      {message && (
        <p role={message.kind === 'error' ? 'alert' : 'status'}
          className={`text-sm ${message.kind === 'ok' ? 'text-green-500' : 'text-red-400'}`}>
          {message.text}
        </p>
      )}

      {keys.length > 0 && (
        <section className="rounded-xl border border-border bg-muted/10 overflow-visible">
          <TableHeader title={t('connectors.keys')} />
          {keys.map(c => {
            const status = keyStatus(c)
            const canTest = c.configured || c.optional
            const subtitle = [
              c.engines.length > 1 ? t('connectors.powers', { sources: c.engines.map(labelOf).join(', ') }) : typesOf(c.engines[0]),
              c.optional ? t('connectors.optionalShort') : '',
            ].filter(Boolean).join(' · ')
            return (
              <Row key={c.key} logo={engineOf(c.engines[0])?.logo} title={c.label} subtitle={subtitle} status={status}
                keyCell={<KeyCell hint={c.hint} has={c.configured} />}
                setup={c.configured
                  ? <Button variant="outline" size="sm" disabled={busy} onClick={() => toggleKeyEditor(c)}
                      aria-expanded={editingKey === c.key} className="h-8 w-full px-2 text-xs">
                      {t('connectors.replace')}
                    </Button>
                  : <Button size="sm" disabled={busy} onClick={() => toggleKeyEditor(c)}
                      aria-expanded={editingKey === c.key} className="h-8 w-full px-2 text-xs">
                      {t('connectors.set')}
                    </Button>}
                testButton={canTest && (
                  <TestButton testing={isTesting(c.key)} disabled={busy || isTesting(c.key)}
                    title={t('connectors.testTitle')} onClick={() => test(c.key, c.engines)} />
                )}
                >
                {editingKey === c.key && (
                  <form onSubmit={e => { e.preventDefault(); saveKey(c) }}
                    className="flex flex-col gap-2 rounded-lg border border-border bg-background/40 p-3">
                    <div className={`grid grid-cols-1 gap-3 ${c.configured ? 'md:grid-cols-2' : ''}`}>
                      {c.configured && (
                        <div className="flex flex-col gap-1 text-xs text-muted-foreground">
                          <span>{t('connectors.currentKey')}{c.source === 'env' && <> · {t('connectors.status.env')}</>}</span>
                          <CurrentSecret hint={c.hint} revealPath={`/connectors/keys/${c.key}/reveal`}
                            label={`${c.label} — ${t('connectors.currentKey')}`} />
                        </div>
                      )}
                      <label className="flex flex-col gap-1 text-xs text-muted-foreground">
                        {t('connectors.newKey')}
                        <Input type="password" value={keyValue} onChange={e => setKeyValue(e.target.value)}
                          placeholder={t('connectors.keyPlaceholder')} autoComplete="off" spellCheck={false} autoFocus
                          className="h-9 font-mono" />
                      </label>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button type="submit" size="sm" disabled={busy || !keyValue.trim()}>
                        {busy ? t('connectors.saving') : t('connectors.save')}
                      </Button>
                      <Button type="button" size="sm" variant="ghost" onClick={() => { setEditingKey(null); setKeyValue('') }}>
                        {t('connectors.cancel')}
                      </Button>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      <span>{t('connectors.envVar')} <code className="font-mono text-foreground">{c.key}</code></span>
                      <a href={c.signup} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-primary hover:underline">
                        <ExternalLink className="h-3 w-3" /> {t('connectors.getKey')}
                      </a>
                      {c.source === 'ui' && (
                        <button type="button" disabled={busy} onClick={() => removeKey(c)}
                          className="ml-auto inline-flex items-center gap-1 text-red-500 dark:text-red-400 hover:underline disabled:opacity-50">
                          <Trash2 className="h-3 w-3" /> {t('connectors.remove')}
                        </button>
                      )}
                    </div>
                  </form>
                )}
                {testPanel(c.key)}
              </Row>
            )
          })}
        </section>
      )}

      {KINDS.filter(showSection).map(kind => {
        const ui = KIND_UI[kind]
        const all = instancesOf(kind)
        return (
          <section key={kind} className="rounded-xl border border-border bg-muted/10 overflow-visible">
            <TableHeader title={t(ui.title)} action={editing !== `${kind}:new` && (
              <Button size="sm" disabled={busy} onClick={() => setEditing(`${kind}:new`)} className="h-7 gap-1 px-2.5 text-xs">
                <Plus className="h-3.5 w-3.5" /> {t('connectors.mispAdd')}
              </Button>
            )} />
            {fromEnv(kind) && all.length > 0 && (
              <p className="mx-4 mt-3 text-xs rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sky-700 dark:text-sky-300">
                {rich(t(ui.fromEnv))}
              </p>
            )}
            {editing === `${kind}:new` && (
              <div className="p-4 border-b border-border/60 flex flex-col gap-2">
                <p className="text-xs text-muted-foreground">{t(ui.subtitle)}</p>
                <InstanceForm kind={kind} certFiles={data.cert_files} busy={busy}
                  onCancel={() => setEditing(null)}
                  onSubmit={async body => {
                    const ok = await run(() => apiJson(`/connectors/${kind}`, 'POST', body),
                      t(ui.created, { name: body.name ?? '' }))
                    if (ok) setEditing(null)
                  }} />
              </div>
            )}
            {all.length === 0 && editing !== `${kind}:new` && (
              <p className="px-4 py-4 text-sm text-muted-foreground">{t(ui.empty)}</p>
            )}
            {visible(kind).map(m => (
              <Row key={m.id} logo={ui.logo} title={m.name} status={instanceStatus(kind, m)}
                subtitle={<>
                  <span className="font-mono">{m.url || '—'}</span>
                  {!m.verify_ssl && <span className="text-amber-600 dark:text-amber-400"> · <ShieldOff className="inline h-3 w-3 -mt-0.5" /> {t('connectors.mispVerifySslOff')}</span>}
                  {m.client_cert && <> · mTLS</>}
                </>}
                keyCell={<KeyCell hint={m.hint} has={m.has_key} />}
                setup={
                  <Button variant={m.connected ? 'outline' : 'default'} size="sm" disabled={busy}
                    onClick={() => setEditing(e => (e === `${kind}:${m.id}` ? null : `${kind}:${m.id}`))} aria-expanded={editing === `${kind}:${m.id}`}
                    className="h-8 w-full px-2 text-xs">
                    {m.connected ? t('connectors.mispEdit') : t('connectors.complete')}
                  </Button>
                }
                testButton={m.connected && (
                  <TestButton testing={isTesting(m.id)} disabled={busy || isTesting(m.id)}
                    title={t('connectors.testTitle')} onClick={() => test(m.id, [m.id])} />
                )}
                >
                {editing === `${kind}:${m.id}` && (
                  <InstanceForm kind={kind} instance={m} certFiles={data.cert_files} busy={busy}
                    onCancel={() => setEditing(null)} onDelete={() => removeInstance(kind, m)}
                    onSubmit={async body => {
                      const ok = await run(() => apiJson(`/connectors/${kind}/${m.id}`, 'PATCH', body),
                        t(ui.updated, { name: body.name ?? m.name }))
                      if (ok) setEditing(null)
                    }} />
                )}
                {testPanel(m.id)}
              </Row>
            ))}
          </section>
        )
      })}

      {showKeyless && data.keyless.length > 0 && (
        <section className="flex flex-col gap-2">
          <h3 className="text-xs uppercase tracking-wide text-muted-foreground font-medium">{t('connectors.keylessHeading')}</h3>
          <div className="flex flex-wrap gap-2">
            {data.keyless.map(k => (
              <span key={k.id} className="inline-flex items-center gap-2 rounded-full border border-border bg-muted/10 py-1 pl-1.5 pr-1 text-sm">
                <Logo src={engineOf(k.id)?.logo} />
                <span aria-hidden="true" className="h-2 w-2 rounded-full bg-green-500" />
                {k.label}
                <TestButton testing={isTesting(k.id)} disabled={busy || isTesting(k.id)}
                  title={t('connectors.testTitle')} onClick={() => test(k.id, [k.id])} className="h-7 !w-auto rounded-full" />
              </span>
            ))}
          </div>
          {data.keyless.map(k => tests[k.id] && <div key={k.id}>{testPanel(k.id)}</div>)}
        </section>
      )}

      {keys.length === 0 && !KINDS.some(showSection) && !showKeyless && (
        <p className="text-sm text-muted-foreground">{t('connectors.noMatches')}</p>
      )}

      <p className="text-xs text-muted-foreground">{rich(t('connectors.storageNote'))}</p>
    </div>
  )
}

interface InstanceBody {
  name?: string
  url?: string
  key?: string
  verify_ssl?: boolean
  client_cert?: string
  client_key?: string
}

function InstanceForm({ kind, instance, certFiles, busy, onSubmit, onCancel, onDelete }: {
  kind: Kind
  instance?: PlatformInstance
  certFiles: string[]
  busy: boolean
  onSubmit: (body: InstanceBody) => void
  onCancel: () => void
  onDelete?: () => void
}) {
  const { t } = useI18n()
  const [name, setName] = useState(instance?.name ?? '')
  const [url, setUrl] = useState(instance?.url ?? '')
  const [key, setKey] = useState('')
  const [verifySsl, setVerifySsl] = useState(instance?.verify_ssl ?? true)
  const [clientCert, setClientCert] = useState(instance?.client_cert ?? '')
  const [clientKey, setClientKey] = useState(instance?.client_key ?? '')
  const isNew = !instance
  // Keep a previously selected file listed even if it was removed from backend/certs/.
  const options = (current: string) => (current && !certFiles.includes(current) ? [current, ...certFiles] : certFiles)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const body: InstanceBody = {
      name: name.trim(), url: url.trim(), verify_ssl: verifySsl,
      client_cert: clientCert, client_key: clientCert ? clientKey : '',
    }
    if (key.trim()) body.key = key.trim()
    onSubmit(body)
  }

  const fieldLabel = 'flex flex-col gap-1 text-xs text-muted-foreground'
  return (
    <form onSubmit={submit} className="rounded-lg border border-border bg-background/40 p-3 flex flex-col gap-3">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label className={fieldLabel}>
          {t('connectors.mispName')}
          <Input value={name} onChange={e => setName(e.target.value)} maxLength={64} required className="h-9" autoFocus={isNew} />
        </label>
        <label className={fieldLabel}>
          {t('connectors.mispUrl')}
          <Input type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder={KIND_UI[kind].placeholder}
            required className="h-9 font-mono" />
        </label>
        {instance?.has_key && (
          <div className={fieldLabel}>
            {t('connectors.currentKey')}
            <CurrentSecret hint={instance.hint} revealPath={`/connectors/${kind}/${instance.id}/reveal`}
              label={`${instance.name} — ${t('connectors.currentKey')}`} />
          </div>
        )}
        <label className={`${fieldLabel} ${instance?.has_key ? '' : 'md:col-span-2'}`}>
          {instance?.has_key ? t('connectors.newKey') : t(KIND_UI[kind].keyLabel)}
          <Input type="password" value={key} onChange={e => setKey(e.target.value)} autoComplete="off" spellCheck={false}
            required={isNew || !instance?.has_key} className="h-9 font-mono"
            placeholder={instance?.has_key ? t('connectors.mispKeyKeep') : ''} />
        </label>
        <label className={fieldLabel}>
          {t('connectors.mispClientCert')}
          <select value={clientCert} onChange={e => setClientCert(e.target.value)} className={selectClass}>
            <option value="">{t('connectors.mispCertNone')}</option>
            {options(clientCert).map(f => <option key={f} value={f}>{f}</option>)}
          </select>
        </label>
        <label className={fieldLabel}>
          {t('connectors.mispClientKey')}
          <select value={clientKey} onChange={e => setClientKey(e.target.value)} disabled={!clientCert} className={selectClass}>
            <option value="">{t('connectors.mispCertNone')}</option>
            {options(clientKey).map(f => <option key={f} value={f}>{f}</option>)}
          </select>
        </label>
      </div>
      <p className="text-xs text-muted-foreground">{rich(t('connectors.mispCertHelp'))}</p>
      <label className="flex items-center gap-2 text-sm text-foreground">
        <input type="checkbox" checked={verifySsl} onChange={e => setVerifySsl(e.target.checked)} className="h-4 w-4" />
        {t('connectors.mispVerifySsl')}
      </label>
      <div className="flex items-center gap-2">
        <Button type="submit" size="sm" disabled={busy || !name.trim() || !url.trim() || ((isNew || !instance?.has_key) && !key.trim())}>
          {busy ? (isNew ? t('connectors.mispAdding') : t('connectors.saving')) : (isNew ? t('connectors.mispAdd') : t('connectors.save'))}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>{t('connectors.cancel')}</Button>
        {onDelete && (
          <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={onDelete}
            className="ml-auto gap-1.5 text-red-500 dark:text-red-400 hover:text-red-500">
            <Trash2 className="h-3.5 w-3.5" /> {t('connectors.mispDelete')}
          </Button>
        )}
      </div>
    </form>
  )
}
