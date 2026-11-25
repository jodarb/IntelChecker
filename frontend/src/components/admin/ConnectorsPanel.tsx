import { useCallback, useEffect, useState } from 'react'
import { ExternalLink, FlaskConical, KeyRound, Loader2, Pencil, Plus, ShieldOff, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { apiJson } from '@/lib/api'
import { useEngines } from '@/EnginesContext'
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

interface MispInstance {
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

interface ConnectorsData {
  keys: KeyConnector[]
  misp: MispInstance[]
  misp_from_env: boolean
  cert_files: string[]
  keyless: { id: string; label: string }[]
}

type Message = { kind: 'ok' | 'error'; text: string }

function TestButton({ testing, disabled, title, onClick }: {
  testing: boolean; disabled: boolean; title: string; onClick: () => void
}) {
  const { t } = useI18n()
  return (
    <Button variant="ghost" size="sm" disabled={disabled} onClick={onClick} title={title} className="h-9 gap-1 px-2 text-xs">
      {testing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />}
      {testing ? t('connectors.testing') : t('connectors.test')}
    </Button>
  )
}

const selectClass =
  'h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

function StatusBadge({ source, hint }: { source: KeyConnector['source']; hint: string }) {
  const { t } = useI18n()
  const styles = {
    ui: 'border-green-500/40 bg-green-500/10 text-green-600 dark:text-green-400',
    env: 'border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-400',
    none: 'border-border bg-muted/40 text-muted-foreground',
  }
  const kind = source ?? 'none'
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs whitespace-nowrap ${styles[kind]}`}>
      {t(`connectors.status.${kind}`)}
      {source && hint && <span className="font-mono opacity-80">· {t('connectors.status.hint', { hint: `…${hint}` })}</span>}
    </span>
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
  const [editingMisp, setEditingMisp] = useState<string | null>(null)   // id, or 'new'

  const labelOf = (id: string) => engines.find(e => e.id === id)?.label ?? id
  const logoOf = (id: string) => engines.find(e => e.id === id)?.logo

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

  const removeMisp = (m: MispInstance) => {
    if (!window.confirm(t('connectors.mispDeleteConfirm', { name: m.name }))) return
    run(() => apiJson(`/connectors/misp/${m.id}`, 'DELETE'), t('connectors.mispDeleted', { name: m.name }))
  }

  return (
    <div className="flex flex-col gap-6">
      <p className="text-sm text-muted-foreground">{rich(t('connectors.storageNote'))}</p>

      {message && (
        <p role={message.kind === 'error' ? 'alert' : 'status'}
          className={`text-sm ${message.kind === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
          {message.text}
        </p>
      )}

      {loadFailed && (
        <div className="flex items-center gap-3">
          <p className="text-sm text-red-400">{t('connectors.loadError')}</p>
          <Button size="sm" variant="ghost" onClick={load}>{t('common.retry')}</Button>
        </div>
      )}
      {!loadFailed && data === null && <p className="text-sm text-muted-foreground">{t('common.loading')}</p>}

      {data && (
        <>
          <section className="flex flex-col gap-2">
            <h3 className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('connectors.keys')}</h3>
            {data.keys.map(c => {
              const logo = logoOf(c.engines[0])
              const editing = editingKey === c.key
              return (
                <div key={c.key} className="rounded-lg border border-border bg-muted/20 px-3 py-2.5 flex flex-col gap-2">
                  <div className="flex flex-wrap items-center gap-3">
                    {logo
                      ? <img src={logo} alt="" className="h-6 w-6 rounded-sm object-contain shrink-0" />
                      : <KeyRound className="h-5 w-5 text-muted-foreground shrink-0" />}
                    <div className="flex flex-col min-w-0 flex-1">
                      <span className="text-sm font-medium text-foreground flex items-center gap-2 flex-wrap">
                        {c.label}
                        <StatusBadge source={c.source} hint={c.hint} />
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {c.engines.length > 1 && <>{t('connectors.powers', { sources: c.engines.map(labelOf).join(', ') })} · </>}
                        <code className="font-mono">{c.key}</code>
                        {c.optional && <> · {t('connectors.optional')}</>}
                      </span>
                    </div>
                    <div className="flex items-center gap-1 justify-end">
                      <Button variant="ghost" size="sm" asChild className="h-9 gap-1 px-2 text-xs">
                        <a href={c.signup} target="_blank" rel="noreferrer noopener">
                          <ExternalLink className="h-3.5 w-3.5" /> {t('connectors.getKey')}
                        </a>
                      </Button>
                      <TestButton testing={isTesting(c.key)}
                        disabled={busy || isTesting(c.key) || !(c.configured || c.optional)}
                        title={c.configured || c.optional ? t('connectors.testTitle') : t('connectors.testNeedsKey')}
                        onClick={() => test(c.key, c.engines)} />
                      {!editing && (
                        <Button variant="outline" size="sm" disabled={busy}
                          onClick={() => { setEditingKey(c.key); setKeyValue('') }} className="h-9 text-xs">
                          {c.configured ? t('connectors.replace') : t('connectors.set')}
                        </Button>
                      )}
                      {c.source === 'ui' && (
                        <Button variant="ghost" size="icon" disabled={busy} onClick={() => removeKey(c)}
                          title={t('connectors.remove')} aria-label={t('connectors.remove')} className="h-9 w-9 hover:text-red-400">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                  {editing && (
                    <form onSubmit={e => { e.preventDefault(); saveKey(c) }} className="flex flex-wrap items-center gap-2">
                      <Input type="password" value={keyValue} onChange={e => setKeyValue(e.target.value)}
                        placeholder={t('connectors.keyPlaceholder')} aria-label={`${c.label} — ${t('connectors.keyPlaceholder')}`}
                        autoComplete="off" spellCheck={false} autoFocus className="h-9 flex-1 min-w-56 font-mono" />
                      <Button type="submit" size="sm" disabled={busy || !keyValue.trim()}>
                        {busy ? t('connectors.saving') : t('connectors.save')}
                      </Button>
                      <Button type="button" size="sm" variant="ghost" onClick={() => { setEditingKey(null); setKeyValue('') }}>
                        {t('connectors.cancel')}
                      </Button>
                    </form>
                  )}
                  {testPanel(c.key)}
                </div>
              )
            })}
          </section>

          <section className="flex flex-col gap-2">
            <div className="flex items-end justify-between gap-3">
              <div>
                <h3 className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('connectors.misp')}</h3>
                <p className="text-sm text-muted-foreground mt-1">{t('connectors.mispSubtitle')}</p>
              </div>
              {editingMisp !== 'new' && (
                <Button size="sm" disabled={busy} onClick={() => setEditingMisp('new')} className="gap-1.5 shrink-0">
                  <Plus className="h-4 w-4" /> {t('connectors.mispAdd')}
                </Button>
              )}
            </div>
            {data.misp_from_env && data.misp.length > 0 && (
              <p className="text-xs rounded-md border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sky-700 dark:text-sky-300">
                {rich(t('connectors.mispFromEnv'))}
              </p>
            )}
            {editingMisp === 'new' && (
              <MispForm certFiles={data.cert_files} busy={busy}
                onCancel={() => setEditingMisp(null)}
                onSubmit={async body => {
                  const ok = await run(() => apiJson('/connectors/misp', 'POST', body),
                    t('connectors.mispCreated', { name: body.name ?? '' }))
                  if (ok) setEditingMisp(null)
                }} />
            )}
            {data.misp.length === 0 && editingMisp !== 'new' && (
              <p className="text-sm text-muted-foreground">{t('connectors.mispEmpty')}</p>
            )}
            {data.misp.map(m => (
              <div key={m.id} className="rounded-lg border border-border bg-muted/20 px-3 py-2.5 flex flex-col gap-2">
                <div className="flex flex-wrap items-center gap-3">
                  <img src="/logos/misp.png" alt="" className="h-6 w-6 rounded-sm object-contain shrink-0" />
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm font-medium text-foreground flex items-center gap-2 flex-wrap">
                      {m.name}
                      {m.connected
                        ? <StatusBadge source={data.misp_from_env ? 'env' : 'ui'} hint={m.hint} />
                        : <span className="rounded-full border border-yellow-500/40 bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-700 dark:text-yellow-300">
                            {t('connectors.mispIncomplete')}
                          </span>}
                    </span>
                    <span className="text-xs text-muted-foreground flex items-center gap-1.5 flex-wrap">
                      <span className="font-mono truncate">{m.url || '—'}</span>
                      {!m.verify_ssl && <span className="inline-flex items-center gap-1 text-yellow-600 dark:text-yellow-400">
                        <ShieldOff className="h-3 w-3" /> {t('connectors.mispVerifySslOff')}</span>}
                      {m.client_cert && <span>· mTLS <code className="font-mono">{m.client_cert}</code></span>}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 justify-end">
                    <TestButton testing={isTesting(m.id)} disabled={busy || isTesting(m.id) || !m.connected}
                      title={m.connected ? t('connectors.testTitle') : t('connectors.testNeedsKey')}
                      onClick={() => test(m.id, [m.id])} />
                    <Button variant="ghost" size="icon" disabled={busy}
                      onClick={() => setEditingMisp(e => (e === m.id ? null : m.id))} aria-expanded={editingMisp === m.id}
                      title={t('connectors.mispEdit')} aria-label={t('connectors.mispEdit')}
                      className={`h-9 w-9 ${editingMisp === m.id ? 'bg-muted/60' : ''}`}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" disabled={busy} onClick={() => removeMisp(m)}
                      title={t('connectors.mispDelete')} aria-label={t('connectors.mispDelete')} className="h-9 w-9 hover:text-red-400">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                {editingMisp === m.id && (
                  <MispForm instance={m} certFiles={data.cert_files} busy={busy}
                    onCancel={() => setEditingMisp(null)}
                    onSubmit={async body => {
                      const ok = await run(() => apiJson(`/connectors/misp/${m.id}`, 'PATCH', body),
                        t('connectors.mispUpdated', { name: body.name ?? m.name }))
                      if (ok) setEditingMisp(null)
                    }} />
                )}
                {testPanel(m.id)}
              </div>
            ))}
          </section>

          {data.keyless.length > 0 && (
            <section className="flex flex-col gap-2">
              <div>
                <h3 className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('connectors.keyless')}</h3>
                <p className="text-sm text-muted-foreground mt-1">{t('connectors.keylessSubtitle')}</p>
              </div>
              {data.keyless.map(k => {
                const logo = logoOf(k.id)
                return (
                  <div key={k.id} className="rounded-lg border border-border bg-muted/20 px-3 py-2.5 flex flex-col gap-2">
                    <div className="flex flex-wrap items-center gap-3">
                      {logo
                        ? <img src={logo} alt="" className="h-6 w-6 rounded-sm object-contain shrink-0" />
                        : <KeyRound className="h-5 w-5 text-muted-foreground shrink-0" />}
                      <span className="text-sm font-medium text-foreground flex-1 min-w-0 truncate">{k.label}</span>
                      <TestButton testing={isTesting(k.id)} disabled={busy || isTesting(k.id)}
                        title={t('connectors.testTitle')} onClick={() => test(k.id, [k.id])} />
                    </div>
                    {testPanel(k.id)}
                  </div>
                )
              })}
            </section>
          )}
        </>
      )}
    </div>
  )
}

interface MispBody {
  name?: string
  url?: string
  key?: string
  verify_ssl?: boolean
  client_cert?: string
  client_key?: string
}

function MispForm({ instance, certFiles, busy, onSubmit, onCancel }: {
  instance?: MispInstance
  certFiles: string[]
  busy: boolean
  onSubmit: (body: MispBody) => void
  onCancel: () => void
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
    const body: MispBody = {
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
          <Input type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://misp.example.org"
            required className="h-9 font-mono" />
        </label>
        <label className={`${fieldLabel} md:col-span-2`}>
          {t('connectors.mispKey')}
          <Input type="password" value={key} onChange={e => setKey(e.target.value)} autoComplete="off" spellCheck={false}
            required={isNew || !instance?.has_key} className="h-9 font-mono"
            placeholder={instance?.has_key ? t('connectors.mispKeyKeep') + (instance.hint ? ` (…${instance.hint})` : '') : ''} />
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
      </div>
    </form>
  )
}
