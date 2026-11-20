import { useCallback, useEffect, useState } from 'react'
import { Check, Copy, KeySquare, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { apiJson } from '@/lib/api'
import { useI18n } from '@/i18n/useI18n'
import { authErrorText } from '@/i18n/errors'
import { rich } from '@/i18n/rich'

interface ApiToken {
  id: number
  name: string
  prefix: string
  created_at: string
  last_used: string | null
  expires_at: string | null
  expired: boolean
}

const EXPIRY_OPTIONS = [30, 90, 365, 0] as const  // 0 = never

const selectClass =
  'h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

function formatTimestamp(ts: string, locale: string): string {
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString(locale)
}

/** API tokens of one user: list, create (the secret is shown once) and revoke. */
export default function TokensSection({ userId, username, onChange }: {
  userId: number
  username: string
  onChange: () => void
}) {
  const i18n = useI18n()
  const { t, locale } = i18n
  const [tokens, setTokens] = useState<ApiToken[] | null>(null)
  const [name, setName] = useState('')
  const [expiry, setExpiry] = useState<number>(90)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const load = useCallback(() => {
    apiJson<ApiToken[]>(`/users/${userId}/tokens`)
      .then(setTokens)
      .catch(err => setError(authErrorText(i18n, err)))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId])

  useEffect(() => { load() }, [load])

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true); setError(null); setCreated(null); setCopied(false)
    try {
      const res = await apiJson<ApiToken & { token: string }>(`/users/${userId}/tokens`, 'POST', {
        name: name.trim(), expires_in_days: expiry === 0 ? null : expiry,
      })
      setCreated(res.token)
      setName('')
      load(); onChange()
    } catch (err) {
      setError(authErrorText(i18n, err))
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (tok: ApiToken) => {
    if (!window.confirm(t('tokens.revokeConfirm', { name: tok.name, username }))) return
    setBusy(true); setError(null)
    try {
      await apiJson(`/users/${userId}/tokens/${tok.id}`, 'DELETE')
      load(); onChange()
    } catch (err) {
      setError(authErrorText(i18n, err))
    } finally {
      setBusy(false)
    }
  }

  const copy = async () => {
    if (!created) return
    try {
      await navigator.clipboard.writeText(created)
      setCopied(true)
    } catch {
      // Clipboard API unavailable (plain HTTP on a non-localhost host): the value is selectable.
    }
  }

  return (
    <div className="flex flex-col gap-3 border-t border-border/60 pt-3 mt-1">
      <p className="text-xs text-muted-foreground">{rich(t('tokens.help'))}</p>

      {created && (
        <div role="status" className="flex flex-col gap-2 rounded-md border border-green-500/40 bg-green-500/10 p-3">
          <span className="text-xs font-medium text-green-700 dark:text-green-300">{t('tokens.createdOnce')}</span>
          <div className="flex items-center gap-2">
            <code className="flex-1 min-w-0 break-all rounded bg-background px-2 py-1.5 text-xs font-mono text-foreground select-all">
              {created}
            </code>
            <Button type="button" size="sm" variant="outline" onClick={copy} className="gap-1.5 shrink-0">
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              {copied ? t('tokens.copied') : t('tokens.copy')}
            </Button>
          </div>
        </div>
      )}

      {tokens && tokens.length === 0 && <p className="text-xs text-muted-foreground">{t('tokens.none')}</p>}
      {tokens && tokens.length > 0 && (
        <ul className="flex flex-col gap-1.5">
          {tokens.map(tok => (
            <li key={tok.id} className={`flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md bg-background/60 px-2 py-1.5 text-xs ${tok.expired ? 'opacity-60' : ''}`}>
              <KeySquare className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <span className="font-medium text-foreground">{tok.name}</span>
              <code className="font-mono text-muted-foreground">{tok.prefix}…</code>
              <span className="text-muted-foreground">
                {t('tokens.created', { date: formatTimestamp(tok.created_at, locale) })}
              </span>
              <span className="text-muted-foreground">
                {tok.last_used ? t('tokens.lastUsed', { date: formatTimestamp(tok.last_used, locale) }) : t('tokens.neverUsed')}
              </span>
              <span className={tok.expired ? 'text-red-400' : 'text-muted-foreground'}>
                {tok.expires_at
                  ? t(tok.expired ? 'tokens.expired' : 'tokens.expires', { date: formatTimestamp(tok.expires_at, locale) })
                  : t('tokens.noExpiry')}
              </span>
              <Button variant="ghost" size="icon" disabled={busy} onClick={() => revoke(tok)}
                title={t('tokens.revoke')} aria-label={t('tokens.revoke')} className="h-7 w-7 ml-auto hover:text-red-400">
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </li>
          ))}
        </ul>
      )}

      <form onSubmit={create} className="flex flex-wrap items-end gap-2">
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          {t('tokens.name')}
          <Input value={name} onChange={e => setName(e.target.value)} maxLength={64}
            placeholder={t('tokens.namePlaceholder')} className="h-9 w-48" required />
        </label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">
          {t('tokens.expiry')}
          <select value={expiry} onChange={e => setExpiry(Number(e.target.value))} className={selectClass}>
            {EXPIRY_OPTIONS.map(d => (
              <option key={d} value={d}>{d === 0 ? t('tokens.never') : t('tokens.days', { n: d })}</option>
            ))}
          </select>
        </label>
        <Button type="submit" size="sm" variant="outline" disabled={busy || !name.trim()} className="gap-1.5">
          <KeySquare className="h-4 w-4" /> {t('tokens.create')}
        </Button>
      </form>

      {error && <p role="alert" className="text-xs text-red-400">{error}</p>}
    </div>
  )
}
