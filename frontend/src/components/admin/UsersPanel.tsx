import { useCallback, useEffect, useState } from 'react'
import { KeyRound, Power, Trash2, UserPlus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { apiJson } from '@/lib/api'
import { ROLES, useAuth, type Role } from '@/auth/context'
import { useI18n } from '@/i18n/useI18n'
import { authErrorText } from '@/i18n/errors'

interface UserRow {
  id: number
  username: string
  role: Role
  active: boolean
  must_change_password: boolean
  created_at: string
  last_login: string | null
}

const selectClass =
  'h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

function formatTimestamp(ts: string, locale: string): string {
  return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString(locale)
}

export default function UsersPanel() {
  const i18n = useI18n()
  const { t, locale } = i18n
  const { user: me } = useAuth()
  const [users, setUsers] = useState<UserRow[] | null>(null)
  const [loadFailed, setLoadFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)

  const [newName, setNewName] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<Role>('analyst')

  const load = useCallback(() => {
    apiJson<UserRow[]>('/users')
      .then(u => { setUsers(u); setLoadFailed(false) })
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
      return true
    } catch (err) {
      setMessage({ kind: 'error', text: authErrorText(i18n, err) })
      return false
    } finally {
      setBusy(false)
    }
  }

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    const username = newName.trim()
    const ok = await run(
      () => apiJson('/users', 'POST', { username, password: newPassword, role: newRole }),
      t('users.created', { username }),
    )
    if (ok) { setNewName(''); setNewPassword('') }
  }

  const patch = (u: UserRow, body: Partial<{ role: Role; active: boolean; password: string }>, ok: string) =>
    run(() => apiJson(`/users/${u.id}`, 'PATCH', body), ok)

  const resetPassword = (u: UserRow) => {
    const password = window.prompt(t('users.resetPrompt', { username: u.username }))
    if (!password) return
    patch(u, { password }, t('users.resetDone', { username: u.username }))
  }

  const remove = (u: UserRow) => {
    if (!window.confirm(t('users.deleteConfirm', { username: u.username }))) return
    run(() => apiJson(`/users/${u.id}`, 'DELETE'), t('users.deleted', { username: u.username }))
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
        <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('users.create')}</p>
        <p className="text-sm text-muted-foreground">{t('users.subtitle')}</p>
        <form onSubmit={create} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            {t('auth.username')}
            <Input value={newName} onChange={e => setNewName(e.target.value)} autoComplete="off"
              className="h-9 w-44" required />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            {t('users.tempPassword')}
            <Input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)}
              autoComplete="new-password" minLength={8} className="h-9 w-44" required />
          </label>
          <label className="flex flex-col gap-1 text-xs text-muted-foreground">
            {t('users.role')}
            <select value={newRole} onChange={e => setNewRole(e.target.value as Role)} className={selectClass}>
              {ROLES.map(r => <option key={r} value={r}>{t(`role.${r}`)}</option>)}
            </select>
          </label>
          <Button type="submit" size="sm" disabled={busy || !newName.trim() || newPassword.length < 8} className="gap-1.5">
            <UserPlus className="h-4 w-4" /> {busy ? t('users.creating') : t('users.create')}
          </Button>
        </form>
        <ul className="text-xs text-muted-foreground list-disc pl-5 flex flex-col gap-0.5">
          {ROLES.map(r => (
            <li key={r}><span className="text-foreground font-medium">{t(`role.${r}`)}</span> — {t(`role.${r}.desc`)}</li>
          ))}
        </ul>
      </section>

      {message && (
        <p role={message.kind === 'error' ? 'alert' : 'status'}
          className={`text-sm ${message.kind === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
          {message.text}
        </p>
      )}

      {loadFailed && (
        <div className="flex items-center gap-3">
          <p className="text-sm text-red-400">{t('users.loadError')}</p>
          <Button size="sm" variant="ghost" onClick={load}>{t('common.retry')}</Button>
        </div>
      )}
      {!loadFailed && users === null && <p className="text-sm text-muted-foreground">{t('common.loading')}</p>}

      {users && (
        <section className="flex flex-col gap-2">
          <div className="hidden md:grid grid-cols-[1fr_9rem_10rem_auto] gap-3 px-3 text-xs text-muted-foreground uppercase tracking-wide font-medium">
            <span>{t('users.colUser')}</span>
            <span>{t('users.colRole')}</span>
            <span>{t('users.colLastLogin')}</span>
            <span className="w-[7.5rem]" />
          </div>
          {users.map(u => {
            const isMe = u.id === me?.id
            return (
              <div key={u.id}
                className={`rounded-lg border border-border bg-muted/20 px-3 py-2 grid grid-cols-1 md:grid-cols-[1fr_9rem_10rem_auto] items-center gap-3 ${u.active ? '' : 'opacity-60'}`}>
                <div className="flex flex-col min-w-0">
                  <span className="text-sm font-medium text-foreground truncate">
                    {u.username}{isMe && <span className="text-muted-foreground font-normal"> ({t('users.you')})</span>}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {u.active ? t('users.active') : t('users.disabled')}
                    {u.must_change_password && <> · {t('users.pendingChange')}</>}
                  </span>
                </div>
                <select
                  value={u.role}
                  disabled={busy || isMe}
                  aria-label={t('users.role')}
                  onChange={e => patch(u, { role: e.target.value as Role }, t('users.updated', { username: u.username }))}
                  className={selectClass}
                >
                  {ROLES.map(r => <option key={r} value={r}>{t(`role.${r}`)}</option>)}
                </select>
                <span className="text-xs text-muted-foreground">
                  {u.last_login ? formatTimestamp(u.last_login, locale) : t('users.never')}
                </span>
                <div className="flex items-center gap-1 justify-end">
                  <Button variant="ghost" size="icon" disabled={busy} onClick={() => resetPassword(u)}
                    title={t('users.resetPassword')} aria-label={t('users.resetPassword')} className="h-9 w-9">
                    <KeyRound className="h-4 w-4" />
                  </Button>
                  <Button variant="ghost" size="icon" disabled={busy || isMe}
                    onClick={() => patch(u, { active: !u.active }, t('users.updated', { username: u.username }))}
                    title={u.active ? t('users.disable') : t('users.enable')}
                    aria-label={u.active ? t('users.disable') : t('users.enable')} className="h-9 w-9">
                    <Power className="h-4 w-4" />
                  </Button>
                  <Button variant="ghost" size="icon" disabled={busy || isMe} onClick={() => remove(u)}
                    title={t('users.delete')} aria-label={t('users.delete')} className="h-9 w-9 hover:text-red-400">
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )
          })}
        </section>
      )}
    </div>
  )
}
