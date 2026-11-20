import { useState } from 'react'
import { KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { useAuth } from '@/auth/context'
import { useI18n } from '@/i18n/useI18n'
import { authErrorText } from '@/i18n/errors'

export default function PasswordChangeForm({ onDone }: { onDone?: () => void }) {
  const { changePassword } = useAuth()
  const i18n = useI18n()
  const { t } = i18n
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (next !== confirm) return setMessage({ kind: 'error', text: t('auth.passwordMismatch') })
    setBusy(true)
    setMessage(null)
    try {
      await changePassword(current, next)
      setCurrent(''); setNext(''); setConfirm('')
      setMessage({ kind: 'ok', text: t('auth.passwordChanged') })
      onDone?.()
    } catch (err) {
      setMessage({ kind: 'error', text: authErrorText(i18n, err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <label className="flex flex-col gap-1 text-sm text-foreground">
        {t('auth.currentPassword')}
        <Input type="password" autoComplete="current-password" value={current}
          onChange={e => setCurrent(e.target.value)} required />
      </label>
      <label className="flex flex-col gap-1 text-sm text-foreground">
        {t('auth.newPassword')}
        <Input type="password" autoComplete="new-password" minLength={8} value={next}
          onChange={e => setNext(e.target.value)} required />
        <span className="text-xs text-muted-foreground">{t('auth.passwordHint')}</span>
      </label>
      <label className="flex flex-col gap-1 text-sm text-foreground">
        {t('auth.confirmPassword')}
        <Input type="password" autoComplete="new-password" minLength={8} value={confirm}
          onChange={e => setConfirm(e.target.value)} required />
      </label>
      <Button type="submit" disabled={busy || !current || !next || !confirm} className="gap-2">
        <KeyRound className="h-4 w-4" /> {t('auth.changePassword')}
      </Button>
      {message && (
        <p role={message.kind === 'error' ? 'alert' : 'status'}
          className={`text-sm ${message.kind === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
          {message.text}
        </p>
      )}
    </form>
  )
}
