import { useState, type ReactNode } from 'react'
import { LogIn, LogOut } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import HeaderControls from '@/components/HeaderControls'
import PasswordChangeForm from '@/components/PasswordChangeForm'
import { useAuth } from '@/auth/context'
import { useI18n } from '@/i18n/useI18n'
import { authErrorText } from '@/i18n/errors'

function AuthShell({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  const { t } = useI18n()
  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div className="flex justify-end items-center gap-1 px-6 py-3">
        <HeaderControls />
      </div>
      <main className="flex-1 flex items-center justify-center px-4 pb-16">
        <div className="w-full max-w-sm flex flex-col gap-6">
          <div className="flex flex-col items-center gap-2">
            <img src="/app-logo.png" alt="" className="h-24 w-auto" />
            <span className="brand-wordmark flex flex-col items-center">
              <span className="text-[2.5rem]">
                <span className="brand-ink">INTEL</span><span className="brand-steel">CHECKER</span>
              </span>
              <span className="brand-tagline text-[0.6rem] font-semibold uppercase text-muted-foreground mt-1">
                {t('layout.tagline')}
              </span>
            </span>
          </div>
          <section className="rounded-lg border border-border bg-muted/20 p-6 flex flex-col gap-4">
            <div>
              <h1 className="text-lg font-semibold text-foreground">{title}</h1>
              <p className="text-sm text-muted-foreground mt-1">{subtitle}</p>
            </div>
            {children}
          </section>
        </div>
      </main>
    </div>
  )
}

export function LoginPage() {
  const { login } = useAuth()
  const i18n = useI18n()
  const { t } = i18n
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username.trim(), password)
    } catch (err) {
      setError(authErrorText(i18n, err))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell title={t('auth.signInTitle')} subtitle={t('auth.signInSubtitle')}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm text-foreground">
          {t('auth.username')}
          <Input autoComplete="username" autoFocus value={username}
            onChange={e => setUsername(e.target.value)} required />
        </label>
        <label className="flex flex-col gap-1 text-sm text-foreground">
          {t('auth.password')}
          <Input type="password" autoComplete="current-password" value={password}
            onChange={e => setPassword(e.target.value)} required />
        </label>
        <Button type="submit" disabled={busy || !username.trim() || !password} className="gap-2">
          <LogIn className="h-4 w-4" /> {busy ? t('auth.signingIn') : t('auth.signIn')}
        </Button>
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
      </form>
    </AuthShell>
  )
}

/** Shown after signing in with a temporary password: nothing else is reachable until it's changed. */
export function ForcePasswordChangePage() {
  const { logout } = useAuth()
  const { t } = useI18n()
  return (
    <AuthShell title={t('auth.mustChangeTitle')} subtitle={t('auth.mustChangeSubtitle')}>
      <PasswordChangeForm />
      <Button variant="ghost" size="sm" onClick={() => logout()} className="gap-1.5 self-center">
        <LogOut className="h-4 w-4" /> {t('auth.signOut')}
      </Button>
    </AuthShell>
  )
}

export function SessionCheckPage() {
  const { t } = useI18n()
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <p className="text-sm text-muted-foreground">{t('auth.checking')}</p>
    </div>
  )
}
