import Layout from '@/components/Layout'
import PasswordChangeForm from '@/components/PasswordChangeForm'
import { useAuth } from '@/auth/context'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'
import BackButton from '@/components/BackButton'

export default function AccountPage() {
  const { user } = useAuth()
  const { t } = useI18n()
  if (!user) return null
  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-md mx-auto flex flex-col gap-6">
        <div className="flex items-start gap-4">
          <BackButton />
          <div>
            <h2 className="text-xl font-semibold text-foreground">{t('auth.accountTitle')}</h2>
            <p className="text-sm text-muted-foreground mt-1">
              {rich(t('auth.accountSubtitle', { username: user.username, role: t(`role.${user.role}`) }))}
            </p>
            <p className="text-xs text-muted-foreground mt-1">{t(`role.${user.role}.desc`)}</p>
          </div>
        </div>
        <section className="rounded-lg border border-border bg-muted/20 p-4 flex flex-col gap-3">
          <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">{t('auth.changePassword')}</p>
          <PasswordChangeForm />
        </section>
      </main>
    </Layout>
  )
}
