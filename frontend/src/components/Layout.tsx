import { History, SlidersHorizontal, BookOpen, LogOut, UserRound } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import HeaderControls from '@/components/HeaderControls'
import { useAuth } from '@/auth/context'
import { useI18n } from '@/i18n/useI18n'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const { t } = useI18n()
  const { user, can, logout } = useAuth()

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between shrink-0">
        <Link to="/" aria-label={t('layout.home')} className="flex items-center gap-3 hover:opacity-85 transition-opacity">
          <img src="/app-logo.png" alt="" className="h-20 w-auto" />
          <span className="brand-wordmark flex flex-col">
            <span className="text-[2.75rem]">
              <span className="brand-ink">INTEL</span><span className="brand-steel">CHECKER</span>
            </span>
            <span className="brand-tagline text-[0.6rem] font-semibold uppercase text-muted-foreground mt-1 pl-0.5">
              {t('layout.tagline')}
            </span>
          </span>
        </Link>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/history">
              <History className="h-4 w-4" />
              {t('layout.history')}
            </Link>
          </Button>
          {can('admin') && (
            <Button variant="ghost" size="sm" asChild className="gap-1.5">
              <Link to="/admin">
                <SlidersHorizontal className="h-4 w-4" />
                {t('layout.admin')}
              </Link>
            </Button>
          )}
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/docs">
              <BookOpen className="h-4 w-4" />
              {t('layout.docs')}
            </Link>
          </Button>
          <HeaderControls />
          {user && (
            <div className="ml-2 pl-2 border-l border-border flex items-center gap-1">
              <Button variant="ghost" size="sm" asChild className="gap-1.5" title={t('auth.account')}>
                <Link to="/account">
                  <UserRound className="h-4 w-4" />
                  <span className="flex flex-col items-start leading-tight">
                    <span className="text-sm">{user.username}</span>
                    <span className="text-[0.65rem] text-muted-foreground uppercase tracking-wide">{t(`role.${user.role}`)}</span>
                  </span>
                </Link>
              </Button>
              <Button variant="ghost" size="icon" onClick={() => logout()} aria-label={t('auth.signOut')} title={t('auth.signOut')}>
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          )}
        </div>
      </header>
      {children}
    </div>
  )
}
