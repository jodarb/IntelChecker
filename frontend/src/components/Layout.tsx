import { Search, History, SlidersHorizontal, BookOpen, LogOut, UserRound, TriangleAlert, Users, Plug, Crosshair, Building2, VenetianMask } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import HeaderControls from '@/components/HeaderControls'
import { useAuth } from '@/auth/context'
import { rich } from '@/i18n/rich'
import { useI18n } from '@/i18n/useI18n'

export type SearchTab = 'artifacts' | 'actors' | 'companies'

interface LayoutProps {
  children: React.ReactNode
  /** Shows the search tabs under the header, with this one active (search and result pages) */
  tab?: SearchTab
}

// The three search tools — artifacts (IOCs), threat actors and companies — as tabs right under the
// header, not in the header menu: they are the app's two workspaces, the menu holds
// everything else (history, admin, docs).
function SearchTabs({ active }: { active: SearchTab }) {
  const { t } = useI18n()
  const tabs: { id: SearchTab; to: string; icon: React.ReactNode; label: string }[] = [
    { id: 'artifacts', to: '/', icon: <Crosshair className="h-5 w-5" />, label: t('tabs.artifacts') },
    { id: 'actors', to: '/actors', icon: <VenetianMask className="h-5 w-5" />, label: t('tabs.actors') },
    { id: 'companies', to: '/companies', icon: <Building2 className="h-5 w-5" />, label: t('tabs.companies') },
  ]
  return (
    <nav aria-label={t('tabs.label')} className="border-b border-border px-6 flex gap-1 shrink-0 bg-muted/10">
      {tabs.map(tab => {
        const on = tab.id === active
        return (
          <Link
            key={tab.id}
            to={tab.to}
            aria-current={on ? 'page' : undefined}
            className={`search-tab inline-flex items-center gap-2 px-5 py-3 -mb-px border-b-[3px] rounded-t-md text-base transition-colors ${
              on ? 'font-semibold text-foreground' : 'font-medium border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40 hover:border-border'
            }`}
          >
            {tab.icon}
            {tab.label}
          </Link>
        )
      })}
    </nav>
  )
}

export default function Layout({ children, tab }: LayoutProps) {
  const { t } = useI18n()
  const { user, can, logout } = useAuth()

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between shrink-0">
        {/* Brand, with the default admin / admin password warning right below the logo */}
        <div className="flex flex-col items-start gap-1.5">
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
        {user?.default_password && (
          <div role="alert" className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border-2 border-yellow-500/60 bg-yellow-500/10 text-xs whitespace-nowrap text-yellow-800 dark:text-yellow-200">
            <TriangleAlert className="h-4 w-4 shrink-0 text-yellow-600 dark:text-yellow-400" />
            <span>{rich(t('auth.defaultPasswordWarning'))}</span>
          </div>
        )}
        </div>
        <div className="flex items-center gap-1">
          {/* Back to the search tools from anywhere (history, admin, docs…) */}
          {can('analyze') && (
            <Button variant="ghost" size="sm" asChild className="gap-1.5">
              <Link to="/">
                <Search className="h-4 w-4" />
                {t('layout.search')}
              </Link>
            </Button>
          )}
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/history">
              <History className="h-4 w-4" />
              {t('layout.history')}
            </Link>
          </Button>
          {can('admin') && (
            <>
              <Button variant="ghost" size="sm" asChild className="gap-1.5">
                <Link to="/admin">
                  <SlidersHorizontal className="h-4 w-4" />
                  {t('layout.admin')}
                </Link>
              </Button>
              <Button variant="ghost" size="sm" asChild className="gap-1.5">
                <Link to="/users">
                  <Users className="h-4 w-4" />
                  {t('layout.users')}
                </Link>
              </Button>
              <Button variant="ghost" size="sm" asChild className="gap-1.5">
                <Link to="/connectors">
                  <Plug className="h-4 w-4" />
                  {t('layout.connectors')}
                </Link>
              </Button>
            </>
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
      {tab && can('analyze') && <SearchTabs active={tab} />}
      {children}
    </div>
  )
}
