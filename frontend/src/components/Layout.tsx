import { useEffect, useRef, useState } from 'react'
import { Search, History, SlidersHorizontal, BookOpen, LogOut, UserRound, TriangleAlert, Users, Plug, Crosshair, Building2, VenetianMask, Menu, X } from 'lucide-react'
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
    <nav aria-label={t('tabs.label')} className="border-b border-border px-2 sm:px-6 flex gap-1 shrink-0 bg-muted/10 overflow-x-auto">
      {tabs.map(tab => {
        const on = tab.id === active
        return (
          <Link
            key={tab.id}
            to={tab.to}
            aria-current={on ? 'page' : undefined}
            className={`search-tab inline-flex items-center gap-2 px-3 sm:px-5 py-3 whitespace-nowrap shrink-0 -mb-px border-b-[3px] rounded-t-md text-base transition-colors ${
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

// Header menu entry. Between `md` and `xl` the labels don't fit next to the brand:
// icon only, with the label as tooltip / accessible name (phones use the drop-down).
function NavItem({ to, icon, label }: { to: string; icon: React.ReactNode; label: string }) {
  return (
    <Button variant="ghost" size="sm" asChild className="gap-1.5" title={label}>
      <Link to={to} aria-label={label}>
        {icon}
        <span className="hidden xl:inline">{label}</span>
      </Link>
    </Button>
  )
}

export default function Layout({ children, tab }: LayoutProps) {
  const { t } = useI18n()
  const { user, can, logout } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  // The drop-down closes with Escape or a click outside it.
  useEffect(() => {
    if (!menuOpen) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenuOpen(false) }
    const onDown = (e: MouseEvent) => { if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false) }
    window.addEventListener('keydown', onKey)
    window.addEventListener('mousedown', onDown)
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('mousedown', onDown) }
  }, [menuOpen])

  const nav: { to: string; icon: React.ReactNode; label: string }[] = [
    // Back to the search tools from anywhere (history, admin, docs…)
    ...(can('analyze') ? [{ to: '/', icon: <Search className="h-4 w-4" />, label: t('layout.search') }] : []),
    { to: '/history', icon: <History className="h-4 w-4" />, label: t('layout.history') },
    ...(can('admin') ? [
      { to: '/admin', icon: <SlidersHorizontal className="h-4 w-4" />, label: t('layout.admin') },
      { to: '/users', icon: <Users className="h-4 w-4" />, label: t('layout.users') },
      { to: '/connectors', icon: <Plug className="h-4 w-4" />, label: t('layout.connectors') },
    ] : []),
    { to: '/docs', icon: <BookOpen className="h-4 w-4" />, label: t('layout.docs') },
  ]

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 shrink-0">
        {/* Brand, with the default admin / admin password warning right below the logo */}
        <div className="flex flex-col items-start gap-1.5 min-w-0">
        <Link to="/" aria-label={t('layout.home')} className="flex items-center gap-3 hover:opacity-85 transition-opacity">
          <img src="/app-logo.png" alt="" className="h-14 sm:h-20 w-auto" />
          <span className="brand-wordmark flex flex-col">
            <span className="text-[2rem] sm:text-[2.75rem]">
              <span className="brand-ink">INTEL</span><span className="brand-steel">CHECKER</span>
            </span>
            <span className="brand-tagline hidden sm:block text-[0.6rem] font-semibold uppercase text-muted-foreground mt-1 pl-0.5">
              {t('layout.tagline')}
            </span>
          </span>
        </Link>
        {user?.default_password && (
          <div role="alert" className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border-2 border-yellow-500/60 bg-yellow-500/10 text-xs sm:whitespace-nowrap text-yellow-800 dark:text-yellow-200">
            <TriangleAlert className="h-4 w-4 shrink-0 text-yellow-600 dark:text-yellow-400" />
            <span>{rich(t('auth.defaultPasswordWarning'))}</span>
          </div>
        )}
        </div>
        {/* Wide screens: the menu in the header (labels from `xl`, icons below) */}
        <div className="hidden md:flex flex-wrap items-center gap-1">
          {nav.map(n => <NavItem key={n.to} {...n} />)}
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
        {/* Phones: one menu button, the entries with their labels in a drop-down */}
        <div ref={menuRef} className="md:hidden relative">
          <Button variant="ghost" size="icon" onClick={() => setMenuOpen(o => !o)}
            aria-expanded={menuOpen} aria-controls="app-menu" aria-label={t('layout.menu')}>
            {menuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
          {menuOpen && (
            <div id="app-menu" className="absolute right-0 top-full mt-2 z-50 w-64 rounded-lg border border-border bg-background shadow-xl p-2 flex flex-col gap-1"
              onClick={e => { if ((e.target as HTMLElement).closest('a')) setMenuOpen(false) }}>
              {nav.map(n => (
                <Link key={n.to} to={n.to} className="flex items-center gap-2 px-3 py-2 rounded-md text-sm hover:bg-muted/60">
                  {n.icon}{n.label}
                </Link>
              ))}
              <div className="flex items-center gap-1 px-2 py-1 border-t border-border mt-1 pt-2"><HeaderControls /></div>
              {user && (
                <div className="flex items-center justify-between gap-1 border-t border-border mt-1 pt-1">
                  <Link to="/account" className="flex items-center gap-2 px-3 py-2 rounded-md text-sm hover:bg-muted/60 min-w-0">
                    <UserRound className="h-4 w-4 shrink-0" />
                    <span className="truncate">{user.username}</span>
                    <span className="text-[0.65rem] text-muted-foreground uppercase tracking-wide">{t(`role.${user.role}`)}</span>
                  </Link>
                  <Button variant="ghost" size="icon" onClick={() => logout()} aria-label={t('auth.signOut')} title={t('auth.signOut')}>
                    <LogOut className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>
      </header>
      {tab && can('analyze') && <SearchTabs active={tab} />}
      {children}
    </div>
  )
}
