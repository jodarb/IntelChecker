import { Sun, Moon, History, SlidersHorizontal, BookOpen } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useTheme } from '@/hooks/useTheme'
import { useI18n } from '@/i18n/useI18n'
import { LANGS } from '@/i18n/types'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const { theme, toggle } = useTheme()
  const { t, lang, setLang } = useI18n()

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
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/admin">
              <SlidersHorizontal className="h-4 w-4" />
              {t('layout.admin')}
            </Link>
          </Button>
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/docs">
              <BookOpen className="h-4 w-4" />
              {t('layout.docs')}
            </Link>
          </Button>
          <div
            role="radiogroup"
            aria-label={t('layout.language')}
            className="ml-1 inline-flex items-center rounded-md border border-border p-0.5 text-xs font-semibold"
          >
            {LANGS.map(l => (
              <button
                key={l.id}
                type="button"
                role="radio"
                aria-checked={lang === l.id}
                title={l.name}
                onClick={() => setLang(l.id)}
                className={`px-2 py-1 rounded transition-colors ${lang === l.id
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:text-foreground hover:bg-muted/60'}`}
              >
                {l.label}
              </button>
            ))}
          </div>
          <Button variant="ghost" size="icon" onClick={toggle} aria-label={t('layout.toggleTheme')}>
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>
      </header>
      {children}
    </div>
  )
}
