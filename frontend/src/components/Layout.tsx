import { Sun, Moon, History, SlidersHorizontal } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useTheme } from '@/hooks/useTheme'

interface LayoutProps {
  children: React.ReactNode
}

export default function Layout({ children }: LayoutProps) {
  const { theme, toggle } = useTheme()

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between shrink-0">
        <Link to="/" aria-label="IntelChecker — home" className="flex items-center gap-3 hover:opacity-85 transition-opacity">
          <img src="/app-logo.png" alt="" className="h-20 w-auto" />
          <span className="brand-wordmark flex flex-col">
            <span className="text-[2.75rem]">
              <span className="brand-ink">INTEL</span><span className="brand-steel">CHECKER</span>
            </span>
            <span className="brand-tagline text-[0.6rem] font-semibold uppercase text-muted-foreground mt-1 pl-0.5">
              Threat intel triage
            </span>
          </span>
        </Link>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/history">
              <History className="h-4 w-4" />
              History
            </Link>
          </Button>
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/admin">
              <SlidersHorizontal className="h-4 w-4" />
              Admin
            </Link>
          </Button>
          <Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>
      </header>
      {children}
    </div>
  )
}
