import { Sun, Moon, ShieldAlert, History } from 'lucide-react'
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
        <Link to="/" className="flex items-center gap-2 text-primary font-semibold tracking-wide hover:opacity-80 transition-opacity">
          <ShieldAlert className="h-5 w-5" />
          <span>IntelChecker</span>
        </Link>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" asChild className="gap-1.5">
            <Link to="/history">
              <History className="h-4 w-4" />
              History
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
