import { useState, useEffect } from 'react'
import { Sun, Moon, Search, ShieldAlert, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

function CustomLogo() {
  const [visible, setVisible] = useState(true)
  const [enabled, setEnabled] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/config.json')
      .then(r => r.json())
      .then(cfg => setEnabled(cfg.showLogo ?? true))
      .catch(() => setEnabled(true))
  }, [])

  if (enabled === null || !enabled || !visible) return null

  return (
    <img
      src="/logo.svg"
      alt="Organization logo"
      className="h-12 mx-auto object-contain"
      onError={() => setVisible(false)}
    />
  )
}

const IOC_TYPES = [
  { value: 'auto', label: 'Auto Detect' },
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'asn', label: 'ASN' },
  { value: 'threat-actor', label: 'Threat Actor' },
]

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('theme') as 'dark' | 'light') ?? 'dark'
  })
  const [query, setQuery] = useState('')
  const [iocType, setIocType] = useState('auto')
  const [result, setResult] = useState<object | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('theme', theme)
  }, [theme])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return

    setLoading(true)
    setResult(null)
    setError(null)

    try {
      const res = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: query.trim(), type: iocType }),
      })
      const json = await res.json()
      setResult(json)
    } catch (err) {
      setError('Could not reach the backend. Is it running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <header className="border-b border-border px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2 text-primary font-semibold tracking-wide">
          <ShieldAlert className="h-5 w-5" />
          <span>IntelChecker</span>
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </header>

      <main className="flex-1 flex flex-col items-center justify-center px-4 gap-8">
        <div className="text-center space-y-6">
          <CustomLogo />
          <div className="space-y-2">
            <h1 className="text-3xl font-bold tracking-tight text-foreground">
              Threat Intelligence Lookup
            </h1>
            <p className="text-muted-foreground text-sm">
              Analyze IPs, domains, URLs, ASNs and threat actors across multiple CTI sources.
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="w-full max-w-2xl flex flex-col gap-3">
          <div className="flex gap-2">
            <Select value={iocType} onValueChange={setIocType}>
              <SelectTrigger className="w-44 shrink-0">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {IOC_TYPES.map(t => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Enter an IP, domain, URL, ASN or threat actor..."
              className="flex-1"
              autoFocus
            />
          </div>
          <Button type="submit" className="w-full gap-2" disabled={!query.trim() || loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            {loading ? 'Analyzing...' : 'Analyze'}
          </Button>
        </form>

        {error && (
          <div className="w-full max-w-2xl rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {error}
          </div>
        )}

        {result && (
          <div className="w-full max-w-2xl">
            <pre className="rounded-md border border-border bg-muted p-4 text-xs text-foreground overflow-auto max-h-[60vh]">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </main>
    </div>
  )
}
