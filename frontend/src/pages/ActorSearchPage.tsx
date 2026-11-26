import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import Layout from '@/components/Layout'
import EngineStatusPanel from '@/components/EngineStatusPanel'
import ActorResolver from '@/components/ActorResolver'
import { useI18n } from '@/i18n/useI18n'

/**
 * Threat actor search: a name or alias. Names are spelled many ways ("Gentleman" for
 * The Gentlemen), so the analyst first picks the actor among candidates; it is then
 * looked up by the name most sources know it by.
 */
export default function ActorSearchPage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [resolving, setResolving] = useState<string | null>(null)

  const go = (name: string) => navigate(`/results?indicator=${encodeURIComponent(name)}&type=threat-actor`)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const q = query.trim()
    if (!q) return
    setResolving(q)
  }

  return (
    <Layout tab="actors">
      <main className="flex-1 flex flex-col items-center justify-start px-4 pt-16 pb-10 gap-8">
        <div className="text-center space-y-2">
          <h1 className="text-3xl font-bold tracking-tight text-foreground">{t('actors.title')}</h1>
          <p className="text-muted-foreground text-sm">{t('actors.subtitle')}</p>
        </div>

        <form onSubmit={handleSubmit} className="w-full max-w-2xl flex flex-col gap-3">
          <Input
            value={query}
            onChange={e => { setQuery(e.target.value); setResolving(null) }}
            placeholder={t('actors.placeholder')}
            autoFocus
          />
          <Button type="submit" className="w-full gap-2" disabled={!query.trim()}>
            <Search className="h-4 w-4" />
            {t('actors.search')}
          </Button>
        </form>

        {resolving && <ActorResolver query={resolving} onPick={go} />}

        <EngineStatusPanel selectedType="threat-actor" scope="actors" />
      </main>
    </Layout>
  )
}
