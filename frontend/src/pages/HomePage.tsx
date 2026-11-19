import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import Layout from '@/components/Layout'
import EngineStatusPanel from '@/components/EngineStatusPanel'
import { useI18n } from '@/i18n/useI18n'

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'asn', 'threat-actor'] as const

export default function HomePage() {
  const navigate = useNavigate()
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [iocType, setIocType] = useState('ip')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return
    navigate(`/results?indicator=${encodeURIComponent(query.trim())}&type=${iocType}`)
  }

  return (
    <Layout>
      <main className="flex-1 flex flex-col items-center justify-center px-4 gap-8">
        <div className="text-center space-y-6">
          <div className="space-y-2">
            <h1 className="text-3xl font-bold tracking-tight text-foreground">
              {t('home.title')}
            </h1>
            <p className="text-muted-foreground text-sm">
              {t('home.subtitle')}
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
                {IOC_TYPES.map(type => (
                  <SelectItem key={type} value={type}>
                    {t(`type.${type}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder={t('home.placeholder')}
              className="flex-1"
              autoFocus
            />
          </div>
          <Button type="submit" className="w-full gap-2" disabled={!query.trim()}>
            <Search className="h-4 w-4" />
            {t('home.analyze')}
          </Button>
        </form>

        <EngineStatusPanel selectedType={iocType} />
      </main>
    </Layout>
  )
}
