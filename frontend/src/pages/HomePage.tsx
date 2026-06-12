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
import CustomLogo from '@/components/CustomLogo'
import EngineStatusPanel from '@/components/EngineStatusPanel'

const IOC_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash', label: 'File Hash' },
  { value: 'asn', label: 'ASN' },
  { value: 'threat-actor', label: 'Threat Actor' },
]

export default function HomePage() {
  const navigate = useNavigate()
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
          <Button type="submit" className="w-full gap-2" disabled={!query.trim()}>
            <Search className="h-4 w-4" />
            Analyze
          </Button>
        </form>

        <EngineStatusPanel selectedType={iocType} />
      </main>
    </Layout>
  )
}
