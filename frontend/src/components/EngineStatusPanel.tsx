import { useEffect, useState } from 'react'
import { ENGINES } from '@/registry'
import { useEngineToggles } from '@/hooks/useEngineToggles'

const BACKEND = 'http://localhost:8002'

const TYPE_CHIP: Record<string, string> = {
  ip: 'IP',
  domain: 'Domain',
  url: 'URL',
  hash: 'Hash',
  asn: 'ASN',
  'threat-actor': 'Actor',
}

interface EngineStatus {
  connected: boolean
  supports: string[]
}

type StatusMap = Record<string, EngineStatus>

interface Props {
  selectedType: string
}

function ToggleSwitch({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      title={enabled ? 'Disable this source for the next search' : 'Enable this source'}
      onClick={onToggle}
      className={`relative inline-flex h-4 w-7 shrink-0 items-center rounded-full transition-colors ${
        enabled ? 'bg-primary' : 'bg-muted-foreground/30'
      }`}
    >
      <span
        className={`inline-block h-3 w-3 transform rounded-full bg-background transition-transform ${
          enabled ? 'translate-x-3.5' : 'translate-x-0.5'
        }`}
      />
    </button>
  )
}

export default function EngineStatusPanel({ selectedType }: Props) {
  const [status, setStatus] = useState<StatusMap | null>(null)
  const { disabled, toggle } = useEngineToggles()

  useEffect(() => {
    fetch(`${BACKEND}/engines/status`)
      .then(r => r.json())
      .then(setStatus)
      .catch(() => setStatus(null))
  }, [])

  if (!status) return null

  return (
    <div className="w-full max-w-2xl flex flex-col gap-2">
      <p className="text-xs text-muted-foreground uppercase tracking-wide font-medium">
        Connected sources
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {ENGINES.map(engine => {
          const s = status[engine.id]
          const connected = s?.connected ?? false
          const relevant = (s?.supports ?? engine.supports).includes(selectedType)
          const enabled = !disabled.has(engine.id)

          return (
            <div
              key={engine.id}
              className={`flex items-center justify-between gap-3 px-3 py-2 rounded-lg border transition-all duration-200 ${
                relevant
                  ? connected
                    ? enabled
                      ? 'border-border bg-muted/30 shadow-sm'
                      : 'border-border/50 bg-muted/10 opacity-60'
                    : 'border-border/50 bg-muted/10 opacity-50'
                  : 'border-border/30 bg-muted/5 opacity-25'
              }`}
            >
              {/* Left: status dot + name */}
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className={`shrink-0 h-2 w-2 rounded-full ${
                    connected ? (enabled ? 'bg-green-500' : 'bg-amber-500') : 'bg-muted-foreground'
                  }`}
                />
                <span className={`text-sm font-medium truncate ${
                  relevant ? 'text-foreground' : 'text-muted-foreground'
                }`}>
                  {engine.label}
                </span>
              </div>

              {/* Right: type chips + on/off */}
              <div className="flex items-center gap-2 shrink-0">
                <div className="flex items-center gap-1">
                  {(s?.supports ?? engine.supports).map(type => (
                    <span
                      key={type}
                      className={`px-1.5 py-0.5 rounded text-xs border transition-colors ${
                        type === selectedType
                          ? 'bg-primary/15 border-primary/40 text-primary font-medium'
                          : 'bg-muted border-border text-muted-foreground'
                      }`}
                    >
                      {TYPE_CHIP[type] ?? type}
                    </span>
                  ))}
                </div>
                {connected && (
                  <ToggleSwitch enabled={enabled} onToggle={() => toggle(engine.id)} />
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
