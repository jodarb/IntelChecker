import { useState } from 'react'
import { ChevronDown, Unplug } from 'lucide-react'

interface Props {
  label: string
}

export default function DisconnectedCard({ label }: Props) {
  const [open, setOpen] = useState(false)

  return (
    <div className="rounded-lg border border-border overflow-hidden opacity-60">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/20 hover:bg-muted/30 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-muted-foreground">{label}</span>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30">
            <Unplug className="h-3 w-3" />
            Disconnected
          </span>
          <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {open && (
        <div className="px-4 py-4">
          <p className="text-sm text-muted-foreground">
            No API key configured for this source. Add it to <code className="text-xs bg-muted px-1 py-0.5 rounded">backend/.env</code> to enable it.
          </p>
        </div>
      )}
    </div>
  )
}
