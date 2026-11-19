import { useState } from 'react'
import { ChevronDown, Unplug, PowerOff } from 'lucide-react'
import { useI18n } from '@/i18n/useI18n'
import { rich } from '@/i18n/rich'

interface Props {
  label: string
  reason?: 'missing-key' | 'disabled'
}

export default function DisconnectedCard({ label, reason = 'missing-key' }: Props) {
  const [open, setOpen] = useState(false)
  const isDisabled = reason === 'disabled'
  const { t } = useI18n()

  return (
    <div className="rounded-lg border border-border overflow-hidden opacity-60">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 border-b border-border bg-muted/20 hover:bg-muted/30 transition-colors text-left"
      >
        <span className="font-semibold text-sm text-muted-foreground">{label}</span>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-border text-xs font-medium text-muted-foreground bg-muted/30">
            {isDisabled ? <PowerOff className="h-3 w-3" /> : <Unplug className="h-3 w-3" />}
            {isDisabled ? t('disconnected.disabled') : t('disconnected.missingKey')}
          </span>
          <ChevronDown className={`h-4 w-4 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {open && (
        <div className="px-4 py-4">
          <p className="text-sm text-muted-foreground">
            {rich(isDisabled ? t('disconnected.disabledText') : t('disconnected.missingKeyText'))}
          </p>
        </div>
      )}
    </div>
  )
}
