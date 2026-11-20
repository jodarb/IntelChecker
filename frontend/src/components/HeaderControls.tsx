import { Sun, Moon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTheme } from '@/hooks/useTheme'
import { useI18n } from '@/i18n/useI18n'
import { LANGS } from '@/i18n/types'

/** Language selector + theme toggle, shared by the app header and the sign-in screen. */
export default function HeaderControls() {
  const { theme, toggle } = useTheme()
  const { t, lang, setLang } = useI18n()
  return (
    <>
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
    </>
  )
}
