import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { I18nContext } from './context'
import { messages } from './messages'
import type { Lang, MessageKey, PluralKey, Vars } from './types'

const STORAGE_KEY = 'intelchecker.lang'

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'en' || saved === 'es') return saved
  } catch { /* storage blocked */ }
  return navigator.language?.toLowerCase().startsWith('es') ? 'es' : 'en'
}

const fill = (s: string, vars?: Vars) =>
  vars ? s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m)) : s

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang)

  useEffect(() => {
    document.documentElement.lang = lang
    try { localStorage.setItem(STORAGE_KEY, lang) } catch { /* storage blocked */ }
  }, [lang])

  const t = useCallback((key: MessageKey, vars?: Vars) => {
    const s = messages[lang][key] ?? messages.en[key] ?? key
    return fill(s, vars)
  }, [lang])

  const tn = useCallback((key: PluralKey, n: number, vars?: Vars) => {
    const k = `${key}_${n === 1 ? 'one' : 'other'}` as MessageKey
    return t(k, { n, ...vars })
  }, [t])

  const value = useMemo(() => ({
    lang,
    setLang: setLangState,
    locale: lang === 'es' ? 'es-ES' : 'en-US',
    t,
    tn,
  }), [lang, t, tn])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}
