import { createContext } from 'react'
import type { Lang, TFunction, TnFunction } from './types'

export interface I18nValue {
  lang: Lang
  setLang: (l: Lang) => void
  /** BCP 47 locale for Intl / toLocaleString */
  locale: string
  t: TFunction
  /** Plural-aware t: picks `<key>_one` when n === 1, `<key>_other` otherwise; `{n}` is filled in. */
  tn: TnFunction
}

export const I18nContext = createContext<I18nValue | null>(null)
