import type { messages } from './messages'

export type Lang = 'en' | 'es'
export const LANGS: { id: Lang; label: string; name: string }[] = [
  { id: 'en', label: 'EN', name: 'English' },
  { id: 'es', label: 'ES', name: 'Español' },
]

export type MessageKey = keyof typeof messages.en
export type Vars = Record<string, string | number>
export type PluralKey = MessageKey extends infer K
  ? K extends `${infer Base}_one` ? Base : never
  : never

export type TFunction = (key: MessageKey, vars?: Vars) => string
export type TnFunction = (key: PluralKey, n: number, vars?: Vars) => string
