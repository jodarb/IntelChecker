import { messages } from './messages'
import type { I18nValue } from './context'
import type { MessageKey } from './types'

/** Frontend fetch failure. Stored verbatim in results and History snapshots; translated on display. */
export const BACKEND_DOWN = 'Could not reach the backend. Is it running?'

/**
 * Human-readable text for a source error. The backend writes actionable English
 * messages (sometimes with extra detail, e.g. a plan's rate limit); English keeps
 * them verbatim, other languages translate by error code and fall back to the
 * original text for codes without a translation.
 */
export function apiErrorText(
  i18n: Pick<I18nValue, 'lang' | 't'>,
  err: { code?: string; message?: string } | string | null | undefined,
  source: string,
): string | null {
  if (!err) return null
  if (typeof err === 'string') return err
  const key = `apiError.${err.code}` as MessageKey
  if (i18n.lang !== 'en' && err.code && key in messages.en) return i18n.t(key, { source })
  return err.message ?? (err.code ? i18n.t(key, { source }) : null)
}

/** Text for an auth / user-management error from the backend, translated by code. */
export function authErrorText(
  i18n: Pick<I18nValue, 't'>,
  err: unknown,
): string {
  if (err instanceof TypeError) return i18n.t('common.backendDown')
  const code = (err as { code?: string })?.code
  const key = `authError.${code}` as MessageKey
  if (code && key in messages.en) return i18n.t(key)
  if (err instanceof Error && err.message) return err.message
  return i18n.t('admin.unexpected')
}
