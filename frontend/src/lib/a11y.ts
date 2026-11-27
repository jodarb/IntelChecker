import type { KeyboardEvent } from 'react'

/**
 * Keyboard support for a `div role="button"` (used where a real <button> can't be:
 * collapsible card headers that hold their own buttons, like RAW). Enter / Space on
 * the element itself act as a click; keys on the buttons inside are left alone.
 */
export function clickOnEnterOrSpace(e: KeyboardEvent<HTMLElement>) {
  if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
    e.preventDefault()
    e.currentTarget.click()
  }
}
