import type { ReactNode } from 'react'
import { useAuth } from './context'
import { LoginPage, ForcePasswordChangePage, SessionCheckPage } from '@/pages/LoginPage'

/** Nothing below this renders (or calls the API) until there is a usable session. */
export function AuthGate({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  if (user === undefined) return <SessionCheckPage />
  if (user === null) return <LoginPage />
  if (user.must_change_password) return <ForcePasswordChangePage />
  return children
}
