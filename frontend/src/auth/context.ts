import { createContext, useContext } from 'react'

export type Role = 'admin' | 'analyst' | 'reader'
export type Permission = 'history:read' | 'analyze' | 'admin'

export const ROLES: Role[] = ['admin', 'analyst', 'reader']

export interface AuthUser {
  id: number
  username: string
  role: Role
  must_change_password: boolean
  /** Still signed in with the built-in admin / admin password: the header shows a warning. */
  default_password: boolean
  permissions: Permission[]
}

export interface AuthValue {
  /** undefined while the session is being checked, null when signed out */
  user: AuthUser | null | undefined
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  changePassword: (current: string, next: string) => Promise<void>
  can: (p: Permission) => boolean
}

export const AuthContext = createContext<AuthValue | null>(null)

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
