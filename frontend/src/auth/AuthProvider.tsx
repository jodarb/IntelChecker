import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { AuthContext, type AuthUser, type Permission } from './context'
import { AUTH_EXPIRED_EVENT, apiFetch, apiJson } from '@/lib/api'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null | undefined>(undefined)

  useEffect(() => {
    apiFetch('/auth/me')
      .then(r => (r.ok ? r.json() : null))
      .then((u: AuthUser | null) => setUser(u))
      .catch(() => setUser(null))
  }, [])

  // Any request answered with 401 (expired or revoked session) signs the UI out.
  useEffect(() => {
    const onExpired = () => setUser(null)
    window.addEventListener(AUTH_EXPIRED_EVENT, onExpired)
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, onExpired)
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    setUser(await apiJson<AuthUser>('/auth/login', 'POST', { username, password }))
  }, [])

  const logout = useCallback(async () => {
    await apiFetch('/auth/logout', { method: 'POST' }).catch(() => {})
    setUser(null)
  }, [])

  const changePassword = useCallback(async (current: string, next: string) => {
    setUser(await apiJson<AuthUser>('/auth/password', 'PUT', {
      current_password: current, new_password: next,
    }))
  }, [])

  const can = useCallback((p: Permission) => !!user?.permissions.includes(p), [user])

  const value = useMemo(
    () => ({ user, login, logout, changePassword, can }),
    [user, login, logout, changePassword, can],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
