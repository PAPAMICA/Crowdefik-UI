import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { apiFetch, setToken, getToken } from './api'

export type Me = { id: number; username: string; is_superuser: boolean }

type Ctx = {
  me: Me | null
  loading: boolean
  refresh: () => Promise<void>
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<Ctx | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    const token = getToken()
    if (!token) {
      setMe(null)
      setLoading(false)
      return
    }
    const res = await apiFetch('/api/auth/me')
    if (!res.ok) {
      setMe(null)
      setLoading(false)
      return
    }
    setMe((await res.json()) as Me)
    setLoading(false)
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const login = useCallback(async (username: string, password: string) => {
    const res = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) throw new Error('Invalid credentials')
    const data = (await res.json()) as { access_token: string }
    setToken(data.access_token)
    await refresh()
  }, [refresh])

  const logout = useCallback(() => {
    setToken(null)
    setMe(null)
  }, [])

  const value = useMemo(() => ({ me, loading, refresh, login, logout }), [me, loading, refresh, login, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const v = useContext(AuthContext)
  if (!v) throw new Error('useAuth must be used within AuthProvider')
  return v
}
