export function apiBase(): string {
  return import.meta.env.VITE_API_URL ?? ''
}

export function getToken(): string | null {
  return localStorage.getItem('crowdefik_token')
}

export function setToken(token: string | null) {
  if (!token) localStorage.removeItem('crowdefik_token')
  else localStorage.setItem('crowdefik_token', token)
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers)
  const token = getToken()
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (!headers.has('Content-Type') && init.body && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }
  const res = await fetch(`${apiBase()}${path}`, { ...init, headers })
  if (res.status === 401) {
    setToken(null)
  }
  return res
}

export function wsDashboardUrl(token: string): string {
  const base = apiBase() || `${window.location.protocol}//${window.location.host}`
  const u = new URL('/ws', base)
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  u.searchParams.set('token', token)
  return u.toString()
}
