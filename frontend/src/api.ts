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
  const t0 = performance.now()
  const res = await fetch(`${apiBase()}${path}`, { ...init, headers })
  const ms = Math.round(performance.now() - t0)
  // Record in the global perf tracker (used by usePagePerf summaries)
  const { recordFetch } = await import('./perf')
  recordFetch(path, ms, res.ok, t0)
  // Per-request debug log
  const label = path.split('?')[0]
  const color = ms > 2000 ? '#ef4444' : ms > 500 ? '#f97316' : '#22c55e'
  // eslint-disable-next-line no-console
  console.debug(`%c[Perf]%c ${label} %c${ms}ms`, 'color:#6366f1;font-weight:bold', 'color:#94a3b8', `color:${color};font-weight:bold`)
  if (res.status === 401) setToken(null)
  return res
}

export function wsDashboardUrl(token: string): string {
  const base = apiBase() || `${window.location.protocol}//${window.location.host}`
  const u = new URL('/ws', base)
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  u.searchParams.set('token', token)
  return u.toString()
}
