/**
 * Lightweight frontend performance tracker.
 *
 * apiFetch() calls recordFetch() on every request.
 * usePagePerf() reads all fetches that started since the page mounted
 * and logs a grouped console.table when loading is done.
 */

export type FetchTiming = {
  path: string      // full path including query string
  ms: number        // elapsed ms
  ok: boolean       // HTTP 2xx
  startedAt: number // performance.now() when request started
}

const MAX_ENTRIES = 500
const _timings: FetchTiming[] = []

export function recordFetch(path: string, ms: number, ok: boolean, startedAt: number): void {
  _timings.push({ path, ms, ok, startedAt })
  if (_timings.length > MAX_ENTRIES) _timings.shift()
}

export function getTimingsSince(since: number): FetchTiming[] {
  return _timings.filter((t) => t.startedAt >= since)
}

export function logPagePerf(pageName: string, since: number): void {
  const timings = getTimingsSince(since)
  if (!timings.length) return

  // Wall-clock time: from page mount to last request completion
  const wallMs = Math.round(
    Math.max(...timings.map((t) => t.startedAt + t.ms)) - since
  )
  const slowest = Math.max(...timings.map((t) => t.ms))
  const errors = timings.filter((t) => !t.ok).length
  const wallColor = wallMs > 3000 ? '#ef4444' : wallMs > 1000 ? '#f97316' : '#22c55e'

  console.groupCollapsed(
    `%c[Perf] %c${pageName}%c  wall: ${wallMs}ms  |  ${timings.length} req  |  slowest: ${slowest}ms${errors ? `  |  ⚠ ${errors} error(s)` : ''}`,
    'color:#6366f1;font-weight:bold;font-size:11px',
    'color:#e2e8f0;font-weight:bold;font-size:11px',
    `color:${wallColor};font-weight:bold;font-size:11px`,
  )

  const rows = [...timings]
    .sort((a, b) => b.ms - a.ms)
    .map((t) => ({
      'Endpoint': t.path.replace(/\?.*/, ''),
      'Query': t.path.includes('?') ? '?' + t.path.split('?')[1] : '',
      'ms': t.ms,
      'Status': t.ok ? '✅' : '❌',
      'Speed': t.ms > 2000 ? '🔴 Slow' : t.ms > 500 ? '🟡 Medium' : '🟢 Fast',
    }))

  console.table(rows)
  console.groupEnd()
}
