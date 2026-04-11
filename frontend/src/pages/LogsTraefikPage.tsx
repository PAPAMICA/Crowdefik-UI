import { Clock, RefreshCw, Search, Server } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { Skeleton } from '../components/Skeleton'
import { TimeRangePicker } from '../components/TimeRangePicker'
import { usePagePerf } from '../hooks/usePagePerf'

type LogEntry = { time: string; level: string; msg: string; raw: string }
type Data = { available: boolean; total: number; page: number; pages: number; minutes: number; source?: string; entries: LogEntry[] }

const LEVEL_COLORS: Record<string, string> = {
  error: 'text-red-600 dark:text-red-400 font-semibold',
  warn: 'text-amber-600 dark:text-amber-400',
  warning: 'text-amber-600 dark:text-amber-400',
  info: 'text-blue-500',
  debug: 'text-slate-400',
}
const LEVEL_BG: Record<string, string> = {
  error: 'bg-red-500/10',
  warn: 'bg-amber-500/10',
  warning: 'bg-amber-500/10',
  info: '',
  debug: '',
}

export function LogsTraefikPage() {
  const { me, loading } = useAuth()
  const [data, setData] = useState<Data | null>(null)
  const [fetching, setFetching] = useState(true)
  usePagePerf('Logs / Traefik', fetching)
  const [minutes, setMinutes] = useState(20)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [levelFilter, setLevelFilter] = useState('')

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 350)
    return () => clearTimeout(t)
  }, [search])
  useEffect(() => { setPage(1) }, [debouncedSearch, levelFilter, minutes])

  async function load() {
    setFetching(true)
    try {
      const p = new URLSearchParams({ page: String(page), limit: '500', minutes: String(minutes) })
      if (debouncedSearch) p.set('search', debouncedSearch)
      if (levelFilter) p.set('level', levelFilter)
      const r = await apiFetch(`/api/logs/traefik?${p}`)
      if (r.ok) setData(await r.json() as Data)
    } finally { setFetching(false) }
  }

  useEffect(() => { void load() }, [page, debouncedSearch, levelFilter, minutes]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!loading && !me) return <Navigate to="/login" replace />

  const rangeLabel = minutes === 0 ? 'all time' : minutes < 60 ? `last ${minutes} min` : `last ${minutes / 60}h`

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Traefik logs</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Traefik application log — {fetching ? '…' : data?.total?.toLocaleString() ?? '0'} lines ({rangeLabel})
            {data?.source === 'docker' && (
              <span className="ml-2 rounded-full bg-blue-500/10 px-2 py-0.5 text-[10px] font-medium text-blue-600 dark:text-blue-400">docker exec</span>
            )}
            {data?.source === 'file' && (
              <span className="ml-2 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400">file</span>
            )}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <TimeRangePicker value={minutes} onChange={(m) => setMinutes(m)} />
          <button type="button" onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${fetching ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="relative min-w-[200px] flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-cyan-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Search messages…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <select className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
          value={levelFilter} onChange={(e) => setLevelFilter(e.target.value)}>
          <option value="">All levels</option>
          {['error', 'warn', 'info', 'debug'].map((l) => <option key={l} value={l}>{l}</option>)}
        </select>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        {data?.available === false ? (
          <div className="px-5 py-16 text-center">
            <Server className="mx-auto mb-3 h-10 w-10 text-slate-300 dark:text-slate-600" />
            <p className="font-medium text-slate-500">Traefik logs not available</p>
            <p className="mt-1 text-xs text-slate-400 max-w-sm mx-auto">
              Set the <strong>Traefik container name</strong> in Settings → Logs,<br />
              or mount the log file and set <code className="rounded bg-slate-100 px-1 dark:bg-slate-700">CROWDEFIK_TRAEFIK_APP_LOG_PATH</code>.
            </p>
          </div>
        ) : (
          <>
            {data && minutes > 0 && (
              <div className="flex items-center gap-2 border-b border-slate-100 bg-slate-50/60 px-4 py-2 text-xs text-slate-500 dark:border-slate-700/50 dark:bg-slate-800/40">
                <Clock className="h-3.5 w-3.5 text-blue-400" />
                Showing entries from the <strong className="text-slate-700 dark:text-slate-300">last {minutes < 60 ? `${minutes} minutes` : `${minutes / 60} hour${minutes > 60 ? 's' : ''}`}</strong>.
                <button type="button" className="ml-1 text-blue-500 hover:underline" onClick={() => setMinutes(0)}>Load all</button>
              </div>
            )}
            <div className="divide-y divide-slate-100 dark:divide-slate-700/30">
              {fetching && !data
                ? Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="flex gap-3 px-4 py-2.5">
                    <Skeleton className="h-4 w-16" />
                    <Skeleton className="h-4 w-12" />
                    <Skeleton className="h-4 flex-1" />
                  </div>
                ))
                : (data?.entries ?? []).length === 0
                  ? <div className="py-12 text-center text-sm text-slate-400">No entries in this time range — try a wider window</div>
                  : (data?.entries ?? []).map((e, i) => (
                    <div key={i} className={`flex items-start gap-3 px-4 py-2 font-mono text-xs ${LEVEL_BG[e.level] ?? ''}`}>
                      <span className="w-36 flex-shrink-0 text-slate-400 whitespace-nowrap">
                        {e.time ? new Date(e.time).toLocaleString() : '—'}
                      </span>
                      <span className={`w-14 flex-shrink-0 uppercase ${LEVEL_COLORS[e.level] ?? 'text-slate-500'}`}>{e.level}</span>
                      <span className="min-w-0 flex-1 break-words text-slate-700 dark:text-slate-300">{e.msg || e.raw}</span>
                    </div>
                  ))}
            </div>
          </>
        )}

        {data && data.pages > 1 && (
          <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
            <span className="text-xs text-slate-500">{data.total.toLocaleString()} lines total</span>
            <div className="flex gap-1">
              <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">‹ Prev</button>
              <span className="flex items-center px-2 text-xs text-slate-400">p.{page}/{data.pages}</span>
              <button type="button" disabled={page >= data.pages} onClick={() => setPage(page + 1)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">Next ›</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
