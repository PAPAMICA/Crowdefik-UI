import { Clock, Download, Filter, RefreshCw, Search, Server } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { Skeleton } from '../components/Skeleton'
import { TimeRangePicker } from '../components/TimeRangePicker'
import { usePagePerf } from '../hooks/usePagePerf'

type Entry = {
  time: string | null; host: string; method: string | null; path: string | null
  status: number | null; client_ip: string | null; duration_ms: number
  bytes: number | null; router: string | null; tls_version: string | null
}

type Data = { available: boolean; total: number; page: number; pages: number; minutes: number; entries: Entry[] }

const PAGE_SIZE = 100

function statusColor(code: number | null) {
  if (!code) return 'text-slate-400'
  if (code < 300) return 'text-emerald-600 dark:text-emerald-400'
  if (code < 400) return 'text-blue-500'
  if (code < 500) return 'text-amber-600 dark:text-amber-400'
  return 'text-red-600 dark:text-red-400'
}

export function LogsAccessPage() {
  const { me, loading } = useAuth()
  const [data, setData] = useState<Data | null>(null)
  const [fetching, setFetching] = useState(true)
  usePagePerf('Logs / Access', fetching)
  const [minutes, setMinutes] = useState(20)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [hostFilter, setHostFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 350)
    return () => clearTimeout(t)
  }, [search])

  useEffect(() => { setPage(1) }, [debouncedSearch, hostFilter, statusFilter, minutes])

  const buildParams = useCallback(() => {
    const p = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE), minutes: String(minutes) })
    if (debouncedSearch) p.set('search', debouncedSearch)
    if (hostFilter) p.set('host', hostFilter)
    if (statusFilter) p.set('status', statusFilter)
    return p
  }, [page, debouncedSearch, hostFilter, statusFilter, minutes])

  async function load() {
    setFetching(true)
    try {
      const r = await apiFetch(`/api/logs/access?${buildParams()}`)
      if (r.ok) setData(await r.json() as Data)
    } finally { setFetching(false) }
  }

  useEffect(() => { void load() }, [page, debouncedSearch, hostFilter, statusFilter, minutes]) // eslint-disable-line react-hooks/exhaustive-deps

  function exportCSV() {
    if (!data?.entries) return
    const h = ['Time', 'Host', 'Method', 'Path', 'Status', 'Client IP', 'Duration (ms)', 'Bytes']
    const rows = data.entries.map((e) => [
      e.time ?? '', e.host, e.method ?? '', e.path ?? '', e.status ?? '', e.client_ip ?? '', e.duration_ms, e.bytes ?? '',
    ])
    const csv = [h, ...rows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    a.download = `access-logs-${new Date().toISOString().slice(0, 10)}.csv`; a.click()
  }

  if (!loading && !me) return <Navigate to="/login" replace />

  const rangeLabel = minutes === 0 ? 'all time' : minutes < 60 ? `last ${minutes} min` : minutes < 1440 ? `last ${minutes / 60}h` : 'last 24h'

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Access logs</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Traefik JSON access log — {fetching ? '…' : data?.total?.toLocaleString() ?? '0'} entries ({rangeLabel})
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <TimeRangePicker value={minutes} onChange={(m) => setMinutes(m)} />
          <button type="button" onClick={exportCSV}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <Download className="h-4 w-4" /> Export CSV
          </button>
          <button type="button" onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${fetching ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative min-w-[200px] flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Path, IP, host…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <input className="w-40 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Host filter…" value={hostFilter} onChange={(e) => setHostFilter(e.target.value)} />
          <select className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All status</option>
            {['2xx', '3xx', '4xx', '5xx'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        {data?.available === false ? (
          <div className="px-5 py-16 text-center">
            <Server className="mx-auto mb-3 h-10 w-10 text-slate-300 dark:text-slate-600" />
            <p className="font-medium text-slate-500">Access logs not available</p>
            <p className="mt-1 text-sm text-slate-400">
              Set <code className="rounded bg-slate-100 px-1 dark:bg-slate-700">CROWDEFIK_TRAEFIK_LOG_PATH</code> and mount the log directory.
            </p>
          </div>
        ) : (
          <>
            {/* Time window banner */}
            {data && minutes > 0 && (
              <div className="flex items-center gap-2 border-b border-slate-100 bg-slate-50/60 px-4 py-2 text-xs text-slate-500 dark:border-slate-700/50 dark:bg-slate-800/40">
                <Clock className="h-3.5 w-3.5 text-violet-400" />
                Showing entries from the <strong className="text-slate-700 dark:text-slate-300">last {minutes < 60 ? `${minutes} minutes` : `${minutes / 60} hour${minutes > 60 ? 's' : ''}`}</strong>.
                <button type="button" className="ml-1 text-violet-500 hover:underline" onClick={() => setMinutes(0)}>Load all</button>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                    {['Time', 'Host', 'Method', 'Path', 'Status', 'Client IP', 'Duration', 'Size', 'TLS'].map((h) => (
                      <th key={h} className="px-3 py-2.5 text-left font-medium text-slate-400">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/30">
                  {fetching && !data
                    ? Array.from({ length: 10 }).map((_, i) => (
                      <tr key={i}>
                        {Array.from({ length: 9 }).map((_, j) => (
                          <td key={j} className="px-3 py-2"><Skeleton className="h-3 w-full" /></td>
                        ))}
                      </tr>
                    ))
                    : (data?.entries ?? []).length === 0
                      ? (
                        <tr>
                          <td colSpan={9} className="py-12 text-center text-sm text-slate-400">
                            No entries in this time range — try a wider window
                          </td>
                        </tr>
                      )
                      : (data?.entries ?? []).map((e, i) => (
                        <tr key={i} className="hover:bg-slate-50/60 dark:hover:bg-white/5">
                          <td className="px-3 py-1.5 font-mono text-slate-500 whitespace-nowrap">
                            {e.time ? new Date(e.time).toLocaleString() : '—'}
                          </td>
                          <td className="px-3 py-1.5 font-mono text-violet-600 dark:text-violet-400 whitespace-nowrap">{e.host || '—'}</td>
                          <td className="px-3 py-1.5 font-mono font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">{e.method ?? '—'}</td>
                          <td className="max-w-[260px] truncate px-3 py-1.5 font-mono text-slate-600 dark:text-slate-300" title={e.path ?? ''}>{e.path ?? '—'}</td>
                          <td className={`px-3 py-1.5 text-center font-semibold whitespace-nowrap ${statusColor(e.status)}`}>{e.status ?? '—'}</td>
                          <td className="px-3 py-1.5 font-mono text-slate-600 dark:text-slate-300 whitespace-nowrap">{e.client_ip ?? '—'}</td>
                          <td className="px-3 py-1.5 text-right font-mono text-slate-500 whitespace-nowrap">{e.duration_ms > 0 ? `${e.duration_ms}ms` : '—'}</td>
                          <td className="px-3 py-1.5 text-right font-mono text-slate-400 whitespace-nowrap">{e.bytes != null ? `${(e.bytes / 1024).toFixed(1)}k` : '—'}</td>
                          <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">{e.tls_version ?? '—'}</td>
                        </tr>
                      ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
            <span className="text-xs text-slate-500">{((page - 1) * PAGE_SIZE + 1).toLocaleString()}–{Math.min(page * PAGE_SIZE, data.total).toLocaleString()} of {data.total.toLocaleString()}</span>
            <div className="flex gap-1">
              <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">‹ Prev</button>
              <span className="flex items-center px-2 text-xs text-slate-400">p.{page}/{data.pages}</span>
              <button type="button" disabled={page >= data.pages} onClick={() => setPage(page + 1)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">Next ›</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
