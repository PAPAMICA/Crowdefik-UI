import { Download, Filter, RefreshCw, Search, Server } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import {
  Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { CountryFlag } from '../components/CountryFlag'
import { LinePicker } from '../components/LinePicker'
import { Skeleton } from '../components/Skeleton'
import { usePagePerf } from '../hooks/usePagePerf'

type Entry = {
  time: string | null; host: string; method: string | null; path: string | null
  status: number | null; client_ip: string | null; duration_ms: number
  bytes: number | null; router: string | null; tls_version: string | null
  country_code: string | null; abuse_score: number | null
}
type Data = { available: boolean; total: number; page: number; pages: number; lines: number; entries: Entry[] }
type Stats = {
  available: boolean
  total_entries: number
  top_hosts: ({ host: string; count: number })[]
  top_methods: ({ method: string; count: number })[]
  status_dist: ({ status: string; count: number })[]
  top_ips: ({ ip: string; count: number; country_code: string | null })[]
}

const PAGE_SIZE = 200

function AbuseScore({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-slate-300 dark:text-slate-600">—</span>
  const cls =
    score >= 75 ? 'bg-red-500/15 text-red-600 dark:text-red-400' :
    score >= 30 ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400' :
    score > 0   ? 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400' :
                  'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
  return (
    <span className={`inline-block rounded-full px-1.5 py-0.5 text-[11px] font-semibold tabular-nums ${cls}`}>
      {score}
    </span>
  )
}

function statusColor(code: number | null) {
  if (!code) return 'text-slate-400'
  if (code < 300) return 'text-emerald-600 dark:text-emerald-400'
  if (code < 400) return 'text-blue-500'
  if (code < 500) return 'text-amber-600 dark:text-amber-400'
  return 'text-red-600 dark:text-red-400'
}

const STATUS_COLORS: Record<string, string> = {
  '2xx': '#22c55e', '3xx': '#3b82f6', '4xx': '#f59e0b', '5xx': '#ef4444', 'other': '#94a3b8',
}

export function LogsAccessPage() {
  const { me, loading } = useAuth()
  const [data, setData] = useState<Data | null>(null)
  const [stats, setStats] = useState<Stats | null>(null)
  const [fetching, setFetching] = useState(true)
  const [fetchingStats, setFetchingStats] = useState(false)
  usePagePerf('Logs / Access', fetching)
  const [lines, setLines] = useState(1_000)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [hostFilter, setHostFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 350)
    return () => clearTimeout(t)
  }, [search])

  // Reset to page 1 whenever any filter or line count changes
  useEffect(() => { setPage(1) }, [debouncedSearch, hostFilter, statusFilter, lines])

  const buildParams = useCallback(() => {
    const p = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE), lines: String(lines) })
    if (debouncedSearch) p.set('search', debouncedSearch)
    if (hostFilter) p.set('host', hostFilter)
    if (statusFilter) p.set('status', statusFilter)
    return p
  }, [page, debouncedSearch, hostFilter, statusFilter, lines])

  const buildStatsParams = useCallback(() => {
    const p = new URLSearchParams({ lines: String(lines) })
    if (debouncedSearch) p.set('search', debouncedSearch)
    if (hostFilter) p.set('host', hostFilter)
    if (statusFilter) p.set('status', statusFilter)
    return p
  }, [debouncedSearch, hostFilter, statusFilter, lines])

  async function load() {
    setFetching(true)
    try {
      const r = await apiFetch(`/api/logs/access?${buildParams()}`)
      if (r.ok) setData(await r.json() as Data)
    } finally { setFetching(false) }
  }

  async function loadStats() {
    setFetchingStats(true)
    try {
      const r = await apiFetch(`/api/logs/access/stats?${buildStatsParams()}`)
      if (r.ok) setStats(await r.json() as Stats)
    } finally { setFetchingStats(false) }
  }

  useEffect(() => { void load() }, [page, debouncedSearch, hostFilter, statusFilter, lines]) // eslint-disable-line react-hooks/exhaustive-deps
  // Stats refresh on filter change (not on page change — they cover the full filtered set)
  useEffect(() => { void loadStats() }, [debouncedSearch, hostFilter, statusFilter, lines]) // eslint-disable-line react-hooks/exhaustive-deps

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

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Access logs</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Traefik JSON access log
            {data && !fetching && (
              <> — <strong className="text-slate-700 dark:text-slate-300">{data.total.toLocaleString()}</strong> matching entries out of last {lines.toLocaleString()} lines</>
            )}
            {fetching && ' — loading…'}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <LinePicker value={lines} onChange={(n) => setLines(n)} />
          <button type="button" onClick={exportCSV}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <Download className="h-4 w-4" /> Export
          </button>
          <button type="button" onClick={() => void load()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${fetching ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative min-w-[200px] flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Path, IP, host…" value={search} onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <input
            className="w-40 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Host filter…" value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}
          />
          <select
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All status</option>
            {['2xx', '3xx', '4xx', '5xx'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* Distribution charts */}
      {(stats?.available !== false) && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {/* Top Hosts */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-700/50 dark:bg-slate-800/60">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Top Hosts</div>
            {fetchingStats ? <Skeleton className="h-[120px] w-full" /> : (stats?.top_hosts?.length ?? 0) > 0 ? (
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={stats!.top_hosts.slice(0, 6).map(h => ({ name: h.host.replace(/^www\./, ''), count: h.count }))}
                  layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} axisLine={false} tickLine={false} width={80} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 10 }}
                    formatter={(v: number) => [v, 'Requests']} />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={14}>
                    {stats!.top_hosts.slice(0, 6).map((_, idx) => <Cell key={idx} fill={`hsl(${250 + idx * 20}, 65%, 55%)`} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[120px] items-center justify-center text-xs text-slate-400">No data</div>
            )}
          </div>

          {/* Methods */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-700/50 dark:bg-slate-800/60">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Methods</div>
            {fetchingStats ? <Skeleton className="h-[120px] w-full" /> : (stats?.top_methods?.length ?? 0) > 0 ? (
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={stats!.top_methods} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="method" tick={{ fontSize: 9, fill: '#94a3b8', fontFamily: 'monospace' }} axisLine={false} tickLine={false} width={40} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 10 }}
                    formatter={(v: number) => [v, 'Requests']} />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={14} fill="#6366f1" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[120px] items-center justify-center text-xs text-slate-400">No data</div>
            )}
          </div>

          {/* Status codes */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-700/50 dark:bg-slate-800/60">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Status codes</div>
            {fetchingStats ? <Skeleton className="h-[120px] w-full" /> : (stats?.status_dist?.length ?? 0) > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={80}>
                  <BarChart data={stats!.status_dist} margin={{ left: 0, right: 0, top: 0, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.1)" vertical={false} />
                    <XAxis dataKey="status" tick={{ fontSize: 9, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                    <YAxis hide />
                    <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 10 }}
                      formatter={(v: number) => [v, 'Requests']} />
                    <Bar dataKey="count" radius={[3, 3, 0, 0]} maxBarSize={30}>
                      {stats!.status_dist.map((s) => <Cell key={s.status} fill={STATUS_COLORS[s.status] ?? '#94a3b8'} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <div className="mt-1 flex flex-wrap gap-2">
                  {stats!.status_dist.map((s) => (
                    <span key={s.status} className="inline-flex items-center gap-1 text-[10px] text-slate-500">
                      <span className="h-2 w-2 rounded-full" style={{ background: STATUS_COLORS[s.status] ?? '#94a3b8' }} />
                      {s.status}: {s.count.toLocaleString()}
                    </span>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex h-[120px] items-center justify-center text-xs text-slate-400">No data</div>
            )}
          </div>

          {/* Top Client IPs */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-700/50 dark:bg-slate-800/60">
            <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Top Client IPs</div>
            {fetchingStats ? <Skeleton className="h-[120px] w-full" /> : (stats?.top_ips?.length ?? 0) > 0 ? (
              <ResponsiveContainer width="100%" height={120}>
                <BarChart data={stats!.top_ips.slice(0, 6).map(i => ({ ip: i.ip, count: i.count }))}
                  layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="ip" tick={{ fontSize: 8, fill: '#94a3b8', fontFamily: 'monospace' }} axisLine={false} tickLine={false} width={90} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 10 }}
                    formatter={(v: number) => [v, 'Requests']} />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={14}>
                    {stats!.top_ips.slice(0, 6).map((_, idx) => <Cell key={idx} fill={`hsl(${10 + idx * 20}, 70%, 55%)`} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[120px] items-center justify-center text-xs text-slate-400">No data</div>
            )}
          </div>
        </div>
      )}

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
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                  {['Time', 'Host', 'Method', 'Path', 'Status', 'Client IP', 'Score', 'Duration', 'Size', 'TLS'].map((h) => (
                    <th key={h} className="px-3 py-2.5 text-left font-medium text-slate-400">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/30">
                  {fetching && !data
                  ? Array.from({ length: 12 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 10 }).map((_, j) => (
                        <td key={j} className="px-3 py-2"><Skeleton className="h-3 w-full" /></td>
                      ))}
                    </tr>
                  ))
                  : (data?.entries ?? []).length === 0
                    ? (
                      <tr>
                        <td colSpan={10} className="py-12 text-center text-sm text-slate-400">
                          No entries match — try increasing the line count or adjusting filters
                        </td>
                      </tr>
                    )
                    : (data?.entries ?? []).map((e, i) => (
                      <tr key={i} className="hover:bg-slate-50/60 dark:hover:bg-white/5">
                        <td className="px-3 py-1.5 font-mono text-slate-500 whitespace-nowrap">
                          {e.time ? new Date(e.time).toLocaleTimeString() : '—'}
                        </td>
                        <td className="px-3 py-1.5 font-mono text-violet-600 dark:text-violet-400 whitespace-nowrap">{e.host || '—'}</td>
                        <td className="px-3 py-1.5 font-mono font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">{e.method ?? '—'}</td>
                        <td className="max-w-[260px] truncate px-3 py-1.5 font-mono text-slate-600 dark:text-slate-300" title={e.path ?? ''}>{e.path ?? '—'}</td>
                        <td className={`px-3 py-1.5 text-center font-semibold whitespace-nowrap ${statusColor(e.status)}`}>{e.status ?? '—'}</td>
                        <td className="px-3 py-1.5 whitespace-nowrap">
                          <span className="inline-flex items-center gap-1.5 font-mono text-slate-600 dark:text-slate-300">
                            {e.country_code && <CountryFlag code={e.country_code} size={14} />}
                            {e.client_ip ?? '—'}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 whitespace-nowrap">
                          <AbuseScore score={e.abuse_score} />
                        </td>
                        <td className="px-3 py-1.5 text-right font-mono text-slate-500 whitespace-nowrap">{e.duration_ms > 0 ? `${e.duration_ms}ms` : '—'}</td>
                        <td className="px-3 py-1.5 text-right font-mono text-slate-400 whitespace-nowrap">{e.bytes != null ? `${(e.bytes / 1024).toFixed(1)}k` : '—'}</td>
                        <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">{e.tls_version ?? '—'}</td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
            <span className="text-xs text-slate-500">
              {((page - 1) * PAGE_SIZE + 1).toLocaleString()}–{Math.min(page * PAGE_SIZE, data.total).toLocaleString()} of {data.total.toLocaleString()}
            </span>
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
