import { ClipboardList, Filter, RefreshCw, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'

type AuditEntry = {
  id: number
  username: string
  action: string
  target: string | null
  detail: string | null
  created_at: string
}

const ACTION_COLORS: Record<string, string> = {
  crowdsec_enable: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20',
  crowdsec_disable: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20',
  crowdsec_reset: 'bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/20',
  crowdsec_bulk_enable: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20',
  crowdsec_bulk_disable: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20',
  crowdsec_bulk_reset: 'bg-slate-500/10 text-slate-700 dark:text-slate-400 border-slate-500/20',
  ban: 'bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20',
  unban: 'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/20',
}

function actionClass(action: string): string {
  return ACTION_COLORS[action] ?? 'bg-violet-500/10 text-violet-700 dark:text-violet-400 border-violet-500/20'
}

const PAGE_SIZE = 50

function Pagination({ page, total, pageSize, onChange }: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500">{(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}</span>
      <div className="flex gap-1">
        <button type="button" disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">‹</button>
        {Array.from({ length: Math.min(pages, 5) }, (_, i) => {
          const p = pages <= 5 ? i + 1 : Math.max(1, Math.min(pages - 4, page - 2)) + i
          return (
            <button key={p} type="button" onClick={() => onChange(p)}
              className={`min-w-[30px] rounded-lg border px-2 py-1 text-xs ${p === page ? 'border-violet-500 bg-violet-500/10 text-violet-600' : 'border-slate-200 bg-white text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400'}`}>
              {p}
            </button>
          )
        })}
        <button type="button" disabled={page >= pages} onClick={() => onChange(page + 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">›</button>
      </div>
    </div>
  )
}

export function AuditPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<AuditEntry[]>([])
  const [search, setSearch] = useState('')
  const [actionFilter, setActionFilter] = useState('all')
  const [page, setPage] = useState(1)

  async function loadData() {
    const res = await apiFetch('/api/admin/audit?limit=500')
    if (res.ok) setRows((await res.json()) as AuditEntry[])
  }

  useEffect(() => { void loadData() }, [])

  if (!loading && (!me || !me.is_superuser)) return <Navigate to="/" replace />

  const actions = useMemo(() => [...new Set(rows.map((r) => r.action))].sort(), [rows])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows.filter((r) => {
      if (actionFilter !== 'all' && r.action !== actionFilter) return false
      if (!q) return true
      return (
        r.username.toLowerCase().includes(q) ||
        r.action.toLowerCase().includes(q) ||
        (r.target ?? '').toLowerCase().includes(q) ||
        (r.detail ?? '').toLowerCase().includes(q)
      )
    })
  }, [rows, search, actionFilter])

  useEffect(() => setPage(1), [search, actionFilter])
  const paged = useMemo(() => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filtered, page])

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Audit Log</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{filtered.length} of {rows.length} events</p>
        </div>
        <button
          type="button" onClick={() => void loadData()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative min-w-[200px] flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="User, action, target…"
            value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <select className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
            <option value="all">All actions</option>
            {actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">User</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Action</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {paged.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-medium text-slate-800 dark:text-slate-200">{r.username}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${actionClass(r.action)}`}>
                      <ClipboardList className="h-3 w-3" />
                      {r.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-300">{r.target ?? '—'}</td>
                  <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{r.detail ?? '—'}</td>
                </tr>
              ))}
              {!paged.length && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No entries match filters' : 'No audit events yet'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} total={filtered.length} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>
    </div>
  )
}
