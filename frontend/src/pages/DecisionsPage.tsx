import { Clock, Filter, RefreshCw, Search, Shield } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'

type Decision = Record<string, unknown>

function TypeBadge({ type }: { type: string }) {
  const t = String(type).toLowerCase()
  if (t === 'ban')
    return <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-700 dark:text-red-400"><Shield className="h-3 w-3" />Ban</span>
  return <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">{type}</span>
}

function DecisionRow({ d }: { d: Decision }) {
  const ip = String(d.value ?? d.ip ?? '')
  const type = String(d.type ?? '')
  const scope = String(d.scope ?? '')
  const duration = String(d.duration ?? '')
  const until = d.until ? new Date(String(d.until)).toLocaleString() : '—'
  const scenario = String(d.scenario ?? d.reason ?? '')

  return (
    <tr className="hover:bg-slate-50/50 dark:hover:bg-white/5">
      <td className="px-4 py-3">{ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}</td>
      <td className="px-4 py-3"><TypeBadge type={type} /></td>
      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{scope || '—'}</td>
      <td className="px-4 py-3">
        <div className="inline-flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
          <Clock className="h-3 w-3" />{duration || '—'}
        </div>
      </td>
      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{until}</td>
      <td className="max-w-[200px] px-4 py-3 text-xs text-slate-500 dark:text-slate-400 truncate">{scenario || '—'}</td>
    </tr>
  )
}

export function DecisionsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<Decision[]>([])
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')

  useEffect(() => {
    void (async () => {
      const res = await apiFetch('/api/crowdsec/decisions?limit=500')
      if (res.ok) setRows((await res.json()) as Decision[])
    })()
  }, [])

  const types = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((d) => { if (d.type) s.add(String(d.type)) })
    return Array.from(s).sort()
  }, [rows])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows.filter((d) => {
      const ip = String(d.value ?? d.ip ?? '')
      const t = String(d.type ?? '')
      if (typeFilter !== 'all' && t !== typeFilter) return false
      if (!q) return true
      return ip.includes(q) || t.includes(q) || String(d.scenario ?? '').toLowerCase().includes(q)
    })
  }, [rows, search, typeFilter])

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Decisions</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {filtered.length} of {rows.length} active decisions from CrowdSec LAPI
          </p>
        </div>
        <button
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          type="button"
          onClick={() => void apiFetch('/api/crowdsec/decisions?limit=500').then(async (r) => { if (r.ok) setRows(await r.json()) })}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Filter by IP or scenario…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <select
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="all">All types</option>
            {types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scope</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Duration</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Until</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.map((d, i) => <DecisionRow key={i} d={d} />)}
              {!filtered.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No decisions match filters' : 'No active decisions — check CrowdSec settings'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
