import { AlertTriangle, Filter, RefreshCw, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'

type Alert = Record<string, unknown>

function flag(cc?: string) {
  if (!cc || cc.length !== 2) return ''
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e0 + c.charCodeAt(0) - 65))
}

function scenarioShort(s?: string) {
  if (!s) return '—'
  return s.replace('crowdsecurity/', '')
}

function AlertRow({ a }: { a: Alert }) {
  const src = (a.source as Record<string, unknown>) ?? {}
  const ip = String(src.ip ?? src.value ?? '')
  const cn = String(src.cn ?? '')
  const scenario = String(a.scenario ?? '')
  const events = Number(a.events_count ?? 0)
  const startAt = a.start_at ? new Date(String(a.start_at)).toLocaleString() : '—'
  const stopAt = a.stop_at ? new Date(String(a.stop_at)).toLocaleString() : '—'

  return (
    <tr className="hover:bg-slate-50/50 dark:hover:bg-white/5">
      <td className="px-4 py-3">
        <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
          <AlertTriangle className="h-3 w-3" />
          {scenarioShort(scenario)}
        </span>
      </td>
      <td className="px-4 py-3">
        {ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}
      </td>
      <td className="px-4 py-3">
        <span className="text-sm">{cn ? `${flag(cn)} ${cn}` : '—'}</span>
      </td>
      <td className="px-4 py-3 text-center">
        <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium dark:bg-slate-700 dark:text-slate-300">
          {events}
        </span>
      </td>
      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{startAt}</td>
      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{stopAt}</td>
    </tr>
  )
}

export function AlertsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<Alert[]>([])
  const [search, setSearch] = useState('')
  const [scenarioFilter, setScenarioFilter] = useState('all')

  useEffect(() => {
    void (async () => {
      const res = await apiFetch('/api/crowdsec/alerts?limit=500')
      if (res.ok) setRows((await res.json()) as Alert[])
    })()
  }, [])

  const scenarios = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((a) => {
      const scen = String(a.scenario ?? '').replace('crowdsecurity/', '')
      if (scen) s.add(scen)
    })
    return Array.from(s).sort()
  }, [rows])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows.filter((a) => {
      const src = (a.source as Record<string, unknown>) ?? {}
      const ip = String(src.ip ?? src.value ?? '')
      const scenario = String(a.scenario ?? '')
      if (scenarioFilter !== 'all' && !scenario.includes(scenarioFilter)) return false
      if (!q) return true
      return ip.includes(q) || scenario.toLowerCase().includes(q)
    })
  }, [rows, search, scenarioFilter])

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Alerts</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {filtered.length} of {rows.length} alerts — click an IP for details
          </p>
        </div>
        <button
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          type="button"
          onClick={() => void apiFetch('/api/crowdsec/alerts?limit=500').then(async (r) => { if (r.ok) setRows(await r.json()) })}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {/* Filters */}
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
            value={scenarioFilter}
            onChange={(e) => setScenarioFilter(e.target.value)}
          >
            <option value="all">All scenarios</option>
            {scenarios.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Source IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Country</th>
                <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Events</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Started</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Ended</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.map((a, i) => <AlertRow key={i} a={a} />)}
              {!filtered.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No alerts match filters' : 'No alerts — check CrowdSec settings'}
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
