import { AlertTriangle, Filter, RefreshCw, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { CountryFlag } from '../components/CountryFlag'
import { IpBadge } from '../components/IpBadge'

type Alert = {
  id?: number
  scenario?: string
  source?: { ip?: string; value?: string; cn?: string }
  events_count?: number
  start_at?: string
  stop_at?: string
  _target_host?: string
  [k: string]: unknown
}

const PAGE_SIZE = 25

// Deterministic scenario color (same logic as DecisionsPage)
const PALETTES = [
  'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20',
  'bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20',
  'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20',
  'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/20',
  'bg-lime-500/10 text-lime-700 dark:text-lime-400 border-lime-500/20',
  'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20',
  'bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border-cyan-500/20',
  'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/20',
  'bg-violet-500/10 text-violet-700 dark:text-violet-400 border-violet-500/20',
  'bg-pink-500/10 text-pink-700 dark:text-pink-400 border-pink-500/20',
]
function scenarioColor(s: string) {
  let h = 0; for (let i = 0; i < s.length; i++) h = ((h * 31) + s.charCodeAt(i)) >>> 0
  return PALETTES[h % PALETTES.length]
}

function ServiceBadge({ host }: { host: string }) {
  return (
    <a
      href={`https://${host}`} target="_blank" rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300 dark:hover:bg-slate-700"
    >
      <img
        src={`https://icons.duckduckgo.com/ip3/${host}.ico`} alt="" width={12} height={12}
        className="h-3 w-3 rounded-sm object-contain"
        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
      />
      {host}
    </a>
  )
}

function Pagination({ page, total, pageSize, onChange }: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500">{(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}</span>
      <div className="flex gap-1">
        <button type="button" disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
          ‹
        </button>
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
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
          ›
        </button>
      </div>
    </div>
  )
}

export function AlertsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<Alert[]>([])
  const [search, setSearch] = useState('')
  const [scenarioFilter, setScenarioFilter] = useState('all')
  const [serviceFilter, setServiceFilter] = useState('all')
  const [page, setPage] = useState(1)

  async function loadData() {
    const res = await apiFetch('/api/crowdsec/alerts?limit=2000')
    if (res.ok) setRows((await res.json()) as Alert[])
  }

  useEffect(() => { void loadData() }, [])

  const scenarios = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((a) => { const sc = String(a.scenario ?? '').replace('crowdsecurity/', ''); if (sc) s.add(sc) })
    return Array.from(s).sort()
  }, [rows])

  const services = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((a) => { if (a._target_host) s.add(a._target_host) })
    return Array.from(s).sort()
  }, [rows])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows.filter((a) => {
      const ip = String(a.source?.ip ?? a.source?.value ?? '')
      const scenario = String(a.scenario ?? '')
      if (scenarioFilter !== 'all' && !scenario.includes(scenarioFilter)) return false
      if (serviceFilter !== 'all' && a._target_host !== serviceFilter) return false
      if (!q) return true
      return ip.includes(q) || scenario.toLowerCase().includes(q) || (a._target_host ?? '').includes(q)
    })
  }, [rows, search, scenarioFilter, serviceFilter])

  useEffect(() => setPage(1), [search, scenarioFilter, serviceFilter])
  const paged = useMemo(() => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filtered, page])

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
          type="button" onClick={() => void loadData()}
        >
          <RefreshCw className="h-4 w-4" /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="IP, scenario, service…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <select className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={scenarioFilter} onChange={(e) => setScenarioFilter(e.target.value)}>
            <option value="all">All scenarios</option>
            {scenarios.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={serviceFilter} onChange={(e) => setServiceFilter(e.target.value)}>
            <option value="all">All services</option>
            {services.map((s) => <option key={s} value={s}>{s}</option>)}
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
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Service ciblé</th>
                <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Events</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {paged.map((a, i) => {
                const ip = String(a.source?.ip ?? a.source?.value ?? '')
                const cn = String(a.source?.cn ?? '')
                const scenario = String(a.scenario ?? '')
                const label = scenario.replace('crowdsecurity/', '')
                const events = Number(a.events_count ?? 0)
                const startAt = a.start_at ? new Date(a.start_at).toLocaleString() : '—'
                return (
                  <tr key={i} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${scenarioColor(scenario)}`}>
                        <AlertTriangle className="h-3 w-3" />{label || '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {cn && <CountryFlag code={cn} size={16} />}
                        {ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {a._target_host
                        ? <ServiceBadge host={a._target_host} />
                        : <span className="text-xs text-slate-400">—</span>}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium dark:bg-slate-700 dark:text-slate-300">{events}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{startAt}</td>
                  </tr>
                )
              })}
              {!paged.length && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No alerts match filters' : 'No alerts — check CrowdSec settings and machine credentials'}
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
