import {
  Activity, AlertTriangle, BookOpen, Clock, Search, Shield, Users,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../api'
import { Skeleton } from '../components/Skeleton'
import { getAttackInfo, SEVERITY_CLASSES } from '../utils/attackKnowledge'

type ScenarioRow = {
  scenario: string
  alert_count: number
  events_total: number
  distinct_ips: number
  last_seen: string | null
  first_seen: string | null
  top_ip: string | null
  top_target: string | null
}

function isWafAnomaly(s: string) {
  return s.toLowerCase().includes('anomaly score')
}

function scenarioLabel(s: string) {
  return s.replace('crowdsecurity/', '').replace('ltsich/', '').replace(/-/g, ' ')
}

export function ScenariosPage() {
  const [rows, setRows] = useState<ScenarioRow[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  useEffect(() => {
    setLoading(true)
    void apiFetch('/api/scenarios')
      .then(async (r) => { if (r.ok) setRows(await r.json() as ScenarioRow[]) })
      .finally(() => setLoading(false))
  }, [])

  const filtered = rows.filter((r) =>
    r.scenario.toLowerCase().includes(search.toLowerCase())
  )

  const totalAlerts = rows.reduce((s, r) => s + r.alert_count, 0)
  const totalIps = new Set(rows.map((r) => r.top_ip)).size

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-slate-900 dark:text-white">
            <BookOpen className="h-5 w-5 text-violet-500" />
            Attack Scenarios
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            All detected attack types with statistics and explanations
          </p>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 pointer-events-none" />
          <input
            type="text"
            placeholder="Filter scenarios…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm text-slate-700 placeholder-slate-400 focus:border-violet-400 focus:outline-none focus:ring-1 focus:ring-violet-400/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
          />
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { icon: BookOpen, label: 'Scenario types', value: rows.length, color: 'border-violet-500/20 bg-violet-500/5' },
          { icon: AlertTriangle, label: 'Total alerts', value: totalAlerts, color: 'border-amber-500/20 bg-amber-500/5' },
          { icon: Users, label: 'Distinct IPs', value: totalIps, color: 'border-red-500/20 bg-red-500/5' },
          { icon: Activity, label: 'Most active', value: rows[0]?.scenario.replace('crowdsecurity/', '') ?? '—', color: 'border-blue-500/20 bg-blue-500/5' },
        ].map(({ icon: Icon, label, value, color }) => (
          <div key={label} className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 ${color}`}>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
                <div className="mt-1 truncate text-xl font-bold text-slate-900 dark:text-white">{typeof value === 'number' ? value.toLocaleString() : value}</div>
              </div>
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/60 dark:bg-slate-700/40">
                <Icon className="h-5 w-5 text-slate-500 dark:text-slate-300" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Scenario cards grid */}
      {loading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-44 rounded-2xl" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center gap-3 py-20 text-slate-400">
          <BookOpen className="h-10 w-10 opacity-30" />
          <span className="text-sm">No scenarios found</span>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((row) => {
            const info = getAttackInfo(row.scenario)
            const waf = isWafAnomaly(row.scenario)
            const sev = info ? SEVERITY_CLASSES[info.severity] : SEVERITY_CLASSES.info
            // For WAF anomaly scenarios, use the parsed title as the primary display name
            const displayTitle = waf && info ? info.title : scenarioLabel(row.scenario)
            const displaySubtitle = waf && info ? null : (info ? info.title : null)
            // For WAF, show the raw scores as a compact secondary line
            const rawScores = waf
              ? row.scenario.replace(/^anomaly score block:\s*/i, '').replace(/,\s*$/, '')
              : null

            return (
              <Link
                key={row.scenario}
                to={`/scenarios/${encodeURIComponent(row.scenario)}`}
                className={`group flex flex-col rounded-2xl border bg-white p-5 transition-all hover:shadow-md dark:bg-slate-800/60 dark:hover:bg-slate-800 ${sev.border}`}
              >
                {/* Top row */}
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-semibold text-sm text-slate-900 group-hover:text-violet-600 dark:text-white dark:group-hover:text-violet-400 transition-colors">
                      {displayTitle}
                    </div>
                    {displaySubtitle && (
                      <div className="mt-0.5 truncate font-mono text-xs text-slate-500 dark:text-slate-400">{displaySubtitle}</div>
                    )}
                    {rawScores && (
                      <div className="mt-0.5 truncate font-mono text-[10px] text-slate-400 dark:text-slate-500">{rawScores}</div>
                    )}
                  </div>
                  {info && (
                    <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${sev.badge}`}>
                      {info.severity}
                    </span>
                  )}
                </div>

                {/* Description preview */}
                {info && (
                  <p className="mt-2 line-clamp-2 text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                    {info.description}
                  </p>
                )}

                {/* Stats */}
                <div className="mt-auto pt-4 grid grid-cols-3 gap-2 border-t border-slate-100 dark:border-slate-700/50">
                  <div className="text-center">
                    <div className="text-sm font-bold text-slate-900 dark:text-white">{row.alert_count.toLocaleString()}</div>
                    <div className="text-[10px] text-slate-400">Alerts</div>
                  </div>
                  <div className="text-center border-x border-slate-100 dark:border-slate-700/50">
                    <div className="text-sm font-bold text-slate-900 dark:text-white">{row.distinct_ips.toLocaleString()}</div>
                    <div className="text-[10px] text-slate-400">IPs</div>
                  </div>
                  <div className="text-center">
                    <div className="flex items-center justify-center gap-1 text-[10px] text-slate-400">
                      <Clock className="h-2.5 w-2.5" />
                      {row.last_seen ? new Date(row.last_seen).toLocaleDateString() : '—'}
                    </div>
                    <div className="text-[10px] text-slate-400">Last seen</div>
                  </div>
                </div>

                {/* Category badge */}
                {info && (
                  <div className="mt-2">
                    <span className="rounded-md bg-slate-100 px-2 py-0.5 text-[10px] font-medium text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                      {info.category}
                    </span>
                  </div>
                )}
              </Link>
            )
          })}
        </div>
      )}

      {/* Unknown scenarios table */}
      {!loading && filtered.some((r) => !getAttackInfo(r.scenario)) && (
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Shield className="h-4 w-4 text-slate-400" />
              Other scenarios
            </h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                {['Scenario', 'Alerts', 'IPs', 'Last seen'].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.filter((r) => !getAttackInfo(r.scenario)).map((r) => (
                <tr key={r.scenario} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                  <td className="px-4 py-2.5">
                    <Link to={`/scenarios/${encodeURIComponent(r.scenario)}`}
                      className="font-mono text-xs text-violet-600 hover:text-violet-700 dark:text-violet-400 dark:hover:text-violet-300">
                      {scenarioLabel(r.scenario)}
                    </Link>
                  </td>
                  <td className="px-4 py-2.5 text-xs font-medium text-slate-700 dark:text-slate-300">{r.alert_count.toLocaleString()}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{r.distinct_ips}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{r.last_seen ? new Date(r.last_seen).toLocaleDateString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
