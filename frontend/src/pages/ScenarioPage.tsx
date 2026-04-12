import {
  Activity, AlertTriangle, ArrowLeft, BookOpen, CheckCircle2,
  Clock, Globe, Info, RefreshCw, Shield, Users,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'
import { Skeleton, SkeletonCard } from '../components/Skeleton'
import { faviconUrl } from '../utils/favicon'
import { getAttackInfo, parseWafAnomalyInfo, SEVERITY_CLASSES } from '../utils/attackKnowledge'

const CHART_COLORS = ['#6366f1', '#f59e0b', '#ef4444', '#10b981', '#3b82f6', '#ec4899', '#8b5cf6', '#14b8a6', '#f97316', '#64748b']

type TopIp = { ip: string; count: number; country_code: string | null; country: string | null; abuse_score: number | null }
type TopTarget = { host: string; count: number }
type RecentAlert = { id: number; source_ip: string | null; target_host: string | null; events_count: number; start_at: string | null }
type TimelinePoint = { date: string; count: number }

type ScenarioData = {
  scenario: string
  total_alerts: number
  events_total: number
  distinct_ips: number
  first_seen: string | null
  last_seen: string | null
  timeline: TimelinePoint[]
  top_ips: TopIp[]
  top_targets: TopTarget[]
  recent_alerts: RecentAlert[]
}

function isWafAnomaly(s: string) {
  return s.toLowerCase().includes('anomaly score')
}

function scenarioLabel(s: string) {
  if (isWafAnomaly(s)) {
    // Use the parsed title from attackKnowledge
    const info = parseWafAnomalyInfo(s)
    return info ? info.title : s.replace(/^anomaly score block:\s*/i, 'WAF Block: ')
  }
  return s.replace('crowdsecurity/', '').replace('ltsich/', '').replace(/-/g, ' ')
}

function StatCard({ icon: Icon, label, value, color }: {
  icon: typeof Shield; label: string; value: string | number; color: string
}) {
  return (
    <div className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 ${color}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{typeof value === 'number' ? value.toLocaleString() : value}</div>
        </div>
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white/60 dark:bg-slate-700/40">
          <Icon className="h-5 w-5 text-slate-500 dark:text-slate-300" />
        </div>
      </div>
    </div>
  )
}

export function ScenarioPage() {
  const { scenario } = useParams<{ scenario: string }>()
  const { me, loading: authLoading } = useAuth()
  const navigate = useNavigate()
  const [data, setData] = useState<ScenarioData | null>(null)
  const [loading, setLoading] = useState(true)

  function load() {
    if (!scenario) return
    setLoading(true)
    void apiFetch(`/api/scenarios/${encodeURIComponent(scenario)}?days=30`)
      .then(async (r) => { if (r.ok) setData(await r.json() as ScenarioData) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [scenario]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!authLoading && !me) return <Navigate to="/login" replace />
  if (!scenario) return <Navigate to="/scenarios" replace />

  const info = scenario ? getAttackInfo(scenario) : null
  const sev = info ? SEVERITY_CLASSES[info.severity] : SEVERITY_CLASSES.info

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <button type="button" onClick={() => navigate(-1)}
            className="mt-1 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </button>
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl font-bold text-slate-900 dark:text-white">
                {scenarioLabel(scenario)}
              </h1>
              {info && (
                <span className={`rounded-full px-3 py-1 text-xs font-bold uppercase ${sev.badge}`}>
                  {info.severity}
                </span>
              )}
              {info && (
                <span className="rounded-md bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                  {info.category}
                </span>
              )}
            </div>
            {/* For WAF anomaly: show raw scores; for named scenarios: show info.title */}
            {isWafAnomaly(scenario) ? (
              <p className="mt-1 font-mono text-xs text-slate-400 dark:text-slate-500">
                {scenario.replace(/^anomaly score block:\s*/i, '').replace(/,\s*$/, '')}
              </p>
            ) : info ? (
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{info.title}</p>
            ) : null}
          </div>
        </div>
        <button type="button" onClick={load}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {loading ? Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />) : (
          <>
            <StatCard icon={AlertTriangle} label="Total alerts" value={data?.total_alerts ?? 0} color="border-amber-500/20 bg-amber-500/5" />
            <StatCard icon={Activity} label="Total events" value={data?.events_total ?? 0} color="border-violet-500/20 bg-violet-500/5" />
            <StatCard icon={Users} label="Distinct IPs" value={data?.distinct_ips ?? 0} color="border-red-500/20 bg-red-500/5" />
            <StatCard icon={Clock} label="Last seen" value={data?.last_seen ? new Date(data.last_seen).toLocaleDateString() : '—'} color="border-slate-200 bg-slate-50 dark:border-slate-700/50" />
          </>
        )}
      </div>

      {/* Knowledge base card */}
      {info && (
        <div className={`rounded-2xl border bg-white p-6 dark:bg-slate-800/60 ${sev.border}`}>
          <div className="grid gap-6 lg:grid-cols-3">
            {/* Description + Impact */}
            <div className="lg:col-span-2 space-y-4">
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <Info className={`h-4 w-4 ${sev.icon}`} />
                  <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">About this attack</span>
                </div>
                <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-300">{info.description}</p>
              </div>
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-500" />
                  <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Potential impact</span>
                </div>
                <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-300">{info.impact}</p>
              </div>
            </div>

            {/* Mitigation */}
            <div>
              <div className="mb-2 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Mitigation</span>
              </div>
              <ul className="space-y-1.5">
                {info.mitigation.map((m, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-slate-600 dark:text-slate-300">
                    <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" />
                    {m}
                  </li>
                ))}
              </ul>
              {info.references && info.references.length > 0 && (
                <div className="mt-3 space-y-1">
                  {info.references.map((ref, i) => (
                    <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                      className="block truncate text-[11px] text-violet-500 hover:underline">
                      {ref}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Examples */}
          <div className="mt-5 border-t border-slate-100 pt-5 dark:border-slate-700/50">
            <div className="mb-3 flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-slate-400" />
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attack examples</span>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {info.examples.map((ex, i) => (
                <div key={i} className="rounded-lg bg-slate-900 px-4 py-2.5 dark:bg-slate-950">
                  <code className="break-all text-[11px] text-emerald-400">{ex}</code>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Timeline + Top IPs side by side */}
      <div className="grid gap-6" style={{ gridTemplateColumns: '1fr 35%' }}>
        {/* Timeline */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <Activity className="h-4 w-4 text-violet-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Alert timeline — last 30 days</span>
          </div>
          {loading ? <Skeleton className="h-[180px] w-full" /> : data?.timeline.some((p) => p.count > 0) ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={data.timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
                <defs>
                  <linearGradient id="scGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" vertical={false} />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false}
                  tickFormatter={(v: string) => v.slice(5)} interval="preserveStartEnd" />
                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} allowDecimals={false} width={32} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#f1f5f9' }} itemStyle={{ color: '#94a3b8' }} />
                <Area type="monotone" dataKey="count" name="Alerts" stroke="#6366f1" strokeWidth={2} fill="url(#scGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[180px] items-center justify-center text-sm text-slate-400">No data for the last 30 days</div>
          )}
        </div>

        {/* Top attacker IPs — donut */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-3 flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Top attacker IPs</span>
          </div>
          {loading ? <Skeleton className="h-[180px] w-full rounded-xl" /> : (data?.top_ips.length ?? 0) > 0 ? (
            <div className="flex items-center gap-3">
              <ResponsiveContainer width={120} height={160}>
                <PieChart>
                  <Pie data={data!.top_ips} dataKey="count" nameKey="ip"
                    cx="50%" cy="50%" innerRadius={36} outerRadius={54} paddingAngle={2}>
                    {data!.top_ips.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                    formatter={(v, _n, entry) => [v, (entry.payload as TopIp).ip]}
                    labelFormatter={() => ''}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex-1 min-w-0 space-y-1.5 overflow-hidden">
                {data!.top_ips.slice(0, 6).map((item, i) => (
                  <div key={item.ip} className="flex items-center gap-2">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                    <span className="w-5 shrink-0 text-right text-[10px] font-bold tabular-nums text-slate-400">{item.count}</span>
                    <IpBadge ip={item.ip} />
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex h-[180px] items-center justify-center text-sm text-slate-400">No data</div>
          )}
        </div>
      </div>

      {/* Top targets + Recent alerts */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Top targets */}
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Globe className="h-4 w-4 text-blue-500" />
              Top targeted services
            </h2>
          </div>
          {loading ? (
            <div className="space-y-2 p-4">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-8 w-full rounded-lg" />)}</div>
          ) : (data?.top_targets.length ?? 0) === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-slate-400">No target data</p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {data!.top_targets.map((t) => (
                <Link key={t.host} to={`/services/${encodeURIComponent(t.host)}`}
                  className="flex items-center justify-between gap-3 px-5 py-2.5 hover:bg-slate-50/50 dark:hover:bg-white/5 transition-colors">
                  <div className="flex items-center gap-2 min-w-0">
                    <img src={faviconUrl(t.host)} alt="" width={14} height={14} className="h-3.5 w-3.5 shrink-0 rounded-sm"
                      onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }} />
                    <span className="truncate font-mono text-xs text-slate-700 dark:text-slate-300">{t.host}</span>
                  </div>
                  <span className="shrink-0 rounded-full bg-blue-500/10 px-2 py-0.5 text-xs font-bold text-blue-700 dark:text-blue-400">{t.count}</span>
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* Recent alerts — 2/3 */}
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60 lg:col-span-2">
          <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              Recent alerts
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                  {['Source IP', 'Target', 'Events', 'Date'].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {loading
                  ? Array.from({ length: 8 }).map((_, i) => (
                    <tr key={i}>{Array.from({ length: 4 }).map((__, j) => <td key={j} className="px-4 py-2.5"><Skeleton className="h-4 w-full" /></td>)}</tr>
                  ))
                  : (data?.recent_alerts ?? []).map((a) => (
                    <tr key={a.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                      <td className="px-4 py-2.5">
                        {a.source_ip ? <IpBadge ip={a.source_ip} /> : <span className="text-xs text-slate-400">—</span>}
                      </td>
                      <td className="px-4 py-2.5">
                        {a.target_host ? (
                          <Link to={`/services/${encodeURIComponent(a.target_host)}`}
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 hover:border-violet-300 hover:text-violet-700 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300">
                            <img src={faviconUrl(a.target_host)} alt="" width={10} height={10} className="h-2.5 w-2.5 rounded-sm"
                              onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }} />
                            {a.target_host}
                          </Link>
                        ) : <span className="text-xs text-slate-400">—</span>}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium dark:bg-slate-700 dark:text-slate-300">{a.events_count}</span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-slate-500">
                        {a.start_at ? new Date(a.start_at).toLocaleString() : '—'}
                      </td>
                    </tr>
                  ))}
                {!loading && data?.recent_alerts.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-10 text-center text-sm text-slate-400">No recent alerts</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Link to all alerts for this scenario */}
      <div className="flex justify-end">
        <Link to={`/alerts?scenario=${encodeURIComponent(scenario)}`}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
          <AlertTriangle className="h-4 w-4 text-amber-500" />
          View all alerts for this scenario →
        </Link>
      </div>
    </div>
  )
}
