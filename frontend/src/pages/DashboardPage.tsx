import { Activity, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wifi } from 'lucide-react'
import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch, getToken, wsDashboardUrl } from '../api'
import { useAuth } from '../auth'

const AttackerMap = lazy(() => import('../components/AttackerMap').then((m) => ({ default: m.AttackerMap })))

type Summary = {
  routers_total: number
  routers_crowdsec_effective: number
  decisions_count: number
  alerts_count: number
  top_attacker_ips: { ip: string; count: number }[]
  attack_types: { type: string; count: number }[]
}
type GeoPoint = { ip: string; lat: number; lon: number; count: number; scenario: string; country: string }
type TimelinePoint = { date: string; count: number }
type ServiceStat = { host: string; alert_count: number; unique_ips: number; favicon: string | null }

const CARD_CONFIG = [
  { key: 'routers_total' as const, label: 'Exposed routers', icon: Activity, color: 'bg-violet-500/10 text-violet-500', border: 'border-violet-500/20' },
  { key: 'routers_crowdsec_effective' as const, label: 'CrowdSec protected', icon: ShieldCheck, color: 'bg-emerald-500/10 text-emerald-500', border: 'border-emerald-500/20' },
  { key: 'decisions_count' as const, label: 'Active bans', icon: Shield, color: 'bg-red-500/10 text-red-500', border: 'border-red-500/20' },
  { key: 'alerts_count' as const, label: 'Alerts', icon: ShieldAlert, color: 'bg-amber-500/10 text-amber-500', border: 'border-amber-500/20' },
]

const CHART_COLORS = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#22c55e', '#06b6d4', '#6366f1', '#a855f7']

const PERIOD_OPTIONS = [
  { label: '24h', days: 1 },
  { label: '7d', days: 7 },
  { label: '30d', days: 30 },
]

export function DashboardPage() {
  const { me, loading } = useAuth()
  const [summary, setSummary] = useState<Summary | null>(null)
  const [geo, setGeo] = useState<GeoPoint[]>([])
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [serviceStats, setServiceStats] = useState<ServiceStat[]>([])
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)
  const [days, setDays] = useState(7)

  useEffect(() => {
    void apiFetch('/api/dashboard/summary').then(async (r) => {
      if (r.ok) setSummary((await r.json()) as Summary)
    })
    void apiFetch(`/api/dashboard/geo?days=${days}`).then(async (r) => {
      if (r.ok) setGeo((await r.json()) as GeoPoint[])
    })
    void apiFetch(`/api/dashboard/timeline?days=${days}`).then(async (r) => {
      if (r.ok) setTimeline((await r.json()) as TimelinePoint[])
    })
    void apiFetch(`/api/dashboard/service-stats?days=${days}`).then(async (r) => {
      if (r.ok) {
        const data = await r.json() as { by_service: ServiceStat[] }
        setServiceStats(data.by_service ?? [])
      }
    })
  }, [days])

  useEffect(() => {
    const token = getToken()
    if (!token) return
    const ws = new WebSocket(wsDashboardUrl(token))
    ws.onopen = () => setWsStatus('connected')
    ws.onclose = () => setWsStatus('disconnected')
    ws.onerror = () => setWsStatus('disconnected')
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(String(e.data))
        if (msg?.type === 'dashboard') {
          setSummary(msg.payload as Summary)
          setLastUpdate(new Date())
        }
      } catch { /* ignore */ }
    }
    return () => ws.close()
  }, [me?.id])

  const topTypes = useMemo(
    () => (summary?.attack_types ?? []).map((a) => ({ ...a, type: a.type.replace('crowdsecurity/', '') })).slice(0, 8),
    [summary],
  )

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Security dashboard</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Real-time overview of your Traefik + CrowdSec infrastructure
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Period selector */}
          <div className="flex rounded-xl border border-slate-200 bg-white p-1 dark:border-slate-700 dark:bg-slate-800">
            {PERIOD_OPTIONS.map(({ label, days: d }) => (
              <button
                key={d}
                type="button"
                onClick={() => setDays(d)}
                className={`rounded-lg px-3 py-1 text-xs font-medium transition ${days === d ? 'bg-violet-500 text-white shadow-sm' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'}`}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs dark:border-slate-700 dark:bg-slate-800">
            <Wifi className={`h-3 w-3 ${wsStatus === 'connected' ? 'text-emerald-500' : 'text-slate-400'}`} />
            <span className={wsStatus === 'connected' ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400'}>
              {wsStatus === 'connected' ? 'Live' : wsStatus}
            </span>
          </div>
          {lastUpdate && (
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <RefreshCw className="h-3 w-3" />
              {lastUpdate.toLocaleTimeString()}
            </div>
          )}
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {CARD_CONFIG.map(({ key, label, icon: Icon, color, border }) => (
          <div
            key={key}
            className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 dark:border-slate-700/50 ${border}`}
          >
            <div className="flex items-center justify-between">
              <div className={`rounded-xl p-2.5 ${color}`}>
                <Icon className="h-5 w-5" />
              </div>
              <span className="text-3xl font-bold text-slate-900 dark:text-white">
                {summary?.[key] ?? '—'}
              </span>
            </div>
            <div className="mt-3 text-sm text-slate-500 dark:text-slate-400">{label}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Attack scenarios */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attack scenarios</span>
          </div>
          {topTypes.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topTypes} layout="vertical" margin={{ left: 0, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="type" width={120} tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#f1f5f9' }}
                  itemStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {topTypes.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[220px] items-center justify-center text-sm text-slate-400">No data yet</div>
          )}
        </div>

        {/* Top attacker IPs */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Top attacker IPs</span>
          </div>
          {(summary?.top_attacker_ips ?? []).length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={summary!.top_attacker_ips} layout="vertical" margin={{ left: 0, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="ip" width={120} tick={{ fontSize: 10, fill: '#94a3b8', fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#f1f5f9' }}
                  itemStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[220px] items-center justify-center text-sm text-slate-400">No data yet</div>
          )}
        </div>
      </div>

      {/* Attacks by service */}
      {serviceStats.length > 0 && (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-violet-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attacks by service — last 7 days</span>
          </div>
          <div className="grid gap-2">
            {serviceStats.map((s) => {
              const max = serviceStats[0]?.alert_count || 1
              const pct = Math.max(4, Math.round((s.alert_count / max) * 100))
              return (
                <div key={s.host} className="flex items-center gap-3">
                  {/* Favicon */}
                  <img
                    src={s.favicon ?? `https://icons.duckduckgo.com/ip3/${s.host}.ico`}
                    alt=""
                    width={16}
                    height={16}
                    className="h-4 w-4 flex-shrink-0 rounded-sm object-contain"
                    onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }}
                  />
                  {/* Host */}
                  <span className="w-44 flex-shrink-0 truncate font-mono text-xs text-slate-600 dark:text-slate-300" title={s.host}>
                    {s.host}
                  </span>
                  {/* Bar */}
                  <div className="flex-1 rounded-full bg-slate-100 dark:bg-slate-700/60" style={{ height: 8 }}>
                    <div
                      className="h-2 rounded-full bg-violet-500"
                      style={{ width: `${pct}%`, transition: 'width 0.4s ease' }}
                    />
                  </div>
                  {/* Stats */}
                  <div className="flex flex-shrink-0 items-center gap-3 text-right">
                    <span className="w-16 text-xs font-semibold text-slate-700 dark:text-slate-200">
                      {s.alert_count.toLocaleString()} alerts
                    </span>
                    <span className="w-14 text-[10px] text-slate-400">
                      {s.unique_ips} IPs
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Alert timeline */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center gap-2">
          <Activity className="h-4 w-4 text-blue-500" />
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Alerts — last 7 days</span>
        </div>
        {timeline.length ? (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false}
                tickFormatter={(v) => v.slice(5)} />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#f1f5f9' }}
                itemStyle={{ color: '#94a3b8' }}
              />
              <Area type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2}
                fill="url(#alertGrad)" dot={{ r: 3, fill: '#6366f1' }} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex h-[180px] items-center justify-center text-sm text-slate-400">No data yet</div>
        )}
      </div>

      {/* Map */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-violet-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attacker origins</span>
          </div>
          <span className="text-xs text-slate-400">{geo.length} unique IPs</span>
        </div>
        {geo.length ? (
          <Suspense fallback={<div className="flex h-64 items-center justify-center text-sm text-slate-500">Loading map…</div>}>
            <AttackerMap points={geo} />
          </Suspense>
        ) : (
          <div className="flex h-64 flex-col items-center justify-center gap-2 text-sm text-slate-400">
            <span>No geolocation data yet</span>
            <span className="text-xs">Data populates automatically every 5 minutes from CrowdSec alerts</span>
          </div>
        )}
      </div>
    </div>
  )
}
