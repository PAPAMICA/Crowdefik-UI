import { Activity, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wifi } from 'lucide-react'
import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import {
  Area, AreaChart, CartesianGrid, Cell,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch, getToken, wsDashboardUrl } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'
import { Skeleton, SkeletonCard } from '../components/Skeleton'
import { setLatestAlertCount } from '../components/Sidebar'
import { usePagePerf } from '../hooks/usePagePerf'
import { faviconUrl } from '../utils/favicon'

const AttackerMap = lazy(() => import('../components/AttackerMap').then((m) => ({ default: m.AttackerMap })))

type AttackerIp = { ip: string; count: number; country_code?: string | null; country?: string | null }
type Summary = {
  routers_total: number
  routers_crowdsec_effective: number
  decisions_count: number
  alerts_count: number
  top_attacker_ips: AttackerIp[]
  attack_types: { type: string; count: number }[]
}
type GeoPoint = { ip: string; lat: number; lon: number; count: number; scenario: string; country: string }
type TimelinePoint = { date: string; alerts: number; blocked: number }
type ServiceStat = { host: string; alert_count: number; unique_ips: number }

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
  const navigate = useNavigate()
  const [summary, setSummary] = useState<Summary | null>(null)
  const [geo, setGeo] = useState<GeoPoint[]>([])
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [serviceStats, setServiceStats] = useState<ServiceStat[]>([])
  const [loadingSummary, setLoadingSummary] = useState(true)
  const [loadingTimeline, setLoadingTimeline] = useState(true)
  const [loadingServices, setLoadingServices] = useState(true)
  usePagePerf('Dashboard', loadingSummary || loadingTimeline || loadingServices)
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)
  const [days, setDays] = useState(7)

  useEffect(() => {
    setLoadingSummary(true)
    setLoadingTimeline(true)
    setLoadingServices(true)

    void apiFetch('/api/dashboard/summary').then(async (r) => {
      if (r.ok) {
        const data = (await r.json()) as Summary
        setSummary(data)
        if (typeof data.alerts_count === 'number') setLatestAlertCount(data.alerts_count)
      }
      setLoadingSummary(false)
    })
    void apiFetch(`/api/dashboard/geo?days=${days}`).then(async (r) => {
      if (r.ok) setGeo((await r.json()) as GeoPoint[])
    })
    void apiFetch(`/api/dashboard/timeline?days=${days}`).then(async (r) => {
      if (r.ok) setTimeline((await r.json()) as TimelinePoint[])
      setLoadingTimeline(false)
    })
    void apiFetch(`/api/dashboard/service-stats?days=${days}`).then(async (r) => {
      if (r.ok) {
        const data = await r.json() as { by_service: ServiceStat[] }
        setServiceStats(data.by_service ?? [])
      }
      setLoadingServices(false)
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
          const payload = msg.payload as Summary
          setSummary(payload)
          setLastUpdate(new Date())
          if (typeof payload.alerts_count === 'number') {
            setLatestAlertCount(payload.alerts_count)
          }
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
        {loadingSummary
          ? Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)
          : CARD_CONFIG.map(({ key, label, icon: Icon, color, border }) => (
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
        {/* Attack scenarios — donut */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-2 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attack scenarios</span>
          </div>
          {loadingSummary ? (
            <div className="flex items-center gap-4 pt-2">
              <Skeleton className="h-[180px] w-[180px] rounded-full" />
              <div className="flex-1 space-y-2">
                {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-4 w-full" />)}
              </div>
            </div>
          ) : topTypes.length ? (
            <div className="flex items-center gap-2">
              <ResponsiveContainer width={180} height={220}>
                <PieChart>
                  <Pie
                    data={topTypes}
                    dataKey="count"
                    nameKey="type"
                    cx="50%"
                    cy="50%"
                    innerRadius={52}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {topTypes.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                    itemStyle={{ color: '#f1f5f9' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex-1 space-y-1.5 min-w-0">
                {topTypes.slice(0, 7).map((t, i) => (
                  <div key={t.type} className="flex items-center gap-2 text-xs">
                    <span className="h-2 w-2 flex-shrink-0 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                    <span className="min-w-0 flex-1 truncate text-slate-600 dark:text-slate-300" title={t.type}>{t.type}</span>
                    <span className="flex-shrink-0 font-semibold text-slate-700 dark:text-slate-200">{t.count}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex h-[220px] items-center justify-center text-sm text-slate-400">No data yet</div>
          )}
        </div>

        {/* Top attacker IPs — donut */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-2 flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Top attacker IPs</span>
          </div>
          {loadingSummary ? (
            <div className="flex items-center gap-4 pt-2">
              <Skeleton className="h-[180px] w-[150px] rounded-full" />
              <div className="flex-1 space-y-2">
                {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-4 w-full" />)}
              </div>
            </div>
          ) : (summary?.top_attacker_ips ?? []).length ? (
            <div className="flex items-center gap-3">
              <ResponsiveContainer width={150} height={220}>
                <PieChart>
                  <Pie
                    data={summary!.top_attacker_ips.slice(0, 8)}
                    dataKey="count"
                    nameKey="ip"
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={68}
                    paddingAngle={2}
                  >
                    {summary!.top_attacker_ips.slice(0, 8).map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                    formatter={(v, _name, entry) => [v, (entry.payload as AttackerIp).ip]}
                    labelFormatter={() => ''}
                  />
                </PieChart>
              </ResponsiveContainer>
              {/* Legend — utilise IpBadge pour flag + score + modal */}
              <div className="flex-1 min-w-0 space-y-2">
                {summary!.top_attacker_ips.slice(0, 8).map((item, i) => (
                  <div key={item.ip} className="flex items-center gap-2">
                    <span className="h-2 w-2 flex-shrink-0 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                    <span className="flex-shrink-0 w-4 text-center text-[10px] font-bold text-slate-400">{item.count}</span>
                    <IpBadge ip={item.ip} />
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex h-[220px] items-center justify-center text-sm text-slate-400">No data yet</div>
          )}
        </div>
      </div>

      {/* Attacks by service */}
      {(loadingServices || serviceStats.length > 0) && (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-violet-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attacks by service — last {days} day{days > 1 ? 's' : ''}</span>
          </div>
          {loadingServices ? (
            <div className="grid gap-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="flex items-center gap-3">
                  <Skeleton className="h-4 w-4 rounded" />
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-2 flex-1 rounded-full" />
                  <Skeleton className="h-4 w-20" />
                </div>
              ))}
            </div>
          ) : (
            <div className="grid gap-2">
              {serviceStats.map((s) => {
                const max = serviceStats[0]?.alert_count || 1
                const pct = Math.max(4, Math.round((s.alert_count / max) * 100))
                return (
                  <button
                    key={s.host}
                    type="button"
                    onClick={() => navigate(`/services/${encodeURIComponent(s.host)}`)}
                    className="flex w-full items-center gap-3 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-50 dark:hover:bg-slate-700/30"
                  >
                    <img
                      src={faviconUrl(s.host)}
                      alt=""
                      width={16}
                      height={16}
                      className="h-4 w-4 flex-shrink-0 rounded-sm object-contain"
                      onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }}
                    />
                    <span className="w-44 flex-shrink-0 truncate font-mono text-xs text-slate-600 dark:text-slate-300 hover:text-violet-600 dark:hover:text-violet-400" title={s.host}>
                      {s.host}
                    </span>
                    <div className="flex-1 rounded-full bg-slate-100 dark:bg-slate-700/60" style={{ height: 8 }}>
                      <div
                        className="h-2 rounded-full bg-violet-500"
                        style={{ width: `${pct}%`, transition: 'width 0.4s ease' }}
                      />
                    </div>
                    <div className="flex flex-shrink-0 items-center gap-3 text-right">
                      <span className="w-16 text-xs font-semibold text-slate-700 dark:text-slate-200">
                        {s.alert_count.toLocaleString()} alerts
                      </span>
                      <span className="w-14 text-[10px] text-slate-400">
                        {s.unique_ips} IPs
                      </span>
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Alert + Blocked timeline */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">
              {days === 1 ? 'Activity — last 24h (per hour)' : `Activity — last ${days} days`}
            </span>
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span className="flex items-center gap-1.5"><span className="inline-block h-2 w-4 rounded-full bg-indigo-500" />Alerts</span>
            <span className="flex items-center gap-1.5"><span className="inline-block h-2 w-4 rounded-full bg-red-500" />Blocked</span>
          </div>
        </div>
        {loadingTimeline ? (
          <Skeleton className="h-[200px] w-full" />
        ) : timeline.length ? (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10, fill: '#94a3b8' }}
                axisLine={false}
                tickLine={false}
                tickFormatter={(v: string) => days === 1 ? v : v.slice(5)}
                interval={days === 1 ? 3 : 'preserveStartEnd'}
              />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#f1f5f9' }}
                itemStyle={{ color: '#94a3b8' }}
              />
              <Area type="monotone" dataKey="alerts" name="Alerts" stroke="#6366f1" strokeWidth={2}
                fill="url(#alertGrad)" dot={false} />
              <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2}
                fill="url(#blockedGrad)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex h-[200px] items-center justify-center text-sm text-slate-400">No data yet</div>
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
        <Suspense fallback={<div className="flex h-[340px] items-center justify-center text-sm text-slate-500">Loading map…</div>}>
          <AttackerMap points={geo} />
        </Suspense>
        {geo.length === 0 && (
          <p className="mt-2 text-center text-xs text-slate-400">
            No geolocation data yet — populates every 5 min from CrowdSec alerts
          </p>
        )}
      </div>
    </div>
  )
}
