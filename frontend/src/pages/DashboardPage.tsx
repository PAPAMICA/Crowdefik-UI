import { Activity, RefreshCw, Shield, ShieldAlert, ShieldCheck, Wifi } from 'lucide-react'
import { lazy, Suspense, useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
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

const CARD_CONFIG = [
  { key: 'routers_total' as const, label: 'Exposed routers', icon: Activity, color: 'bg-violet-500/10 text-violet-500', border: 'border-violet-500/20' },
  { key: 'routers_crowdsec_effective' as const, label: 'CrowdSec protected', icon: ShieldCheck, color: 'bg-emerald-500/10 text-emerald-500', border: 'border-emerald-500/20' },
  { key: 'decisions_count' as const, label: 'Active bans', icon: Shield, color: 'bg-red-500/10 text-red-500', border: 'border-red-500/20' },
  { key: 'alerts_count' as const, label: 'Alerts', icon: ShieldAlert, color: 'bg-amber-500/10 text-amber-500', border: 'border-amber-500/20' },
]

const CHART_COLORS = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#22c55e', '#06b6d4', '#6366f1', '#a855f7']

export function DashboardPage() {
  const { me, loading } = useAuth()
  const [summary, setSummary] = useState<Summary | null>(null)
  const [geo, setGeo] = useState<GeoPoint[]>([])
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null)

  useEffect(() => {
    void apiFetch('/api/dashboard/summary').then(async (r) => {
      if (r.ok) setSummary((await r.json()) as Summary)
    })
    void apiFetch('/api/dashboard/geo').then(async (r) => {
      if (r.ok) setGeo((await r.json()) as GeoPoint[])
    })
  }, [])

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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Security dashboard</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Real-time overview of your Traefik + CrowdSec infrastructure
          </p>
        </div>
        <div className="flex items-center gap-3">
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
          <div className="flex h-64 items-center justify-center text-sm text-slate-400">
            No geolocation data — requires CrowdSec alerts with location info
          </div>
        )}
      </div>
    </div>
  )
}
