import {
  AlertTriangle, ArrowLeft, Ban, Clock, Globe,
  RefreshCw, Shield, ShieldBan, ShieldCheck, Trash2,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { CountryFlag } from '../components/CountryFlag'
import { Skeleton, SkeletonCard } from '../components/Skeleton'
import { useToast } from '../components/Toast'
import { faviconUrl } from '../utils/favicon'

// ── Types ──────────────────────────────────────────────────────────────────────

type GeoData = { country?: string; countryCode?: string; city?: string; isp?: string; lat?: number; lon?: number }
type AbuseData = {
  abuseConfidenceScore?: number; totalReports?: number; numDistinctUsers?: number
  isTor?: boolean; lastReportedAt?: string; domain?: string; isp?: string; countryCode?: string
}
type IpInfo = { ip: string; geo: GeoData | null; abuse: AbuseData | null }

type IpAlert = {
  id: number; scenario: string; target_host: string | null
  events_count: number; start_at: string | null; stop_at: string | null
  context: { key: string; value: string }[]
}
type AlertsData = { total: number; page: number; pages: number; alerts: IpAlert[] }

type IpDecision = {
  id: number; type: string | null; scenario: string | null
  duration: string | null; until: string | null; synced_at: string | null
}

type TimelinePoint = { date: string; count: number }

// ── Helpers ────────────────────────────────────────────────────────────────────

function scoreClasses(score: number) {
  if (score >= 75) return 'bg-red-500/15 text-red-700 dark:text-red-400'
  if (score >= 30) return 'bg-amber-500/15 text-amber-700 dark:text-amber-400'
  if (score > 0)   return 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-400'
  return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
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
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${color.split(' ')[1] ?? ''}`}>
          <Icon className="h-5 w-5 text-slate-600 dark:text-slate-300" />
        </div>
      </div>
    </div>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg bg-slate-50 px-3 py-2 dark:bg-slate-800/60">
      <div className="text-[10px] text-slate-400">{label}</div>
      <div className="mt-0.5 truncate text-xs font-medium text-slate-700 dark:text-slate-200">{value}</div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function IpPage() {
  const { ip } = useParams<{ ip: string }>()
  const { me, loading: authLoading } = useAuth()
  const navigate = useNavigate()
  const { addToast } = useToast()

  const [info, setInfo] = useState<IpInfo | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [alertsData, setAlertsData] = useState<AlertsData | null>(null)
  const [allAlerts, setAllAlerts] = useState<IpAlert[]>([])
  const [decisions, setDecisions] = useState<IpDecision[]>([])
  const [alertPage, setAlertPage] = useState(1)

  const [loadingInfo, setLoadingInfo] = useState(true)
  const [loadingAlerts, setLoadingAlerts] = useState(true)
  const [banning, setBanning] = useState(false)
  const [unbanning, setUnbanning] = useState(false)
  const [banModal, setBanModal] = useState(false)
  const [unbanModal, setUnbanModal] = useState<number | null>(null)
  const [banDuration, setBanDuration] = useState('24h')
  const [banReason, setBanReason] = useState('manual')

  useEffect(() => {
    setAllAlerts([])
    setAlertPage(1)
  }, [ip])

  useEffect(() => {
    if (!ip) return
    setLoadingInfo(true)
    void Promise.all([
      apiFetch(`/api/ip/${encodeURIComponent(ip)}`).then(async (r) => {
        if (r.ok) setInfo(await r.json() as IpInfo)
      }),
      apiFetch(`/api/ip/${encodeURIComponent(ip)}/timeline?days=30`).then(async (r) => {
        if (r.ok) setTimeline(await r.json() as TimelinePoint[])
      }),
      apiFetch(`/api/ip/${encodeURIComponent(ip)}/decisions`).then(async (r) => {
        if (r.ok) setDecisions(await r.json() as IpDecision[])
      }),
    ]).finally(() => setLoadingInfo(false))
  }, [ip])

  useEffect(() => {
    if (!ip) return
    setLoadingAlerts(true)
    void apiFetch(`/api/ip/${encodeURIComponent(ip)}/alerts?page=${alertPage}&limit=25`)
      .then(async (r) => {
        if (r.ok) {
          const data = await r.json() as AlertsData
          setAlertsData(data)
          // Accumulate alerts from all pages for service distribution chart
          setAllAlerts((prev) => {
            const ids = new Set(prev.map((a) => a.id))
            return [...prev, ...data.alerts.filter((a) => !ids.has(a.id))]
          })
        }
      })
      .finally(() => setLoadingAlerts(false))
  }, [ip, alertPage])

  async function handleBan() {
    if (!ip) return
    setBanning(true)
    try {
      const res = await apiFetch('/api/crowdsec/decisions', {
        method: 'POST',
        body: JSON.stringify({ ip, duration: banDuration, reason: banReason }),
      })
      if (res.ok) {
        addToast(`${ip} banned for ${banDuration}`, 'success')
        setBanModal(false)
        void apiFetch(`/api/ip/${encodeURIComponent(ip)}/decisions`).then(async (r) => {
          if (r.ok) setDecisions(await r.json() as IpDecision[])
        })
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Ban failed', 'error')
      }
    } finally {
      setBanning(false)
    }
  }

  async function handleUnban(id: number) {
    setUnbanning(true)
    try {
      const res = await apiFetch(`/api/crowdsec/decisions/${id}`, { method: 'DELETE' })
      if (res.ok) {
        addToast('Decision deleted', 'success')
        setDecisions((prev) => prev.filter((d) => d.id !== id))
      } else {
        addToast('Unban failed', 'error')
      }
    } finally {
      setUnbanning(false)
      setUnbanModal(null)
    }
  }

  if (!authLoading && !me) return <Navigate to="/login" replace />
  if (!ip) return <Navigate to="/" replace />

  const geo = info?.geo
  const abuse = info?.abuse
  const score = abuse?.abuseConfidenceScore ?? null
  const cc = abuse?.countryCode ?? geo?.countryCode ?? ''
  const totalAlerts = alertsData?.total ?? 0
  const totalDecisions = decisions.length
  const firstSeen = alertsData?.alerts[alertsData.alerts.length - 1]?.start_at
  const lastSeen = alertsData?.alerts[0]?.start_at

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <button type="button" onClick={() => navigate(-1)}
            className="mt-1 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </button>
          <div>
            <div className="flex flex-wrap items-center gap-3">
              {cc && <CountryFlag code={cc} size={24} />}
              <h1 className="font-mono text-2xl font-bold text-slate-900 dark:text-white">{ip}</h1>
              {score !== null && (
                <span className={`rounded-full px-3 py-1 text-sm font-bold ${scoreClasses(score)}`}>
                  Score {score}%
                </span>
              )}
              {abuse?.isTor && (
                <span className="rounded-full bg-purple-500/15 px-2.5 py-1 text-xs font-semibold text-purple-700 dark:text-purple-300">
                  Tor exit
                </span>
              )}
            </div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {geo?.isp ?? abuse?.isp ?? ''}{geo?.city ? ` · ${geo.city}` : ''}{geo?.country ? `, ${geo.country}` : ''}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {me?.is_superuser && (
            <button type="button" onClick={() => setBanModal(true)}
              className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700">
              <ShieldBan className="h-4 w-4" /> Ban IP
            </button>
          )}
          <button type="button" onClick={() => { setLoadingInfo(true); void apiFetch(`/api/ip/${encodeURIComponent(ip)}`).then(async (r) => { if (r.ok) setInfo(await r.json() as IpInfo) }).finally(() => setLoadingInfo(false)) }}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${loadingInfo ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {loadingInfo ? Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />) : (
          <>
            <StatCard icon={AlertTriangle} label="Total alerts" value={totalAlerts} color="border-amber-500/20 bg-amber-500/5" />
            <StatCard icon={Shield} label="Decisions" value={totalDecisions} color="border-red-500/20 bg-red-500/5" />
            <StatCard icon={Clock} label="First seen" value={firstSeen ? new Date(firstSeen).toLocaleDateString() : '—'} color="border-slate-200 bg-slate-50 dark:border-slate-700/50" />
            <StatCard icon={Clock} label="Last seen" value={lastSeen ? new Date(lastSeen).toLocaleDateString() : '—'} color="border-slate-200 bg-slate-50 dark:border-slate-700/50" />
          </>
        )}
      </div>

      {/* Geo + Abuse cards */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Geo */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Geolocation</span>
          </div>
          {loadingInfo ? (
            <div className="grid grid-cols-2 gap-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}</div>
          ) : geo ? (
            <div className="grid grid-cols-2 gap-2">
              {geo.country && <InfoRow label="Country" value={`${cc ? `[${cc}] ` : ''}${geo.country}`} />}
              {geo.city && <InfoRow label="City" value={geo.city} />}
              {geo.isp && <InfoRow label="ISP" value={geo.isp} />}
              {geo.lat != null && geo.lon != null && <InfoRow label="Coordinates" value={`${geo.lat.toFixed(2)}, ${geo.lon.toFixed(2)}`} />}
            </div>
          ) : (
            <p className="text-sm text-slate-400">No geolocation data</p>
          )}
        </div>

        {/* AbuseIPDB */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-amber-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">AbuseIPDB</span>
          </div>
          {loadingInfo ? (
            <div className="grid grid-cols-2 gap-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}</div>
          ) : abuse ? (
            <div className="grid grid-cols-2 gap-2">
              {score !== null && <InfoRow label="Confidence score" value={`${score}%`} />}
              {abuse.totalReports != null && <InfoRow label="Total reports" value={String(abuse.totalReports)} />}
              {abuse.numDistinctUsers != null && <InfoRow label="Distinct reporters" value={String(abuse.numDistinctUsers)} />}
              {abuse.domain && <InfoRow label="Domain" value={abuse.domain} />}
              {abuse.lastReportedAt && <InfoRow label="Last reported" value={new Date(abuse.lastReportedAt).toLocaleDateString()} />}
            </div>
          ) : (
            <p className="text-sm text-slate-400">No AbuseIPDB data — configure an API key in Settings</p>
          )}
        </div>
      </div>

      {/* Service distribution — computed from loaded alerts */}
      {(() => {
        const dist = Object.entries(
          allAlerts.reduce<Record<string, number>>((acc, a) => {
            if (a.target_host) acc[a.target_host] = (acc[a.target_host] ?? 0) + (a.events_count || 1)
            return acc
          }, {})
        )
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
        if (!dist.length) return null
        return (
          <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
            <div className="mb-4 flex items-center gap-2">
              <Globe className="h-4 w-4 text-violet-500" />
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attacks by service</span>
              <span className="text-xs text-slate-400">— based on {allAlerts.length} loaded alerts</span>
            </div>
            <ResponsiveContainer width="100%" height={Math.max(80, dist.length * 28)}>
              <BarChart data={dist.map(([host, count]) => ({ host, count }))} layout="vertical"
                margin={{ left: 8, right: 24, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="host" tick={{ fontSize: 10, fill: '#94a3b8', fontFamily: 'monospace' }}
                  axisLine={false} tickLine={false} width={130} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }}
                  formatter={(v: unknown) => [v, 'Events']} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={18}>
                  {dist.map((_, idx) => (
                    <Cell key={idx} fill={`hsl(${250 + idx * 25}, 65%, 55%)`} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )
      })()}

      {/* Attack timeline */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-violet-500" />
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attack history — last 30 days</span>
        </div>
        {loadingInfo ? <Skeleton className="h-[140px] w-full" /> : timeline.some((p) => p.count > 0) ? (
          <ResponsiveContainer width="100%" height={140}>
            <AreaChart data={timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="ipGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false}
                tickFormatter={(v: string) => v.slice(5)} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} allowDecimals={false} width={45} tickFormatter={(v: number) => v >= 1000 ? `${(v / 1000).toFixed(v % 1000 === 0 ? 0 : 1)}k` : String(v)} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: '#f1f5f9' }} itemStyle={{ color: '#94a3b8' }} />
              <Area type="monotone" dataKey="count" name="Alerts" stroke="#ef4444" strokeWidth={2}
                fill="url(#ipGrad)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex h-[140px] items-center justify-center text-sm text-slate-400">No attack history in the last 30 days</div>
        )}
      </div>

      {/* Alerts + Decisions */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Alerts — 2/3 */}
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60 lg:col-span-2">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              Alerts ({alertsData?.total ?? 0})
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                  {['Scenario', 'Target', 'Events', 'Date'].map((h) => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {loadingAlerts && !alertsData
                  ? Array.from({ length: 8 }).map((_, i) => (
                    <tr key={i}>{Array.from({ length: 4 }).map((__, j) => <td key={j} className="px-4 py-2"><Skeleton className="h-4 w-full" /></td>)}</tr>
                  ))
                  : (alertsData?.alerts ?? []).map((a) => (
                    <tr key={a.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                      <td className="max-w-[180px] truncate px-4 py-2.5 text-xs" title={a.scenario}>
                        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-400">
                          <AlertTriangle className="h-3 w-3 shrink-0" />
                          {a.scenario.replace('crowdsecurity/', '')}
                        </span>
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
                {!loadingAlerts && alertsData?.alerts.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-10 text-center text-sm text-slate-400">No alerts recorded</td></tr>
                )}
              </tbody>
            </table>
          </div>
          {alertsData && alertsData.pages > 1 && (
            <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
              <span className="text-xs text-slate-500">{(alertPage - 1) * 25 + 1}–{Math.min(alertPage * 25, alertsData.total)} of {alertsData.total}</span>
              <div className="flex gap-1">
                <button type="button" disabled={alertPage <= 1} onClick={() => setAlertPage(alertPage - 1)}
                  className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">‹ Prev</button>
                <button type="button" disabled={alertPage >= alertsData.pages} onClick={() => setAlertPage(alertPage + 1)}
                  className="rounded-lg border border-slate-200 bg-white px-2 py-1 text-xs text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">Next ›</button>
              </div>
            </div>
          )}
        </div>

        {/* Decisions — 1/3 */}
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Ban className="h-4 w-4 text-red-500" />
              Decisions ({totalDecisions})
            </h2>
          </div>
          {loadingInfo ? (
            <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {Array.from({ length: 4 }).map((_, i) => <div key={i} className="px-5 py-3"><Skeleton className="h-10 w-full rounded-lg" /></div>)}
            </div>
          ) : decisions.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-slate-400">No decisions found for this IP</p>
          ) : (
            <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {decisions.map((d) => (
                <div key={d.id} className="flex items-start justify-between gap-2 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-700 dark:text-red-400">
                        {d.type ?? 'ban'}
                      </span>
                      {d.scenario && (
                        <span className="max-w-[120px] truncate text-[10px] text-slate-500" title={d.scenario}>
                          {d.scenario.replace('crowdsecurity/', '')}
                        </span>
                      )}
                    </div>
                    {d.until && (
                      <div className="mt-1 flex items-center gap-1 text-[10px] text-slate-400">
                        <Clock className="h-3 w-3" />
                        until {new Date(d.until).toLocaleString()}
                      </div>
                    )}
                  </div>
                  {me?.is_superuser && (
                    <button type="button" onClick={() => setUnbanModal(d.id)}
                      className="shrink-0 rounded-lg border border-red-500/30 bg-red-500/10 p-1.5 text-red-600 hover:bg-red-500/20 dark:text-red-400">
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Ban modal */}
      {banModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setBanModal(false)} />
          <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
            <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-4 dark:border-slate-800">
              <ShieldBan className="h-4 w-4 text-red-500" />
              <span className="font-semibold text-slate-900 dark:text-white">Ban IP</span>
              <code className="ml-auto font-mono text-xs text-slate-500">{ip}</code>
            </div>
            <div className="space-y-4 p-5">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Duration</label>
                <select value={banDuration} onChange={(e) => setBanDuration(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
                  {['1h','6h','24h','72h','168h','720h'].map((d) => (
                    <option key={d} value={d}>{d === '1h' ? '1 hour' : d === '6h' ? '6 hours' : d === '24h' ? '24 hours' : d === '72h' ? '3 days' : d === '168h' ? '1 week' : '1 month'}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Reason</label>
                <input type="text" value={banReason} onChange={(e) => setBanReason(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={() => setBanModal(false)}
                  className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  Cancel
                </button>
                <button type="button" onClick={() => void handleBan()} disabled={banning}
                  className="flex-1 rounded-xl bg-red-600 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-60">
                  {banning ? 'Banning…' : 'Confirm ban'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Unban confirm modal */}
      {unbanModal !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setUnbanModal(null)} />
          <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900 p-5 space-y-4">
            <p className="text-sm font-medium text-slate-900 dark:text-white">Delete decision #{unbanModal}?</p>
            <p className="text-xs text-slate-500">This will remove the ban for <code className="font-mono">{ip}</code>.</p>
            <div className="flex gap-2">
              <button type="button" onClick={() => setUnbanModal(null)}
                className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                Cancel
              </button>
              <button type="button" onClick={() => void handleUnban(unbanModal)} disabled={unbanning}
                className="flex-1 rounded-xl bg-red-600 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-60">
                {unbanning ? 'Removing…' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
