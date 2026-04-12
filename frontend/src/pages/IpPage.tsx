import {
  AlertTriangle, ArrowLeft, Ban, CheckCircle2, Clock, Filter,
  Globe, RefreshCw, Search, Shield, ShieldBan, ShieldCheck, ShieldOff, Trash2,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom'
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart,
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
type DecisionsData = { total: number; page: number; pages: number; decisions: IpDecision[] }

type RequestEntry = {
  time: string; host: string; method: string; path: string
  status: number | null; duration_ms: number; bytes: number | null
  router: string | null; user_agent: string | null
}
type RequestsData = { available: boolean; total: number; page: number; pages: number; entries: RequestEntry[] }

type TimelinePoint = { date: string; count: number }

const PAGE_SIZE = 10
const CHART_COLORS = ['#6366f1', '#f59e0b', '#ef4444', '#10b981', '#3b82f6', '#ec4899', '#8b5cf6', '#14b8a6', '#f97316', '#64748b']

// ── Helpers ────────────────────────────────────────────────────────────────────

function scoreClasses(score: number) {
  if (score >= 75) return 'bg-red-500/15 text-red-700 dark:text-red-400'
  if (score >= 30) return 'bg-amber-500/15 text-amber-700 dark:text-amber-400'
  if (score > 0)   return 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-400'
  return 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400'
}

function statusColor(code: number | null) {
  if (!code) return 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400'
  if (code < 300) return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
  if (code < 400) return 'bg-blue-500/10 text-blue-700 dark:text-blue-400'
  if (code < 500) return 'bg-amber-500/10 text-amber-700 dark:text-amber-400'
  return 'bg-red-500/10 text-red-700 dark:text-red-400'
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

function Pagination({ page, pages, total, pageSize, onChange }: {
  page: number; pages: number; total: number; pageSize: number; onChange: (p: number) => void
}) {
  if (pages <= 1) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500">{from}–{to} of {total}</span>
      <div className="flex gap-1">
        <button type="button" disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">‹ Prev</button>
        <span className="flex items-center px-2 text-xs text-slate-400">{page}/{pages}</span>
        <button type="button" disabled={page >= pages} onClick={() => onChange(page + 1)}
          className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-xs text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">Next ›</button>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function IpPage() {
  const { ip } = useParams<{ ip: string }>()
  const { me, loading: authLoading } = useAuth()
  const navigate = useNavigate()
  const { addToast } = useToast()

  // Core data
  const [info, setInfo] = useState<IpInfo | null>(null)
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [allDecisions, setAllDecisions] = useState<IpDecision[]>([]) // for unban-all + badge
  const [chartAlerts, setChartAlerts] = useState<IpAlert[]>([])      // for service donut

  // Alerts (paginated + filtered)
  const [alertsData, setAlertsData] = useState<AlertsData | null>(null)
  const [alertPage, setAlertPage] = useState(1)
  const [alertScenario, setAlertScenario] = useState('')
  const [alertHost, setAlertHost] = useState('')
  const [loadingAlerts, setLoadingAlerts] = useState(true)

  // Decisions (paginated + filtered)
  const [decisionsData, setDecisionsData] = useState<DecisionsData | null>(null)
  const [decisionPage, setDecisionPage] = useState(1)
  const [decisionTypeFilter, setDecisionTypeFilter] = useState('')
  const [loadingDecisions, setLoadingDecisions] = useState(true)

  // Requests (paginated + filtered)
  const [requestsData, setRequestsData] = useState<RequestsData | null>(null)
  const [requestPage, setRequestPage] = useState(1)
  const [requestMethod, setRequestMethod] = useState('')
  const [requestStatus, setRequestStatus] = useState('')
  const [requestPath, setRequestPath] = useState('')
  const [loadingRequests, setLoadingRequests] = useState(false)
  const [requestsTriggered, setRequestsTriggered] = useState(false)

  // UI state
  const [loadingInfo, setLoadingInfo] = useState(true)
  const [banning, setBanning] = useState(false)
  const [unbanning, setUnbanning] = useState(false)
  const [banModal, setBanModal] = useState(false)
  const [unbanModal, setUnbanModal] = useState<number | null>(null)
  const [unbanAllModal, setUnbanAllModal] = useState(false)
  const [banDuration, setBanDuration] = useState('24h')
  const [banReason, setBanReason] = useState('manual')
  const [allowlistEntry, setAllowlistEntry] = useState<{ id: number; reason: string | null; expires_at: string | null } | null>(null)
  const [allowlistLoading, setAllowlistLoading] = useState(false)
  const [allowlistModal, setAllowlistModal] = useState(false)
  const [allowlistReason, setAllowlistReason] = useState('manual whitelist')
  const [allowlistDuration, setAllowlistDuration] = useState<string>('permanent')
  const [removeAllowlistModal, setRemoveAllowlistModal] = useState(false)

  // Debounce refs for filter inputs
  const alertDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)
  const decisionDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)
  const requestDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ── Reset on IP change ─────────────────────────────────────────────────────
  useEffect(() => {
    setAlertPage(1)
    setDecisionPage(1)
    setRequestPage(1)
    setChartAlerts([])
    setRequestsTriggered(false)
  }, [ip])

  // ── Core data (info, timeline, all decisions, chart alerts) ───────────────
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
      // Full list of decisions for unban-all + badge
      apiFetch(`/api/ip/${encodeURIComponent(ip)}/decisions?page=1&limit=200`).then(async (r) => {
        if (r.ok) {
          const data = await r.json() as DecisionsData
          setAllDecisions(data.decisions ?? [])
        }
      }),
      // Chart alerts — top 200, no filters
      apiFetch(`/api/ip/${encodeURIComponent(ip)}/alerts?page=1&limit=200`).then(async (r) => {
        if (r.ok) {
          const data = await r.json() as AlertsData
          setChartAlerts(data.alerts)
        }
      }),
      apiFetch('/api/crowdsec/allowlist/check', {
        method: 'POST',
        body: JSON.stringify({ ip }),
      }).then(async (r) => {
        if (r.ok) {
          const data = await r.json() as { protected: boolean; entry?: { id: number; reason: string | null; expires_at: string | null } }
          setAllowlistEntry(data.protected && data.entry ? data.entry : null)
        }
      }),
    ]).finally(() => setLoadingInfo(false))
  }, [ip])

  // ── Alerts (paginated + filtered) ─────────────────────────────────────────
  useEffect(() => {
    if (!ip) return
    if (alertDebounce.current) clearTimeout(alertDebounce.current)
    alertDebounce.current = setTimeout(() => {
      setLoadingAlerts(true)
      const params = new URLSearchParams({
        page: String(alertPage),
        limit: String(PAGE_SIZE),
        ...(alertScenario ? { scenario: alertScenario } : {}),
        ...(alertHost ? { target_host: alertHost } : {}),
      })
      void apiFetch(`/api/ip/${encodeURIComponent(ip)}/alerts?${params}`)
        .then(async (r) => { if (r.ok) setAlertsData(await r.json() as AlertsData) })
        .finally(() => setLoadingAlerts(false))
    }, alertScenario || alertHost ? 300 : 0)
    return () => { if (alertDebounce.current) clearTimeout(alertDebounce.current) }
  }, [ip, alertPage, alertScenario, alertHost])

  // ── Decisions (paginated + filtered) ──────────────────────────────────────
  useEffect(() => {
    if (!ip) return
    if (decisionDebounce.current) clearTimeout(decisionDebounce.current)
    decisionDebounce.current = setTimeout(() => {
      setLoadingDecisions(true)
      const params = new URLSearchParams({
        page: String(decisionPage),
        limit: String(PAGE_SIZE),
        ...(decisionTypeFilter ? { type_filter: decisionTypeFilter } : {}),
      })
      void apiFetch(`/api/ip/${encodeURIComponent(ip)}/decisions?${params}`)
        .then(async (r) => { if (r.ok) setDecisionsData(await r.json() as DecisionsData) })
        .finally(() => setLoadingDecisions(false))
    }, decisionTypeFilter ? 300 : 0)
    return () => { if (decisionDebounce.current) clearTimeout(decisionDebounce.current) }
  }, [ip, decisionPage, decisionTypeFilter])

  // ── Requests (lazy-loaded) ─────────────────────────────────────────────────
  useEffect(() => {
    if (!ip || !requestsTriggered) return
    if (requestDebounce.current) clearTimeout(requestDebounce.current)
    requestDebounce.current = setTimeout(() => {
      setLoadingRequests(true)
      const params = new URLSearchParams({
        page: String(requestPage),
        limit: String(PAGE_SIZE),
        ...(requestMethod ? { method: requestMethod } : {}),
        ...(requestStatus ? { status: requestStatus } : {}),
        ...(requestPath ? { path_filter: requestPath } : {}),
      })
      void apiFetch(`/api/ip/${encodeURIComponent(ip)}/requests?${params}`)
        .then(async (r) => { if (r.ok) setRequestsData(await r.json() as RequestsData) })
        .finally(() => setLoadingRequests(false))
    }, requestMethod || requestStatus || requestPath ? 300 : 0)
    return () => { if (requestDebounce.current) clearTimeout(requestDebounce.current) }
  }, [ip, requestPage, requestMethod, requestStatus, requestPath, requestsTriggered])

  // ── Actions ────────────────────────────────────────────────────────────────
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
        void apiFetch(`/api/ip/${encodeURIComponent(ip)}/decisions?page=1&limit=200`)
          .then(async (r) => { if (r.ok) { const d = await r.json() as DecisionsData; setAllDecisions(d.decisions ?? []) } })
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Ban failed', 'error')
      }
    } finally { setBanning(false) }
  }

  async function handleUnbanAll() {
    setUnbanning(true)
    try {
      await Promise.all(allDecisions.map((d) => apiFetch(`/api/crowdsec/decisions/${d.id}`, { method: 'DELETE' })))
      addToast(`All decisions deleted for ${ip ?? ''}`, 'success')
      setAllDecisions([])
      setDecisionsData(null)
    } catch { addToast('Unban failed', 'error') }
    finally { setUnbanning(false); setUnbanAllModal(false) }
  }

  async function handleUnban(id: number) {
    setUnbanning(true)
    try {
      const res = await apiFetch(`/api/crowdsec/decisions/${id}`, { method: 'DELETE' })
      if (res.ok) {
        addToast('Decision deleted', 'success')
        setAllDecisions((prev) => prev.filter((d) => d.id !== id))
        setDecisionsData((prev) => prev ? { ...prev, decisions: prev.decisions.filter((d) => d.id !== id), total: prev.total - 1 } : null)
      } else { addToast('Unban failed', 'error') }
    } finally { setUnbanning(false); setUnbanModal(null) }
  }

  async function handleWhitelist() {
    if (!ip) return
    setAllowlistLoading(true)
    try {
      const hoursMap: Record<string, number | undefined> = { permanent: undefined, '24h': 24, '168h': 168, '720h': 720, '8760h': 8760 }
      const res = await apiFetch('/api/crowdsec/allowlist', {
        method: 'POST',
        body: JSON.stringify({ value: ip, reason: allowlistReason || 'manual whitelist', expires_hours: hoursMap[allowlistDuration] ?? null }),
      })
      if (res.ok) {
        const data = await res.json() as { id: number; reason: string | null; expires_at: string | null }
        setAllowlistEntry(data)
        setAllowlistModal(false)
        addToast(`${ip} added to allowlist`, 'success')
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Allowlist failed', 'error')
      }
    } finally { setAllowlistLoading(false) }
  }

  async function handleRemoveAllowlist() {
    if (!allowlistEntry) return
    setAllowlistLoading(true)
    try {
      const res = await apiFetch(`/api/crowdsec/allowlist/${allowlistEntry.id}`, { method: 'DELETE' })
      if (res.ok || res.status === 204) {
        setAllowlistEntry(null)
        setRemoveAllowlistModal(false)
        addToast(`${ip ?? ''} removed from allowlist`, 'success')
      } else { addToast('Remove allowlist failed', 'error') }
    } finally { setAllowlistLoading(false) }
  }

  // ── Guard ──────────────────────────────────────────────────────────────────
  if (!authLoading && !me) return <Navigate to="/login" replace />
  if (!ip) return <Navigate to="/" replace />

  const geo = info?.geo
  const abuse = info?.abuse
  const score = abuse?.abuseConfidenceScore ?? null
  const cc = abuse?.countryCode ?? geo?.countryCode ?? ''
  const totalAlerts = alertsData?.total ?? 0
  const totalDecisions = allDecisions.length
  const firstSeen = alertsData?.alerts[alertsData.alerts.length - 1]?.start_at
  const lastSeen = alertsData?.alerts[0]?.start_at

  // Service distribution from chart alerts
  const serviceDist = Object.entries(
    chartAlerts.reduce<Record<string, number>>((acc, a) => {
      if (a.target_host) acc[a.target_host] = (acc[a.target_host] ?? 0) + (a.events_count || 1)
      return acc
    }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([host, count]) => ({ host, count }))

  const inputClass = "rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-700 placeholder-slate-400 focus:border-violet-400 focus:outline-none focus:ring-1 focus:ring-violet-400/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:placeholder-slate-600"

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
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
                <span className={`rounded-full px-3 py-1 text-sm font-bold ${scoreClasses(score)}`}>Score {score}%</span>
              )}
              {allDecisions.length > 0 && (
                <span className="inline-flex items-center gap-1 rounded-full bg-red-500/15 px-2.5 py-1 text-xs font-semibold text-red-700 dark:text-red-400">
                  <ShieldBan className="h-3 w-3" /> Banned
                </span>
              )}
              {allowlistEntry && (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" /> Allowlisted
                </span>
              )}
              {abuse?.isTor && (
                <span className="rounded-full bg-purple-500/15 px-2.5 py-1 text-xs font-semibold text-purple-700 dark:text-purple-300">Tor exit</span>
              )}
            </div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {geo?.isp ?? abuse?.isp ?? ''}{geo?.city ? ` · ${geo.city}` : ''}{geo?.country ? `, ${geo.country}` : ''}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {me?.is_superuser && (
            <>
              {allowlistEntry ? (
                <button type="button" onClick={() => setRemoveAllowlistModal(true)}
                  className="inline-flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-400">
                  <ShieldOff className="h-4 w-4" /> Remove from Allowlist
                </button>
              ) : (
                <button type="button" onClick={() => setAllowlistModal(true)}
                  className="inline-flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-500/20 dark:text-emerald-400">
                  <ShieldCheck className="h-4 w-4" /> Whitelist
                </button>
              )}
              {allDecisions.length > 0 ? (
                <button type="button" onClick={() => setUnbanAllModal(true)} disabled={unbanning}
                  className="inline-flex items-center gap-2 rounded-xl bg-amber-500 px-4 py-2 text-sm font-semibold text-white hover:bg-amber-600 disabled:opacity-60">
                  <ShieldCheck className="h-4 w-4" /> Unban IP
                </button>
              ) : (
                <button type="button" onClick={() => setBanModal(true)}
                  className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700">
                  <ShieldBan className="h-4 w-4" /> Ban IP
                </button>
              )}
            </>
          )}
          <button type="button"
            onClick={() => { setLoadingInfo(true); void apiFetch(`/api/ip/${encodeURIComponent(ip)}`).then(async (r) => { if (r.ok) setInfo(await r.json() as IpInfo) }).finally(() => setLoadingInfo(false)) }}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${loadingInfo ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* ── Stat cards ── */}
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

      {/* ── Geo + Abuse ── */}
      <div className="grid gap-6 lg:grid-cols-2">
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
          ) : <p className="text-sm text-slate-400">No geolocation data</p>}
        </div>

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
          ) : <p className="text-sm text-slate-400">No AbuseIPDB data — configure an API key in Settings</p>}
        </div>
      </div>

      {/* ── Attacks by service (30%) + Attack history (70%) side by side ── */}
      <div className="grid gap-6" style={{ gridTemplateColumns: '30% 1fr' }}>
        {/* Attacks by service — donut */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-3 flex items-center gap-2">
            <Globe className="h-4 w-4 text-violet-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attacks by service</span>
          </div>
          {serviceDist.length === 0 ? (
            <div className="flex h-[200px] items-center justify-center text-sm text-slate-400">No data</div>
          ) : (
            <div className="flex flex-col gap-3">
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={serviceDist} dataKey="count" nameKey="host"
                    cx="50%" cy="50%" innerRadius={44} outerRadius={68} paddingAngle={2}>
                    {serviceDist.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                    formatter={(v, _n, entry) => [v, (entry.payload as { host: string }).host]}
                    labelFormatter={() => ''}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1.5 overflow-auto">
                {serviceDist.map((item, i) => (
                  <button key={item.host} type="button"
                    onClick={() => navigate(`/services/${encodeURIComponent(item.host)}`)}
                    className="flex w-full items-center gap-2 rounded-lg px-1 py-0.5 text-left hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors">
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                    <span className="w-6 shrink-0 text-right text-[10px] font-bold tabular-nums text-slate-400">{item.count}</span>
                    <img src={faviconUrl(item.host)} alt="" width={10} height={10}
                      className="h-2.5 w-2.5 shrink-0 rounded-sm object-contain"
                      onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }} />
                    <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-slate-600 hover:text-violet-600 dark:text-slate-300 dark:hover:text-violet-400" title={item.host}>
                      {item.host}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Attack history timeline */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-violet-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attack history — last 30 days</span>
          </div>
          {loadingInfo ? <Skeleton className="h-[200px] w-full" /> : timeline.some((p) => p.count > 0) ? (
            <ResponsiveContainer width="100%" height={200}>
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
                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} allowDecimals={false} width={36}
                  tickFormatter={(v: number) => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : String(v)} />
                <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#f1f5f9' }} itemStyle={{ color: '#94a3b8' }} />
                <Area type="monotone" dataKey="count" name="Alerts" stroke="#ef4444" strokeWidth={2} fill="url(#ipGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[200px] items-center justify-center text-sm text-slate-400">No attack history in the last 30 days</div>
          )}
        </div>
      </div>

      {/* ── Alerts (full width, filters + pagination) ── */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        {/* Header + filters */}
        <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <span className="text-sm font-semibold text-slate-900 dark:text-white">
                Alerts {alertsData ? `(${alertsData.total})` : ''}
              </span>
            </div>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Filter className="h-3.5 w-3.5 text-slate-400" />
              <div className="relative">
                <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-400 pointer-events-none" />
                <input placeholder="Scenario…" value={alertScenario}
                  onChange={(e) => { setAlertScenario(e.target.value); setAlertPage(1) }}
                  className={`${inputClass} pl-6 w-36`} />
              </div>
              <div className="relative">
                <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-400 pointer-events-none" />
                <input placeholder="Target host…" value={alertHost}
                  onChange={(e) => { setAlertHost(e.target.value); setAlertPage(1) }}
                  className={`${inputClass} pl-6 w-36`} />
              </div>
              {(alertScenario || alertHost) && (
                <button type="button" onClick={() => { setAlertScenario(''); setAlertHost(''); setAlertPage(1) }}
                  className="rounded-lg px-2 py-1.5 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">✕ Clear</button>
              )}
            </div>
          </div>
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
              {loadingAlerts
                ? Array.from({ length: PAGE_SIZE }).map((_, i) => (
                  <tr key={i}>{Array.from({ length: 4 }).map((__, j) => <td key={j} className="px-4 py-2.5"><Skeleton className="h-4 w-full" /></td>)}</tr>
                ))
                : (alertsData?.alerts ?? []).map((a) => (
                  <tr key={a.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-4 py-2.5">
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
        {alertsData && (
          <Pagination page={alertPage} pages={alertsData.pages} total={alertsData.total} pageSize={PAGE_SIZE} onChange={(p) => setAlertPage(p)} />
        )}
      </div>

      {/* ── Decisions (full width, filters + pagination) ── */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <Ban className="h-4 w-4 text-red-500" />
              <span className="text-sm font-semibold text-slate-900 dark:text-white">
                Decisions {decisionsData ? `(${decisionsData.total})` : `(${allDecisions.length})`}
              </span>
            </div>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Filter className="h-3.5 w-3.5 text-slate-400" />
              <div className="relative">
                <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-400 pointer-events-none" />
                <input placeholder="Type (ban, allow…)" value={decisionTypeFilter}
                  onChange={(e) => { setDecisionTypeFilter(e.target.value); setDecisionPage(1) }}
                  className={`${inputClass} pl-6 w-40`} />
              </div>
              {decisionTypeFilter && (
                <button type="button" onClick={() => { setDecisionTypeFilter(''); setDecisionPage(1) }}
                  className="rounded-lg px-2 py-1.5 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">✕ Clear</button>
              )}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                {['Type', 'Scenario', 'Duration', 'Until', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {loadingDecisions
                ? Array.from({ length: PAGE_SIZE }).map((_, i) => (
                  <tr key={i}>{Array.from({ length: 5 }).map((__, j) => <td key={j} className="px-4 py-2.5"><Skeleton className="h-4 w-full" /></td>)}</tr>
                ))
                : (decisionsData?.decisions ?? allDecisions.slice((decisionPage - 1) * PAGE_SIZE, decisionPage * PAGE_SIZE)).map((d) => (
                  <tr key={d.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-4 py-2.5">
                      <span className="rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-700 dark:text-red-400">{d.type ?? 'ban'}</span>
                    </td>
                    <td className="max-w-[160px] truncate px-4 py-2.5 text-xs text-slate-500" title={d.scenario ?? ''}>
                      {d.scenario ? d.scenario.replace('crowdsecurity/', '') : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">{d.duration ?? '—'}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-500">
                      {d.until ? new Date(d.until).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      {me?.is_superuser && (
                        <button type="button" onClick={() => setUnbanModal(d.id)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-500/20 dark:text-red-400">
                          <Trash2 className="h-3 w-3" /> Unban
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              {!loadingDecisions && (decisionsData?.decisions.length === 0 ?? allDecisions.length === 0) && (
                <tr><td colSpan={5} className="px-4 py-10 text-center text-sm text-slate-400">No decisions found for this IP</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {decisionsData ? (
          <Pagination page={decisionPage} pages={decisionsData.pages} total={decisionsData.total} pageSize={PAGE_SIZE} onChange={(p) => setDecisionPage(p)} />
        ) : allDecisions.length > PAGE_SIZE ? (
          <Pagination page={decisionPage} pages={Math.ceil(allDecisions.length / PAGE_SIZE)} total={allDecisions.length} pageSize={PAGE_SIZE} onChange={(p) => setDecisionPage(p)} />
        ) : null}
      </div>

      {/* ── HTTP Requests ── */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-500" />
              <span className="text-sm font-semibold text-slate-900 dark:text-white">
                HTTP Requests {requestsData ? `(${requestsData.total})` : ''}
              </span>
            </div>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              {!requestsTriggered && (
                <button type="button" onClick={() => setRequestsTriggered(true)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  <Search className="h-3.5 w-3.5" /> Load requests from access logs
                </button>
              )}
              {requestsTriggered && (
                <>
                  <Filter className="h-3.5 w-3.5 text-slate-400" />
                  <select value={requestMethod} onChange={(e) => { setRequestMethod(e.target.value); setRequestPage(1) }}
                    className={inputClass}>
                    <option value="">All methods</option>
                    {['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                  <select value={requestStatus} onChange={(e) => { setRequestStatus(e.target.value); setRequestPage(1) }}
                    className={inputClass}>
                    <option value="">All statuses</option>
                    {['2xx','3xx','4xx','5xx'].map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-slate-400 pointer-events-none" />
                    <input placeholder="Path…" value={requestPath}
                      onChange={(e) => { setRequestPath(e.target.value); setRequestPage(1) }}
                      className={`${inputClass} pl-6 w-32`} />
                  </div>
                  {(requestMethod || requestStatus || requestPath) && (
                    <button type="button" onClick={() => { setRequestMethod(''); setRequestStatus(''); setRequestPath(''); setRequestPage(1) }}
                      className="rounded-lg px-2 py-1.5 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">✕ Clear</button>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {!requestsTriggered ? (
          <div className="flex flex-col items-center gap-2 py-12 text-sm text-slate-400">
            <Globe className="h-8 w-8 opacity-30" />
            <span>Click "Load requests" to search through access logs</span>
          </div>
        ) : requestsData && !requestsData.available ? (
          <div className="px-5 py-10 text-center text-sm text-slate-400">Access log not available — configure the path in Settings</div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/60 dark:border-slate-700/50 dark:bg-slate-800/40">
                    {['Time', 'Method', 'Host', 'Path', 'Status', 'Duration', 'Size'].map((h) => (
                      <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-slate-400">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                  {loadingRequests
                    ? Array.from({ length: PAGE_SIZE }).map((_, i) => (
                      <tr key={i}>{Array.from({ length: 7 }).map((__, j) => <td key={j} className="px-4 py-2.5"><Skeleton className="h-4 w-full" /></td>)}</tr>
                    ))
                    : (requestsData?.entries ?? []).map((r, i) => (
                      <tr key={i} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-500">
                          {r.time ? new Date(r.time).toLocaleString() : '—'}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="rounded bg-blue-500/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-blue-700 dark:text-blue-400">{r.method}</span>
                        </td>
                        <td className="px-4 py-2.5">
                          {r.host ? (
                            <div className="flex items-center gap-1">
                              <img src={faviconUrl(r.host)} alt="" width={10} height={10} className="h-2.5 w-2.5 rounded-sm"
                                onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }} />
                              <Link to={`/services/${encodeURIComponent(r.host)}`}
                                className="font-mono text-[11px] text-slate-600 hover:text-violet-600 dark:text-slate-300 dark:hover:text-violet-400">{r.host}</Link>
                            </div>
                          ) : '—'}
                        </td>
                        <td className="max-w-[220px] truncate px-4 py-2.5 font-mono text-[11px] text-slate-700 dark:text-slate-300" title={r.path}>{r.path}</td>
                        <td className="px-4 py-2.5">
                          <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${statusColor(r.status)}`}>{r.status ?? '—'}</span>
                        </td>
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-500">{r.duration_ms > 0 ? `${r.duration_ms}ms` : '—'}</td>
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-500">
                          {r.bytes != null ? (r.bytes > 1024 ? `${(r.bytes / 1024).toFixed(1)}kb` : `${r.bytes}b`) : '—'}
                        </td>
                      </tr>
                    ))}
                  {!loadingRequests && requestsData?.entries.length === 0 && (
                    <tr><td colSpan={7} className="px-4 py-10 text-center text-sm text-slate-400">No requests found in access logs</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            {requestsData && (
              <Pagination page={requestPage} pages={requestsData.pages} total={requestsData.total} pageSize={PAGE_SIZE} onChange={(p) => setRequestPage(p)} />
            )}
          </>
        )}
      </div>

      {/* ── Modals ── */}

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

      {unbanAllModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setUnbanAllModal(false)} />
          <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900 p-5 space-y-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-amber-500" />
              <span className="font-semibold text-slate-900 dark:text-white">Unban IP</span>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Delete all <strong>{allDecisions.length}</strong> active decision{allDecisions.length > 1 ? 's' : ''} for{' '}
              <code className="font-mono text-xs">{ip}</code> ?
            </p>
            <div className="flex gap-2">
              <button type="button" onClick={() => setUnbanAllModal(false)}
                className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                Cancel
              </button>
              <button type="button" onClick={() => void handleUnbanAll()} disabled={unbanning}
                className="flex-1 rounded-xl bg-amber-500 py-2 text-sm font-semibold text-white hover:bg-amber-600 disabled:opacity-60">
                {unbanning ? 'Unbanning…' : 'Confirm Unban'}
              </button>
            </div>
          </div>
        </div>
      )}

      {allowlistModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setAllowlistModal(false)} />
          <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
            <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-4 dark:border-slate-800">
              <ShieldCheck className="h-4 w-4 text-emerald-500" />
              <span className="font-semibold text-slate-900 dark:text-white">Add to Allowlist</span>
              <code className="ml-auto font-mono text-xs text-slate-500">{ip}</code>
            </div>
            <div className="space-y-4 p-5">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Reason</label>
                <input type="text" value={allowlistReason} onChange={(e) => setAllowlistReason(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Duration</label>
                <select value={allowlistDuration} onChange={(e) => setAllowlistDuration(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
                  <option value="permanent">Permanent</option>
                  <option value="24h">24 hours</option>
                  <option value="168h">1 week</option>
                  <option value="720h">1 month</option>
                  <option value="8760h">1 year</option>
                </select>
              </div>
              <p className="rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">
                This IP will be excluded from automatic bans by Crowdefik.
              </p>
              <div className="flex gap-2">
                <button type="button" onClick={() => setAllowlistModal(false)}
                  className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                  Cancel
                </button>
                <button type="button" onClick={() => void handleWhitelist()} disabled={allowlistLoading}
                  className="flex-1 rounded-xl bg-emerald-600 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-60">
                  {allowlistLoading ? 'Adding…' : 'Add to Allowlist'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {removeAllowlistModal && allowlistEntry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setRemoveAllowlistModal(false)} />
          <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900 p-5 space-y-4">
            <div className="flex items-center gap-2">
              <ShieldOff className="h-4 w-4 text-amber-500" />
              <span className="font-semibold text-slate-900 dark:text-white">Remove from Allowlist</span>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Remove <code className="font-mono text-xs">{ip}</code> from the allowlist?
              {allowlistEntry.reason && (
                <span className="block mt-1 text-xs text-slate-400">Reason: {allowlistEntry.reason}</span>
              )}
            </p>
            <div className="flex gap-2">
              <button type="button" onClick={() => setRemoveAllowlistModal(false)}
                className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                Cancel
              </button>
              <button type="button" onClick={() => void handleRemoveAllowlist()} disabled={allowlistLoading}
                className="flex-1 rounded-xl bg-amber-600 py-2 text-sm font-semibold text-white hover:bg-amber-700 disabled:opacity-60">
                {allowlistLoading ? 'Removing…' : 'Remove'}
              </button>
            </div>
          </div>
        </div>
      )}

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
