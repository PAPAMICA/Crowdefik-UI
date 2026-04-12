import {
  Activity, AlertTriangle, ArrowLeft, Ban, ExternalLink,
  FileText, Globe, RefreshCw, Server, Settings, Shield, Users,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, Navigate, useParams, useSearchParams } from 'react-router-dom'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'
import { Skeleton, SkeletonCard, SkeletonRow } from '../components/Skeleton'
import { useToast } from '../components/Toast'
import { usePagePerf } from '../hooks/usePagePerf'
import { faviconUrl } from '../utils/favicon'

// ── Types ─────────────────────────────────────────────────────────────────────

type Stats = {
  total_alerts: number
  unique_ips: number
  blocked_decisions: number
  total_events: number
}

type TimelinePoint = { date: string; alerts: number; blocked: number }

type TopIp = {
  ip: string; count: number
  country_code: string | null; country: string | null
  city: string | null; isp: string | null
  abuse_score?: number | null
}

type TopScenario = { scenario: string; count: number }

type RecentAlert = {
  id: number; scenario: string; source_ip: string | null
  country: string | null; events_count: number
  start_at: string | null; context: Record<string, string>
}

type Overview = {
  host: string; days: number; stats: Stats
  timeline: TimelinePoint[]
  top_ips: TopIp[]
  top_scenarios: TopScenario[]
  recent_alerts: RecentAlert[]
}

type LogEntry = {
  time: string | null; method: string | null; path: string | null
  status: number | null; client_ip: string | null; duration_ms: number
  router: string | null; service: string | null
  tls_version: string | null; bytes: number | null
}

type LogsData = {
  host: string; available: boolean
  entries: LogEntry[]; total: number
  page: number; pages: number; source?: string
}

type Policy = {
  host: string
  min_events_to_display: number
  auto_ban_enabled: boolean
  auto_ban_min_score: number | null
  auto_ban_min_events: number | null
  auto_ban_window_hours: number
  auto_ban_duration: string
  muted_scenarios: string[]
  notes: string | null
  updated_at: string | null
}

// ── Policy editor ─────────────────────────────────────────────────────────────

function PolicyTab({ host, isSuperuser }: { host: string; isSuperuser: boolean }) {
  const { addToast } = useToast()
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState<Policy | null>(null)
  const [knownScenarios, setKnownScenarios] = useState<string[]>([])

  useEffect(() => {
    async function load() {
      setLoading(true)
      const [pRes, sRes] = await Promise.all([
        apiFetch(`/api/services/${encodeURIComponent(host)}/policy`),
        apiFetch(`/api/services/${encodeURIComponent(host)}/overview?days=30`),
      ])
      if (pRes.ok) {
        const p = await pRes.json() as Policy
        setPolicy(p)
        setForm(p)
      }
      if (sRes.ok) {
        const data = await sRes.json() as { top_scenarios: { scenario: string }[] }
        setKnownScenarios(data.top_scenarios?.map((s) => s.scenario) ?? [])
      }
      setLoading(false)
    }
    void load()
  }, [host])

  async function handleSave() {
    if (!form) return
    setSaving(true)
    try {
      const res = await apiFetch(`/api/services/${encodeURIComponent(host)}/policy`, {
        method: 'PUT',
        body: JSON.stringify({
          ...form,
          min_events_to_display: form.min_events_to_display,
        }),
      })
      if (res.ok) {
        const p = await res.json() as Policy
        setPolicy(p); setForm(p)
        addToast('Policy saved', 'success')
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Save failed', 'error')
      }
    } finally {
      setSaving(false)
    }
  }

  function toggleScenario(scenario: string) {
    if (!form) return
    const muted = form.muted_scenarios.includes(scenario)
      ? form.muted_scenarios.filter((s) => s !== scenario)
      : [...form.muted_scenarios, scenario]
    setForm({ ...form, muted_scenarios: muted })
  }

  if (loading) return <div className="p-6 text-sm text-slate-400">Loading policy…</div>
  if (!form) return <div className="p-6 text-sm text-red-400">Failed to load policy</div>

  return (
    <div className="space-y-6 p-6">
      {/* Display settings */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
          <Globe className="h-4 w-4 text-blue-500" /> Display settings
        </h3>
        <label className="flex items-center gap-3 text-sm text-slate-700 dark:text-slate-300">
          <span className="min-w-[220px]">Min events to display alert</span>
          <input type="number" min={1} max={100} value={form.min_events_to_display}
            disabled={!isSuperuser}
            onChange={(e) => setForm({ ...form, min_events_to_display: Number(e.target.value) })}
            className="w-20 rounded-xl border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
        </label>
      </div>

      {/* Auto-ban */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
            <Ban className="h-4 w-4 text-red-500" /> Auto-ban engine
          </h3>
          <label className="flex items-center gap-2 cursor-pointer">
            <span className="text-xs text-slate-500">Enabled</span>
            <div className="relative">
              <input type="checkbox" checked={form.auto_ban_enabled} disabled={!isSuperuser}
                onChange={(e) => setForm({ ...form, auto_ban_enabled: e.target.checked })}
                className="sr-only peer" />
              <div aria-hidden="true" className={`h-5 w-9 rounded-full transition-colors ${form.auto_ban_enabled ? 'bg-red-500' : 'bg-slate-300 dark:bg-slate-600'} peer-disabled:opacity-60`} />
              <div aria-hidden="true" className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${form.auto_ban_enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
            </div>
          </label>
        </div>
        <div className="space-y-3">
          {[
            { label: 'Min AbuseIPDB score to trigger ban (0–100)', key: 'auto_ban_min_score', min: 0, max: 100 },
            { label: 'Min events in window to trigger ban', key: 'auto_ban_min_events', min: 1, max: 9999 },
            { label: 'Rolling window (hours)', key: 'auto_ban_window_hours', min: 1, max: 720 },
          ].map(({ label, key, min, max }) => (
            <div key={key} className="flex items-center gap-3 text-sm">
              <span className="min-w-[280px] text-slate-600 dark:text-slate-400">{label}</span>
              <input type="number" min={min} max={max}
                value={(form as unknown as Record<string, number | null>)[key] ?? ''}
                disabled={!isSuperuser || !form.auto_ban_enabled}
                onChange={(e) => setForm({ ...form, [key]: e.target.value ? Number(e.target.value) : null } as Policy)}
                className="w-24 rounded-xl border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
            </div>
          ))}
          <div className="flex items-center gap-3 text-sm">
            <span className="min-w-[280px] text-slate-600 dark:text-slate-400">Ban duration</span>
            <select value={form.auto_ban_duration} disabled={!isSuperuser || !form.auto_ban_enabled}
              onChange={(e) => setForm({ ...form, auto_ban_duration: e.target.value })}
              className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-1.5 text-sm disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
              {['1h', '6h', '24h', '48h', '168h', '720h'].map((d) => (
                <option key={d} value={d}>{d}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Muted scenarios */}
      {knownScenarios.length > 0 && (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
            <Shield className="h-4 w-4 text-amber-500" /> Muted scenarios
            <span className="text-xs font-normal text-slate-400">— alerts from these scenarios are suppressed for this service</span>
          </h3>
          <div className="flex flex-wrap gap-2">
            {knownScenarios.map((scenario) => {
              const muted = form.muted_scenarios.includes(scenario)
              return (
                <button key={scenario} type="button" disabled={!isSuperuser}
                  onClick={() => toggleScenario(scenario)}
                  className={`rounded-full px-3 py-1 text-xs font-medium transition ${muted
                    ? 'bg-amber-500/20 text-amber-700 dark:text-amber-400 line-through opacity-60'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-300'}`}>
                  {scenario}
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Notes */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
          <FileText className="h-4 w-4 text-slate-400" /> Admin notes
        </h3>
        <textarea rows={4} value={form.notes ?? ''} disabled={!isSuperuser}
          onChange={(e) => setForm({ ...form, notes: e.target.value || null })}
          placeholder="Internal notes about this service…"
          className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
      </div>

      {isSuperuser && (
        <div className="flex justify-end">
          <button type="button" onClick={() => void handleSave()} disabled={saving}
            className="inline-flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-violet-700 disabled:opacity-60">
            {saving ? 'Saving…' : 'Save policy'}
          </button>
        </div>
      )}
      {policy?.updated_at && (
        <p className="text-center text-xs text-slate-400">Last updated: {new Date(policy.updated_at).toLocaleString()}</p>
      )}
    </div>
  )
}

// ── Color helpers ─────────────────────────────────────────────────────────────

const SCENARIO_COLORS = [
  '#6366f1', '#f59e0b', '#ef4444', '#10b981', '#3b82f6',
  '#ec4899', '#8b5cf6', '#14b8a6', '#f97316', '#64748b',
]

function statusColor(code: number | null) {
  if (!code) return 'text-slate-400'
  if (code < 300) return 'text-emerald-600 dark:text-emerald-400'
  if (code < 400) return 'text-blue-500'
  if (code < 500) return 'text-amber-600 dark:text-amber-400'
  return 'text-red-600 dark:text-red-400'
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, color }: {
  icon: typeof Shield; label: string; value: number | string; color: string
}) {
  return (
    <div className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 ${color}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{value.toLocaleString()}</div>
        </div>
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${color.split(' ')[1]}`}>
          <Icon className="h-5 w-5 text-slate-600 dark:text-slate-300" />
        </div>
      </div>
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({ title, icon: Icon, children, iconColor = 'text-violet-500' }: {
  title: string; icon: typeof Shield; children: React.ReactNode; iconColor?: string
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
      <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
        <h2 className={`flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white`}>
          <Icon className={`h-4 w-4 ${iconColor}`} />{title}
        </h2>
      </div>
      {children}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function ServicePage() {
  const { host } = useParams<{ host: string }>()
  const { me, loading: authLoading } = useAuth()
  const [days, setDays] = useState(7)
  const [overview, setOverview] = useState<Overview | null>(null)
  const [logsData, setLogsData] = useState<LogsData | null>(null)
  const [loadingOverview, setLoadingOverview] = useState(true)
  const [loadingLogs, setLoadingLogs] = useState(true)
  const decodedHost = host ? decodeURIComponent(host) : 'Service'
  usePagePerf(decodedHost, loadingOverview || loadingLogs)
  const [searchParams] = useSearchParams()
  const [logSearch, setLogSearch] = useState('')
  const [logTab, setLogTab] = useState<'all' | '2xx' | '3xx' | '4xx' | '5xx'>('all')
  const [mainTab, setMainTab] = useState<'overview' | 'policy'>(
    searchParams.get('tab') === 'policy' ? 'policy' : 'overview'
  )

  async function loadOverview() {
    if (!host) return
    setLoadingOverview(true)
    try {
      const r = await apiFetch(`/api/services/${encodeURIComponent(host)}/overview?days=${days}`)
      if (r.ok) setOverview(await r.json() as Overview)
    } finally {
      setLoadingOverview(false)
    }
  }

  async function loadLogs() {
    if (!host) return
    setLoadingLogs(true)
    try {
      const r = await apiFetch(`/api/services/${encodeURIComponent(host)}/logs?lines=2000&limit=500`)
      if (r.ok) setLogsData(await r.json() as LogsData)
    } finally {
      setLoadingLogs(false)
    }
  }

  useEffect(() => { void loadOverview() }, [host, days])
  useEffect(() => { void loadLogs() }, [host])

  const filteredLogs = useMemo(() => {
    if (!logsData?.entries) return []
    const q = logSearch.toLowerCase()
    return logsData.entries.filter((e) => {
      const code = e.status ?? 0
      if (logTab === '2xx' && (code < 200 || code >= 300)) return false
      if (logTab === '3xx' && (code < 300 || code >= 400)) return false
      if (logTab === '4xx' && (code < 400 || code >= 500)) return false
      if (logTab === '5xx' && code < 500) return false
      if (!q) return true
      return (
        (e.path ?? '').toLowerCase().includes(q) ||
        (e.client_ip ?? '').includes(q) ||
        String(e.status ?? '').includes(q) ||
        (e.method ?? '').toLowerCase().includes(q)
      )
    })
  }, [logsData, logSearch, logTab])

  if (!authLoading && !me) return <Navigate to="/login" replace />
  if (!host) return <Navigate to="/" replace />

  const s = overview?.stats

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <Link to="/alerts"
            className="mt-1 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            <ArrowLeft className="h-3.5 w-3.5" /> Back
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <img
                src={faviconUrl(host)}
                alt="" width={24} height={24}
                className="h-6 w-6 rounded-md object-contain"
                onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
              />
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">{host}</h1>
              <a
                href={host.includes(':') ? `http://${host}` : `https://${host}`}
                target="_blank" rel="noopener noreferrer"
                title="Open in browser"
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-xs text-slate-500 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-700/40 dark:text-slate-400">
                <ExternalLink className="h-3 w-3" /> Visit
              </a>
            </div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              Security overview — last {days} day{days !== 1 ? 's' : ''}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select value={days} onChange={(e) => setDays(Number(e.target.value))}
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            {[1, 7, 14, 30].map((d) => <option key={d} value={d}>{d === 1 ? 'Last 24h' : `Last ${d} days`}</option>)}
          </select>
          <button type="button" onClick={() => { void loadOverview(); void loadLogs() }}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <RefreshCw className={`h-4 w-4 ${loadingOverview ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 rounded-xl border border-slate-200 bg-white p-1 dark:border-slate-700 dark:bg-slate-800 w-fit">
        {([['overview', 'Overview', Shield], ['policy', 'Policy', Settings]] as const).map(([id, label, Icon]) => (
          <button key={id} type="button" onClick={() => setMainTab(id)}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition ${mainTab === id ? 'bg-violet-600 text-white shadow' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'}`}>
            <Icon className="h-3.5 w-3.5" />{label}
          </button>
        ))}
      </div>

      {mainTab === 'policy' && host && (
        <PolicyTab host={decodedHost} isSuperuser={!!me?.is_superuser} />
      )}

      {mainTab === 'overview' && <>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {loadingOverview ? (
          Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)
        ) : (
          <>
            <StatCard icon={AlertTriangle} label="Total alerts" value={s?.total_alerts ?? '—'} color="border-red-500/20 bg-red-500/5" />
            <StatCard icon={Users} label="Unique attacker IPs" value={s?.unique_ips ?? '—'} color="border-amber-500/20 bg-amber-500/5" />
            <StatCard icon={Ban} label="Blocked decisions" value={s?.blocked_decisions ?? '—'} color="border-violet-500/20 bg-violet-500/5" />
            <StatCard icon={Shield} label="Total events" value={s?.total_events ?? '—'} color="border-blue-500/20 bg-blue-500/5" />
          </>
        )}
      </div>

      {/* Timeline + Scenarios */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Timeline — 2/3 */}
        <div className="lg:col-span-2 rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-indigo-500" />
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">
                {days === 1 ? 'Activity — last 24h (per hour)' : `Alerts over time — last ${days} days`}
              </span>
            </div>
            <div className="flex items-center gap-3 text-[11px]">
              <span className="flex items-center gap-1.5"><span className="inline-block h-2 w-4 rounded-full bg-indigo-500" />Alerts</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2 w-4 rounded-full bg-red-500" />Blocked</span>
            </div>
          </div>
          {loadingOverview ? (
            <Skeleton className="h-[180px] w-full" />
          ) : overview?.timeline?.length ? (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={overview.timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
                <defs>
                  <linearGradient id="svcGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="svcBlockedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" vertical={false} />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false}
                  tickFormatter={(v: string) => days === 1 ? v : v.slice(5)}
                  interval={days === 1 ? 3 : 'preserveStartEnd'} />
                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} allowDecimals={false} width={45} tickFormatter={(v: number) => v >= 1000 ? `${(v / 1000).toFixed(v % 1000 === 0 ? 0 : 1)}k` : String(v)} />
                <Tooltip
                  contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#f1f5f9' }} itemStyle={{ color: '#94a3b8' }} />
                <Area type="monotone" dataKey="alerts" name="Alerts" stroke="#6366f1" strokeWidth={2}
                  fill="url(#svcGrad)" dot={false} />
                <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" strokeWidth={2}
                  fill="url(#svcBlockedGrad)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[180px] items-center justify-center text-sm text-slate-400">
              No data for this period
            </div>
          )}
        </div>

        {/* Top scenarios — 1/3 */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Top attack types</span>
          </div>
          {loadingOverview ? (
            <div className="space-y-2 pt-2">
              <Skeleton className="mx-auto h-[120px] w-[120px] rounded-full" />
              {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-4 w-full" />)}
            </div>
          ) : overview?.top_scenarios?.length ? (
            <>
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie data={overview.top_scenarios} dataKey="count" nameKey="scenario"
                    cx="50%" cy="50%" innerRadius={30} outerRadius={55} paddingAngle={3}>
                    {overview.top_scenarios.map((_, idx) => (
                      <Cell key={idx} fill={SCENARIO_COLORS[idx % SCENARIO_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }}
                    formatter={(v, name) => [v, String(name).replace('crowdsecurity/', '')]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-3 space-y-1.5">
                {overview.top_scenarios.slice(0, 5).map((s, idx) => (
                  <div key={s.scenario} className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="h-2.5 w-2.5 flex-shrink-0 rounded-full"
                        style={{ background: SCENARIO_COLORS[idx % SCENARIO_COLORS.length] }} />
                      <span className="truncate text-xs text-slate-600 dark:text-slate-300">
                        {s.scenario.replace('crowdsecurity/', '')}
                      </span>
                    </div>
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-200">{s.count}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex h-[180px] items-center justify-center text-sm text-slate-400">
              No attacks recorded
            </div>
          )}
        </div>
      </div>

      {/* Top attacker IPs */}
      <Section title="Top attacker IPs" icon={Globe} iconColor="text-red-500">
        {loadingOverview ? (
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)}
          </div>
        ) : overview?.top_ips?.length ? (
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {overview.top_ips.map((ip) => (
              <div key={ip.ip} className="flex items-center gap-3 px-5 py-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <IpBadge ip={ip.ip} countryCode={ip.country_code} score={ip.abuse_score} />
                    {ip.country && (
                      <span className="text-xs text-slate-400">{ip.city ? `${ip.city}, ` : ''}{ip.country}</span>
                    )}
                    {ip.isp && <span className="truncate text-xs text-slate-400">{ip.isp}</span>}
                  </div>
                </div>
                <div className="flex-shrink-0">
                  <span className="rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-semibold text-red-700 dark:bg-red-900/30 dark:text-red-400">
                    {ip.count} alert{ip.count !== 1 ? 's' : ''}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="px-5 py-8 text-center text-sm text-slate-400">
            No attacker data for this period
          </p>
        )}
      </Section>

      {/* Top IPs distribution chart */}
      {!loadingOverview && (overview?.top_ips?.length ?? 0) > 0 && (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="mb-4 flex items-center gap-2">
            <Globe className="h-4 w-4 text-red-500" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Attack distribution by IP</span>
            <span className="text-xs text-slate-400">— top {overview!.top_ips.length} attackers</span>
          </div>
          <ResponsiveContainer width="100%" height={Math.max(120, overview!.top_ips.length * 28)}>
            <BarChart
              data={overview!.top_ips.map(ip => ({ ip: ip.ip, count: ip.count }))}
              layout="vertical"
              margin={{ left: 8, right: 24, top: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false}
                tickFormatter={(v: number) => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : String(v)} />
              <YAxis type="category" dataKey="ip" tick={{ fontSize: 10, fill: '#94a3b8', fontFamily: 'monospace' }}
                axisLine={false} tickLine={false} width={110} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }}
                formatter={(v: unknown) => [String(v ?? ''), 'Alerts']} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
                {overview!.top_ips.map((_, idx) => (
                  <Cell key={idx} fill={`hsl(${(idx * 37) % 360}, 70%, 55%)`} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent alerts */}
      <Section title="Recent alerts" icon={AlertTriangle} iconColor="text-amber-500">
        {loadingOverview ? (
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)}
          </div>
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Source IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Context</th>
                <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Events</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {overview?.recent_alerts?.length ? overview.recent_alerts.map((a) => (
                <tr key={a.id} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-700 dark:text-red-400">
                      <AlertTriangle className="h-3 w-3" />
                      {String(a.scenario ?? '').replace('crowdsecurity/', '') || '—'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {a.source_ip ? <IpBadge ip={a.source_ip} /> : <span className="text-xs text-slate-400">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(a.context).slice(0, 4).map(([k, v]) => (
                        <span key={k} className="inline-block rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-600 dark:bg-slate-700 dark:text-slate-300"
                          title={`${k}: ${v}`}>
                          {k}: {String(v).length > 30 ? String(v).slice(0, 30) + '…' : v}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium dark:bg-slate-700 dark:text-slate-300">
                      {a.events_count}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">
                    {a.start_at ? new Date(a.start_at).toLocaleString() : '—'}
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-sm text-slate-400">
                    No alerts for this period
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        )}
      </Section>

      {/* Traefik request logs */}
      <Section title="Request logs" icon={FileText} iconColor="text-blue-500">
        {loadingLogs && !logsData ? (
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {Array.from({ length: 6 }).map((_, i) => <SkeletonRow key={i} />)}
          </div>
        ) : logsData?.available === false ? (
          <div className="px-5 py-8 text-center">
            <Server className="mx-auto mb-3 h-8 w-8 text-slate-300 dark:text-slate-600" />
            <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Access logs not available</p>
            <p className="mt-1 text-xs text-slate-400">
              Set <code className="rounded bg-slate-100 px-1 dark:bg-slate-700">CROWDEFIK_TRAEFIK_LOG_PATH</code> and mount the log directory.
            </p>
          </div>
        ) : (
          <>
            {/* Log filters */}
            <div className="flex flex-wrap items-center gap-3 border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
              <input
                className="flex-1 min-w-[180px] rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-blue-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                placeholder="Filter by path, IP, status…"
                value={logSearch} onChange={(e) => setLogSearch(e.target.value)}
              />
              <div className="flex gap-1 rounded-lg border border-slate-200 bg-white p-0.5 dark:border-slate-700 dark:bg-slate-800">
                {(['all', '2xx', '3xx', '4xx', '5xx'] as const).map((t) => (
                  <button key={t} type="button" onClick={() => setLogTab(t)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition ${logTab === t ? 'bg-blue-500 text-white' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400'}`}>
                    {t}
                  </button>
                ))}
              </div>
              <span className="text-xs text-slate-400">{filteredLogs.length} entries</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50 dark:border-slate-700/50 dark:bg-slate-800/40">
                    <th className="px-4 py-2.5 text-left font-medium text-slate-400">Time</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-400">Method</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-400 w-1/3">Path</th>
                    <th className="px-4 py-2.5 text-center font-medium text-slate-400">Status</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-400">Client IP</th>
                    <th className="px-4 py-2.5 text-right font-medium text-slate-400">Duration</th>
                    <th className="px-4 py-2.5 text-right font-medium text-slate-400">Size</th>
                    <th className="px-4 py-2.5 text-left font-medium text-slate-400">TLS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/30">
                  {filteredLogs.slice(0, 200).map((entry, i) => (
                    <tr key={i} className="hover:bg-slate-50/60 dark:hover:bg-white/5">
                      <td className="px-4 py-2 font-mono text-slate-500 whitespace-nowrap">
                        {entry.time ? new Date(entry.time).toLocaleTimeString() : '—'}
                      </td>
                      <td className="px-4 py-2 font-mono font-semibold text-slate-700 dark:text-slate-300 whitespace-nowrap">
                        {entry.method ?? '—'}
                      </td>
                      <td className="px-4 py-2 font-mono text-slate-600 dark:text-slate-300 max-w-xs truncate" title={entry.path ?? ''}>
                        {entry.path ?? '—'}
                      </td>
                      <td className={`px-4 py-2 text-center font-semibold ${statusColor(entry.status)}`}>
                        {entry.status ?? '—'}
                      </td>
                      <td className="px-4 py-2 font-mono text-slate-600 dark:text-slate-300 whitespace-nowrap">
                        {entry.client_ip ?? '—'}
                      </td>
                      <td className="px-4 py-2 text-right font-mono text-slate-500 whitespace-nowrap">
                        {entry.duration_ms > 0 ? `${entry.duration_ms}ms` : '—'}
                      </td>
                      <td className="px-4 py-2 text-right font-mono text-slate-400 whitespace-nowrap">
                        {entry.bytes != null ? `${(entry.bytes / 1024).toFixed(1)}k` : '—'}
                      </td>
                      <td className="px-4 py-2 text-slate-400 whitespace-nowrap">
                        {entry.tls_version ?? '—'}
                      </td>
                    </tr>
                  ))}
                  {filteredLogs.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-10 text-center text-slate-400">
                        {loadingLogs ? 'Loading…' : 'No log entries match the current filter'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
              {filteredLogs.length > 200 && (
                <p className="px-5 py-2 text-center text-xs text-slate-400">
                  Showing 200 of {filteredLogs.length} entries — refine filter to see more
                </p>
              )}
            </div>
          </>
        )}
      </Section>

      </> /* end overview tab */}
    </div>
  )
}
