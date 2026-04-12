import {
  AlertTriangle, ChevronLeft, ChevronRight, Clock,
  Download, ExternalLink, Filter, Info, Loader2,
  RefreshCw, Search, Settings, ShieldBan, X,
} from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'
import { useToast } from '../components/Toast'
import { usePagePerf } from '../hooks/usePagePerf'
import { faviconUrl } from '../utils/favicon'

// ── CSV export ─────────────────────────────────────────────────────────────────

function exportCSV(rows: Alert[], filename: string) {
  const headers = ['ID', 'Scenario', 'Source IP', 'Country', 'Service', 'Events', 'Started']
  const lines = rows.map((a) => [
    a.id ?? '',
    String(a.scenario ?? '').replace('crowdsecurity/', ''),
    String(a.source?.ip ?? a.source?.value ?? ''),
    String(a.source?.cn ?? ''),
    a._target_host ?? '',
    a.events_count ?? 0,
    a.start_at ? new Date(a.start_at).toISOString() : '',
  ])
  const csv = [headers, ...lines].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

// ── Types ──────────────────────────────────────────────────────────────────────

type CrowdsecStatus = {
  bouncer_configured: boolean; watcher_configured: boolean
  machine_id: string | null; lapi_url: string
}

type AlertContext = { key: string; value: string }

type Alert = {
  id?: number
  scenario?: string
  source?: { ip?: string; value?: string; cn?: string }
  events_count?: number
  start_at?: string
  stop_at?: string
  context?: AlertContext[]
  decisions?: { type: string; duration: string; value: string }[]
  _target_host?: string
  [k: string]: unknown
}

const PAGE_SIZE = 25

// ── Scenario coloring ──────────────────────────────────────────────────────────
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

// ── Sub-components ─────────────────────────────────────────────────────────────

function ServiceBadge({ host }: { host: string }) {
  const navigate = useNavigate()
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); navigate(`/services/${encodeURIComponent(host)}`) }}
      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 hover:border-violet-300 hover:bg-violet-50 hover:text-violet-700 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300 transition-colors"
    >
      <img src={faviconUrl(host)} alt="" width={12} height={12}
        className="h-3 w-3 rounded-sm object-contain"
        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }} />
      {host}
    </button>
  )
}

function EnrichButton({ alertId, onEnriched }: { alertId: number; onEnriched: (host: string) => void }) {
  const [loading, setLoading] = useState(false)
  async function handle(e: React.MouseEvent) {
    e.stopPropagation()
    setLoading(true)
    try {
      const r = await apiFetch(`/api/crowdsec/alerts/${alertId}/enrich`, { method: 'POST' })
      if (r.ok) {
        const data = await r.json() as { target_host?: string }
        if (data.target_host) onEnriched(data.target_host)
      }
    } finally {
      setLoading(false)
    }
  }
  return (
    <button type="button" onClick={handle} disabled={loading}
      title="Search target service in Traefik logs"
      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] font-medium text-slate-500 hover:border-violet-300 hover:bg-violet-50 hover:text-violet-700 disabled:opacity-50 dark:border-slate-600 dark:bg-slate-700/40 dark:text-slate-400 transition-colors">
      {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
    </button>
  )
}

function Pagination({ page, total, pageSize, onChange }: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500">{from}–{to} of {total.toLocaleString()}</span>
      <div className="flex gap-1">
        <button type="button" disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
          <ChevronLeft className="h-4 w-4" />
        </button>
        {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
          let p: number
          if (pages <= 7) p = i + 1
          else if (i === 0) p = 1
          else if (i === 6) p = pages
          else p = Math.max(2, Math.min(pages - 1, page - 2 + i))
          return (
            <button key={p} type="button" onClick={() => onChange(p)}
              className={`min-w-[30px] rounded-lg border px-2 py-1.5 text-xs ${p === page ? 'border-violet-500 bg-violet-500/10 text-violet-600 dark:text-violet-400' : 'border-slate-200 bg-white text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400'}`}>
              {p}
            </button>
          )
        })}
        <button type="button" disabled={page >= pages} onClick={() => onChange(page + 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// ── Alert detail panel ─────────────────────────────────────────────────────────

function AlertDetailPanel({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const ip = String(alert.source?.ip ?? alert.source?.value ?? '')
  const scenario = String(alert.scenario ?? '')
  const contexts = alert.context ?? []
  const decisions = alert.decisions ?? []

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed right-0 top-0 z-50 flex h-dvh w-full max-w-md flex-col border-l border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900 overflow-hidden">
        {/* Header */}
        <div className="flex shrink-0 items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            <span className="font-mono text-sm font-semibold text-slate-900 dark:text-white">
              Alert #{alert.id}
            </span>
          </div>
          <button type="button" onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Scenario */}
          <div>
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Scenario</div>
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${scenarioColor(scenario)}`}>
              <AlertTriangle className="h-3.5 w-3.5" />
              {scenario || '—'}
            </span>
          </div>

          {/* IP + Links */}
          <div>
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Source IP</div>
            <div className="flex items-center gap-2">
              {ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}
              {ip && (
                <Link to={`/ip/${encodeURIComponent(ip)}`} onClick={onClose}
                  className="inline-flex items-center gap-1 rounded-lg border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[11px] text-violet-700 hover:bg-violet-500/15 dark:text-violet-400">
                  <ExternalLink className="h-3 w-3" /> IP page
                </Link>
              )}
            </div>
          </div>

          {/* Target service */}
          <div>
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Target service</div>
            {alert._target_host ? (
              <div className="flex items-center gap-2">
                <ServiceBadge host={alert._target_host} />
                <Link to={`/services/${encodeURIComponent(alert._target_host)}`} onClick={onClose}
                  className="inline-flex items-center gap-1 rounded-lg border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[11px] text-violet-700 hover:bg-violet-500/15 dark:text-violet-400">
                  <ExternalLink className="h-3 w-3" /> Service page
                </Link>
              </div>
            ) : <span className="text-xs text-slate-400">Not identified</span>}
          </div>

          {/* Timing */}
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-xl bg-slate-50 px-3 py-2.5 dark:bg-slate-800/60">
              <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                <Clock className="h-3 w-3" /> Started
              </div>
              <div className="mt-0.5 text-xs font-medium text-slate-700 dark:text-slate-200">
                {alert.start_at ? new Date(alert.start_at).toLocaleString() : '—'}
              </div>
            </div>
            <div className="rounded-xl bg-slate-50 px-3 py-2.5 dark:bg-slate-800/60">
              <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                <Clock className="h-3 w-3" /> Events
              </div>
              <div className="mt-0.5 text-xs font-bold text-slate-700 dark:text-slate-200">
                {alert.events_count ?? 0}
              </div>
            </div>
          </div>

          {/* Context */}
          {contexts.length > 0 && (
            <div>
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Context</div>
              <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-700">
                {contexts.map((c, idx) => (
                  <div key={idx} className={`flex items-start gap-2 px-3 py-2 text-xs ${idx > 0 ? 'border-t border-slate-100 dark:border-slate-800' : ''}`}>
                    <span className="w-28 shrink-0 font-medium text-slate-500 dark:text-slate-400">{c.key}</span>
                    <span className="min-w-0 break-all text-slate-700 dark:text-slate-300">{c.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Decisions embedded */}
          {decisions.length > 0 && (
            <div>
              <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Decisions</div>
              <div className="space-y-1.5">
                {decisions.map((d, idx) => (
                  <div key={idx} className="flex items-center gap-2 rounded-xl bg-red-500/10 px-3 py-2 text-xs">
                    <ShieldBan className="h-3.5 w-3.5 text-red-500 shrink-0" />
                    <span className="font-medium text-red-700 dark:text-red-400">{d.type}</span>
                    <span className="text-slate-500">·</span>
                    <span className="text-slate-600 dark:text-slate-300">{d.duration}</span>
                    {d.value !== ip && <span className="font-mono text-[10px] text-slate-400">{d.value}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function AlertsPage() {
  const { me, loading } = useAuth()
  const { addToast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()

  // Sync state with URL params
  const [search, setSearch] = useState(searchParams.get('search') ?? '')
  const [debouncedSearch, setDebouncedSearch] = useState(searchParams.get('search') ?? '')
  const [scenarioFilter, setScenarioFilter] = useState(searchParams.get('scenario') ?? 'all')
  const [serviceFilter, setServiceFilter] = useState(searchParams.get('service') ?? 'all')
  const [page, setPage] = useState(Number(searchParams.get('page') ?? '1'))

  const [rows, setRows] = useState<Alert[]>([])
  const [total, setTotal] = useState(0)
  const [fetching, setFetching] = useState(false)
  const [csStatus, setCsStatus] = useState<CrowdsecStatus | null>(null)
  const [scenarios, setScenarios] = useState<string[]>([])
  const [services, setServices] = useState<string[]>([])
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [bulkBanning, setBulkBanning] = useState(false)

  // Ban modal
  const [banModal, setBanModal] = useState<{ ip: string } | null>(null)
  const [banDuration, setBanDuration] = useState('24h')
  const [banReason, setBanReason] = useState('manual')
  const [banning, setBanning] = useState(false)

  usePagePerf('Alerts', fetching)

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 350)
    return () => clearTimeout(t)
  }, [search])

  // Sync URL when filters change
  useEffect(() => {
    const p: Record<string, string> = {}
    if (debouncedSearch) p.search = debouncedSearch
    if (scenarioFilter !== 'all') p.scenario = scenarioFilter
    if (serviceFilter !== 'all') p.service = serviceFilter
    if (page > 1) p.page = String(page)
    setSearchParams(p, { replace: true })
  }, [debouncedSearch, scenarioFilter, serviceFilter, page]) // eslint-disable-line react-hooks/exhaustive-deps

  // Reset page to 1 when filters change
  useEffect(() => { setPage(1) }, [debouncedSearch, scenarioFilter, serviceFilter])

  const buildParams = useCallback((overridePage?: number) => {
    const p = new URLSearchParams({ page: String(overridePage ?? page), limit: String(PAGE_SIZE) })
    if (debouncedSearch) p.set('search', debouncedSearch)
    if (scenarioFilter !== 'all') p.set('scenario', scenarioFilter)
    if (serviceFilter !== 'all') p.set('host', serviceFilter)
    return p
  }, [page, debouncedSearch, scenarioFilter, serviceFilter])

  async function loadPage() {
    setFetching(true)
    try {
      const r = await apiFetch(`/api/crowdsec/alerts?${buildParams()}`)
      if (r.ok) {
        const data = await r.json() as { total: number; alerts: Alert[] }
        setRows(data.alerts)
        setTotal(data.total)
      }
    } finally {
      setFetching(false)
    }
  }

  async function handleBan() {
    if (!banModal) return
    setBanning(true)
    try {
      const res = await apiFetch('/api/crowdsec/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: banModal.ip, duration: banDuration, reason: banReason }),
      })
      if (res.ok) {
        addToast(`${banModal.ip} banned for ${banDuration}`, 'success')
        setBanModal(null)
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Ban failed', 'error')
      }
    } finally {
      setBanning(false)
    }
  }

  async function handleBulkBan() {
    const ips = rows
      .filter((a) => typeof a.id === 'number' && selectedIds.has(a.id))
      .map((a) => String(a.source?.ip ?? a.source?.value ?? ''))
      .filter(Boolean)
    const uniqueIps = [...new Set(ips)]
    if (!uniqueIps.length) return
    setBulkBanning(true)
    try {
      const res = await apiFetch('/api/crowdsec/decisions/bulk', {
        method: 'POST',
        body: JSON.stringify({ ips: uniqueIps, duration: '24h', reason: 'bulk-ban' }),
      })
      if (res.ok) {
        const data = await res.json() as { count: number }
        addToast(`${data.count} IPs banned`, 'success')
        setSelectedIds(new Set())
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Bulk ban failed', 'error')
      }
    } finally {
      setBulkBanning(false)
    }
  }

  async function handleExportCSV() {
    const p = buildParams(1)
    p.set('limit', '10000')
    const r = await apiFetch(`/api/crowdsec/alerts?${p}`)
    if (r.ok) {
      const data = await r.json() as { alerts: Alert[] }
      exportCSV(data.alerts, `alerts-${new Date().toISOString().slice(0, 10)}.csv`)
    }
  }

  // Load filter options
  useEffect(() => {
    void apiFetch('/api/crowdsec/alerts/filters').then(async (r) => {
      if (r.ok) {
        const data = await r.json() as { scenarios: string[]; hosts: string[] }
        setScenarios(data.scenarios)
        setServices(data.hosts)
      }
    })
    void apiFetch('/api/crowdsec/status').then(async (r) => {
      if (r.ok) setCsStatus(await r.json() as CrowdsecStatus)
    })
  }, [])

  // Re-fetch when page or filters change
  useEffect(() => { void loadPage() }, [page, debouncedSearch, scenarioFilter, serviceFilter]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Alerts</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {total.toLocaleString()} alert{total !== 1 ? 's' : ''}{fetching ? ' — loading…' : ''}
          </p>
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={() => void handleExportCSV()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <Download className="h-4 w-4" /> Export CSV
          </button>
          <button type="button" onClick={() => void loadPage()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <RefreshCw className={`h-4 w-4 ${fetching ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* CrowdSec machine credentials warning */}
      {csStatus && !csStatus.watcher_configured && (
        <div className="flex items-start gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm dark:border-amber-500/30 dark:bg-amber-900/20">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
          <div className="flex-1 text-amber-800 dark:text-amber-300">
            <p className="font-semibold">CrowdSec machine credentials missing</p>
            <p className="mt-0.5 text-xs">
              Alerts require <em>watcher</em> (machine) authentication, not the bouncer key.
            </p>
            <pre className="mt-1.5 rounded-lg bg-amber-100/60 px-3 py-2 font-mono text-[11px] dark:bg-amber-900/40">
              {`docker exec crowdsec cscli machines add crowdefik --password <password>`}
            </pre>
            <Link to="/settings"
              className="mt-2 inline-flex items-center gap-1.5 rounded-lg bg-amber-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-600">
              <Settings className="h-3 w-3" /> Configure in settings
            </Link>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="IP, scenario, service…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
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

      {/* Bulk action bar */}
      {selectedIds.size > 0 && me?.is_superuser && (
        <div className="fixed bottom-6 left-1/2 z-40 -translate-x-1/2 flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-5 py-3 shadow-2xl dark:border-slate-700 dark:bg-slate-800">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{selectedIds.size} alert{selectedIds.size !== 1 ? 's' : ''} selected</span>
          <button type="button" onClick={() => void handleBulkBan()} disabled={bulkBanning}
            className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-60">
            <ShieldBan className="h-4 w-4" />
            {bulkBanning ? 'Banning…' : `Ban ${selectedIds.size} IP${selectedIds.size !== 1 ? 's' : ''}`}
          </button>
          <button type="button" onClick={() => setSelectedIds(new Set())}
            className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:hover:bg-slate-700">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                {me?.is_superuser && (
                  <th className="w-10 px-3 py-3">
                    <input type="checkbox"
                      checked={rows.length > 0 && rows.every((a) => typeof a.id === 'number' && selectedIds.has(a.id))}
                      onChange={(e) => setSelectedIds(e.target.checked ? new Set(rows.filter((a) => typeof a.id === 'number').map((a) => a.id as number)) : new Set())}
                      className="rounded" />
                  </th>
                )}
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Source IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Target service</th>
                <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Events</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Started</th>
                {me?.is_superuser && <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-slate-400" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {rows.map((a, i) => {
                const ip = String(a.source?.ip ?? a.source?.value ?? '')
                const scenario = String(a.scenario ?? '')
                const label = scenario.replace('crowdsecurity/', '')
                const events = Number(a.events_count ?? 0)
                const startAt = a.start_at ? new Date(a.start_at).toLocaleString() : '—'
                const isSelected = typeof a.id === 'number' && selectedIds.has(a.id)
                return (
                  <tr
                    key={a.id ?? i}
                    className={`cursor-pointer hover:bg-slate-50/70 dark:hover:bg-white/5 ${isSelected ? 'bg-violet-50/50 dark:bg-violet-900/10' : ''}`}
                    onClick={() => setSelectedAlert(a)}
                  >
                    {me?.is_superuser && (
                      <td className="w-10 px-3 py-3" onClick={(e) => e.stopPropagation()}>
                        {typeof a.id === 'number' && (
                          <input type="checkbox" checked={isSelected}
                            onChange={(e) => {
                              const next = new Set(selectedIds)
                              if (e.target.checked) next.add(a.id as number)
                              else next.delete(a.id as number)
                              setSelectedIds(next)
                            }}
                            className="rounded" />
                        )}
                      </td>
                    )}
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${scenarioColor(scenario)}`}>
                        <AlertTriangle className="h-3 w-3" />{label || '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      {a._target_host
                        ? <ServiceBadge host={a._target_host} />
                        : typeof a.id === 'number'
                          ? <EnrichButton alertId={a.id} onEnriched={(host) => {
                              setRows((prev) => prev.map((r) => r.id === a.id ? { ...r, _target_host: host } : r))
                              if (selectedAlert?.id === a.id) setSelectedAlert({ ...a, _target_host: host })
                            }} />
                          : <span className="text-xs text-slate-400">—</span>}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium dark:bg-slate-700 dark:text-slate-300">{events}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400">{startAt}</td>
                    {me?.is_superuser && (
                      <td className="px-4 py-3">
                        {ip && (
                          <button type="button"
                            onClick={(e) => { e.stopPropagation(); setBanModal({ ip }); setBanDuration('24h'); setBanReason('manual') }}
                            className="inline-flex items-center gap-1 rounded-lg border border-red-200 bg-red-50 px-2 py-1 text-[11px] font-medium text-red-700 hover:bg-red-100 dark:border-red-500/30 dark:bg-red-900/20 dark:text-red-400"
                            title="Ban this IP">
                            <ShieldBan className="h-3 w-3" /> Ban
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
              {!rows.length && !fetching && (
                <tr>
                  <td colSpan={me?.is_superuser ? 7 : 5} className="px-4 py-12 text-center text-sm text-slate-400">
                    {total === 0 && !debouncedSearch && scenarioFilter === 'all' && serviceFilter === 'all'
                      ? 'No alerts — check CrowdSec settings and machine credentials'
                      : 'No alerts match filters'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} total={total} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>

      {/* Alert detail panel */}
      {selectedAlert && (
        <AlertDetailPanel alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}

      {/* Ban IP modal */}
      {banModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setBanModal(null)} />
          <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
            <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-4 dark:border-slate-800">
              <ShieldBan className="h-4 w-4 text-red-500" />
              <span className="font-semibold text-slate-900 dark:text-white">Ban IP</span>
              <code className="ml-auto font-mono text-xs text-slate-500">{banModal.ip}</code>
            </div>
            <div className="space-y-4 p-5">
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Duration</label>
                <select value={banDuration} onChange={(e) => setBanDuration(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200">
                  <option value="1h">1 hour</option>
                  <option value="6h">6 hours</option>
                  <option value="24h">24 hours</option>
                  <option value="72h">3 days</option>
                  <option value="168h">1 week</option>
                  <option value="720h">1 month</option>
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Reason</label>
                <input type="text" value={banReason} onChange={(e) => setBanReason(e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200" />
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={() => setBanModal(null)}
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
    </div>
  )
}
