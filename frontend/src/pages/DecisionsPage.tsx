import {
  Ban, ChevronLeft, ChevronRight, Clock, Download,
  Filter, Plus, RefreshCw, Search, Shield, ShieldBan,
  Trash2, X,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Navigate, useSearchParams } from 'react-router-dom'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { CountryFlag } from '../components/CountryFlag'
import { IpBadge } from '../components/IpBadge'
import { useToast } from '../components/Toast'
import { usePagePerf } from '../hooks/usePagePerf'
import { faviconUrl } from '../utils/favicon'

// ── Donut helpers ──────────────────────────────────────────────────────────────

const DONUT_COLORS = ['#8b5cf6','#6366f1','#3b82f6','#06b6d4','#10b981','#f59e0b','#f97316','#ef4444','#ec4899','#a855f7']

type DonutEntry = { name: string; value: number }

function MiniDonut({ title, data, renderLabel }: {
  title: string
  data: DonutEntry[]
  renderLabel?: (e: DonutEntry) => React.ReactNode
}) {
  if (!data.length) return null
  const top = data.slice(0, 8)
  const total = top.reduce((s, e) => s + e.value, 0)
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 dark:border-slate-700/50 dark:bg-slate-800/60">
      <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{title}</p>
      <div className="flex items-center gap-4">
        <div className="h-[110px] w-[110px] shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={top} dataKey="value" cx="50%" cy="50%" innerRadius={32} outerRadius={52} paddingAngle={2} strokeWidth={0}>
                {top.map((_, i) => <Cell key={i} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />)}
              </Pie>
              <Tooltip
                contentStyle={{ background: 'var(--tw-bg, #1e293b)', border: 'none', borderRadius: 8, fontSize: 12 }}
                formatter={(v: unknown) => [String(v ?? ''), '']}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <ul className="min-w-0 flex-1 space-y-1 text-xs">
          {top.map((e, i) => (
            <li key={i} className="flex items-center gap-1.5 truncate">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }} />
              <span className="flex-1 truncate text-slate-700 dark:text-slate-300">
                {renderLabel ? renderLabel(e) : e.name}
              </span>
              <span className="ml-auto shrink-0 tabular-nums text-slate-400">
                {total > 0 ? `${Math.round((e.value / total) * 100)}%` : ''}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}

// ── CSV export ─────────────────────────────────────────────────────────────────

function exportCSV(rows: Decision[], filename: string) {
  const headers = ['ID', 'IP', 'Type', 'Scenario', 'Service', 'Until']
  const lines = rows.map((d) => [
    d.id ?? '',
    String(d.value ?? d.ip ?? ''),
    d.type ?? '',
    String(d.scenario ?? '').replace('crowdsecurity/', ''),
    d._target_host ?? '',
    d.until ? new Date(d.until).toISOString() : '',
  ])
  const csv = [headers, ...lines].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

// ── Types ──────────────────────────────────────────────────────────────────────

type Decision = {
  id?: number; value?: string; ip?: string; type?: string; scope?: string
  duration?: string; until?: string; scenario?: string; reason?: string
  origin?: string; _target_host?: string; [k: string]: unknown
}

type DecisionPage = { total: number; page: number; pages: number; decisions: Decision[] }

const PAGE_SIZE = 25

// ── Helpers ────────────────────────────────────────────────────────────────────

const SCENARIO_PALETTES = [
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

function scenarioColor(scenario: string): string {
  let hash = 0
  for (let i = 0; i < scenario.length; i++) hash = ((hash * 31) + scenario.charCodeAt(i)) >>> 0
  return SCENARIO_PALETTES[hash % SCENARIO_PALETTES.length]
}

function extractCountry(d: Decision): string {
  const cc = (d.country_code || d.countryCode || d.cn || '') as string
  return typeof cc === 'string' ? cc.toUpperCase() : ''
}

function ScenarioBadge({ scenario }: { scenario: string }) {
  const label = scenario.replace(/^crowdsecurity\//, '').replace(/^firehol\//, '')
  return (
    <span className={`inline-flex max-w-[200px] items-center truncate rounded-full border px-2.5 py-0.5 text-xs font-medium ${scenarioColor(scenario)}`}
      title={scenario}>
      {label || '—'}
    </span>
  )
}

function TypeBadge({ type }: { type: string }) {
  const t = type.toLowerCase()
  if (t === 'ban')
    return <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-700 dark:text-red-400"><Ban className="h-3 w-3" />Ban</span>
  if (t === 'captcha')
    return <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-400"><Shield className="h-3 w-3" />Captcha</span>
  return <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-300">{type}</span>
}

// ── Pagination ─────────────────────────────────────────────────────────────────

function Pagination({ page, total, pageSize, onChange }: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500 dark:text-slate-400">{from}–{to} of {total.toLocaleString()}</span>
      <div className="flex gap-1">
        <button type="button" disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
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
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// ── Confirm modal ──────────────────────────────────────────────────────────────

function ConfirmModal({ ip, decisionId, onConfirm, onCancel, loading }: {
  ip: string; decisionId: number; onConfirm: () => void; onCancel: () => void; loading: boolean
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onCancel} />
      <div className="relative z-10 w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-5 shadow-2xl dark:border-slate-700 dark:bg-slate-900 space-y-4">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-slate-900 dark:text-white">Remove ban?</span>
          <button type="button" onClick={onCancel} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Delete decision <code className="font-mono text-xs">#{decisionId}</code> for{' '}
          <code className="font-mono text-xs font-semibold">{ip}</code>?
        </p>
        <div className="flex gap-2">
          <button type="button" onClick={onCancel}
            className="flex-1 rounded-xl border border-slate-200 bg-white py-2 text-sm font-medium text-slate-600 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            Cancel
          </button>
          <button type="button" onClick={onConfirm} disabled={loading}
            className="flex-1 rounded-xl bg-red-600 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-60">
            {loading ? 'Removing…' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function DecisionsPage() {
  const { me, loading } = useAuth()
  const { addToast } = useToast()
  const [searchParams, setSearchParams] = useSearchParams()

  const [search, setSearch] = useState(searchParams.get('search') ?? '')
  const [debouncedSearch, setDebouncedSearch] = useState(searchParams.get('search') ?? '')
  const [typeFilter, setTypeFilter] = useState(searchParams.get('type') ?? 'all')
  const [page, setPage] = useState(Number(searchParams.get('page') ?? '1'))

  const [data, setData] = useState<DecisionPage | null>(null)
  const [fetchingData, setFetchingData] = useState(true)
  const [unbanning, setUnbanning] = useState(false)
  const [confirmUnban, setConfirmUnban] = useState<{ ip: string; id: number } | null>(null)
  const [showBanForm, setShowBanForm] = useState(false)
  const [banIp, setBanIp] = useState('')
  const [banDuration, setBanDuration] = useState('24h')
  const [banReason, setBanReason] = useState('manual')
  const [banning, setBanning] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [bulkUnbanning, setBulkUnbanning] = useState(false)

  usePagePerf('Decisions', fetchingData)

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 350)
    return () => clearTimeout(t)
  }, [search])

  // Sync URL params
  useEffect(() => {
    const p: Record<string, string> = {}
    if (debouncedSearch) p.search = debouncedSearch
    if (typeFilter !== 'all') p.type = typeFilter
    if (page > 1) p.page = String(page)
    setSearchParams(p, { replace: true })
  }, [debouncedSearch, typeFilter, page]) // eslint-disable-line react-hooks/exhaustive-deps

  // Reset page when filters change
  useEffect(() => { setPage(1) }, [debouncedSearch, typeFilter])

  const buildParams = useCallback(() => {
    const p = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) })
    if (debouncedSearch) p.set('search', debouncedSearch)
    if (typeFilter !== 'all') p.set('type_filter', typeFilter)
    return p
  }, [page, debouncedSearch, typeFilter])

  async function loadData() {
    setFetchingData(true)
    try {
      const res = await apiFetch(`/api/crowdsec/decisions?${buildParams()}`)
      if (res.ok) setData(await res.json() as DecisionPage)
    } finally {
      setFetchingData(false)
    }
  }

  useEffect(() => { void loadData() }, [page, debouncedSearch, typeFilter]) // eslint-disable-line react-hooks/exhaustive-deps

  // Type options from current page data — ideally from API but derived locally works
  const types = useMemo(() => {
    const s = new Set<string>()
    ;(data?.decisions ?? []).forEach((d) => { if (d.type) s.add(String(d.type)) })
    return Array.from(s).sort()
  }, [data])

  // Distribution charts
  const scenarioDist = useMemo<DonutEntry[]>(() => {
    const m = new Map<string, number>()
    ;(data?.decisions ?? []).forEach((d) => { const k = String(d.scenario ?? d.reason ?? '').replace('crowdsecurity/', ''); if (k) m.set(k, (m.get(k) ?? 0) + 1) })
    return Array.from(m.entries()).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
  }, [data])

  const ipDist = useMemo<DonutEntry[]>(() => {
    const m = new Map<string, number>()
    ;(data?.decisions ?? []).forEach((d) => { const ip = String(d.value ?? d.ip ?? ''); if (ip) m.set(ip, (m.get(ip) ?? 0) + 1) })
    return Array.from(m.entries()).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
  }, [data])

  const serviceDist = useMemo<DonutEntry[]>(() => {
    const m = new Map<string, number>()
    ;(data?.decisions ?? []).forEach((d) => { if (d._target_host) m.set(d._target_host, (m.get(d._target_host) ?? 0) + 1) })
    return Array.from(m.entries()).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value)
  }, [data])

  async function handleBan() {
    if (!banIp.trim()) return
    setBanning(true)
    try {
      const res = await apiFetch('/api/crowdsec/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: banIp.trim(), duration: banDuration, reason: banReason }),
      })
      if (res.ok) {
        addToast(`${banIp.trim()} banned for ${banDuration}`, 'success')
        setBanIp(''); setShowBanForm(false)
        void loadData()
      } else {
        const err = await res.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Ban failed', 'error')
      }
    } finally {
      setBanning(false)
    }
  }

  async function handleUnban() {
    if (!confirmUnban) return
    setUnbanning(true)
    try {
      const res = await apiFetch(`/api/crowdsec/decisions/${confirmUnban.id}`, { method: 'DELETE' })
      if (res.ok) {
        addToast(`Decision #${confirmUnban.id} removed`, 'success')
        void loadData()
      } else {
        addToast('Failed to remove decision', 'error')
      }
    } finally {
      setUnbanning(false)
      setConfirmUnban(null)
    }
  }

  async function handleBulkUnban() {
    const ids = [...selectedIds]
    if (!ids.length) return
    setBulkUnbanning(true)
    try {
      const res = await apiFetch('/api/crowdsec/decisions/bulk', {
        method: 'DELETE',
        body: JSON.stringify({ ids }),
      })
      if (res.ok) {
        const d = await res.json() as { success: number; failed: number[] }
        addToast(`${d.success} decision${d.success !== 1 ? 's' : ''} removed`, 'success')
        if (d.failed.length) addToast(`${d.failed.length} failed to remove`, 'warning')
        setSelectedIds(new Set())
        void loadData()
      } else {
        addToast('Bulk unban failed', 'error')
      }
    } finally {
      setBulkUnbanning(false)
    }
  }

  if (!loading && !me) return <Navigate to="/login" replace />

  const rows = data?.decisions ?? []
  const total = data?.total ?? 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Decisions</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {total.toLocaleString()} active decision{total !== 1 ? 's' : ''} from CrowdSec LAPI
          </p>
        </div>
        <div className="flex gap-2">
          {me?.is_superuser && (
            <button type="button" onClick={() => { setShowBanForm(!showBanForm) }}
              className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700">
              <Plus className="h-4 w-4" /> Ban IP
            </button>
          )}
          <button
            type="button"
            title={`Export current page (${rows.length} rows)`}
            onClick={() => exportCSV(rows, `decisions-page${page}-${new Date().toISOString().slice(0,10)}.csv`)}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <Download className="h-4 w-4" /> Export page ({rows.length})
          </button>
          <button type="button" onClick={() => void loadData()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <RefreshCw className={`h-4 w-4 ${fetchingData ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
      </div>

      {/* Ban IP form */}
      {showBanForm && (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 dark:border-red-500/30 dark:bg-red-900/20">
          <div className="mb-3 flex items-center gap-2">
            <ShieldBan className="h-4 w-4 text-red-500" />
            <span className="text-sm font-semibold text-red-800 dark:text-red-300">Ban an IP manually</span>
          </div>
          <div className="flex flex-wrap gap-3">
            <input type="text" placeholder="IP or CIDR (e.g. 1.2.3.4 or 10.0.0.0/8)" value={banIp} onChange={(e) => setBanIp(e.target.value)}
              className="flex-1 min-w-[240px] rounded-xl border border-red-200 bg-white px-3 py-2 text-sm dark:border-red-500/30 dark:bg-slate-800 dark:text-slate-200" />
            <select value={banDuration} onChange={(e) => setBanDuration(e.target.value)}
              className="rounded-xl border border-red-200 bg-white px-3 py-2 text-sm dark:border-red-500/30 dark:bg-slate-800 dark:text-slate-200">
              <option value="1h">1 hour</option>
              <option value="6h">6 hours</option>
              <option value="24h">24 hours</option>
              <option value="72h">3 days</option>
              <option value="168h">1 week</option>
              <option value="720h">1 month</option>
            </select>
            <input type="text" placeholder="Reason" value={banReason} onChange={(e) => setBanReason(e.target.value)}
              className="flex-1 min-w-[140px] rounded-xl border border-red-200 bg-white px-3 py-2 text-sm dark:border-red-500/30 dark:bg-slate-800 dark:text-slate-200" />
            <button type="button" onClick={() => void handleBan()} disabled={banning || !banIp.trim()}
              className="rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 disabled:opacity-60">
              {banning ? 'Banning…' : 'Ban'}
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Filter by IP or scenario…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <select
            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="all">All types</option>
            {types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </div>

      {/* Distribution charts */}
      {rows.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <MiniDonut title="Scenario distribution" data={scenarioDist} />
          <MiniDonut title="Source IP distribution" data={ipDist}
            renderLabel={(e) => <IpBadge ip={e.name} compact />}
          />
          <MiniDonut title="Target service distribution" data={serviceDist}
            renderLabel={(e) => (
              <span className="flex items-center gap-1.5 truncate">
                <img src={faviconUrl(e.name)} alt="" className="h-3.5 w-3.5 rounded-sm" onError={(ev) => { (ev.target as HTMLImageElement).style.display = 'none' }} />
                <span className="truncate">{e.name}</span>
              </span>
            )}
          />
        </div>
      )}

      {/* Bulk action bar */}
      {selectedIds.size > 0 && me?.is_superuser && (
        <div className="fixed bottom-6 left-1/2 z-40 -translate-x-1/2 flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-5 py-3 shadow-2xl dark:border-slate-700 dark:bg-slate-800">
          <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{selectedIds.size} decision{selectedIds.size !== 1 ? 's' : ''} selected</span>
          <button type="button" onClick={() => void handleBulkUnban()} disabled={bulkUnbanning}
            className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-60">
            <Ban className="h-4 w-4" />
            {bulkUnbanning ? 'Removing…' : `Unban ${selectedIds.size}`}
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
                      checked={rows.length > 0 && rows.every((d) => typeof d.id === 'number' && selectedIds.has(d.id))}
                      onChange={(e) => setSelectedIds(e.target.checked ? new Set(rows.filter((d) => typeof d.id === 'number').map((d) => d.id as number)) : new Set())}
                      className="rounded" />
                  </th>
                )}
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Target service</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Until</th>
                <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {rows.map((d, i) => {
                const ip = String(d.value ?? d.ip ?? '')
                const type = String(d.type ?? '')
                const until = d.until ? new Date(String(d.until)).toLocaleString() : null
                const duration = String(d.duration ?? '')
                const scenario = String(d.scenario ?? d.reason ?? '')
                const cc = extractCountry(d)
                const decisionId = typeof d.id === 'number' ? d.id : null
                const isSelected = typeof d.id === 'number' && selectedIds.has(d.id)

                return (
                  <tr key={d.id ?? i} className={`hover:bg-slate-50/50 dark:hover:bg-white/5 ${isSelected ? 'bg-emerald-50/50 dark:bg-emerald-900/10' : ''}`}>
                    {me?.is_superuser && (
                      <td className="w-10 px-3 py-3">
                        {decisionId !== null && (
                          <input type="checkbox" checked={isSelected}
                            onChange={(e) => {
                              const next = new Set(selectedIds)
                              if (e.target.checked) next.add(decisionId)
                              else next.delete(decisionId)
                              setSelectedIds(next)
                            }}
                            className="rounded" />
                        )}
                      </td>
                    )}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {cc && <CountryFlag code={cc} size={20} />}
                        {ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <TypeBadge type={type} />
                    </td>
                    <td className="px-4 py-3">
                      <ScenarioBadge scenario={scenario} />
                    </td>
                    <td className="px-4 py-3">
                      {d._target_host ? (
                        <a href={`https://${d._target_host}`} target="_blank" rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300">
                          <img src={faviconUrl(d._target_host)} alt="" width={12} height={12}
                            className="h-3 w-3 rounded-sm object-contain"
                            onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }} />
                          {d._target_host}
                        </a>
                      ) : <span className="text-xs text-slate-400">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        {until && <span className="text-xs text-slate-700 dark:text-slate-300">{until}</span>}
                        {duration && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-slate-400">
                            <Clock className="h-3 w-3" />{duration}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end">
                        {me?.is_superuser && decisionId !== null && (
                          <button type="button"
                            title={`Unban — delete decision #${decisionId}`}
                            className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-red-700 hover:bg-red-500/20 dark:text-red-400"
                            onClick={() => setConfirmUnban({ ip, id: decisionId })}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!rows.length && (
                <tr>
                  <td colSpan={me?.is_superuser ? 7 : 6} className="px-4 py-12 text-center text-sm text-slate-400">
                    {total === 0 ? 'No active decisions — check CrowdSec settings' : 'No decisions match filters'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} total={total} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>

      {/* Confirm unban modal */}
      {confirmUnban && (
        <ConfirmModal
          ip={confirmUnban.ip}
          decisionId={confirmUnban.id}
          onConfirm={() => void handleUnban()}
          onCancel={() => setConfirmUnban(null)}
          loading={unbanning}
        />
      )}
    </div>
  )
}
