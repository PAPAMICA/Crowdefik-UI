import { Ban, ChevronLeft, ChevronRight, Clock, Download, Filter, Plus, RefreshCw, Search, Shield, ShieldBan, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { CountryFlag } from '../components/CountryFlag'
import { IpBadge } from '../components/IpBadge'

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

type Decision = {
  id?: number
  value?: string
  ip?: string
  type?: string
  scope?: string
  duration?: string
  until?: string
  scenario?: string
  reason?: string
  origin?: string
  _target_host?: string
  [k: string]: unknown
}

const PAGE_SIZE = 25

// Deterministic color from scenario string
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

// ── Country code extraction ───────────────────────────────────
// decisions sometimes carry country info in various fields
function extractCountry(d: Decision): string {
  // Try common keys
  const cc = (d.country_code || d.countryCode || d.cn || '') as string
  return typeof cc === 'string' ? cc.toUpperCase() : ''
}

// ── Pagination controls ───────────────────────────────────────
function Pagination({
  page, total, pageSize, onChange,
}: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)

  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500 dark:text-slate-400">
        {from}–{to} of {total}
      </span>
      <div className="flex gap-1">
        <button
          type="button"
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
          // show first, last, and pages around current
          let p: number
          if (pages <= 7) p = i + 1
          else if (i === 0) p = 1
          else if (i === 6) p = pages
          else p = Math.max(2, Math.min(pages - 1, page - 2 + i))
          return (
            <button
              key={p}
              type="button"
              onClick={() => onChange(p)}
              className={[
                'min-w-[30px] rounded-lg border px-2 py-1.5 text-xs',
                p === page
                  ? 'border-violet-500 bg-violet-500/10 text-violet-600 dark:text-violet-400'
                  : 'border-slate-200 bg-white text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400',
              ].join(' ')}
            >
              {p}
            </button>
          )
        })}
        <button
          type="button"
          disabled={page >= pages}
          onClick={() => onChange(page + 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

export function DecisionsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<Decision[]>([])
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [unbanning, setUnbanning] = useState<number | null>(null)
  const [showBanForm, setShowBanForm] = useState(false)
  const [banIp, setBanIp] = useState('')
  const [banDuration, setBanDuration] = useState('24h')
  const [banReason, setBanReason] = useState('manual')
  const [banning, setBanning] = useState(false)
  const [banMsg, setBanMsg] = useState<{ text: string; ok: boolean } | null>(null)

  async function handleBan() {
    if (!banIp.trim()) return
    setBanning(true)
    setBanMsg(null)
    try {
      const res = await apiFetch('/api/crowdsec/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: banIp.trim(), duration: banDuration, reason: banReason }),
      })
      if (res.ok) {
        setBanMsg({ text: `${banIp} banned for ${banDuration}`, ok: true })
        setBanIp('')
        setTimeout(() => { setShowBanForm(false); setBanMsg(null) }, 1500)
        void loadData()
      } else {
        const err = await res.json().catch(() => ({}))
        setBanMsg({ text: (err as { detail?: string }).detail ?? 'Ban failed', ok: false })
      }
    } finally {
      setBanning(false)
    }
  }

  async function loadData() {
    const res = await apiFetch('/api/crowdsec/decisions?limit=2000')
    if (res.ok) setRows((await res.json()) as Decision[])
  }

  useEffect(() => { void loadData() }, [])

  const types = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((d) => { if (d.type) s.add(String(d.type)) })
    return Array.from(s).sort()
  }, [rows])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows.filter((d) => {
      const ip = String(d.value ?? d.ip ?? '')
      const t = String(d.type ?? '')
      if (typeFilter !== 'all' && t !== typeFilter) return false
      if (!q) return true
      return ip.includes(q) || t.includes(q) || String(d.scenario ?? '').toLowerCase().includes(q)
    })
  }, [rows, search, typeFilter])

  // Reset to page 1 when filters change
  useEffect(() => setPage(1), [search, typeFilter])

  const paged = useMemo(
    () => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [filtered, page],
  )

  async function unban(id: number) {
    if (!confirm(`Unban decision #${id}?`)) return
    setUnbanning(id)
    try {
      const res = await apiFetch(`/api/crowdsec/decisions/${id}`, { method: 'DELETE' })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
        alert(err.detail ?? JSON.stringify(err))
      } else {
        await loadData()
      }
    } finally {
      setUnbanning(null)
    }
  }

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Decisions</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {filtered.length} of {rows.length} active decisions from CrowdSec LAPI
          </p>
        </div>
        <div className="flex gap-2">
          {me?.is_superuser && (
            <button type="button" onClick={() => { setShowBanForm(!showBanForm); setBanMsg(null) }}
              className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700">
              <Plus className="h-4 w-4" /> Ban IP
            </button>
          )}
          <button type="button" onClick={() => exportCSV(filtered, `decisions-${new Date().toISOString().slice(0,10)}.csv`)}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <Download className="h-4 w-4" /> Export CSV
          </button>
          <button type="button" onClick={() => void loadData()}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <RefreshCw className="h-4 w-4" /> Refresh
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
            <input type="text" placeholder="IP address" value={banIp} onChange={(e) => setBanIp(e.target.value)}
              className="flex-1 min-w-[180px] rounded-xl border border-red-200 bg-white px-3 py-2 text-sm dark:border-red-500/30 dark:bg-slate-800 dark:text-slate-200" />
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
          {banMsg && (
            <p className={`mt-2 text-xs ${banMsg.ok ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>{banMsg.text}</p>
          )}
        </div>
      )}

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

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Target service</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Until</th>
                <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {paged.map((d, i) => {
                const ip = String(d.value ?? d.ip ?? '')
                const type = String(d.type ?? '')
                const until = d.until ? new Date(String(d.until)).toLocaleString() : null
                const duration = String(d.duration ?? '')
                const scenario = String(d.scenario ?? d.reason ?? '')
                const cc = extractCountry(d)
                const decisionId = typeof d.id === 'number' ? d.id : null

                return (
                  <tr key={`${ip}-${i}`} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
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
                        <a
                          href={`https://${d._target_host}`} target="_blank" rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300"
                        >
                          <img src={`https://icons.duckduckgo.com/ip3/${d._target_host}.ico`} alt="" width={12} height={12}
                            className="h-3 w-3 rounded-sm object-contain"
                            onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }} />
                          {d._target_host}
                        </a>
                      ) : <span className="text-xs text-slate-400">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        {until && (
                          <span className="text-xs text-slate-700 dark:text-slate-300">{until}</span>
                        )}
                        {duration && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-slate-400">
                            <Clock className="h-3 w-3" />{duration}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end">
                        {/* align colSpan */}
                    {me?.is_superuser && decisionId !== null && (
                          <button
                            type="button"
                            disabled={unbanning === decisionId}
                            title={`Unban — delete decision #${decisionId}`}
                            className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-red-700 hover:bg-red-500/20 disabled:opacity-40 dark:text-red-400"
                            onClick={() => void unban(decisionId)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!paged.length && (
                <tr>
                  <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No decisions match filters' : 'No active decisions — check CrowdSec settings'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} total={filtered.length} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>
    </div>
  )
}
