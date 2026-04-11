import { AlertTriangle, Download, Filter, Info, RefreshCw, Search, Settings, ShieldBan } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { IpBadge } from '../components/IpBadge'

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

type CrowdsecStatus = {
  bouncer_configured: boolean
  watcher_configured: boolean
  machine_id: string | null
  lapi_url: string
}

type Alert = {
  id?: number
  scenario?: string
  source?: { ip?: string; value?: string; cn?: string }
  events_count?: number
  start_at?: string
  stop_at?: string
  _target_host?: string
  [k: string]: unknown
}

const PAGE_SIZE = 25

// Deterministic scenario color (same logic as DecisionsPage)
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

function ServiceBadge({ host }: { host: string }) {
  return (
    <a
      href={`https://${host}`} target="_blank" rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300 dark:hover:bg-slate-700"
    >
      <img
        src={`https://icons.duckduckgo.com/ip3/${host}.ico`} alt="" width={12} height={12}
        className="h-3 w-3 rounded-sm object-contain"
        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = 'none' }}
      />
      {host}
    </a>
  )
}

function Pagination({ page, total, pageSize, onChange }: { page: number; total: number; pageSize: number; onChange: (p: number) => void }) {
  const pages = Math.ceil(total / pageSize)
  if (pages <= 1) return null
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 dark:border-slate-700/50">
      <span className="text-xs text-slate-500">{(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}</span>
      <div className="flex gap-1">
        <button type="button" disabled={page <= 1} onClick={() => onChange(page - 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
          ‹
        </button>
        {Array.from({ length: Math.min(pages, 5) }, (_, i) => {
          const p = pages <= 5 ? i + 1 : Math.max(1, Math.min(pages - 4, page - 2)) + i
          return (
            <button key={p} type="button" onClick={() => onChange(p)}
              className={`min-w-[30px] rounded-lg border px-2 py-1 text-xs ${p === page ? 'border-violet-500 bg-violet-500/10 text-violet-600' : 'border-slate-200 bg-white text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400'}`}>
              {p}
            </button>
          )
        })}
        <button type="button" disabled={page >= pages} onClick={() => onChange(page + 1)}
          className="rounded-lg border border-slate-200 bg-white p-1.5 text-slate-500 hover:bg-slate-50 disabled:opacity-40 dark:border-slate-700 dark:bg-slate-800">
          ›
        </button>
      </div>
    </div>
  )
}

type BanModal = { ip: string } | null

export function AlertsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<Alert[]>([])
  const [csStatus, setCsStatus] = useState<CrowdsecStatus | null>(null)
  const [search, setSearch] = useState('')
  const [scenarioFilter, setScenarioFilter] = useState('all')
  const [serviceFilter, setServiceFilter] = useState('all')
  const [page, setPage] = useState(1)
  const [banModal, setBanModal] = useState<BanModal>(null)
  const [banDuration, setBanDuration] = useState('24h')
  const [banReason, setBanReason] = useState('manual')
  const [banning, setBanning] = useState(false)
  const [banMsg, setBanMsg] = useState<{ text: string; ok: boolean } | null>(null)

  async function handleBan() {
    if (!banModal) return
    setBanning(true)
    setBanMsg(null)
    try {
      const res = await apiFetch('/api/crowdsec/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: banModal.ip, duration: banDuration, reason: banReason }),
      })
      if (res.ok) {
        setBanMsg({ text: `${banModal.ip} banned for ${banDuration}`, ok: true })
        setTimeout(() => setBanModal(null), 1500)
      } else {
        const err = await res.json().catch(() => ({}))
        setBanMsg({ text: (err as { detail?: string }).detail ?? 'Ban failed', ok: false })
      }
    } finally {
      setBanning(false)
    }
  }

  async function loadData() {
    const [alertsRes, statusRes] = await Promise.all([
      apiFetch('/api/crowdsec/alerts?limit=2000'),
      apiFetch('/api/crowdsec/status'),
    ])
    if (alertsRes.ok) setRows((await alertsRes.json()) as Alert[])
    if (statusRes.ok) setCsStatus((await statusRes.json()) as CrowdsecStatus)
  }

  useEffect(() => { void loadData() }, [])

  const scenarios = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((a) => { const sc = String(a.scenario ?? '').replace('crowdsecurity/', ''); if (sc) s.add(sc) })
    return Array.from(s).sort()
  }, [rows])

  const services = useMemo(() => {
    const s = new Set<string>()
    rows.forEach((a) => { if (a._target_host) s.add(a._target_host) })
    return Array.from(s).sort()
  }, [rows])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows.filter((a) => {
      const ip = String(a.source?.ip ?? a.source?.value ?? '')
      const scenario = String(a.scenario ?? '')
      if (scenarioFilter !== 'all' && !scenario.includes(scenarioFilter)) return false
      if (serviceFilter !== 'all' && a._target_host !== serviceFilter) return false
      if (!q) return true
      return ip.includes(q) || scenario.toLowerCase().includes(q) || (a._target_host ?? '').includes(q)
    })
  }, [rows, search, scenarioFilter, serviceFilter])

  useEffect(() => setPage(1), [search, scenarioFilter, serviceFilter])
  const paged = useMemo(() => filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), [filtered, page])

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Alerts</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {filtered.length} of {rows.length} alerts — click an IP for details
          </p>
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={() => exportCSV(filtered, `alerts-${new Date().toISOString().slice(0,10)}.csv`)}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
            <Download className="h-4 w-4" /> Export CSV
          </button>
          <button
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            type="button" onClick={() => void loadData()}
          >
            <RefreshCw className="h-4 w-4" /> Refresh
          </button>
        </div>
      </div>

      {/* Machine credentials warning */}
      {csStatus && !csStatus.watcher_configured && (
        <div className="flex items-start gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm dark:border-amber-500/30 dark:bg-amber-900/20">
          <Info className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
          <div className="flex-1 text-amber-800 dark:text-amber-300">
            <p className="font-semibold">Credentials machine CrowdSec manquants</p>
            <p className="mt-0.5 text-xs">
              Les alertes nécessitent une authentification <em>watcher</em> (machine), pas la clé bouncer.
              Créez un compte machine et configurez-le dans les paramètres&nbsp;:
            </p>
            <pre className="mt-1.5 rounded-lg bg-amber-100/60 px-3 py-2 font-mono text-[11px] dark:bg-amber-900/40">
              {`docker exec crowdsec cscli machines add crowdefik --password <mot_de_passe>`}
            </pre>
            <Link
              to="/settings"
              className="mt-2 inline-flex items-center gap-1.5 rounded-lg bg-amber-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-600"
            >
              <Settings className="h-3 w-3" /> Configurer dans les paramètres
            </Link>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="IP, scenario, service…" value={search} onChange={(e) => setSearch(e.target.value)} />
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

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Source IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Service ciblé</th>
                <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Events</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Started</th>
                {me?.is_superuser && <th className="px-4 py-3 text-xs font-medium uppercase tracking-wide text-slate-400" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {paged.map((a, i) => {
                const ip = String(a.source?.ip ?? a.source?.value ?? '')
                const cn = String(a.source?.cn ?? '')
                const scenario = String(a.scenario ?? '')
                const label = scenario.replace('crowdsecurity/', '')
                const events = Number(a.events_count ?? 0)
                const startAt = a.start_at ? new Date(a.start_at).toLocaleString() : '—'
                return (
                  <tr key={i} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${scenarioColor(scenario)}`}>
                        <AlertTriangle className="h-3 w-3" />{label || '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {ip ? <IpBadge ip={ip} /> : <span className="text-xs text-slate-400">—</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {a._target_host
                        ? <ServiceBadge host={a._target_host} />
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
                            onClick={() => { setBanModal({ ip }); setBanMsg(null) }}
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
              {!paged.length && (
                <tr>
                  <td colSpan={me?.is_superuser ? 6 : 5} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No alerts match filters' : 'No alerts — check CrowdSec settings and machine credentials'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <Pagination page={page} total={filtered.length} pageSize={PAGE_SIZE} onChange={setPage} />
      </div>

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
              {banMsg && (
                <div className={`rounded-xl px-3 py-2 text-xs ${banMsg.ok ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400' : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'}`}>
                  {banMsg.text}
                </div>
              )}
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
