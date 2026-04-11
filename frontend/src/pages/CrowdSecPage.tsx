import {
  Activity, AlertCircle, BarChart2, Bot, CheckCircle2, Clock,
  Plus, RefreshCw, Shield, Trash2, Users, XCircle,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../api'

// ── Types ────────────────────────────────────────────────────────────────────

type Bouncer = {
  name: string; revoked?: boolean; ip?: string; type?: string
  version?: string; last_pull?: string; auth_type?: string; created_at?: string
}

type Machine = {
  machineId?: string; machine_id?: string; created_at?: string; updated_at?: string
  last_push?: string; last_heartbeat?: string; isValidated?: boolean; is_validated?: boolean
  status?: string; version?: string
}

// cscli metrics -o json structure (varies between versions, use unknown fallback)
type CscliMetrics = Record<string, unknown>

// ── Helpers ──────────────────────────────────────────────────────────────────

function timeAgo(dt: string | undefined): string {
  if (!dt) return '—'
  try {
    const diff = Math.floor((Date.now() - new Date(dt).getTime()) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return `${Math.floor(diff / 86400)}d ago`
  } catch { return '—' }
}

function StatusBadge({ active, label }: { active: boolean; label?: string }) {
  return active ? (
    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
      <CheckCircle2 className="h-3 w-3" />{label ?? 'Active'}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-700 dark:text-red-400">
      <XCircle className="h-3 w-3" />{label ?? 'Inactive'}
    </span>
  )
}

// ── Generic metric table renderer ────────────────────────────────────────────

function MetricTable({ title, rows }: {
  title: string
  rows: Record<string, unknown>[]
}) {
  if (!rows || rows.length === 0) return null
  const cols = Object.keys(rows[0])
  return (
    <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60 overflow-hidden">
      <div className="border-b border-slate-100 px-5 py-3 dark:border-slate-700/50">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{title}</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-xs">
          <thead>
            <tr className="bg-slate-50 dark:bg-slate-700/30">
              {cols.map((c) => (
                <th key={c} className="px-4 py-2 text-left font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap">{c}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-700/30">
            {rows.map((row, i) => (
              <tr key={i} className="hover:bg-slate-50/50 dark:hover:bg-slate-700/20">
                {cols.map((c) => (
                  <td key={c} className="px-4 py-2 font-mono text-slate-700 dark:text-slate-300 whitespace-nowrap">
                    {String(row[c] ?? '—')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Parse `cscli metrics -o json` into displayable sections.
// The JSON structure varies between CrowdSec versions; this handles both v1.5-v1.6+.
function parseMetrics(raw: CscliMetrics): Array<{ title: string; rows: Record<string, unknown>[] }> {
  const sections: Array<{ title: string; rows: Record<string, unknown>[] }> = []

  function addSection(title: string, data: unknown) {
    if (!data) return
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object') {
      sections.push({ title, rows: data as Record<string, unknown>[] })
    } else if (typeof data === 'object' && !Array.isArray(data)) {
      // Convert object of objects to array of rows
      const d = data as Record<string, unknown>
      const keys = Object.keys(d)
      if (keys.length === 0) return
      const firstVal = d[keys[0]]
      if (typeof firstVal === 'object' && firstVal !== null) {
        const rows = keys.map((k) => ({ name: k, ...(d[k] as Record<string, unknown>) }))
        sections.push({ title, rows })
      } else {
        // flat key→value object
        const rows = keys.map((k) => ({ metric: k, value: String(d[k] ?? '—') }))
        sections.push({ title, rows })
      }
    }
  }

  // v1.6+ format uses top-level keys like "acquisition", "lapi", "appsec", etc.
  const knownKeys: Record<string, string> = {
    acquisition: 'Acquisition',
    lapi: 'Local API',
    lapi_bouncer: 'Bouncers — API',
    lapi_machine: 'Machines — API',
    lapi_decisions: 'Décisions',
    appsec: 'AppSec Engine',
    appsec_rules: 'Règles AppSec',
    parsers: 'Parsers',
    scenarios: 'Scénarios',
    whitelists: 'Listes blanches',
    alerts: 'Alertes LAPI',
    buckets: 'Buckets',
  }

  for (const [key, label] of Object.entries(knownKeys)) {
    if (raw[key] !== undefined) addSection(label, raw[key])
  }

  // Fallback: any key we don't recognise
  for (const key of Object.keys(raw)) {
    if (!knownKeys[key]) addSection(key, raw[key])
  }

  return sections
}

// ── Main page ────────────────────────────────────────────────────────────────

type Tab = 'bouncers' | 'machines' | 'metrics'

export function CrowdSecPage() {
  const [tab, setTab] = useState<Tab>('bouncers')
  const [bouncers, setBouncers] = useState<Bouncer[]>([])
  const [machines, setMachines] = useState<Machine[]>([])
  const [metrics, setMetrics] = useState<CscliMetrics | null>(null)
  const [metricsRaw, setMetricsRaw] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [metricsLoading, setMetricsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Add forms state
  const [showAddBouncer, setShowAddBouncer] = useState(false)
  const [newBouncerName, setNewBouncerName] = useState('')
  const [showAddMachine, setShowAddMachine] = useState(false)
  const [newMachineId, setNewMachineId] = useState('')
  const [newMachinePass, setNewMachinePass] = useState('')
  const [saving, setSaving] = useState(false)
  const [addResult, setAddResult] = useState<{ ok: boolean; msg: string } | null>(null)

  async function loadData() {
    setLoading(true)
    setError(null)
    try {
      const [bRes, mRes] = await Promise.all([
        apiFetch('/api/crowdsec/bouncers'),
        apiFetch('/api/crowdsec/machines'),
      ])
      if (bRes.ok) {
        const bd = await bRes.json() as { ok: boolean; data?: Bouncer[]; error?: string }
        if (bd.ok) setBouncers(bd.data ?? [])
        else setError(bd.error ?? 'Unable to load bouncers')
      }
      if (mRes.ok) {
        const md = await mRes.json() as { ok: boolean; data?: Machine[]; error?: string }
        if (md.ok) setMachines(md.data ?? [])
      }
    } catch (e) { setError(String(e)) }
    finally { setLoading(false) }
  }

  async function loadMetrics() {
    setMetricsLoading(true)
    try {
      const r = await apiFetch('/api/crowdsec/metrics')
      const d = await r.json() as { ok: boolean; data?: CscliMetrics; error?: string }
      if (d.ok && d.data) {
        setMetrics(d.data)
        setMetricsRaw(null)
      } else if (!d.ok) {
        // Might be unparseable text output — store raw for fallback display
        setMetrics(null)
        setMetricsRaw(d.error ?? 'No data')
      }
    } catch (e) {
      setMetricsRaw(String(e))
    } finally {
      setMetricsLoading(false)
    }
  }

  useEffect(() => { void loadData() }, [])
  useEffect(() => { if (tab === 'metrics' && !metrics && !metricsRaw) void loadMetrics() }, [tab])

  async function doAddBouncer() {
    if (!newBouncerName.trim()) return
    setSaving(true); setAddResult(null)
    try {
      const r = await apiFetch('/api/crowdsec/bouncers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newBouncerName.trim() }),
      })
      const d = await r.json() as { ok: boolean; error?: string }
      if (d.ok) {
        setAddResult({ ok: true, msg: `Bouncer "${newBouncerName}" créé.` })
        setNewBouncerName(''); setShowAddBouncer(false)
        await loadData()
      } else { setAddResult({ ok: false, msg: d.error ?? 'Erreur' }) }
    } finally { setSaving(false) }
  }

  async function doDeleteBouncer(name: string) {
    if (!confirm(`Supprimer le bouncer "${name}" ?`)) return
    await apiFetch(`/api/crowdsec/bouncers/${encodeURIComponent(name)}`, { method: 'DELETE' })
    await loadData()
  }

  async function doAddMachine() {
    if (!newMachineId.trim() || !newMachinePass.trim()) return
    setSaving(true); setAddResult(null)
    try {
      const r = await apiFetch('/api/crowdsec/machines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ machine_id: newMachineId.trim(), password: newMachinePass.trim() }),
      })
      const d = await r.json() as { ok: boolean; error?: string }
      if (d.ok) {
        setAddResult({ ok: true, msg: `Machine "${newMachineId}" créée. Configurez-la dans les paramètres.` })
        setNewMachineId(''); setNewMachinePass(''); setShowAddMachine(false)
        await loadData()
      } else { setAddResult({ ok: false, msg: d.error ?? 'Erreur' }) }
    } finally { setSaving(false) }
  }

  async function doDeleteMachine(id: string) {
    if (!confirm(`Supprimer la machine "${id}" ?`)) return
    await apiFetch(`/api/crowdsec/machines/${encodeURIComponent(id)}`, { method: 'DELETE' })
    await loadData()
  }

  async function doValidateMachine(id: string) {
    await apiFetch(`/api/crowdsec/machines/${encodeURIComponent(id)}/validate`, { method: 'POST' })
    await loadData()
  }

  const activeBouncers = bouncers.filter((b) => !b.revoked)
  const validatedMachines = machines.filter((m) => m.isValidated ?? m.is_validated)
  const metricsSections = metrics ? parseMetrics(metrics) : []

  const TABS: { id: Tab; label: string; icon: typeof Shield }[] = [
    { id: 'bouncers', label: 'Bouncers', icon: Shield },
    { id: 'machines', label: 'Machines', icon: Bot },
    { id: 'metrics', label: 'Métriques', icon: BarChart2 },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">CrowdSec</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Gestion des bouncers, machines et métriques LAPI</p>
        </div>
        <button type="button"
          onClick={() => { void loadData(); if (tab === 'metrics') void loadMetrics() }}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
          <RefreshCw className={`h-4 w-4 ${(loading || metricsLoading) ? 'animate-spin' : ''}`} /> Actualiser
        </button>
      </div>

      {/* Banners */}
      {error && (
        <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm dark:border-red-500/30 dark:bg-red-900/20">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-500" />
          <div className="text-red-800 dark:text-red-300">
            <p className="font-semibold">Impossible d'accéder à cscli</p>
            <p className="mt-0.5 text-xs">{error}</p>
            <p className="mt-1 text-xs">Vérifiez le nom du conteneur dans <Link to="/settings" className="underline">les paramètres</Link>.</p>
          </div>
        </div>
      )}

      {addResult && (
        <div className={`flex items-start gap-3 rounded-2xl border px-4 py-3 text-sm ${addResult.ok ? 'border-emerald-200 bg-emerald-50 dark:border-emerald-500/30 dark:bg-emerald-900/20' : 'border-red-200 bg-red-50 dark:border-red-500/30 dark:bg-red-900/20'}`}>
          {addResult.ok
            ? <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-500" />
            : <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-500" />}
          <p className={addResult.ok ? 'text-emerald-800 dark:text-emerald-300' : 'text-red-800 dark:text-red-300'}>{addResult.msg}</p>
          <button onClick={() => setAddResult(null)} className="ml-auto text-slate-400 hover:text-slate-600">✕</button>
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { icon: Shield, label: 'Bouncers total', value: bouncers.length, color: 'border-violet-500/20 bg-violet-500/5' },
          { icon: CheckCircle2, label: 'Bouncers actifs', value: activeBouncers.length, color: 'border-emerald-500/20 bg-emerald-500/5' },
          { icon: Users, label: 'Machines total', value: machines.length, color: 'border-blue-500/20 bg-blue-500/5' },
          { icon: Bot, label: 'Machines validées', value: validatedMachines.length, color: 'border-indigo-500/20 bg-indigo-500/5' },
        ].map(({ icon: Icon, label, value, color }) => (
          <div key={label} className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 ${color}`}>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
                <div className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{loading ? '…' : value}</div>
              </div>
              <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${color.split(' ')[1]}`}>
                <Icon className="h-5 w-5 text-slate-600 dark:text-slate-300" />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 rounded-xl border border-slate-200 bg-white p-1 dark:border-slate-700 dark:bg-slate-800 w-fit">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button key={id} type="button" onClick={() => setTab(id)}
            className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition ${tab === id ? 'bg-violet-500 text-white shadow-sm' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'}`}>
            <Icon className="h-4 w-4" />{label}
          </button>
        ))}
      </div>

      {/* ── Tab: Bouncers ── */}
      {tab === 'bouncers' && (
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Shield className="h-4 w-4 text-violet-500" /> Bouncers
              <span className="ml-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500 dark:bg-slate-700 dark:text-slate-400">{bouncers.length}</span>
            </h2>
            <button type="button" onClick={() => setShowAddBouncer((v) => !v)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-violet-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-violet-600">
              <Plus className="h-3 w-3" /> Ajouter
            </button>
          </div>

          {showAddBouncer && (
            <div className="border-b border-slate-100 bg-slate-50 px-5 py-4 dark:border-slate-700/50 dark:bg-slate-800/40">
              <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-300">Nouveau bouncer</p>
              <div className="flex gap-2">
                <input value={newBouncerName} onChange={(e) => setNewBouncerName(e.target.value)}
                  placeholder="Nom (ex: traefik-bouncer)"
                  className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
                  onKeyDown={(e) => { if (e.key === 'Enter') void doAddBouncer() }} />
                <button type="button" onClick={() => void doAddBouncer()} disabled={saving || !newBouncerName.trim()}
                  className="rounded-lg bg-violet-500 px-3 py-2 text-xs font-semibold text-white hover:bg-violet-600 disabled:opacity-40">
                  {saving ? '…' : 'Créer'}
                </button>
              </div>
            </div>
          )}

          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {loading ? <p className="px-5 py-8 text-center text-sm text-slate-400">Chargement…</p>
              : bouncers.length === 0 ? <p className="px-5 py-8 text-center text-sm text-slate-400">Aucun bouncer enregistré</p>
              : bouncers.map((b) => (
                <div key={b.name} className="flex items-center gap-3 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm text-slate-800 dark:text-slate-100">{b.name}</span>
                      <StatusBadge active={!b.revoked} />
                    </div>
                    <div className="mt-0.5 flex items-center gap-3 text-[11px] text-slate-400">
                      {b.type && <span>{b.type}</span>}
                      {b.version && <span>v{b.version}</span>}
                      {b.last_pull && <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{timeAgo(b.last_pull)}</span>}
                      {b.ip && <span className="font-mono">{b.ip}</span>}
                    </div>
                  </div>
                  <button type="button" onClick={() => void doDeleteBouncer(b.name)}
                    className="flex-shrink-0 rounded-lg p-1.5 text-red-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/30" title="Supprimer">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* ── Tab: Machines ── */}
      {tab === 'machines' && (
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Bot className="h-4 w-4 text-blue-500" /> Machines / Watchers
              <span className="ml-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500 dark:bg-slate-700 dark:text-slate-400">{machines.length}</span>
            </h2>
            <button type="button" onClick={() => setShowAddMachine((v) => !v)}
              className="inline-flex items-center gap-1.5 rounded-lg bg-blue-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-600">
              <Plus className="h-3 w-3" /> Ajouter
            </button>
          </div>

          {showAddMachine && (
            <div className="border-b border-slate-100 bg-slate-50 px-5 py-4 dark:border-slate-700/50 dark:bg-slate-800/40">
              <p className="mb-2 text-xs font-medium text-slate-600 dark:text-slate-300">Nouvelle machine</p>
              <div className="space-y-2">
                <input value={newMachineId} onChange={(e) => setNewMachineId(e.target.value)}
                  placeholder="ID (ex: crowdefik)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200" />
                <div className="flex gap-2">
                  <input type="password" value={newMachinePass} onChange={(e) => setNewMachinePass(e.target.value)}
                    placeholder="Mot de passe"
                    className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
                    onKeyDown={(e) => { if (e.key === 'Enter') void doAddMachine() }} />
                  <button type="button" onClick={() => void doAddMachine()} disabled={saving || !newMachineId.trim() || !newMachinePass.trim()}
                    className="rounded-lg bg-blue-500 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-600 disabled:opacity-40">
                    {saving ? '…' : 'Créer'}
                  </button>
                </div>
                <p className="text-[11px] text-slate-400">
                  Après création, configurez l'ID et mot de passe dans <Link to="/settings" className="underline text-blue-500">les paramètres</Link>.
                </p>
              </div>
            </div>
          )}

          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {loading ? <p className="px-5 py-8 text-center text-sm text-slate-400">Chargement…</p>
              : machines.length === 0 ? <p className="px-5 py-8 text-center text-sm text-slate-400">Aucune machine enregistrée</p>
              : machines.map((m) => {
                const id = m.machineId ?? m.machine_id ?? '?'
                const validated = m.isValidated ?? m.is_validated
                const lastSeen = m.last_push ?? m.last_heartbeat ?? m.updated_at
                return (
                  <div key={id} className="flex items-center gap-3 px-5 py-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm font-medium text-slate-800 dark:text-slate-100">{id}</span>
                        {validated
                          ? <StatusBadge active={true} label="Validée" />
                          : <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400">
                              <AlertCircle className="h-3 w-3" /> En attente
                            </span>}
                      </div>
                      <div className="mt-0.5 flex items-center gap-3 text-[11px] text-slate-400">
                        {m.version && <span>v{m.version}</span>}
                        {lastSeen && <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{timeAgo(lastSeen)}</span>}
                      </div>
                    </div>
                    <div className="flex flex-shrink-0 items-center gap-1">
                      {!validated && (
                        <button type="button" onClick={() => void doValidateMachine(id)}
                          className="rounded-lg p-1.5 text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-900/30" title="Valider">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                      <button type="button" onClick={() => void doDeleteMachine(id)}
                        className="rounded-lg p-1.5 text-red-400 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-900/30" title="Supprimer">
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                )
              })}
          </div>
        </div>
      )}

      {/* ── Tab: Metrics ── */}
      {tab === 'metrics' && (
        <div className="space-y-4">
          {metricsLoading && (
            <div className="flex h-40 items-center justify-center gap-2 text-sm text-slate-400">
              <RefreshCw className="h-4 w-4 animate-spin" /> Chargement des métriques…
            </div>
          )}

          {!metricsLoading && metricsRaw && (
            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-5 dark:border-amber-500/30 dark:bg-amber-900/20">
              <div className="mb-2 flex items-center gap-2">
                <Activity className="h-4 w-4 text-amber-500" />
                <span className="text-sm font-semibold text-amber-800 dark:text-amber-300">Sortie brute cscli</span>
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-[11px] text-amber-900 dark:text-amber-200">{metricsRaw}</pre>
            </div>
          )}

          {!metricsLoading && metricsSections.length > 0 && (
            <>
              {/* Quick summary cards from well-known keys */}
              {metrics && (
                <MetricsSummary raw={metrics} />
              )}
              <div className="grid gap-4">
                {metricsSections.map((s) => (
                  <MetricTable key={s.title} title={s.title} rows={s.rows} />
                ))}
              </div>
            </>
          )}

          {!metricsLoading && !metrics && !metricsRaw && (
            <div className="flex h-40 items-center justify-center text-sm text-slate-400">
              Aucune donnée — cliquez sur Actualiser
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Quick summary cards extracted from metrics JSON ───────────────────────────

function MetricsSummary({ raw }: { raw: CscliMetrics }) {
  // Try to extract a few high-value numbers from the raw metrics
  const cards: { label: string; value: string; color: string }[] = []

  function num(v: unknown): string {
    if (v === null || v === undefined) return '—'
    if (typeof v === 'number') return v.toLocaleString()
    return String(v)
  }

  // appsec
  const appsec = raw.appsec as Record<string, unknown> | undefined
  if (appsec) {
    // v1.6 format: appsec is an array or object keyed by engine
    const engines = Array.isArray(appsec) ? appsec as Record<string, unknown>[]
      : Object.values(appsec) as Record<string, unknown>[]
    const totalProcessed = engines.reduce((acc, e) => acc + (Number(e.processed ?? e.Processed ?? 0)), 0)
    const totalBlocked = engines.reduce((acc, e) => acc + (Number(e.blocked ?? e.Blocked ?? 0)), 0)
    if (totalProcessed > 0) {
      cards.push({ label: 'AppSec — traitées', value: num(totalProcessed), color: 'border-blue-500/20 bg-blue-500/5' })
      cards.push({ label: 'AppSec — bloquées', value: num(totalBlocked), color: 'border-red-500/20 bg-red-500/5' })
    }
  }

  // lapi decisions
  const decisions = raw.lapi_decisions ?? raw.decisions
  if (decisions && typeof decisions === 'object') {
    const total: number = Array.isArray(decisions)
      ? (decisions as Record<string, unknown>[]).reduce((acc: number, r) => acc + Number(r.count ?? r.Count ?? 0), 0)
      : Object.values(decisions as Record<string, number | unknown>).reduce((acc: number, v) => acc + Number(v), 0)
    if (total > 0) cards.push({ label: 'Décisions actives', value: num(total), color: 'border-amber-500/20 bg-amber-500/5' })
  }

  // scenarios
  const scenarios = raw.scenarios as Record<string, unknown>[] | undefined
  if (Array.isArray(scenarios)) {
    const overflows = scenarios.reduce((acc, s) => acc + Number(s.overflows ?? s.Overflows ?? 0), 0)
    if (overflows > 0) cards.push({ label: 'Scénarios déclenchés', value: num(overflows), color: 'border-violet-500/20 bg-violet-500/5' })
  }

  if (cards.length === 0) return null

  return (
    <div className={`grid gap-4 ${cards.length >= 3 ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}>
      {cards.map(({ label, value, color }) => (
        <div key={label} className={`rounded-2xl border bg-white p-4 dark:bg-slate-800/60 ${color}`}>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{value}</div>
        </div>
      ))}
    </div>
  )
}
