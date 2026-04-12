import {
  AlertTriangle, BookOpen, CheckCircle, ChevronRight,
  Download, Globe, Layers, Loader2, Plus, RefreshCw,
  Save, Settings2, Shield, ShieldAlert, ShieldOff, Trash2, Upload,
  Zap,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { useToast } from '../components/Toast'

// ── Types ──────────────────────────────────────────────────────────────────────

type Scenario = {
  name: string
  description: string
  version: string
  status: string
  up_to_date: boolean
  tainted: boolean
  alert_count: number
}

type Collection = {
  name: string
  description: string
  version: string
  status: string
  up_to_date: boolean
  tainted: boolean
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
  alert_count?: number
  updated_at: string | null
}

type TabId = 'scenarios' | 'collections' | 'global' | 'services'

// ── Helpers ────────────────────────────────────────────────────────────────────

const inputCls =
  'w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm outline-none transition focus:border-violet-400 focus:ring-2 focus:ring-violet-500/20 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-200 dark:focus:border-violet-500'

const DURATIONS = ['1h', '6h', '12h', '24h', '48h', '72h', '168h', '720h']

function StatusBadge({ upToDate, tainted }: { upToDate: boolean; tainted: boolean }) {
  if (tainted)
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400">
        <AlertTriangle className="h-3 w-3" /> Tainted
      </span>
    )
  if (!upToDate)
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-blue-500/10 px-2 py-0.5 text-[11px] font-medium text-blue-700 dark:text-blue-400">
        <Upload className="h-3 w-3" /> Update available
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
      <CheckCircle className="h-3 w-3" /> Up to date
    </span>
  )
}

function AlertCount({ count }: { count: number }) {
  if (!count) return <span className="text-xs text-slate-400">0</span>
  const cls =
    count > 100
      ? 'bg-red-500/10 text-red-700 dark:text-red-400'
      : count > 10
        ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400'
        : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cls}`}>
      <ShieldAlert className="h-3 w-3" />
      {count.toLocaleString()}
    </span>
  )
}

// ── Policy form (shared between global and per-service) ────────────────────────

function PolicyForm({
  policy,
  allScenarios,
  isSuperuser,
  onSave,
  saving,
}: {
  policy: Policy
  allScenarios: string[]
  isSuperuser: boolean
  onSave: (p: Policy) => void
  saving: boolean
}) {
  const [form, setForm] = useState<Policy>(policy)
  useEffect(() => setForm(policy), [policy])

  const set = <K extends keyof Policy>(k: K, v: Policy[K]) =>
    setForm((f) => ({ ...f, [k]: v }))

  function toggleScenario(name: string) {
    const next = form.muted_scenarios.includes(name)
      ? form.muted_scenarios.filter((s) => s !== name)
      : [...form.muted_scenarios, name]
    set('muted_scenarios', next)
  }

  const hasChanges = JSON.stringify(form) !== JSON.stringify(policy)

  return (
    <div className="space-y-6">
      {/* Display threshold */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center gap-2">
          <Zap className="h-4 w-4 text-violet-500" />
          <h3 className="font-semibold text-slate-800 dark:text-white">Display threshold</h3>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">
              Minimum events to show an alert
            </label>
            <input
              type="number"
              min={1}
              max={1000}
              className={inputCls}
              value={form.min_events_to_display}
              disabled={!isSuperuser}
              onChange={(e) => set('min_events_to_display', Number(e.target.value))}
            />
            <p className="mt-1 text-[11px] text-slate-400">Alerts with fewer events are hidden from the Alerts page.</p>
          </div>
        </div>
      </div>

      {/* Auto-ban */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-4 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-500" />
            <h3 className="font-semibold text-slate-800 dark:text-white">Auto-ban</h3>
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <div
              onClick={() => isSuperuser && set('auto_ban_enabled', !form.auto_ban_enabled)}
              className={`relative h-5 w-9 rounded-full transition-colors ${form.auto_ban_enabled ? 'bg-red-500' : 'bg-slate-300 dark:bg-slate-600'} ${isSuperuser ? 'cursor-pointer' : 'cursor-not-allowed opacity-60'}`}
            >
              <span className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${form.auto_ban_enabled ? 'translate-x-4' : ''}`} />
            </div>
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
              {form.auto_ban_enabled ? 'Enabled' : 'Disabled'}
            </span>
          </label>
        </div>

        {form.auto_ban_enabled && (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">
                Min events (window)
              </label>
              <input
                type="number"
                min={1}
                className={inputCls}
                placeholder="e.g. 10"
                value={form.auto_ban_min_events ?? ''}
                disabled={!isSuperuser}
                onChange={(e) => set('auto_ban_min_events', e.target.value ? Number(e.target.value) : null)}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">
                Time window (hours)
              </label>
              <input
                type="number"
                min={1}
                max={720}
                className={inputCls}
                value={form.auto_ban_window_hours}
                disabled={!isSuperuser}
                onChange={(e) => set('auto_ban_window_hours', Number(e.target.value))}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">
                Min AbuseIPDB score
              </label>
              <input
                type="number"
                min={0}
                max={100}
                className={inputCls}
                placeholder="0–100 (optional)"
                value={form.auto_ban_min_score ?? ''}
                disabled={!isSuperuser}
                onChange={(e) => set('auto_ban_min_score', e.target.value ? Number(e.target.value) : null)}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">
                Ban duration
              </label>
              <select
                className={inputCls}
                value={form.auto_ban_duration}
                disabled={!isSuperuser}
                onChange={(e) => set('auto_ban_duration', e.target.value)}
              >
                {DURATIONS.map((d) => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>
          </div>
        )}

        {form.auto_ban_enabled && (
          <p className="mt-3 rounded-xl bg-amber-500/10 px-3 py-2 text-[11px] text-amber-700 dark:text-amber-400">
            IPs that trigger more than {form.auto_ban_min_events ?? '?'} alerts in {form.auto_ban_window_hours}h
            {form.auto_ban_min_score ? ` with AbuseIPDB ≥ ${form.auto_ban_min_score}` : ''} will be automatically banned for {form.auto_ban_duration}.
          </p>
        )}
      </div>

      {/* Muted scenarios */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="mb-3 flex items-center gap-2">
          <ShieldOff className="h-4 w-4 text-slate-400" />
          <h3 className="font-semibold text-slate-800 dark:text-white">Muted scenarios</h3>
          {form.muted_scenarios.length > 0 && (
            <span className="ml-auto rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400">
              {form.muted_scenarios.length} muted
            </span>
          )}
        </div>
        <p className="mb-3 text-[11px] text-slate-400">
          Muted scenarios are ignored when calculating alerts and auto-ban thresholds for this scope.
        </p>
        {allScenarios.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {allScenarios.map((s) => {
              const muted = form.muted_scenarios.includes(s)
              return (
                <button
                  key={s}
                  type="button"
                  disabled={!isSuperuser}
                  onClick={() => toggleScenario(s)}
                  title={muted ? 'Click to unmute' : 'Click to mute'}
                  className={`rounded-full px-3 py-1 text-xs font-medium transition ${
                    muted
                      ? 'bg-amber-500/20 text-amber-700 dark:text-amber-400 line-through opacity-70'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600'
                  } ${!isSuperuser ? 'cursor-not-allowed' : 'cursor-pointer'}`}
                >
                  {s.replace('crowdsecurity/', '')}
                </button>
              )
            })}
          </div>
        ) : (
          <p className="text-xs text-slate-400">No scenarios detected in DB yet — install scenarios and wait for the next sync.</p>
        )}
      </div>

      {/* Notes */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700/50 dark:bg-slate-800/60">
        <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Notes</label>
        <textarea
          rows={3}
          className={`${inputCls} resize-none`}
          placeholder="Optional admin notes…"
          value={form.notes ?? ''}
          disabled={!isSuperuser}
          onChange={(e) => set('notes', e.target.value || null)}
        />
      </div>

      {isSuperuser && (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={() => onSave(form)}
            disabled={saving || !hasChanges}
            className="inline-flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-violet-500 disabled:opacity-60"
          >
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            {saving ? 'Saving…' : 'Save policy'}
          </button>
        </div>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export function RulesPage() {
  const { me, loading } = useAuth()
  const { addToast } = useToast()
  const [tab, setTab] = useState<TabId>('scenarios')

  // Scenarios tab
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [loadingScenarios, setLoadingScenarios] = useState(false)
  const [scenarioSearch, setScenarioSearch] = useState('')
  const [installing, setInstalling] = useState<string | null>(null)
  const [removing, setRemoving] = useState<string | null>(null)
  const [updatingHub, setUpdatingHub] = useState(false)

  // Collections tab
  const [collections, setCollections] = useState<Collection[]>([])
  const [loadingCollections, setLoadingCollections] = useState(false)
  const [colSearch, setColSearch] = useState('')

  // Global policy tab
  const [globalPolicy, setGlobalPolicy] = useState<Policy | null>(null)
  const [savingGlobal, setSavingGlobal] = useState(false)

  // Per-service policies tab
  const [servicePolicies, setServicePolicies] = useState<Policy[]>([])
  const [loadingServices, setLoadingServices] = useState(false)

  // All known scenarios from DB (for muted scenario pickers)
  const allScenarioNames = useMemo(
    () => scenarios.map((s) => s.name).sort(),
    [scenarios],
  )

  async function loadScenarios() {
    setLoadingScenarios(true)
    try {
      const r = await apiFetch('/api/crowdsec/hub/scenarios')
      if (r.ok) {
        const d = await r.json() as { ok: boolean; scenarios: Scenario[]; error?: string }
        if (d.ok) setScenarios(d.scenarios)
        else addToast(d.error ?? 'Failed to load scenarios', 'error')
      }
    } finally {
      setLoadingScenarios(false)
    }
  }

  async function loadCollections() {
    setLoadingCollections(true)
    try {
      const r = await apiFetch('/api/crowdsec/hub/collections')
      if (r.ok) {
        const d = await r.json() as { ok: boolean; collections: Collection[]; error?: string }
        if (d.ok) setCollections(d.collections)
        else addToast(d.error ?? 'Failed to load collections', 'error')
      }
    } finally {
      setLoadingCollections(false)
    }
  }

  async function loadGlobalPolicy() {
    const r = await apiFetch('/api/crowdsec/global-policy')
    if (r.ok) setGlobalPolicy(await r.json() as Policy)
  }

  async function loadServicePolicies() {
    setLoadingServices(true)
    try {
      const r = await apiFetch('/api/crowdsec/service-policies')
      if (r.ok) {
        const d = await r.json() as { policies: Policy[] }
        setServicePolicies(d.policies)
      }
    } finally {
      setLoadingServices(false)
    }
  }

  useEffect(() => {
    void loadScenarios()
    void loadCollections()
    void loadGlobalPolicy()
    void loadServicePolicies()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleHubUpdate() {
    setUpdatingHub(true)
    try {
      const r = await apiFetch('/api/crowdsec/hub/update', { method: 'POST' })
      if (r.ok) {
        addToast('Hub updated — refreshing lists…', 'success')
        await loadScenarios()
        await loadCollections()
      } else {
        const err = await r.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Hub update failed', 'error')
      }
    } finally {
      setUpdatingHub(false)
    }
  }

  async function handleInstallScenario(name: string, upgrade = false) {
    setInstalling(name)
    try {
      const action = upgrade ? 'upgrade' : 'install'
      const r = await apiFetch(`/api/crowdsec/hub/scenarios/${encodeURIComponent(name)}/${action}`, { method: 'POST' })
      if (r.ok) {
        addToast(upgrade ? `${name} updated` : `${name} installed`, 'success')
        await loadScenarios()
      } else {
        const err = await r.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? (upgrade ? 'Update failed' : 'Install failed'), 'error')
      }
    } finally {
      setInstalling(null)
    }
  }

  async function handleRemoveScenario(name: string) {
    if (!confirm(`Remove scenario "${name}"? CrowdSec will no longer detect this attack pattern.`)) return
    setRemoving(name)
    try {
      const r = await apiFetch(`/api/crowdsec/hub/scenarios/${encodeURIComponent(name)}`, { method: 'DELETE' })
      if (r.ok) {
        addToast(`${name} removed`, 'success')
        await loadScenarios()
      } else {
        const err = await r.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Remove failed', 'error')
      }
    } finally {
      setRemoving(null)
    }
  }

  async function handleInstallCollection(name: string, upgrade = false) {
    setInstalling(name)
    try {
      const action = upgrade ? 'upgrade' : 'install'
      const r = await apiFetch(`/api/crowdsec/hub/collections/${encodeURIComponent(name)}/${action}`, { method: 'POST' })
      if (r.ok) {
        addToast(upgrade ? `${name} updated` : `${name} installed`, 'success')
        await loadCollections()
        await loadScenarios()
      } else {
        const err = await r.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? (upgrade ? 'Update failed' : 'Install failed'), 'error')
      }
    } finally {
      setInstalling(null)
    }
  }

  async function handleRemoveCollection(name: string) {
    if (!confirm(`Remove collection "${name}"? All scenarios in this collection will be removed.`)) return
    setRemoving(name)
    try {
      const r = await apiFetch(`/api/crowdsec/hub/collections/${encodeURIComponent(name)}`, { method: 'DELETE' })
      if (r.ok) {
        addToast(`${name} removed`, 'success')
        await loadCollections()
        await loadScenarios()
      } else {
        const err = await r.json().catch(() => ({}))
        addToast((err as { detail?: string }).detail ?? 'Remove failed', 'error')
      }
    } finally {
      setRemoving(null)
    }
  }

  async function saveGlobalPolicy(p: Policy) {
    setSavingGlobal(true)
    try {
      const r = await apiFetch('/api/crowdsec/global-policy', {
        method: 'PUT',
        body: JSON.stringify(p),
      })
      if (r.ok) {
        setGlobalPolicy(await r.json() as Policy)
        addToast('Global policy saved', 'success')
      } else {
        addToast('Save failed', 'error')
      }
    } finally {
      setSavingGlobal(false)
    }
  }

  const filteredScenarios = useMemo(
    () => scenarios.filter((s) => s.name.toLowerCase().includes(scenarioSearch.toLowerCase()) || s.description.toLowerCase().includes(scenarioSearch.toLowerCase())),
    [scenarios, scenarioSearch],
  )
  const filteredCollections = useMemo(
    () => collections.filter((c) => c.name.toLowerCase().includes(colSearch.toLowerCase())),
    [collections, colSearch],
  )

  if (!loading && !me) return <Navigate to="/login" replace />

  const TABS: { id: TabId; label: string; icon: React.ElementType; color: string; count?: number }[] = [
    { id: 'scenarios',   label: 'Scenarios',       icon: ShieldAlert, color: 'text-violet-500', count: scenarios.length },
    { id: 'collections', label: 'Collections',     icon: Layers,      color: 'text-blue-500',   count: collections.length },
    { id: 'global',      label: 'Global policy',   icon: Globe,       color: 'text-emerald-500' },
    { id: 'services',    label: 'Per-service',      icon: Settings2,   color: 'text-amber-500',  count: servicePolicies.length },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="rounded-2xl bg-violet-500/10 p-2.5">
            <BookOpen className="h-5 w-5 text-violet-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Rules & Policies</h1>
            <p className="text-sm text-slate-500">Manage CrowdSec detection scenarios and per-service security policies</p>
          </div>
        </div>
        {me?.is_superuser && (
          <button
            type="button"
            onClick={() => void handleHubUpdate()}
            disabled={updatingHub}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
          >
            <RefreshCw className={`h-4 w-4 ${updatingHub ? 'animate-spin' : ''}`} />
            {updatingHub ? 'Updating hub…' : 'Update hub'}
          </button>
        )}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 rounded-2xl border border-slate-200 bg-slate-50 p-1 dark:border-slate-700/50 dark:bg-slate-800/40">
        {TABS.map(({ id, label, icon: Icon, color, count }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={`flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2 text-sm font-medium transition ${
              tab === id
                ? 'bg-white shadow-sm text-slate-900 dark:bg-slate-700 dark:text-white'
                : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <Icon className={`h-4 w-4 ${tab === id ? color : 'text-slate-400'}`} />
            <span className="hidden sm:inline">{label}</span>
            {count != null && count > 0 && (
              <span className="rounded-full bg-slate-200 px-1.5 py-0.5 text-[10px] font-bold dark:bg-slate-600">
                {count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Scenarios ─────────────────────────────────────────────────────── */}
      {tab === 'scenarios' && (
        <div className="space-y-4">
          <div className="flex gap-3">
            <input
              className="flex-1 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
              placeholder="Filter scenarios…"
              value={scenarioSearch}
              onChange={(e) => setScenarioSearch(e.target.value)}
            />
            <button
              type="button"
              onClick={() => void loadScenarios()}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
            >
              <RefreshCw className={`h-4 w-4 ${loadingScenarios ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
            {loadingScenarios ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 dark:border-slate-700/50">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Scenario</th>
                    <th className="hidden px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400 md:table-cell">Description</th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Status</th>
                    <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Alerts (DB)</th>
                    {me?.is_superuser && <th className="px-4 py-3" />}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                  {filteredScenarios.map((s) => (
                    <tr key={s.name} className="hover:bg-slate-50/70 dark:hover:bg-white/5">
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                          {s.name.replace('crowdsecurity/', '')}
                        </span>
                        <div className="text-[11px] text-slate-400">{s.version}</div>
                      </td>
                      <td className="hidden px-4 py-3 text-xs text-slate-500 dark:text-slate-400 md:table-cell max-w-xs">
                        <span className="line-clamp-2">{s.description}</span>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge upToDate={s.up_to_date} tainted={s.tainted} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <AlertCount count={s.alert_count} />
                      </td>
                      {me?.is_superuser && (
                        <td className="px-4 py-3">
                          <div className="flex justify-end gap-2">
                            {!s.up_to_date && (
                              <button
                                type="button"
                                onClick={() => void handleInstallScenario(s.name, true)}
                                disabled={installing === s.name}
                                className="inline-flex items-center gap-1 rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1 text-[11px] font-medium text-blue-700 hover:bg-blue-100 disabled:opacity-50 dark:border-blue-500/30 dark:bg-blue-900/20 dark:text-blue-400"
                              >
                                {installing === s.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Upload className="h-3 w-3" />}
                                Update
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => void handleRemoveScenario(s.name)}
                              disabled={removing === s.name}
                              className="inline-flex items-center gap-1 rounded-lg border border-red-200 bg-red-50 px-2.5 py-1 text-[11px] font-medium text-red-700 hover:bg-red-100 disabled:opacity-50 dark:border-red-500/30 dark:bg-red-900/20 dark:text-red-400"
                            >
                              {removing === s.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                              Remove
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                  {!filteredScenarios.length && !loadingScenarios && (
                    <tr>
                      <td colSpan={me?.is_superuser ? 5 : 4} className="px-4 py-12 text-center text-sm text-slate-400">
                        {scenarios.length === 0
                          ? 'Could not load scenarios — ensure Docker socket is mounted and the CrowdSec container is running'
                          : 'No scenarios match the filter'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Collections ───────────────────────────────────────────────────── */}
      {tab === 'collections' && (
        <div className="space-y-4">
          <div className="flex gap-3">
            <input
              className="flex-1 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
              placeholder="Filter collections…"
              value={colSearch}
              onChange={(e) => setColSearch(e.target.value)}
            />
            <button
              type="button"
              onClick={() => void loadCollections()}
              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-500 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
            >
              <RefreshCw className={`h-4 w-4 ${loadingCollections ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="rounded-xl border border-blue-200 bg-blue-50/50 px-4 py-3 text-xs text-blue-800 dark:border-blue-500/30 dark:bg-blue-900/20 dark:text-blue-300">
            <strong>Collections</strong> are curated bundles of parsers + scenarios for a specific technology (e.g. nginx, apache, ssh). Installing a collection installs all its components at once.
          </div>

          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
            {loadingCollections ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 dark:border-slate-700/50">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Collection</th>
                    <th className="hidden px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400 md:table-cell">Description</th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Status</th>
                    {me?.is_superuser && <th className="px-4 py-3" />}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                  {filteredCollections.map((c) => (
                    <tr key={c.name} className="hover:bg-slate-50/70 dark:hover:bg-white/5">
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-300">
                          {c.name.replace('crowdsecurity/', '')}
                        </span>
                        <div className="text-[11px] text-slate-400">{c.version}</div>
                      </td>
                      <td className="hidden px-4 py-3 text-xs text-slate-500 dark:text-slate-400 md:table-cell max-w-xs">
                        <span className="line-clamp-2">{c.description}</span>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge upToDate={c.up_to_date} tainted={c.tainted} />
                      </td>
                      {me?.is_superuser && (
                        <td className="px-4 py-3">
                          <div className="flex justify-end gap-2">
                            {!c.up_to_date && (
                              <button
                                type="button"
                                onClick={() => void handleInstallCollection(c.name, true)}
                                disabled={installing === c.name}
                                className="inline-flex items-center gap-1 rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1 text-[11px] font-medium text-blue-700 hover:bg-blue-100 disabled:opacity-50 dark:border-blue-500/30 dark:bg-blue-900/20 dark:text-blue-400"
                              >
                                {installing === c.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Upload className="h-3 w-3" />}
                                Update
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => void handleRemoveCollection(c.name)}
                              disabled={removing === c.name}
                              className="inline-flex items-center gap-1 rounded-lg border border-red-200 bg-red-50 px-2.5 py-1 text-[11px] font-medium text-red-700 hover:bg-red-100 disabled:opacity-50 dark:border-red-500/30 dark:bg-red-900/20 dark:text-red-400"
                            >
                              {removing === c.name ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                              Remove
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                  {!filteredCollections.length && !loadingCollections && (
                    <tr>
                      <td colSpan={me?.is_superuser ? 4 : 3} className="px-4 py-12 text-center text-sm text-slate-400">
                        {collections.length === 0
                          ? 'Could not load collections — ensure Docker socket is mounted'
                          : 'No collections match the filter'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Global policy ─────────────────────────────────────────────────── */}
      {tab === 'global' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-emerald-200 bg-emerald-50/50 px-4 py-3 text-xs text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-900/20 dark:text-emerald-300">
            <strong>Global policy</strong> defines the default auto-ban behaviour and muted scenarios for all services that don't have a specific per-service policy configured.
          </div>

          {globalPolicy ? (
            <PolicyForm
              policy={globalPolicy}
              allScenarios={allScenarioNames}
              isSuperuser={!!me?.is_superuser}
              onSave={(p) => void saveGlobalPolicy(p)}
              saving={savingGlobal}
            />
          ) : (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
            </div>
          )}
        </div>
      )}

      {/* ── Per-service policies ──────────────────────────────────────────── */}
      {tab === 'services' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-amber-200 bg-amber-50/50 px-4 py-3 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-900/20 dark:text-amber-300">
            Per-service policies override the global policy for a specific virtual host. Configure them from each service's detail page, or click a service below.
          </div>

          {loadingServices ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-slate-400" />
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 dark:border-slate-700/50">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Service</th>
                    <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Alerts</th>
                    <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Auto-ban</th>
                    <th className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wide text-slate-400">Muted</th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Updated</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                  {servicePolicies.map((p) => (
                    <tr key={p.host} className="hover:bg-slate-50/70 dark:hover:bg-white/5">
                      <td className="px-4 py-3 font-medium text-slate-700 dark:text-slate-300">{p.host}</td>
                      <td className="px-4 py-3 text-center">
                        <AlertCount count={p.alert_count ?? 0} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        {p.auto_ban_enabled ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-700 dark:text-red-400">
                            <Shield className="h-3 w-3" /> {p.auto_ban_min_events ?? '?'} events / {p.auto_ban_window_hours}h → {p.auto_ban_duration}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {p.muted_scenarios.length > 0 ? (
                          <span className="rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400">
                            {p.muted_scenarios.length}
                          </span>
                        ) : (
                          <span className="text-xs text-slate-400">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {p.updated_at ? new Date(p.updated_at).toLocaleDateString() : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          to={`/services/${encodeURIComponent(p.host)}?tab=policy`}
                          className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-600 hover:border-violet-300 hover:bg-violet-50 hover:text-violet-700 dark:border-slate-600 dark:bg-slate-700/60 dark:text-slate-300"
                        >
                          <Settings2 className="h-3 w-3" /> Edit
                          <ChevronRight className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {!servicePolicies.length && (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center text-sm text-slate-400">
                        No per-service policies configured yet. Visit a service page and open the Policy tab to configure one.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* Quick action: add a service policy */}
          {me?.is_superuser && servicePolicies.length === 0 && (
            <div className="flex justify-center">
              <Link
                to="/routers"
                className="inline-flex items-center gap-2 rounded-xl border border-dashed border-slate-300 px-5 py-3 text-sm text-slate-500 hover:border-violet-400 hover:text-violet-600 dark:border-slate-600 dark:text-slate-400"
              >
                <Plus className="h-4 w-4" /> Browse services to configure policies
              </Link>
            </div>
          )}
        </div>
      )}

      {/* Export note */}
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <Download className="h-3.5 w-3.5" />
        Scenario and collection changes apply immediately to CrowdSec detection. Auto-ban policies are evaluated during the next sync cycle.
      </div>
    </div>
  )
}
