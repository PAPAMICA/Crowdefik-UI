import {
  AlertCircle, Bot, CheckCircle2, Clock, Plus, RefreshCw, Shield, Trash2, Users, XCircle,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../api'

type Bouncer = {
  name: string
  revoked?: boolean
  ip?: string
  type?: string
  version?: string
  last_pull?: string
  auth_type?: string
  created_at?: string
}

type Machine = {
  machineId?: string
  machine_id?: string
  created_at?: string
  updated_at?: string
  last_push?: string
  last_heartbeat?: string
  isValidated?: boolean
  is_validated?: boolean
  status?: string
  version?: string
}

function timeAgo(dt: string | undefined): string {
  if (!dt) return '—'
  try {
    const d = new Date(dt)
    const diff = Math.floor((Date.now() - d.getTime()) / 1000)
    if (diff < 60) return `${diff}s ago`
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
    return `${Math.floor(diff / 86400)}d ago`
  } catch {
    return '—'
  }
}

function StatusBadge({ active, label }: { active: boolean; label?: string }) {
  return active ? (
    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
      <CheckCircle2 className="h-3 w-3" /> {label ?? 'Active'}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-700 dark:text-red-400">
      <XCircle className="h-3 w-3" /> {label ?? 'Inactive'}
    </span>
  )
}

export function CrowdSecPage() {
  const [bouncers, setBouncers] = useState<Bouncer[]>([])
  const [machines, setMachines] = useState<Machine[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Forms
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
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadData() }, [])

  async function doAddBouncer() {
    if (!newBouncerName.trim()) return
    setSaving(true)
    setAddResult(null)
    try {
      const r = await apiFetch('/api/crowdsec/bouncers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newBouncerName.trim() }),
      })
      const d = await r.json() as { ok: boolean; data?: unknown; error?: string }
      if (d.ok) {
        setAddResult({ ok: true, msg: `Bouncer "${newBouncerName}" added. API key is in the cscli output.` })
        setNewBouncerName('')
        setShowAddBouncer(false)
        await loadData()
      } else {
        setAddResult({ ok: false, msg: d.error ?? 'Error adding bouncer' })
      }
    } finally {
      setSaving(false)
    }
  }

  async function doDeleteBouncer(name: string) {
    if (!confirm(`Delete bouncer "${name}"?`)) return
    await apiFetch(`/api/crowdsec/bouncers/${encodeURIComponent(name)}`, { method: 'DELETE' })
    await loadData()
  }

  async function doAddMachine() {
    if (!newMachineId.trim() || !newMachinePass.trim()) return
    setSaving(true)
    setAddResult(null)
    try {
      const r = await apiFetch('/api/crowdsec/machines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ machine_id: newMachineId.trim(), password: newMachinePass.trim() }),
      })
      const d = await r.json() as { ok: boolean; error?: string }
      if (d.ok) {
        setAddResult({ ok: true, msg: `Machine "${newMachineId}" added. You can now use it in Settings → CrowdSec machine credentials.` })
        setNewMachineId('')
        setNewMachinePass('')
        setShowAddMachine(false)
        await loadData()
      } else {
        setAddResult({ ok: false, msg: d.error ?? 'Error adding machine' })
      }
    } finally {
      setSaving(false)
    }
  }

  async function doDeleteMachine(id: string) {
    if (!confirm(`Delete machine "${id}"?`)) return
    await apiFetch(`/api/crowdsec/machines/${encodeURIComponent(id)}`, { method: 'DELETE' })
    await loadData()
  }

  async function doValidateMachine(id: string) {
    await apiFetch(`/api/crowdsec/machines/${encodeURIComponent(id)}/validate`, { method: 'POST' })
    await loadData()
  }

  const activeBouncers = bouncers.filter((b) => !b.revoked)
  const validatedMachines = machines.filter((m) => m.isValidated ?? m.is_validated)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">CrowdSec</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Gestion des bouncers, machines et santé du LAPI</p>
        </div>
        <button type="button" onClick={() => void loadData()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Actualiser
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm dark:border-red-500/30 dark:bg-red-900/20">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-500" />
          <div className="text-red-800 dark:text-red-300">
            <p className="font-semibold">Impossible d'accéder aux données cscli</p>
            <p className="mt-0.5 text-xs">{error}</p>
            <p className="mt-1 text-xs">
              Vérifiez le nom du conteneur CrowdSec dans{' '}
              <Link to="/settings" className="underline">les paramètres</Link>.
            </p>
          </div>
        </div>
      )}

      {/* Add result */}
      {addResult && (
        <div className={`flex items-start gap-3 rounded-2xl border px-4 py-3 text-sm ${addResult.ok ? 'border-emerald-200 bg-emerald-50 dark:border-emerald-500/30 dark:bg-emerald-900/20' : 'border-red-200 bg-red-50 dark:border-red-500/30 dark:bg-red-900/20'}`}>
          {addResult.ok
            ? <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-500" />
            : <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-500" />}
          <p className={addResult.ok ? 'text-emerald-800 dark:text-emerald-300' : 'text-red-800 dark:text-red-300'}>
            {addResult.msg}
          </p>
          <button onClick={() => setAddResult(null)} className="ml-auto text-slate-400 hover:text-slate-600">✕</button>
        </div>
      )}

      {/* Stats */}
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

      <div className="grid gap-6 lg:grid-cols-2">
        {/* ── Bouncers ── */}
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
                <input
                  value={newBouncerName}
                  onChange={(e) => setNewBouncerName(e.target.value)}
                  placeholder="Nom du bouncer (ex: traefik-bouncer)"
                  className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
                  onKeyDown={(e) => { if (e.key === 'Enter') void doAddBouncer() }}
                />
                <button type="button" onClick={() => void doAddBouncer()} disabled={saving || !newBouncerName.trim()}
                  className="rounded-lg bg-violet-500 px-3 py-2 text-xs font-semibold text-white hover:bg-violet-600 disabled:opacity-40">
                  {saving ? '…' : 'Créer'}
                </button>
              </div>
            </div>
          )}

          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {loading ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">Chargement…</p>
            ) : bouncers.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">Aucun bouncer enregistré</p>
            ) : bouncers.map((b) => (
              <div key={b.name} className="flex items-center gap-3 px-5 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-sm text-slate-800 dark:text-slate-100">{b.name}</span>
                    <StatusBadge active={!b.revoked} />
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-[11px] text-slate-400">
                    {b.type && <span>{b.type}</span>}
                    {b.version && <span>v{b.version}</span>}
                    {b.last_pull && (
                      <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {timeAgo(b.last_pull)}</span>
                    )}
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

        {/* ── Machines ── */}
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
                <input
                  value={newMachineId}
                  onChange={(e) => setNewMachineId(e.target.value)}
                  placeholder="ID de la machine (ex: crowdefik)"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
                />
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={newMachinePass}
                    onChange={(e) => setNewMachinePass(e.target.value)}
                    placeholder="Mot de passe"
                    className="flex-1 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-blue-500/30 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-200"
                    onKeyDown={(e) => { if (e.key === 'Enter') void doAddMachine() }}
                  />
                  <button type="button" onClick={() => void doAddMachine()} disabled={saving || !newMachineId.trim() || !newMachinePass.trim()}
                    className="rounded-lg bg-blue-500 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-600 disabled:opacity-40">
                    {saving ? '…' : 'Créer'}
                  </button>
                </div>
                <p className="text-[11px] text-slate-400">
                  Après la création, configurez cet ID et ce mot de passe dans{' '}
                  <Link to="/settings" className="underline text-blue-500">les paramètres</Link>{' '}
                  (section Credentials Machine CrowdSec).
                </p>
              </div>
            </div>
          )}

          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {loading ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">Chargement…</p>
            ) : machines.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">Aucune machine enregistrée</p>
            ) : machines.map((m) => {
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
                          </span>
                      }
                    </div>
                    <div className="mt-0.5 flex items-center gap-3 text-[11px] text-slate-400">
                      {m.version && <span>v{m.version}</span>}
                      {lastSeen && <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {timeAgo(lastSeen)}</span>}
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
      </div>
    </div>
  )
}
