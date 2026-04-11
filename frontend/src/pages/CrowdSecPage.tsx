import {
  Activity, Bot, CheckCircle2, Clock, RefreshCw, Shield, Users, XCircle,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { apiFetch } from '../api'

type Bouncer = {
  name: string
  api_key?: string
  created_at?: string
  updated_at?: string
  revoked?: boolean
  ip?: string
  type?: string
  version?: string
  last_pull?: string
  auth_type?: string
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

function StatusDot({ active }: { active: boolean }) {
  return (
    <span className={`inline-flex h-2 w-2 rounded-full ${active ? 'bg-emerald-500' : 'bg-red-400'}`} />
  )
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

export function CrowdSecPage() {
  const [bouncers, setBouncers] = useState<Bouncer[]>([])
  const [machines, setMachines] = useState<Machine[]>([])
  const [loading, setLoading] = useState(true)
  const [noAuth, setNoAuth] = useState(false)

  async function loadData() {
    setLoading(true)
    setNoAuth(false)
    try {
      const [bRes, mRes] = await Promise.all([
        apiFetch('/api/crowdsec/bouncers'),
        apiFetch('/api/crowdsec/machines'),
      ])
      if (bRes.status === 403 || mRes.status === 403) {
        setNoAuth(true)
        return
      }
      if (bRes.ok) setBouncers((await bRes.json()) as Bouncer[])
      if (mRes.ok) setMachines((await mRes.json()) as Machine[])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadData() }, [])

  const activeBouncers = bouncers.filter((b) => !b.revoked)
  const validatedMachines = machines.filter((m) => m.isValidated ?? m.is_validated)

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">CrowdSec</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Bouncers, machines and LAPI health</p>
        </div>
        <button type="button" onClick={() => void loadData()}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {noAuth && (
        <div className="flex items-start gap-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm dark:border-amber-500/30 dark:bg-amber-900/20">
          <Activity className="mt-0.5 h-4 w-4 flex-shrink-0 text-amber-500" />
          <div className="text-amber-800 dark:text-amber-300">
            <p className="font-semibold">Watcher credentials required</p>
            <p className="mt-0.5 text-xs">Configure CrowdSec machine credentials in Settings to view bouncers and machines.</p>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { icon: Shield, label: 'Total bouncers', value: bouncers.length, color: 'border-violet-500/20' },
          { icon: CheckCircle2, label: 'Active bouncers', value: activeBouncers.length, color: 'border-emerald-500/20' },
          { icon: Users, label: 'Total machines', value: machines.length, color: 'border-blue-500/20' },
          { icon: Bot, label: 'Validated machines', value: validatedMachines.length, color: 'border-indigo-500/20' },
        ].map(({ icon: Icon, label, value, color }) => (
          <div key={label} className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 ${color}`}>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
                <div className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{value}</div>
              </div>
              <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${color.replace('border-', 'bg-').replace('/20', '/10')}`}>
                <Icon className="h-5 w-5" />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Bouncers */}
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Shield className="h-4 w-4 text-violet-500" /> Bouncers
              <span className="ml-auto rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                {bouncers.length}
              </span>
            </h2>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {bouncers.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">
                {loading ? 'Loading…' : noAuth ? 'Requires watcher credentials' : 'No bouncers registered'}
              </p>
            ) : bouncers.map((b) => (
              <div key={b.name} className="px-5 py-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <StatusDot active={!b.revoked} />
                    <span className="font-medium text-sm text-slate-800 dark:text-slate-100">{b.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {b.revoked ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-700 dark:text-red-400">
                        <XCircle className="h-3 w-3" /> Revoked
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                        <CheckCircle2 className="h-3 w-3" /> Active
                      </span>
                    )}
                  </div>
                </div>
                <div className="mt-1 flex items-center gap-3 text-[11px] text-slate-400">
                  {b.type && <span>{b.type}</span>}
                  {b.version && <span>v{b.version}</span>}
                  {(b.ip || b.last_pull) && (
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {b.last_pull ? timeAgo(b.last_pull) : b.ip}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Machines */}
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Bot className="h-4 w-4 text-blue-500" /> Machines / Watchers
              <span className="ml-auto rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                {machines.length}
              </span>
            </h2>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {machines.length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">
                {loading ? 'Loading…' : noAuth ? 'Requires watcher credentials' : 'No machines registered'}
              </p>
            ) : machines.map((m) => {
              const id = m.machineId ?? m.machine_id ?? '?'
              const validated = m.isValidated ?? m.is_validated
              const lastSeen = m.last_push ?? m.last_heartbeat ?? m.updated_at
              return (
                <div key={id} className="px-5 py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusDot active={!!validated} />
                      <span className="font-mono text-sm font-medium text-slate-800 dark:text-slate-100">{id}</span>
                    </div>
                    {validated ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                        <CheckCircle2 className="h-3 w-3" /> Validated
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400">
                        <AlertCircle className="h-3 w-3" /> Pending
                      </span>
                    )}
                  </div>
                  <div className="mt-1 flex items-center gap-3 text-[11px] text-slate-400">
                    {m.version && <span>v{m.version}</span>}
                    {lastSeen && (
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {timeAgo(lastSeen)}
                      </span>
                    )}
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

function AlertCircle({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  )
}
