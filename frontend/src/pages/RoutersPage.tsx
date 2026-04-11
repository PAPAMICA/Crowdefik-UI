import { RefreshCw, RotateCcw, Search, Shield, ShieldCheck, ShieldOff, ShieldX } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'

type OverrideState = 'on' | 'off' | 'none'
type RouterRow = {
  name: string
  rule: string | null
  service: string | null
  entry_points: string[]
  crowdsec_effective: boolean
  label_crowdsec: boolean
  override_state: OverrideState
  priority: number
}

type FilterState = 'all' | 'protected' | 'unprotected'

// ── Status badge ─────────────────────────────────────────────
function StatusBadge({ row }: { row: RouterRow }) {
  if (row.crowdsec_effective) {
    const isFile = row.override_state === 'on'
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
        <ShieldCheck className="h-3 w-3" />
        Protected{isFile ? ' (file)' : ' (label)'}
      </span>
    )
  }
  if (row.override_state === 'off') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
        <ShieldOff className="h-3 w-3" />
        Disabled (file)
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-500 dark:bg-slate-700 dark:text-slate-400">
      <ShieldX className="h-3 w-3" />
      Unprotected
    </span>
  )
}

export function RoutersPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<RouterRow[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<FilterState>('all')

  async function reload() {
    const res = await apiFetch('/api/routers')
    if (res.ok) setRows((await res.json()) as RouterRow[])
  }

  useEffect(() => { void reload() }, [])

  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return rows
      .filter((r) => {
        if (filter === 'protected' && !r.crowdsec_effective) return false
        if (filter === 'unprotected' && r.crowdsec_effective) return false
        if (!q) return true
        return (
          r.name.toLowerCase().includes(q) ||
          r.rule?.toLowerCase().includes(q) ||
          r.service?.toLowerCase().includes(q)
        )
      })
      .sort((a, b) => a.name.localeCompare(b.name))
  }, [rows, search, filter])

  async function doAction(name: string, action: 'enable' | 'disable' | 'reset') {
    setBusy(name)
    try {
      const res = await apiFetch(`/api/routers/${encodeURIComponent(name)}/crowdsec`, {
        method: 'POST',
        body: JSON.stringify({ action }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Unknown error' }))
        alert(err.detail ?? JSON.stringify(err))
      }
      await reload()
    } finally {
      setBusy(null)
    }
  }

  if (!loading && !me) return <Navigate to="/login" replace />

  const protectedCount = rows.filter((r) => r.crowdsec_effective).length

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Exposed services</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {protectedCount}/{rows.length} services protected by CrowdSec
          </p>
          {/* Explanation */}
          <div className="mt-3 max-w-2xl rounded-xl border border-blue-500/30 bg-blue-500/5 px-4 py-3 text-xs text-blue-700 dark:text-blue-300">
            <span className="font-semibold">How it works:</span> Crowdefik writes a high-priority Traefik file-router override in{' '}
            <code>crowdefik-overrides/</code>. <strong>Enable</strong> adds <code>crowdsec@file</code> middleware; <strong>Disable</strong>{' '}
            removes it; <strong>Reset</strong> deletes the override (reverts to Docker label state). No containers are restarted.
          </div>
        </div>
        <button
          className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
          type="button"
          onClick={() => void reload()}
        >
          <RefreshCw className="h-4 w-4" /> Reload
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Search by name, rule, service…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-1 rounded-xl border border-slate-200 bg-white p-1 dark:border-slate-700 dark:bg-slate-800">
          {(['all', 'protected', 'unprotected'] as FilterState[]).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setFilter(f)}
              className={[
                'rounded-lg px-3 py-1.5 text-xs font-medium capitalize transition',
                filter === f ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200',
              ].join(' ')}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-100 dark:border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Router</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Rule</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Service</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Status</th>
                <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.map((r) => {
                const isBusy = busy === r.name
                return (
                  <tr key={r.name} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-slate-700 dark:text-slate-300">{r.name}</span>
                      {r.label_crowdsec && (
                        <span className="ml-2 rounded bg-violet-500/10 px-1.5 py-0.5 text-[10px] text-violet-600 dark:text-violet-400">
                          label
                        </span>
                      )}
                    </td>
                    <td className="max-w-[200px] px-4 py-3">
                      <span className="block truncate text-xs text-slate-500 dark:text-slate-400">{r.rule ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{r.service ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge row={r} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-1.5">
                        <button
                          className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-40 dark:text-emerald-400"
                          type="button"
                          disabled={isBusy || r.crowdsec_effective}
                          title={r.crowdsec_effective ? 'Already protected' : 'Enable CrowdSec via file override'}
                          onClick={() => void doAction(r.name, 'enable')}
                        >
                          <Shield className="h-3 w-3" /> Enable
                        </button>
                        <button
                          className="inline-flex items-center gap-1 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-40 dark:text-red-400"
                          type="button"
                          disabled={isBusy || !r.crowdsec_effective}
                          title={!r.crowdsec_effective ? 'Not currently protected' : 'Disable CrowdSec via file override'}
                          onClick={() => void doAction(r.name, 'disable')}
                        >
                          <ShieldOff className="h-3 w-3" /> Disable
                        </button>
                        {r.override_state !== 'none' && (
                          <button
                            className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 disabled:opacity-40 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
                            type="button"
                            disabled={isBusy}
                            title="Reset — remove override file (revert to Docker label state)"
                            onClick={() => void doAction(r.name, 'reset')}
                          >
                            <RotateCcw className="h-3 w-3" /> Reset
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!filtered.length && (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No results for this search / filter' : 'No routers found — check Traefik settings'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
