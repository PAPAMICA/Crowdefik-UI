import { RefreshCw, Search, Shield, ShieldOff } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'

type RouterRow = {
  name: string
  rule: string | null
  service: string | null
  entry_points: string[]
  crowdsec_effective: boolean
  label_crowdsec: boolean
  bypass_file: boolean
  priority: number
}

type FilterState = 'all' | 'protected' | 'unprotected'

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

  async function setCrowdsec(name: string, enabled: boolean) {
    setBusy(name)
    try {
      const res = await apiFetch(`/api/routers/${encodeURIComponent(name)}/crowdsec`, {
        method: 'POST',
        body: JSON.stringify({ enabled }),
      })
      if (!res.ok) alert(await res.text())
      await reload()
    } finally {
      setBusy(null)
    }
  }

  if (!loading && !me) return <Navigate to="/login" replace />

  const protectedCount = rows.filter((r) => r.crowdsec_effective).length

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Exposed services</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {protectedCount}/{rows.length} services protected by CrowdSec
          </p>
        </div>
        <button
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-200"
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
                filter === f
                  ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900'
                  : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200',
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
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">CrowdSec</th>
                <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.map((r) => (
                <tr key={r.name} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-slate-700 dark:text-slate-300">{r.name}</span>
                  </td>
                  <td className="max-w-[220px] px-4 py-3">
                    <span className="truncate block text-xs text-slate-500 dark:text-slate-400">{r.rule ?? '—'}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{r.service ?? '—'}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={[
                        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
                        r.crowdsec_effective
                          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
                          : r.label_crowdsec
                          ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400'
                          : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400',
                      ].join(' ')}
                    >
                      {r.crowdsec_effective ? (
                        <><Shield className="h-3 w-3" /> Protected</>
                      ) : r.label_crowdsec ? (
                        <><ShieldOff className="h-3 w-3" /> Bypassed</>
                      ) : (
                        'No label'
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="inline-flex gap-2">
                      <button
                        className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-40 dark:text-emerald-400"
                        type="button"
                        disabled={busy === r.name || !r.label_crowdsec || r.crowdsec_effective}
                        title={!r.label_crowdsec ? 'No crowdsec@file label' : 'Enable CrowdSec'}
                        onClick={() => void setCrowdsec(r.name, true)}
                      >
                        Enable
                      </button>
                      <button
                        className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-500/20 disabled:opacity-40 dark:text-red-400"
                        type="button"
                        disabled={busy === r.name || !r.label_crowdsec || !r.crowdsec_effective}
                        title={!r.label_crowdsec ? 'No crowdsec@file label' : 'Disable CrowdSec (override)'}
                        onClick={() => void setCrowdsec(r.name, false)}
                      >
                        Disable
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
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
