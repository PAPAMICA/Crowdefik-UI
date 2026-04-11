import {
  ExternalLink, RefreshCw, RotateCcw, Search,
  Shield, ShieldCheck, ShieldOff, ShieldX, Wifi, WifiOff, Zap,
} from 'lucide-react'
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

type WafResult = { blocked: boolean; status_code: number | null; url: string; probe_url?: string; error?: string }

// ── Helpers ──────────────────────────────────────────────────
function extractUrl(rule: string | null): string | null {
  if (!rule) return null
  const m = rule.match(/Host\(`([^`]+)`\)/)
  return m ? `https://${m[1]}` : null
}

// ── WAF status badge ─────────────────────────────────────────
function WafBadge({ result }: { result: WafResult | null | 'loading' | 'idle' }) {
  if (result === 'idle' || result === null) return null
  if (result === 'loading')
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-[10px] text-slate-400 dark:bg-slate-700">
        Probing WAF…
      </span>
    )
  if (result.error)
    return (
      <span
        className="inline-flex max-w-xs cursor-help items-center gap-1 rounded-full bg-orange-500/10 px-2 py-0.5 text-[10px] font-medium text-orange-600 dark:text-orange-400"
        title={result.error}
      >
        WAF — unreachable ⚠
      </span>
    )
  if (result.blocked)
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400"
        title={`Probe GET /.env → HTTP ${result.status_code} — WAF is active`}
      >
        WAF ✓ actif (403)
      </span>
    )
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-[10px] font-medium text-red-600 dark:text-red-400"
      title={`Probe GET /.env → HTTP ${result.status_code ?? '?'} — WAF is NOT active on this service`}
    >
      WAF ✗ inactif ({result.status_code ?? '?'})
    </span>
  )
}

// ── CrowdSec status badge ─────────────────────────────────────
function StatusBadge({ row }: { row: RouterRow }) {
  if (row.crowdsec_effective) {
    const isFile = row.override_state === 'on'
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-400">
        <ShieldCheck className="h-3 w-3" />
        {isFile ? 'Protected (override)' : 'Protected (label)'}
      </span>
    )
  }
  if (row.override_state === 'off') {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
        <ShieldOff className="h-3 w-3" />
        Disabled (override)
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
  const [bulkBusy, setBulkBusy] = useState(false)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<FilterState>('all')
  const [wafResults, setWafResults] = useState<Record<string, WafResult | 'loading'>>({})

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
        const url = extractUrl(r.rule)
        return (
          r.name.toLowerCase().includes(q) ||
          r.rule?.toLowerCase().includes(q) ||
          url?.toLowerCase().includes(q) ||
          r.service?.toLowerCase().includes(q)
        )
      })
      .sort((a, b) => {
        const ua = extractUrl(a.rule) ?? a.name
        const ub = extractUrl(b.rule) ?? b.name
        return ua.localeCompare(ub)
      })
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

  async function doBulkAction(action: 'enable' | 'disable' | 'reset') {
    if (!confirm(`Apply "${action}" to ALL visible services?`)) return
    setBulkBusy(true)
    try {
      await apiFetch('/api/routers/crowdsec/bulk', { method: 'POST', body: JSON.stringify({ action }) })
      await reload()
    } finally {
      setBulkBusy(false)
    }
  }

  async function testWaf(name: string) {
    setWafResults((p) => ({ ...p, [name]: 'loading' }))
    const res = await apiFetch(`/api/routers/${encodeURIComponent(name)}/waf-test`)
    if (res.ok) {
      const data = (await res.json()) as WafResult
      setWafResults((p) => ({ ...p, [name]: data }))
    } else {
      setWafResults((p) => ({ ...p, [name]: { blocked: false, status_code: null, url: '', error: 'API error' } }))
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
          <div className="mt-3 max-w-2xl rounded-xl border border-blue-500/30 bg-blue-500/5 px-4 py-3 text-xs text-blue-700 dark:text-blue-300">
            <span className="font-semibold">How it works:</span> Crowdefik writes a high-priority Traefik file-router in{' '}
            <code>custom/</code>. <strong>Enable</strong> adds <code>crowdsec@file</code>; <strong>Disable</strong> removes it;{' '}
            <strong>Reset</strong> reverts to Docker label state.
          </div>
        </div>
        <div className="flex gap-2">
          <button
            className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-400"
            type="button"
            disabled={bulkBusy}
            title="Enable CrowdSec on every visible service"
            onClick={() => void doBulkAction('enable')}
          >
            <Zap className="h-4 w-4" /> Protect all
          </button>
          <button
            className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
            type="button"
            disabled={bulkBusy}
            onClick={() => void reload()}
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-4 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
            placeholder="Search by URL, service…"
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
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">URL</th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Status</th>
                <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wide text-slate-400">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
              {filtered.map((r) => {
                const isBusy = busy === r.name
                const url = extractUrl(r.rule)
                const waf = wafResults[r.name] ?? 'idle'
                return (
                  <tr key={r.name} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-4 py-3">
                      <div className="flex items-start gap-2.5">
                        {/* Favicon */}
                        {url && (
                          <img
                            src={`https://icons.duckduckgo.com/ip3/${new URL(url).hostname}.ico`}
                            alt=""
                            width={20}
                            height={20}
                            className="mt-0.5 h-5 w-5 flex-shrink-0 rounded-sm object-contain"
                            onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }}
                          />
                        )}
                        <div className="flex flex-col gap-0.5 min-w-0">
                          {url ? (
                            <a
                              href={url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-sm font-medium text-violet-600 hover:underline dark:text-violet-400"
                            >
                              <span className="truncate">{url.replace('https://', '')}</span>
                              <ExternalLink className="h-3 w-3 flex-shrink-0 opacity-60" />
                            </a>
                          ) : (
                            <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{r.rule ?? '—'}</span>
                          )}
                          <span className="font-mono text-[10px] text-slate-400">{r.name}</span>
                          <WafBadge result={waf} />
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge row={r} />
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        {/* WAF test */}
                        <button
                          className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-2 text-blue-600 hover:bg-blue-500/20 disabled:opacity-40 dark:text-blue-400"
                          type="button"
                          disabled={waf === 'loading'}
                          title="Test if WAF blocks malicious requests on this service"
                          onClick={() => void testWaf(r.name)}
                        >
                          {waf === 'loading' ? <WifiOff className="h-3.5 w-3.5 animate-pulse" /> : <Wifi className="h-3.5 w-3.5" />}
                        </button>

                        {/* Enable */}
                        <button
                          className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2 text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-40 dark:text-emerald-400"
                          type="button"
                          disabled={isBusy || r.crowdsec_effective}
                          title={r.crowdsec_effective ? 'Already protected' : 'Enable CrowdSec'}
                          onClick={() => void doAction(r.name, 'enable')}
                        >
                          <Shield className="h-3.5 w-3.5" />
                        </button>

                        {/* Disable */}
                        <button
                          className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-red-700 hover:bg-red-500/20 disabled:opacity-40 dark:text-red-400"
                          type="button"
                          disabled={isBusy || !r.crowdsec_effective}
                          title={!r.crowdsec_effective ? 'Not currently protected' : 'Disable CrowdSec'}
                          onClick={() => void doAction(r.name, 'disable')}
                        >
                          <ShieldOff className="h-3.5 w-3.5" />
                        </button>

                        {/* Reset */}
                        {r.override_state !== 'none' && (
                          <button
                            className="rounded-lg border border-slate-300 bg-slate-50 p-2 text-slate-600 hover:bg-slate-100 disabled:opacity-40 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300 dark:hover:bg-slate-600"
                            type="button"
                            disabled={isBusy}
                            title="Reset — remove override (revert to Docker label)"
                            onClick={() => void doAction(r.name, 'reset')}
                          >
                            <RotateCcw className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!filtered.length && (
                <tr>
                  <td colSpan={3} className="px-4 py-12 text-center text-sm text-slate-400">
                    {rows.length ? 'No results' : 'No routers found — check Traefik settings'}
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
