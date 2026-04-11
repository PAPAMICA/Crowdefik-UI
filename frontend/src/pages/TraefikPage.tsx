import {
  AlertCircle, ArrowRightLeft, CheckCircle2, Globe, Layers,
  RefreshCw, Route, Server, Shield, XCircle,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { apiFetch } from '../api'

type Entrypoint = { name: string; address: string; tls: boolean; protocol: string }
type Middleware = { name: string; type: string | null; provider: string | null; status: string | null }
type Overview = {
  version: string | null
  code_name: string | null
  http_routers_total: number
  http_routers_tls: number
  http_services_total: number
  http_middlewares_total: number
  entrypoints: Entrypoint[]
  middlewares: Middleware[]
  features: string[]
}
type Cert = {
  domain: string
  router: string
  expiry: string | null
  days_left: number | null
  status: 'ok' | 'warning' | 'critical' | 'unknown' | 'unreachable'
}

function StatCard({ icon: Icon, label, value, sub, color }: {
  icon: React.ElementType; label: string; value: string | number; sub?: string; color: string
}) {
  return (
    <div className={`rounded-2xl border bg-white p-5 dark:bg-slate-800/60 ${color}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
          <div className="mt-1 text-2xl font-bold text-slate-900 dark:text-white">{value}</div>
          {sub && <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{sub}</div>}
        </div>
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${color.replace('border-', 'bg-').replace('/20', '/10')}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  )
}

function certBadge(status: Cert['status']) {
  switch (status) {
    case 'ok': return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20'
    case 'warning': return 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20'
    case 'critical': return 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20'
    default: return 'bg-slate-500/10 text-slate-500 border-slate-500/20'
  }
}

function certIcon(status: Cert['status']) {
  switch (status) {
    case 'ok': return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
    case 'warning': return <AlertCircle className="h-3.5 w-3.5 text-amber-500" />
    case 'critical': return <XCircle className="h-3.5 w-3.5 text-red-500" />
    default: return <AlertCircle className="h-3.5 w-3.5 text-slate-400" />
  }
}

export function TraefikPage() {
  const [overview, setOverview] = useState<Overview | null>(null)
  const [certs, setCerts] = useState<Cert[]>([])
  const [loadingCerts, setLoadingCerts] = useState(false)
  const [certsLoaded, setCertsLoaded] = useState(false)
  const [refreshing, setRefreshing] = useState(false)

  async function loadOverview() {
    setRefreshing(true)
    try {
      const res = await apiFetch('/api/traefik/overview')
      if (res.ok) setOverview((await res.json()) as Overview)
    } finally {
      setRefreshing(false)
    }
  }

  async function loadCerts() {
    setLoadingCerts(true)
    try {
      const res = await apiFetch('/api/traefik/certs')
      if (res.ok) setCerts((await res.json()) as Cert[])
      setCertsLoaded(true)
    } finally {
      setLoadingCerts(false)
    }
  }

  useEffect(() => { void loadOverview() }, [])

  const criticalCerts = certs.filter((c) => c.status === 'critical')

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Traefik</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {overview?.version ? `v${overview.version}${overview.code_name ? ` — ${overview.code_name}` : ''}` : 'Infrastructure overview'}
          </p>
        </div>
        <button type="button" onClick={() => void loadOverview()}
          disabled={refreshing}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-medium hover:bg-slate-50 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700">
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Critical cert alert */}
      {criticalCerts.length > 0 && (
        <div className="flex items-start gap-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm dark:border-red-500/30 dark:bg-red-900/20">
          <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-500" />
          <div className="text-red-700 dark:text-red-300">
            <p className="font-semibold">Critical: {criticalCerts.length} certificate{criticalCerts.length > 1 ? 's' : ''} expire{criticalCerts.length === 1 ? 's' : ''} in less than 7 days</p>
            <p className="mt-0.5 text-xs">{criticalCerts.map((c) => c.domain).join(', ')}</p>
          </div>
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard icon={Route} label="HTTP Routers" value={overview?.http_routers_total ?? '—'} sub={`${overview?.http_routers_tls ?? 0} with TLS`} color="border-violet-500/20" />
        <StatCard icon={Server} label="Services" value={overview?.http_services_total ?? '—'} color="border-blue-500/20" />
        <StatCard icon={Layers} label="Middlewares" value={overview?.http_middlewares_total ?? '—'} color="border-indigo-500/20" />
        <StatCard icon={ArrowRightLeft} label="Entrypoints" value={overview?.entrypoints?.length ?? '—'} color="border-cyan-500/20" />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Entrypoints */}
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <ArrowRightLeft className="h-4 w-4 text-cyan-500" /> Entrypoints
            </h2>
          </div>
          <div className="divide-y divide-slate-100 dark:divide-slate-700/50">
            {(overview?.entrypoints ?? []).length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">No entrypoints found</p>
            ) : (
              (overview?.entrypoints ?? []).map((ep) => (
                <div key={ep.name} className="flex items-center justify-between px-5 py-3">
                  <div>
                    <div className="font-medium text-sm text-slate-800 dark:text-slate-100">{ep.name}</div>
                    <div className="font-mono text-xs text-slate-500 dark:text-slate-400">{ep.address}</div>
                  </div>
                  {ep.tls ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                      <Shield className="h-3 w-3" /> TLS
                    </span>
                  ) : (
                    <span className="inline-flex rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500 dark:bg-slate-700 dark:text-slate-400">HTTP</span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Middlewares */}
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
              <Layers className="h-4 w-4 text-indigo-500" /> Middlewares
              <span className="ml-auto rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500 dark:bg-slate-700 dark:text-slate-400">
                {overview?.middlewares?.length ?? 0}
              </span>
            </h2>
          </div>
          <div className="max-h-72 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-700/50">
            {(overview?.middlewares ?? []).length === 0 ? (
              <p className="px-5 py-8 text-center text-sm text-slate-400">No middlewares found</p>
            ) : (
              (overview?.middlewares ?? []).map((mw) => (
                <div key={mw.name} className="flex items-center justify-between px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs font-medium text-slate-800 dark:text-slate-100">{mw.name}</div>
                    <div className="text-[10px] text-slate-400">{mw.provider ?? ''}</div>
                  </div>
                  {mw.type && (
                    <span className="ml-2 flex-shrink-0 rounded-full bg-indigo-500/10 px-2 py-0.5 text-[10px] font-medium text-indigo-700 dark:text-indigo-300">
                      {mw.type}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* TLS Certificates */}
      <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white">
            <Globe className="h-4 w-4 text-emerald-500" /> TLS Certificates
          </h2>
          {!certsLoaded ? (
            <button type="button" onClick={() => void loadCerts()} disabled={loadingCerts}
              className="inline-flex items-center gap-1.5 rounded-xl bg-violet-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-violet-700 disabled:opacity-60">
              {loadingCerts ? <><RefreshCw className="h-3 w-3 animate-spin" /> Checking…</> : 'Check certificates'}
            </button>
          ) : (
            <button type="button" onClick={() => void loadCerts()} disabled={loadingCerts}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-60 dark:border-slate-600 dark:bg-slate-700 dark:text-slate-300">
              <RefreshCw className={`h-3 w-3 ${loadingCerts ? 'animate-spin' : ''}`} /> Refresh
            </button>
          )}
        </div>

        {!certsLoaded ? (
          <p className="px-5 py-10 text-center text-sm text-slate-400">
            Click "Check certificates" to probe TLS expiry for all HTTPS routers.<br />
            <span className="text-xs text-slate-300 dark:text-slate-500">This may take a few seconds.</span>
          </p>
        ) : certs.length === 0 ? (
          <p className="px-5 py-10 text-center text-sm text-slate-400">No HTTPS routers found or no certificates detected.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 dark:border-slate-700/50">
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Domain</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Router</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Expiry</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Days left</th>
                  <th className="px-5 py-3 text-left text-xs font-medium uppercase tracking-wide text-slate-400">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {certs.map((c) => (
                  <tr key={c.domain} className="hover:bg-slate-50/50 dark:hover:bg-white/5">
                    <td className="px-5 py-3 font-mono text-xs font-medium text-slate-800 dark:text-slate-100">{c.domain}</td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-500 dark:text-slate-400">{c.router}</td>
                    <td className="px-5 py-3 text-xs text-slate-500 dark:text-slate-400">
                      {c.expiry ? new Date(c.expiry).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-5 py-3 text-xs font-semibold">
                      {c.days_left != null
                        ? <span className={c.days_left <= 7 ? 'text-red-600' : c.days_left <= 30 ? 'text-amber-600' : 'text-emerald-600'}>{c.days_left}d</span>
                        : <span className="text-slate-400">—</span>}
                    </td>
                    <td className="px-5 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${certBadge(c.status)}`}>
                        {certIcon(c.status)} {c.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
