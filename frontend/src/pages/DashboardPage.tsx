import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { apiFetch, getToken, wsDashboardUrl } from '../api'

type Summary = {
  routers_total: number
  routers_crowdsec_effective: number
  decisions_count: number
  alerts_count: number
  top_attacker_ips: { ip: string; count: number }[]
  attack_types: { type: string; count: number }[]
}

function Card({ title, value }: { title: string; value: string | number }) {
  return (
    <div className="rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5">
      <div className="text-xs uppercase tracking-wide text-neutral-500">{title}</div>
      <div className="mt-3 text-3xl font-semibold tracking-tight">{value}</div>
    </div>
  )
}

export function DashboardPage() {
  const { me, loading } = useAuth()
  const [summary, setSummary] = useState<Summary | null>(null)

  useEffect(() => {
    const token = getToken()
    if (!token) return
    const url = wsDashboardUrl(token)
    const ws = new WebSocket(url)
    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(String(evt.data))
        if (msg?.type === 'dashboard') setSummary(msg.payload as Summary)
      } catch {
        // ignore
      }
    }
    return () => ws.close()
  }, [me?.id])

  useEffect(() => {
    void (async () => {
      const res = await apiFetch('/api/dashboard/summary')
      if (res.ok) setSummary((await res.json()) as Summary)
    })()
  }, [])

  const topIps = useMemo(() => summary?.top_attacker_ips ?? [], [summary])
  const types = useMemo(() => summary?.attack_types ?? [], [summary])

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Security overview</h1>
        <p className="mt-2 max-w-2xl text-sm text-neutral-600 dark:text-neutral-300">
          Live updates via WebSocket (10s). Traefik/Docker discovery is cached (2h) unless you refresh manually.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card title="Exposed routers" value={summary?.routers_total ?? '—'} />
        <Card title="CrowdSec effective" value={summary?.routers_crowdsec_effective ?? '—'} />
        <Card title="Active decisions" value={summary?.decisions_count ?? '—'} />
        <Card title="Alerts" value={summary?.alerts_count ?? '—'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5">
          <div className="text-sm font-medium">Top attacker IPs</div>
          <div className="mt-4 space-y-2 text-sm">
            {topIps.length ? (
              topIps.map((x) => (
                <div key={x.ip} className="flex items-center justify-between rounded-2xl border border-neutral-100 px-3 py-2 dark:border-white/10">
                  <span className="font-mono text-xs">{x.ip}</span>
                  <span className="text-neutral-500">{x.count}</span>
                </div>
              ))
            ) : (
              <div className="text-sm text-neutral-500">No data yet</div>
            )}
          </div>
        </div>
        <div className="rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5">
          <div className="text-sm font-medium">Attack scenarios</div>
          <div className="mt-4 space-y-2 text-sm">
            {types.length ? (
              types.map((x) => (
                <div key={x.type} className="flex items-center justify-between rounded-2xl border border-neutral-100 px-3 py-2 dark:border-white/10">
                  <span className="truncate">{x.type}</span>
                  <span className="text-neutral-500">{x.count}</span>
                </div>
              ))
            ) : (
              <div className="text-sm text-neutral-500">No data yet</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
