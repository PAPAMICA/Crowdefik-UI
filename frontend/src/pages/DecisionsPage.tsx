import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { apiFetch } from '../api'

type Decision = Record<string, unknown>

export function DecisionsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<Decision[]>([])

  useEffect(() => {
    void (async () => {
      const res = await apiFetch('/api/crowdsec/decisions?limit=200')
      if (res.ok) setRows((await res.json()) as Decision[])
    })()
  }, [])

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Decisions</h1>
        <p className="mt-2 max-w-3xl text-sm text-neutral-600 dark:text-neutral-300">
          Active bans and decisions returned by CrowdSec LAPI.
        </p>
      </div>

      <div className="overflow-hidden rounded-3xl border border-neutral-200 bg-white dark:border-white/10 dark:bg-white/5">
        <div className="grid grid-cols-12 gap-3 border-b border-neutral-100 px-4 py-3 text-xs uppercase tracking-wide text-neutral-500 dark:border-white/10">
          <div className="col-span-3">Value</div>
          <div className="col-span-2">Type</div>
          <div className="col-span-2">Scenario</div>
          <div className="col-span-2">Duration</div>
          <div className="col-span-3">Reason</div>
        </div>
        <div className="divide-y divide-neutral-100 dark:divide-white/10">
          {rows.map((d, idx) => (
            <div key={idx} className="grid grid-cols-12 items-start gap-3 px-4 py-3 text-sm">
              <div className="col-span-3 font-mono text-xs">{String(d.value ?? d.ip ?? '')}</div>
              <div className="col-span-2 text-xs text-neutral-600 dark:text-neutral-300">{String(d.type ?? '')}</div>
              <div className="col-span-2 truncate text-xs text-neutral-600 dark:text-neutral-300">{String(d.scenario ?? '')}</div>
              <div className="col-span-2 text-xs text-neutral-600 dark:text-neutral-300">{String(d.duration ?? '')}</div>
              <div className="col-span-3 text-xs text-neutral-600 dark:text-neutral-300">{String(d.reason ?? '')}</div>
            </div>
          ))}
          {!rows.length ? <div className="px-4 py-10 text-center text-sm text-neutral-500">No decisions</div> : null}
        </div>
      </div>
    </div>
  )
}
