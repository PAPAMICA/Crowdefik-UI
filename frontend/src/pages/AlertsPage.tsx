import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { apiFetch } from '../api'

export function AlertsPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<unknown[]>([])

  useEffect(() => {
    void (async () => {
      const res = await apiFetch('/api/crowdsec/alerts?limit=100')
      if (res.ok) setRows((await res.json()) as unknown[])
    })()
  }, [])

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Alerts</h1>
        <p className="mt-2 max-w-3xl text-sm text-neutral-600 dark:text-neutral-300">
          Scoped users see alerts only when the alert payload contains one of their allowed hostnames (best-effort match).
        </p>
      </div>
      <div className="overflow-hidden rounded-3xl border border-neutral-200 bg-white dark:border-white/10 dark:bg-white/5">
        <div className="max-h-[70dvh] overflow-auto p-4">
          <pre className="whitespace-pre-wrap break-words font-mono text-xs text-neutral-800 dark:text-neutral-200">
            {JSON.stringify(rows, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  )
}
