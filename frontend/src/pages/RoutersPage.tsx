import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { apiFetch } from '../api'

type RouterRow = {
  name: string
  rule: string | null
  service: string | null
  crowdsec_effective: boolean
  label_crowdsec: boolean
  bypass_file: boolean
}

export function RoutersPage() {
  const { me, loading } = useAuth()
  const [rows, setRows] = useState<RouterRow[]>([])
  const [busy, setBusy] = useState<string | null>(null)

  async function reload() {
    const res = await apiFetch('/api/routers')
    if (res.ok) setRows((await res.json()) as RouterRow[])
  }

  useEffect(() => {
    void reload()
  }, [])

  const sorted = useMemo(() => [...rows].sort((a, b) => a.name.localeCompare(b.name)), [rows])

  async function setCrowdsec(name: string, enabled: boolean) {
    setBusy(name)
    try {
      const res = await apiFetch(`/api/routers/${encodeURIComponent(name)}/crowdsec`, {
        method: 'POST',
        body: JSON.stringify({ enabled }),
      })
      if (!res.ok) {
        const t = await res.text()
        alert(t || 'Failed')
      }
      await reload()
    } finally {
      setBusy(null)
    }
  }

  if (!loading && !me) return <Navigate to="/login" replace />

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Exposed services</h1>
          <p className="mt-2 max-w-3xl text-sm text-neutral-600 dark:text-neutral-300">
            Disabling CrowdSec writes a high-priority Traefik file-router override in <span className="font-mono">crowdefik-overrides/</span> (no Docker label changes).
          </p>
        </div>
        <button
          className="self-start rounded-full border border-neutral-200 bg-white px-4 py-2 text-sm hover:bg-neutral-50 dark:border-white/10 dark:bg-white/5 dark:hover:bg-white/10"
          type="button"
          onClick={() => void reload()}
        >
          Reload list
        </button>
      </div>

      <div className="overflow-hidden rounded-3xl border border-neutral-200 bg-white dark:border-white/10 dark:bg-white/5">
        <div className="grid grid-cols-12 gap-3 border-b border-neutral-100 px-4 py-3 text-xs uppercase tracking-wide text-neutral-500 dark:border-white/10">
          <div className="col-span-3">Router</div>
          <div className="col-span-4">Rule</div>
          <div className="col-span-2">Service</div>
          <div className="col-span-1">CS</div>
          <div className="col-span-2 text-right">Actions</div>
        </div>
        <div className="divide-y divide-neutral-100 dark:divide-white/10">
          {sorted.map((r) => (
            <div key={r.name} className="grid grid-cols-12 items-center gap-3 px-4 py-4 text-sm">
              <div className="col-span-3 font-mono text-xs">{r.name}</div>
              <div className="col-span-4 truncate text-neutral-600 dark:text-neutral-300">{r.rule}</div>
              <div className="col-span-2 truncate font-mono text-xs text-neutral-600 dark:text-neutral-300">{r.service}</div>
              <div className="col-span-1">
                <span
                  className={[
                    'inline-flex rounded-full px-2 py-1 text-xs',
                    r.crowdsec_effective ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : 'bg-neutral-500/10 text-neutral-600 dark:text-neutral-300',
                  ].join(' ')}
                >
                  {r.crowdsec_effective ? 'on' : 'off'}
                </span>
              </div>
              <div className="col-span-2 flex justify-end gap-2">
                <button
                  className="rounded-full border border-neutral-200 bg-white px-3 py-1 text-xs hover:bg-neutral-50 disabled:opacity-50 dark:border-white/10 dark:bg-black/20 dark:hover:bg-white/10"
                  type="button"
                  disabled={busy === r.name || !r.label_crowdsec}
                  title={!r.label_crowdsec ? 'No crowdsec@file on this router' : 'Enable CrowdSec'}
                  onClick={() => void setCrowdsec(r.name, true)}
                >
                  Enable
                </button>
                <button
                  className="rounded-full border border-neutral-200 bg-white px-3 py-1 text-xs hover:bg-neutral-50 disabled:opacity-50 dark:border-white/10 dark:bg-black/20 dark:hover:bg-white/10"
                  type="button"
                  disabled={busy === r.name || !r.label_crowdsec}
                  title={!r.label_crowdsec ? 'No crowdsec@file on this router' : 'Disable CrowdSec (override)'}
                  onClick={() => void setCrowdsec(r.name, false)}
                >
                  Disable
                </button>
              </div>
            </div>
          ))}
          {!sorted.length ? <div className="px-4 py-10 text-center text-sm text-neutral-500">No routers found</div> : null}
        </div>
      </div>
    </div>
  )
}
