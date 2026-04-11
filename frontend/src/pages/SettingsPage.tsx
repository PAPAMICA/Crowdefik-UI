import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { apiFetch } from '../api'

type SettingsOut = {
  traefik_api_url: string
  traefik_basic_user: string | null
  crowdsec_lapi_url: string
  has_traefik_basic_password: boolean
  has_crowdsec_api_key: boolean
}

export function SettingsPage() {
  const { me, loading } = useAuth()
  const [s, setS] = useState<SettingsOut | null>(null)
  const [form, setForm] = useState({
    traefik_api_url: '',
    traefik_basic_user: '',
    traefik_basic_password: '',
    crowdsec_lapi_url: '',
    crowdsec_api_key: '',
  })
  const [msg, setMsg] = useState<string | null>(null)

  useEffect(() => {
    void (async () => {
      const res = await apiFetch('/api/settings')
      if (!res.ok) return
      const data = (await res.json()) as SettingsOut
      setS(data)
      setForm((f) => ({
        ...f,
        traefik_api_url: data.traefik_api_url,
        traefik_basic_user: data.traefik_basic_user ?? '',
        crowdsec_lapi_url: data.crowdsec_lapi_url,
      }))
    })()
  }, [])

  if (!loading && !me) return <Navigate to="/login" replace />
  if (!loading && me && !me.is_superuser) return <Navigate to="/" replace />

  async function onSave(e: React.FormEvent) {
    e.preventDefault()
    setMsg(null)
    const payload: Record<string, unknown> = {
      traefik_api_url: form.traefik_api_url,
      traefik_basic_user: form.traefik_basic_user || null,
      crowdsec_lapi_url: form.crowdsec_lapi_url,
    }
    if (form.traefik_basic_password) payload.traefik_basic_password = form.traefik_basic_password
    if (form.crowdsec_api_key) payload.crowdsec_api_key = form.crowdsec_api_key

    const res = await apiFetch('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      setMsg('Save failed')
      return
    }
    const data = (await res.json()) as SettingsOut
    setS(data)
    setForm((f) => ({ ...f, traefik_basic_password: '', crowdsec_api_key: '' }))
    setMsg('Saved')
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Integration settings</h1>
        <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-300">
          Secrets are stored encrypted in SQLite (server-side). Leave password fields empty to keep existing values.
        </p>
      </div>

      <form className="flex flex-col gap-4 rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5" onSubmit={onSave}>
        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">Traefik API URL</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
            value={form.traefik_api_url}
            onChange={(e) => setForm({ ...form, traefik_api_url: e.target.value })}
          />
        </label>
        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">Traefik basic auth user (optional)</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
            value={form.traefik_basic_user}
            onChange={(e) => setForm({ ...form, traefik_basic_user: e.target.value })}
          />
        </label>
        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">Traefik basic auth password</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
            type="password"
            value={form.traefik_basic_password}
            placeholder={s?.has_traefik_basic_password ? '(unchanged)' : ''}
            onChange={(e) => setForm({ ...form, traefik_basic_password: e.target.value })}
          />
        </label>
        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">CrowdSec LAPI URL</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
            value={form.crowdsec_lapi_url}
            onChange={(e) => setForm({ ...form, crowdsec_lapi_url: e.target.value })}
          />
        </label>
        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">CrowdSec API key</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
            type="password"
            value={form.crowdsec_api_key}
            placeholder={s?.has_crowdsec_api_key ? '(unchanged)' : ''}
            onChange={(e) => setForm({ ...form, crowdsec_api_key: e.target.value })}
          />
        </label>
        {msg ? <div className="text-sm text-neutral-600 dark:text-neutral-300">{msg}</div> : null}
        <button
          className="rounded-2xl bg-neutral-900 px-4 py-3 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-950 dark:hover:bg-neutral-200"
          type="submit"
        >
          Save
        </button>
      </form>
    </div>
  )
}
