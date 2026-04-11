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

type TestResult = {
  ok: boolean
  url?: string
  error?: string
  version?: string | null
  http_routers?: number | null
  active_decisions?: number | null
  api_version?: string | null
  os?: string | null
  arch?: string | null
}

function StatusBadge({ result }: { result: TestResult | null | 'pending' }) {
  if (result === null) return null
  if (result === 'pending')
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-neutral-100 px-3 py-1 text-xs dark:bg-white/10">
        <span className="animate-pulse">Testing…</span>
      </span>
    )
  if (result.ok) {
    const details = [
      result.version && `v${result.version}`,
      result.api_version && `API ${result.api_version}`,
      result.http_routers != null && `${result.http_routers} routers`,
      result.active_decisions != null && `${result.active_decisions} decisions`,
      result.os && result.arch && `${result.os}/${result.arch}`,
    ]
      .filter(Boolean)
      .join(' · ')
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-3 py-1 text-xs text-emerald-700 dark:text-emerald-300">
        <span className="size-1.5 rounded-full bg-emerald-500" />
        Connected{details ? ` — ${details}` : ''}
      </span>
    )
  }
  return (
    <span className="inline-flex items-start gap-1.5 rounded-2xl bg-red-500/10 px-3 py-2 text-xs text-red-700 dark:text-red-300">
      <span className="mt-0.5 size-1.5 shrink-0 rounded-full bg-red-500" />
      <span className="break-all">{result.error ?? 'Unreachable'}</span>
    </span>
  )
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
  const [traefikTest, setTraefikTest] = useState<TestResult | null | 'pending'>(null)
  const [crowdsecTest, setCrowdsecTest] = useState<TestResult | null | 'pending'>(null)
  const [dockerTest, setDockerTest] = useState<TestResult | null | 'pending'>(null)

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
    setTraefikTest(null)
    setCrowdsecTest(null)
  }

  async function runTest(endpoint: 'traefik' | 'crowdsec' | 'docker') {
    const set = endpoint === 'traefik' ? setTraefikTest : endpoint === 'crowdsec' ? setCrowdsecTest : setDockerTest
    set('pending')
    const res = await apiFetch(`/api/test/${endpoint}`)
    if (!res.ok) {
      set({ ok: false, error: `HTTP ${res.status}` })
      return
    }
    set((await res.json()) as TestResult)
  }

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Integration settings</h1>
        <p className="mt-2 text-sm text-neutral-600 dark:text-neutral-300">
          Secrets are stored encrypted in SQLite. Leave password/key fields empty to keep the current value.
        </p>
      </div>

      {/* ── Traefik ── */}
      <form
        className="flex flex-col gap-4 rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5"
        onSubmit={onSave}
      >
        <div className="flex items-center justify-between">
          <div className="text-sm font-medium">Traefik</div>
          <button
            type="button"
            className="rounded-full border border-neutral-200 px-3 py-1.5 text-xs hover:bg-neutral-50 dark:border-white/10 dark:hover:bg-white/10"
            onClick={() => void runTest('traefik')}
          >
            Test connection
          </button>
        </div>
        <StatusBadge result={traefikTest} />

        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-xs text-amber-800 dark:text-amber-300">
          <span className="font-medium">Note :</span> l'URL doit pointer vers l'API insecure Traefik, accessible depuis ce conteneur.<br />
          Si <code>api.insecure: true</code> est activé → <code>http://traefik:8080</code><br />
          Sinon utilise l'URL HTTPS du dashboard avec les identifiants basic auth → ex. <code>https://traefik.example.com</code>
        </div>

        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">Traefik API URL</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none focus:ring-2 focus:ring-neutral-900/10 dark:border-white/10 dark:bg-black/20 dark:focus:ring-white/10"
            value={form.traefik_api_url}
            onChange={(e) => setForm({ ...form, traefik_api_url: e.target.value })}
            placeholder="http://traefik:8080"
          />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="flex flex-col gap-2 text-sm">
            <span className="text-neutral-600 dark:text-neutral-300">Basic auth user (optional)</span>
            <input
              className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
              value={form.traefik_basic_user}
              onChange={(e) => setForm({ ...form, traefik_basic_user: e.target.value })}
            />
          </label>
          <label className="flex flex-col gap-2 text-sm">
            <span className="text-neutral-600 dark:text-neutral-300">Basic auth password</span>
            <input
              className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
              type="password"
              value={form.traefik_basic_password}
              placeholder={s?.has_traefik_basic_password ? '(unchanged)' : ''}
              onChange={(e) => setForm({ ...form, traefik_basic_password: e.target.value })}
            />
          </label>
        </div>

        <hr className="border-neutral-100 dark:border-white/10" />

        {/* ── CrowdSec ── */}
        <div className="flex items-center justify-between">
          <div className="text-sm font-medium">CrowdSec LAPI</div>
          <button
            type="button"
            className="rounded-full border border-neutral-200 px-3 py-1.5 text-xs hover:bg-neutral-50 dark:border-white/10 dark:hover:bg-white/10"
            onClick={() => void runTest('crowdsec')}
          >
            Test connection
          </button>
        </div>
        <StatusBadge result={crowdsecTest} />

        <div className="rounded-2xl border border-blue-500/30 bg-blue-500/5 px-4 py-3 text-xs text-blue-800 dark:text-blue-300">
          Créer la clé API dans le conteneur CrowdSec :<br />
          <code className="mt-1 block font-mono">docker exec crowdsec cscli bouncers add crowdefik-bouncer</code>
        </div>

        <label className="flex flex-col gap-2 text-sm">
          <span className="text-neutral-600 dark:text-neutral-300">CrowdSec LAPI URL</span>
          <input
            className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 text-sm outline-none dark:border-white/10 dark:bg-black/20"
            value={form.crowdsec_lapi_url}
            onChange={(e) => setForm({ ...form, crowdsec_lapi_url: e.target.value })}
            placeholder="http://crowdsec:8080"
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

        {msg ? (
          <div className={`text-sm ${msg === 'Saved' ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600'}`}>{msg}</div>
        ) : null}
        <button
          className="rounded-2xl bg-neutral-900 px-4 py-3 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-950 dark:hover:bg-neutral-200"
          type="submit"
        >
          Save settings
        </button>
      </form>

      {/* ── Docker ── */}
      <div className="flex flex-col gap-4 rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Docker socket</div>
            <div className="mt-0.5 text-xs text-neutral-500">Monté en lecture seule depuis <code>/var/run/docker.sock</code></div>
          </div>
          <button
            type="button"
            className="rounded-full border border-neutral-200 px-3 py-1.5 text-xs hover:bg-neutral-50 dark:border-white/10 dark:hover:bg-white/10"
            onClick={() => void runTest('docker')}
          >
            Test connection
          </button>
        </div>
        <StatusBadge result={dockerTest} />
      </div>
    </div>
  )
}
