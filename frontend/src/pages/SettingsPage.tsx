import { AlertTriangle, CheckCircle, Loader2, Settings } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'

type SettingsOut = {
  traefik_api_url: string
  traefik_basic_user: string | null
  crowdsec_lapi_url: string
  has_traefik_basic_password: boolean
  has_crowdsec_api_key: boolean
  has_abuseipdb_api_key: boolean
  crowdsec_machine_id: string | null
  has_crowdsec_machine_password: boolean
}
type TestResult = {
  ok: boolean; error?: string; version?: string | null; http_routers?: number | null
  active_decisions?: number | null; api_version?: string | null; os?: string | null
  arch?: string | null; test_ip?: string; abuse_score?: number; country?: string
  machine_id?: string
}

function TestBadge({ result }: { result: TestResult | null | 'pending' }) {
  if (!result) return null
  if (result === 'pending')
    return <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1.5 text-xs text-slate-500 dark:bg-slate-700"><Loader2 className="h-3 w-3 animate-spin" />Testing…</span>
  if (result.ok) {
    const details = [
      result.version && `v${result.version}`,
      result.api_version && `API ${result.api_version}`,
      result.http_routers != null && `${result.http_routers} routers`,
      result.active_decisions != null && `${result.active_decisions} decisions`,
      result.abuse_score != null && `score:${result.abuse_score}`,
      result.machine_id && `machine: ${result.machine_id}`,
      result.os && `${result.os}/${result.arch}`,
    ].filter(Boolean).join(' · ')
    return <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-700 dark:text-emerald-400"><CheckCircle className="h-3 w-3" />Connected{details ? ` — ${details}` : ''}</span>
  }
  return <span className="inline-flex items-start gap-1.5 rounded-xl bg-red-500/10 px-3 py-2 text-xs text-red-700 dark:text-red-400"><AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" /><span className="break-all">{result.error ?? 'Failed'}</span></span>
}

type SectionProps = { title: string; description?: string; onTest?: () => void; testResult?: TestResult | null | 'pending'; children: React.ReactNode; note?: React.ReactNode }

function Section({ title, description, onTest, testResult, children, note }: SectionProps) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
      <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4 dark:border-slate-700/50">
        <div>
          <div className="font-semibold text-slate-900 dark:text-white">{title}</div>
          {description && <div className="mt-0.5 text-xs text-slate-500">{description}</div>}
        </div>
        {onTest && (
          <button type="button" onClick={onTest} className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-700 dark:text-slate-200 dark:hover:bg-slate-600">
            Test connection
          </button>
        )}
      </div>
      <div className="space-y-4 p-6">
        {testResult && <TestBadge result={testResult} />}
        {note}
        {children}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5 text-sm">
      <span className="font-medium text-slate-600 dark:text-slate-300">{label}</span>
      {children}
    </label>
  )
}

const inputClass = "rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm outline-none focus:ring-2 focus:ring-violet-500/30 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-200"

export function SettingsPage() {
  const { me, loading } = useAuth()
  const [s, setS] = useState<SettingsOut | null>(null)
  const [form, setForm] = useState({
    traefik_api_url: '', traefik_basic_user: '', traefik_basic_password: '',
    crowdsec_lapi_url: '', crowdsec_api_key: '',
    crowdsec_machine_id: '', crowdsec_machine_password: '',
    abuseipdb_api_key: '',
  })
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [tests, setTests] = useState<Record<string, TestResult | 'pending' | null>>({
    traefik: null, crowdsec: null, 'crowdsec-watcher': null, docker: null, abuseipdb: null,
  })

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
        crowdsec_machine_id: data.crowdsec_machine_id ?? '',
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
      crowdsec_machine_id: form.crowdsec_machine_id || null,
    }
    if (form.traefik_basic_password) payload.traefik_basic_password = form.traefik_basic_password
    if (form.crowdsec_api_key) payload.crowdsec_api_key = form.crowdsec_api_key
    if (form.crowdsec_machine_password) payload.crowdsec_machine_password = form.crowdsec_machine_password
    if (form.abuseipdb_api_key) payload.abuseipdb_api_key = form.abuseipdb_api_key
    const res = await apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify(payload) })
    if (!res.ok) { setMsg({ text: 'Save failed', ok: false }); return }
    const data = (await res.json()) as SettingsOut
    setS(data)
    setForm((f) => ({ ...f, traefik_basic_password: '', crowdsec_api_key: '', crowdsec_machine_password: '', abuseipdb_api_key: '' }))
    setMsg({ text: 'Settings saved', ok: true })
    setTests({ traefik: null, crowdsec: null, 'crowdsec-watcher': null, docker: null, abuseipdb: null })
  }

  async function runTest(name: string) {
    setTests((t) => ({ ...t, [name]: 'pending' }))
    const res = await apiFetch(`/api/test/${name}`)
    const data: TestResult = res.ok ? await res.json() as TestResult : { ok: false, error: `HTTP ${res.status}` }
    setTests((t) => ({ ...t, [name]: data }))
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex items-center gap-3">
        <Settings className="h-6 w-6 text-slate-600 dark:text-slate-300" />
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Settings</h1>
          <p className="mt-0.5 text-sm text-slate-500">Integration URLs and API keys — encrypted in SQLite</p>
        </div>
      </div>

      <form onSubmit={onSave} className="space-y-6">
        {/* Traefik */}
        <Section
          title="Traefik"
          description="Reverse proxy API access"
          onTest={() => void runTest('traefik')}
          testResult={tests.traefik}
          note={
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-xs text-amber-700 dark:text-amber-300">
              <strong>Note:</strong> requires <code>api.insecure: true</code> in traefik.yml for <code>http://traefik:8080</code>,
              or use the HTTPS dashboard URL with basic-auth credentials.
            </div>
          }
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="API URL">
              <input className={inputClass} value={form.traefik_api_url} placeholder="http://traefik:8080" onChange={(e) => setForm({ ...form, traefik_api_url: e.target.value })} />
            </Field>
            <Field label="Basic auth user (optional)">
              <input className={inputClass} value={form.traefik_basic_user} onChange={(e) => setForm({ ...form, traefik_basic_user: e.target.value })} />
            </Field>
          </div>
          <Field label="Basic auth password">
            <input className={inputClass} type="password" value={form.traefik_basic_password} placeholder={s?.has_traefik_basic_password ? '(unchanged)' : 'Enter password'} onChange={(e) => setForm({ ...form, traefik_basic_password: e.target.value })} />
          </Field>
        </Section>

        {/* CrowdSec — Bouncer key */}
        <Section
          title="CrowdSec — Bouncer key"
          description="Required for decisions (ban list) and WAF middleware"
          onTest={() => void runTest('crowdsec')}
          testResult={tests.crowdsec}
          note={
            <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 px-4 py-3 text-xs text-blue-700 dark:text-blue-300 space-y-1">
              <p><strong>Bouncer key</strong> — gives access to <code>/v1/decisions</code> only.</p>
              <p>Create it: <code className="font-mono">docker exec crowdsec cscli bouncers add crowdefik-bouncer</code></p>
            </div>
          }
        >
          <Field label="LAPI URL">
            <input className={inputClass} value={form.crowdsec_lapi_url} placeholder="http://crowdsec:8080" onChange={(e) => setForm({ ...form, crowdsec_lapi_url: e.target.value })} />
          </Field>
          <Field label="Bouncer API Key">
            <input className={inputClass} type="password" value={form.crowdsec_api_key} placeholder={s?.has_crowdsec_api_key ? '(unchanged)' : 'Enter bouncer API key'} onChange={(e) => setForm({ ...form, crowdsec_api_key: e.target.value })} />
          </Field>
        </Section>

        {/* CrowdSec — Machine credentials */}
        <Section
          title="CrowdSec — Machine credentials"
          description="Required for alerts — bouncer keys cannot access /v1/alerts"
          onTest={() => void runTest('crowdsec-watcher')}
          testResult={tests['crowdsec-watcher']}
          note={
            <div className="rounded-xl border border-violet-500/30 bg-violet-500/5 px-4 py-3 text-xs text-violet-700 dark:text-violet-300 space-y-2">
              <p>
                <strong>Why?</strong> CrowdSec LAPI restricts <code>/v1/alerts</code> to <em>watchers</em> (machines), not bouncers.
                Without this, the Alerts page will be empty.
              </p>
              <p>Create a machine and get its password:</p>
              <pre className="rounded-lg bg-violet-500/10 px-3 py-2 font-mono leading-relaxed whitespace-pre-wrap">
{`docker exec crowdsec cscli machines add crowdefik \\
  --password YOUR_PASSWORD --force`}
              </pre>
              <p>Then enter the same <code>crowdefik</code> and <code>YOUR_PASSWORD</code> below.</p>
            </div>
          }
        >
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Machine ID">
              <input
                className={inputClass}
                value={form.crowdsec_machine_id}
                placeholder={s?.crowdsec_machine_id ?? 'e.g. crowdefik'}
                onChange={(e) => setForm({ ...form, crowdsec_machine_id: e.target.value })}
              />
            </Field>
            <Field label="Machine password">
              <input
                className={inputClass}
                type="password"
                value={form.crowdsec_machine_password}
                placeholder={s?.has_crowdsec_machine_password ? '(unchanged)' : 'Enter machine password'}
                onChange={(e) => setForm({ ...form, crowdsec_machine_password: e.target.value })}
              />
            </Field>
          </div>
        </Section>

        {/* AbuseIPDB */}
        <Section
          title="AbuseIPDB"
          description="IP reputation lookup (optional)"
          onTest={() => void runTest('abuseipdb')}
          testResult={tests.abuseipdb}
          note={
            <div className="rounded-xl border border-violet-500/30 bg-violet-500/5 px-4 py-3 text-xs text-violet-700 dark:text-violet-300">
              Free tier: 1,000 checks/day. Get your key at{' '}
              <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noreferrer" className="underline">abuseipdb.com</a>.
              When set, clicking any IP in Alerts/Decisions shows its abuse score.
            </div>
          }
        >
          <Field label="API Key">
            <input className={inputClass} type="password" value={form.abuseipdb_api_key} placeholder={s?.has_abuseipdb_api_key ? '(unchanged)' : 'Enter AbuseIPDB API key'} onChange={(e) => setForm({ ...form, abuseipdb_api_key: e.target.value })} />
          </Field>
        </Section>

        {/* Docker */}
        <Section title="Docker socket" description="/var/run/docker.sock (read-only)" onTest={() => void runTest('docker')} testResult={tests.docker}>
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Used to list containers with <code>traefik.enable=true</code> labels. No configuration needed if the socket is mounted correctly in docker-compose.
          </div>
        </Section>

        {/* Save */}
        {msg && (
          <div className={`rounded-xl px-4 py-3 text-sm ${msg.ok ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400' : 'bg-red-500/10 text-red-700 dark:text-red-400'}`}>
            {msg.text}
          </div>
        )}
        <button
          className="w-full rounded-xl bg-violet-600 px-4 py-3 text-sm font-semibold text-white hover:bg-violet-500 transition"
          type="submit"
        >
          Save all settings
        </button>
      </form>
    </div>
  )
}
