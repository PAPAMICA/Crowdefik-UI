import {
  Activity, AlertTriangle, Box, CheckCircle, ChevronRight,
  Container, Eye, FileText, Loader2, Lock, Save, Settings, Shield,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'

// ── Types ─────────────────────────────────────────────────────────────────────

type SettingsOut = {
  traefik_api_url: string
  traefik_basic_user: string | null
  crowdsec_lapi_url: string
  has_traefik_basic_password: boolean
  has_crowdsec_api_key: boolean
  has_abuseipdb_api_key: boolean
  crowdsec_machine_id: string | null
  has_crowdsec_machine_password: boolean
  crowdsec_container_name: string | null
  traefik_container_name: string | null
  log_path_access: string | null
  log_path_traefik: string | null
  log_path_crowdsec: string | null
}
type TestResult = {
  ok: boolean; error?: string; version?: string | null; http_routers?: number | null
  active_decisions?: number | null; api_version?: string | null; os?: string | null
  arch?: string | null; test_ip?: string; abuse_score?: number; country?: string
  machine_id?: string
}
type TabId = 'traefik' | 'crowdsec' | 'logs' | 'abuseipdb' | 'docker'

// ── Small helpers ─────────────────────────────────────────────────────────────

function TestBadge({ result }: { result: TestResult | null | 'pending' }) {
  if (!result) return null
  if (result === 'pending')
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1.5 text-xs text-slate-500 dark:bg-slate-700">
        <Loader2 className="h-3 w-3 animate-spin" />Testing…
      </span>
    )
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
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
        <CheckCircle className="h-3.5 w-3.5" />
        Connected{details ? ` — ${details}` : ''}
      </span>
    )
  }
  return (
    <span className="inline-flex items-start gap-1.5 rounded-xl bg-red-500/10 px-3 py-2 text-xs text-red-700 dark:text-red-400">
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span className="break-all">{result.error ?? 'Connection failed'}</span>
    </span>
  )
}

function StatusDot({ result }: { result: TestResult | null | 'pending' }) {
  if (!result) return <span className="h-2 w-2 rounded-full bg-slate-300 dark:bg-slate-600" />
  if (result === 'pending') return <Loader2 className="h-3 w-3 animate-spin text-slate-400" />
  if (result.ok) return <span className="h-2 w-2 rounded-full bg-emerald-500" />
  return <span className="h-2 w-2 rounded-full bg-red-500" />
}

const inputClass =
  'w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm outline-none transition focus:border-violet-400 focus:ring-2 focus:ring-violet-500/20 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-200 dark:focus:border-violet-500'

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-sm font-medium text-slate-700 dark:text-slate-300">{label}</label>
      {hint && <p className="text-[11px] text-slate-400 leading-relaxed">{hint}</p>}
      {children}
    </div>
  )
}

function InfoBox({ color, children }: { color: 'blue' | 'violet' | 'amber' | 'emerald'; children: React.ReactNode }) {
  const cls = {
    blue: 'border-blue-500/30 bg-blue-500/5 text-blue-800 dark:text-blue-300',
    violet: 'border-violet-500/30 bg-violet-500/5 text-violet-800 dark:text-violet-300',
    amber: 'border-amber-500/30 bg-amber-500/5 text-amber-800 dark:text-amber-300',
    emerald: 'border-emerald-500/30 bg-emerald-500/5 text-emerald-800 dark:text-emerald-300',
  }[color]
  return (
    <div className={`rounded-xl border px-4 py-3 text-xs leading-relaxed space-y-1 ${cls}`}>
      {children}
    </div>
  )
}

function CodeSnippet({ children }: { children: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg bg-slate-900/90 px-4 py-3 text-[11px] font-mono leading-relaxed text-slate-200 dark:bg-slate-950/60">
      {children}
    </pre>
  )
}

// ── Tab definitions ───────────────────────────────────────────────────────────

const TABS: { id: TabId; label: string; icon: React.ElementType; color: string; testKey?: string }[] = [
  { id: 'traefik',   label: 'Traefik',   icon: Activity, color: 'text-blue-500',   testKey: 'traefik' },
  { id: 'crowdsec',  label: 'CrowdSec',  icon: Shield,   color: 'text-violet-500', testKey: 'crowdsec' },
  { id: 'logs',      label: 'Logs',      icon: FileText, color: 'text-cyan-500' },
  { id: 'abuseipdb', label: 'AbuseIPDB', icon: Eye,      color: 'text-amber-500',  testKey: 'abuseipdb' },
  { id: 'docker',    label: 'Docker',    icon: Box,      color: 'text-slate-500',  testKey: 'docker' },
]

// ── Main page ─────────────────────────────────────────────────────────────────

export function SettingsPage() {
  const { me, loading } = useAuth()
  const [s, setS] = useState<SettingsOut | null>(null)
  const [form, setForm] = useState({
    traefik_api_url: '',
    traefik_basic_user: '',
    traefik_basic_password: '',
    crowdsec_lapi_url: '',
    crowdsec_api_key: '',
    crowdsec_machine_id: '',
    crowdsec_machine_password: '',
    crowdsec_container_name: 'crowdsec',
    traefik_container_name: 'traefik',
    abuseipdb_api_key: '',
    log_path_access: '',
    log_path_traefik: '',
    log_path_crowdsec: '',
  })
  const [tab, setTab] = useState<TabId>('traefik')
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [tests, setTests] = useState<Record<string, TestResult | 'pending' | null>>({
    traefik: null, crowdsec: null, 'crowdsec-watcher': null, docker: null, abuseipdb: null,
  })
  const msgTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

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
        crowdsec_container_name: data.crowdsec_container_name ?? 'crowdsec',
        traefik_container_name: data.traefik_container_name ?? 'traefik',
        log_path_access: data.log_path_access ?? '',
        log_path_traefik: data.log_path_traefik ?? '',
        log_path_crowdsec: data.log_path_crowdsec ?? '',
      }))
    })()
  }, [])

  if (!loading && !me) return <Navigate to="/login" replace />
  if (!loading && me && !me.is_superuser) return <Navigate to="/" replace />

  const f = form
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((prev) => ({ ...prev, [k]: e.target.value }))

  async function onSave(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setMsg(null)
    const payload: Record<string, unknown> = {
      traefik_api_url: f.traefik_api_url,
      traefik_basic_user: f.traefik_basic_user || null,
      crowdsec_lapi_url: f.crowdsec_lapi_url,
      crowdsec_machine_id: f.crowdsec_machine_id || null,
      crowdsec_container_name: f.crowdsec_container_name || 'crowdsec',
      traefik_container_name: f.traefik_container_name || 'traefik',
      log_path_access: f.log_path_access || null,
      log_path_traefik: f.log_path_traefik || null,
      log_path_crowdsec: f.log_path_crowdsec || null,
    }
    if (f.traefik_basic_password) payload.traefik_basic_password = f.traefik_basic_password
    if (f.crowdsec_api_key) payload.crowdsec_api_key = f.crowdsec_api_key
    if (f.crowdsec_machine_password) payload.crowdsec_machine_password = f.crowdsec_machine_password
    if (f.abuseipdb_api_key) payload.abuseipdb_api_key = f.abuseipdb_api_key
    try {
      const res = await apiFetch('/api/settings', { method: 'PUT', body: JSON.stringify(payload) })
      if (!res.ok) { setMsg({ text: 'Save failed', ok: false }); return }
      const data = (await res.json()) as SettingsOut
      setS(data)
      setForm((prev) => ({ ...prev, traefik_basic_password: '', crowdsec_api_key: '', crowdsec_machine_password: '', abuseipdb_api_key: '' }))
      setMsg({ text: 'Settings saved successfully', ok: true })
      setTests({ traefik: null, crowdsec: null, 'crowdsec-watcher': null, docker: null, abuseipdb: null })
      if (msgTimer.current) clearTimeout(msgTimer.current)
      msgTimer.current = setTimeout(() => setMsg(null), 4000)
    } finally {
      setSaving(false)
    }
  }

  async function runTest(name: string) {
    setTests((t) => ({ ...t, [name]: 'pending' }))
    const res = await apiFetch(`/api/test/${name}`)
    const data: TestResult = res.ok ? await res.json() as TestResult : { ok: false, error: `HTTP ${res.status}` }
    setTests((t) => ({ ...t, [name]: data }))
  }

  const tabDef = TABS.find((t) => t.id === tab)!

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="rounded-2xl bg-violet-500/10 p-2.5">
          <Settings className="h-5 w-5 text-violet-500" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Settings</h1>
          <p className="text-sm text-slate-500">Integration URLs, API keys and container names — encrypted at rest</p>
        </div>
      </div>

      <form onSubmit={onSave} className="flex gap-6">
        {/* ── Left navigation ─────────────────────────────────────────── */}
        <nav className="flex w-44 shrink-0 flex-col gap-1">
          {TABS.map(({ id, label, icon: Icon, color, testKey }) => {
            const active = id === tab
            return (
              <button
                key={id}
                type="button"
                onClick={() => setTab(id)}
                className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all ${
                  active
                    ? 'bg-violet-500/10 text-violet-700 dark:bg-violet-500/15 dark:text-violet-300'
                    : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'
                }`}
              >
                <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-violet-500' : color}`} />
                <span className="flex-1 text-left">{label}</span>
                {testKey && <StatusDot result={tests[testKey] ?? null} />}
                {active && <ChevronRight className="h-3.5 w-3.5 text-violet-400" />}
              </button>
            )
          })}
        </nav>

        {/* ── Right panel ─────────────────────────────────────────────── */}
        <div className="flex-1 space-y-5">
          {/* Tab header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <tabDef.icon className={`h-5 w-5 ${tabDef.color}`} />
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{tabDef.label}</h2>
            </div>
            {tabDef.testKey && (
              <button
                type="button"
                onClick={() => void runTest(tabDef.testKey!)}
                disabled={tests[tabDef.testKey] === 'pending'}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-xs font-medium transition hover:bg-slate-50 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700"
              >
                {tests[tabDef.testKey] === 'pending'
                  ? <Loader2 className="h-3 w-3 animate-spin" />
                  : <Activity className="h-3 w-3" />}
                Test connection
              </button>
            )}
            {/* CrowdSec tab has two test buttons */}
            {tab === 'crowdsec' && (
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => void runTest('crowdsec')}
                  disabled={tests.crowdsec === 'pending'}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium transition hover:bg-slate-50 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                >
                  {tests.crowdsec === 'pending' ? <Loader2 className="h-3 w-3 animate-spin" /> : <Shield className="h-3 w-3" />}
                  Test bouncer
                </button>
                <button
                  type="button"
                  onClick={() => void runTest('crowdsec-watcher')}
                  disabled={tests['crowdsec-watcher'] === 'pending'}
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium transition hover:bg-slate-50 disabled:opacity-60 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
                >
                  {tests['crowdsec-watcher'] === 'pending' ? <Loader2 className="h-3 w-3 animate-spin" /> : <Eye className="h-3 w-3" />}
                  Test watcher
                </button>
              </div>
            )}
          </div>

          {/* Tab content */}
          <div className="rounded-2xl border border-slate-200 bg-white p-6 dark:border-slate-700/50 dark:bg-slate-800/60">

            {/* ── TRAEFIK ── */}
            {tab === 'traefik' && (
              <div className="space-y-5">
                <TestBadge result={tests.traefik} />
                <InfoBox color="blue">
                  <p>Requires <code>api.insecure: true</code> in <code>traefik.yml</code> for <code>http://traefik:8080</code>, or use the HTTPS dashboard URL with basic-auth credentials.</p>
                </InfoBox>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="API URL">
                    <input className={inputClass} value={f.traefik_api_url} placeholder="http://traefik:8080" onChange={set('traefik_api_url')} />
                  </Field>
                  <Field label="Basic auth username" hint="Optional — only needed if the dashboard is protected">
                    <input className={inputClass} value={f.traefik_basic_user} onChange={set('traefik_basic_user')} />
                  </Field>
                </div>
                <Field label="Basic auth password">
                  <input className={inputClass} type="password" value={f.traefik_basic_password}
                    placeholder={s?.has_traefik_basic_password ? '(unchanged)' : 'Enter password'}
                    onChange={set('traefik_basic_password')} />
                </Field>
              </div>
            )}

            {/* ── CROWDSEC ── */}
            {tab === 'crowdsec' && (
              <div className="space-y-6">
                {/* Bouncer section */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-slate-100 pb-3 dark:border-slate-700/50">
                    <Lock className="h-4 w-4 text-violet-500" />
                    <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Bouncer key</span>
                    <StatusDot result={tests.crowdsec} />
                  </div>
                  <TestBadge result={tests.crowdsec} />
                  <InfoBox color="violet">
                    <p><strong>Bouncer key</strong> — access to <code>/v1/decisions</code> and WAF middleware.</p>
                    <CodeSnippet>docker exec crowdsec cscli bouncers add crowdefik-bouncer</CodeSnippet>
                  </InfoBox>
                  <Field label="LAPI URL">
                    <input className={inputClass} value={f.crowdsec_lapi_url} placeholder="http://crowdsec:8080" onChange={set('crowdsec_lapi_url')} />
                  </Field>
                  <Field label="Bouncer API key">
                    <input className={inputClass} type="password" value={f.crowdsec_api_key}
                      placeholder={s?.has_crowdsec_api_key ? '(unchanged)' : 'Enter bouncer API key'}
                      onChange={set('crowdsec_api_key')} />
                  </Field>
                </div>

                {/* Watcher / machine section */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-slate-100 pb-3 dark:border-slate-700/50">
                    <Eye className="h-4 w-4 text-purple-500" />
                    <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Machine credentials</span>
                    <StatusDot result={tests['crowdsec-watcher']} />
                  </div>
                  <TestBadge result={tests['crowdsec-watcher']} />
                  <InfoBox color="violet">
                    <p><strong>Required for Alerts</strong> — <code>/v1/alerts</code> is restricted to <em>watchers</em>, not bouncers.</p>
                    <CodeSnippet>{`docker exec crowdsec cscli machines add crowdefik \\\n  --password YOUR_PASSWORD --force`}</CodeSnippet>
                  </InfoBox>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Machine ID">
                      <input className={inputClass} value={f.crowdsec_machine_id}
                        placeholder={s?.crowdsec_machine_id ?? 'e.g. crowdefik'}
                        onChange={set('crowdsec_machine_id')} />
                    </Field>
                    <Field label="Machine password">
                      <input className={inputClass} type="password" value={f.crowdsec_machine_password}
                        placeholder={s?.has_crowdsec_machine_password ? '(unchanged)' : 'Enter machine password'}
                        onChange={set('crowdsec_machine_password')} />
                    </Field>
                  </div>
                </div>
              </div>
            )}

            {/* ── LOGS ── */}
            {tab === 'logs' && (
              <div className="space-y-6">
                <InfoBox color="emerald">
                  <p>Log paths set here take priority over environment variables. Leave blank to fall back to the env var, then to <code>docker exec</code>.</p>
                </InfoBox>

                {/* Traefik access log */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-slate-100 pb-3 dark:border-slate-700/50">
                    <Activity className="h-4 w-4 text-blue-500" />
                    <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Traefik access log (JSON)</span>
                  </div>
                  <Field
                    label="Access log path"
                    hint="Path to Traefik JSON access log inside the container (e.g. /traefik-logs/access.log)"
                  >
                    <input
                      className={inputClass}
                      value={f.log_path_access}
                      placeholder="/traefik-logs/access.log"
                      onChange={set('log_path_access')}
                    />
                  </Field>
                  <Field
                    label="Traefik app log path"
                    hint="Path to the Traefik operational log (e.g. /traefik-logs/traefik.log)"
                  >
                    <input
                      className={inputClass}
                      value={f.log_path_traefik}
                      placeholder="/traefik-logs/traefik.log"
                      onChange={set('log_path_traefik')}
                    />
                  </Field>
                  <Field
                    label="Container name"
                    hint="Fallback: used to read logs via docker exec when no path is set above"
                  >
                    <input className={inputClass} value={f.traefik_container_name} placeholder="traefik" onChange={set('traefik_container_name')} />
                  </Field>
                </div>

                {/* CrowdSec log */}
                <div className="space-y-4">
                  <div className="flex items-center gap-2 border-b border-slate-100 pb-3 dark:border-slate-700/50">
                    <Shield className="h-4 w-4 text-violet-500" />
                    <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">CrowdSec log</span>
                  </div>
                  <Field
                    label="CrowdSec log path"
                    hint="Path to crowdsec.log inside the container (e.g. /var/log/crowdsec/crowdsec.log)"
                  >
                    <input
                      className={inputClass}
                      value={f.log_path_crowdsec}
                      placeholder="/var/log/crowdsec/crowdsec.log"
                      onChange={set('log_path_crowdsec')}
                    />
                  </Field>
                  <Field
                    label="Container name"
                    hint="Used for cscli commands and as fallback to read logs via docker exec"
                  >
                    <input className={inputClass} value={f.crowdsec_container_name} placeholder="crowdsec" onChange={set('crowdsec_container_name')} />
                  </Field>
                </div>
              </div>
            )}

            {/* ── ABUSEIPDB ── */}
            {tab === 'abuseipdb' && (
              <div className="space-y-5">
                <TestBadge result={tests.abuseipdb} />
                <InfoBox color="amber">
                  <p>IP reputation lookup — free tier: 1,000 checks/day.</p>
                  <p>Get your key at <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noreferrer" className="underline font-medium">abuseipdb.com/account/api</a>. When configured, clicking any IP in Alerts or Decisions shows its abuse score.</p>
                </InfoBox>
                <Field label="API Key">
                  <input className={inputClass} type="password" value={f.abuseipdb_api_key}
                    placeholder={s?.has_abuseipdb_api_key ? '(unchanged)' : 'Enter AbuseIPDB API key'}
                    onChange={set('abuseipdb_api_key')} />
                </Field>
              </div>
            )}

            {/* ── DOCKER ── */}
            {tab === 'docker' && (
              <div className="space-y-5">
                <TestBadge result={tests.docker} />
                <div className="flex items-start gap-3 rounded-xl border border-slate-200 bg-slate-50/50 p-4 dark:border-slate-700/50 dark:bg-slate-900/30">
                  <Container className="mt-0.5 h-5 w-5 shrink-0 text-slate-500" />
                  <div className="space-y-1 text-sm text-slate-600 dark:text-slate-400">
                    <p className="font-medium text-slate-700 dark:text-slate-300">Docker socket — <code>/var/run/docker.sock</code></p>
                    <p>Used to list containers with <code>traefik.enable=true</code> labels and to run <code>cscli</code> commands via <code>docker exec</code>.</p>
                    <p>No configuration needed — the socket must be mounted read-only in your docker-compose:</p>
                  </div>
                </div>
                <CodeSnippet>{`volumes:\n  - /var/run/docker.sock:/var/run/docker.sock:ro`}</CodeSnippet>
              </div>
            )}
          </div>

          {/* Save bar */}
          <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-white px-5 py-4 dark:border-slate-700/50 dark:bg-slate-800/60">
            <div>
              {msg && (
                <span className={`text-sm font-medium ${msg.ok ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                  {msg.ok ? <CheckCircle className="mr-1.5 inline h-4 w-4" /> : <AlertTriangle className="mr-1.5 inline h-4 w-4" />}
                  {msg.text}
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-violet-500 disabled:opacity-60"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              {saving ? 'Saving…' : 'Save settings'}
            </button>
          </div>
        </div>
      </form>
    </div>
  )
}
