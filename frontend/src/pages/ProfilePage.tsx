import { Eye, EyeOff, KeyRound, Save, Shield, User } from 'lucide-react'
import { useState } from 'react'
import { apiFetch } from '../api'
import { useAuth } from '../auth'

export function ProfilePage() {
  const { me } = useAuth()
  const [current, setCurrent] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setMsg(null)
    if (newPwd !== confirm) {
      setMsg({ text: 'New passwords do not match', ok: false })
      return
    }
    if (newPwd.length < 8) {
      setMsg({ text: 'Password must be at least 8 characters', ok: false })
      return
    }
    setSaving(true)
    try {
      const res = await apiFetch('/api/profile/password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: newPwd }),
      })
      if (res.ok) {
        setMsg({ text: 'Password changed successfully', ok: true })
        setCurrent('')
        setNewPwd('')
        setConfirm('')
      } else {
        const err = await res.json().catch(() => ({}))
        setMsg({ text: (err as { detail?: string }).detail ?? 'Failed to change password', ok: false })
      }
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Profile</h1>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Manage your account</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Account info card */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="flex flex-col items-center gap-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-violet-500 to-indigo-600 text-2xl font-bold text-white shadow-lg">
              {me?.username?.[0]?.toUpperCase()}
            </div>
            <div className="text-center">
              <div className="text-lg font-semibold text-slate-900 dark:text-white">{me?.username}</div>
              <div className="mt-0.5 flex items-center justify-center gap-1.5 text-sm text-slate-500 dark:text-slate-400">
                {me?.is_superuser
                  ? <><Shield className="h-3.5 w-3.5 text-violet-500" /> Administrator</>
                  : <><User className="h-3.5 w-3.5 text-blue-500" /> Standard user</>}
              </div>
            </div>
          </div>
        </div>

        {/* Change password card */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 dark:border-slate-700/50 dark:bg-slate-800/60 lg:col-span-2">
          <div className="mb-5 flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-violet-500" />
            <h2 className="text-base font-semibold text-slate-900 dark:text-white">Change password</h2>
          </div>

          <form onSubmit={(e) => { void handleSubmit(e) }} className="space-y-4">
            {/* Current password */}
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Current password</label>
              <div className="relative">
                <input
                  type={showCurrent ? 'text' : 'password'}
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  required
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 pr-10 text-sm outline-none focus:border-violet-400 focus:ring-2 focus:ring-violet-500/20 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-100"
                  placeholder="Enter current password"
                />
                <button type="button" onClick={() => setShowCurrent(!showCurrent)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                  {showCurrent ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* New password */}
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">New password</label>
              <div className="relative">
                <input
                  type={showNew ? 'text' : 'password'}
                  value={newPwd}
                  onChange={(e) => setNewPwd(e.target.value)}
                  required
                  minLength={8}
                  className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 pr-10 text-sm outline-none focus:border-violet-400 focus:ring-2 focus:ring-violet-500/20 dark:border-slate-700 dark:bg-slate-900/60 dark:text-slate-100"
                  placeholder="At least 8 characters"
                />
                <button type="button" onClick={() => setShowNew(!showNew)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                  {showNew ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Confirm password */}
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-600 dark:text-slate-400">Confirm new password</label>
              <input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                className={`w-full rounded-xl border px-4 py-2.5 text-sm outline-none focus:ring-2 focus:ring-violet-500/20 dark:bg-slate-900/60 dark:text-slate-100 ${confirm && confirm !== newPwd ? 'border-red-400 bg-red-50 dark:border-red-500' : 'border-slate-200 bg-slate-50 focus:border-violet-400 dark:border-slate-700'}`}
                placeholder="Repeat new password"
              />
              {confirm && confirm !== newPwd && (
                <p className="mt-1 text-xs text-red-500">Passwords do not match</p>
              )}
            </div>

            {msg && (
              <div className={`rounded-xl px-4 py-2.5 text-sm ${msg.ok ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400' : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-400'}`}>
                {msg.text}
              </div>
            )}

            <button
              type="submit"
              disabled={saving || !current || !newPwd || !confirm}
              className="inline-flex items-center gap-2 rounded-xl bg-violet-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-violet-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Save className="h-4 w-4" />
              {saving ? 'Saving…' : 'Change password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
