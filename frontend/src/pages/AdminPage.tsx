import { Plus, Trash2, Users } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { apiFetch } from '../api'
import { useAuth } from '../auth'
import { useToast } from '../components/Toast'

type UserRow = { id: number; username: string; is_superuser: boolean }

export function AdminPage() {
  const { me, loading } = useAuth()
  const { addToast } = useToast()
  const [users, setUsers] = useState<UserRow[]>([])
  const [selected, setSelected] = useState<number | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const [newUser, setNewUser] = useState({ username: '', password: '', is_superuser: false })
  const [scopeName, setScopeName] = useState('')

  async function reloadUsers() {
    const res = await apiFetch('/api/admin/users')
    if (res.ok) setUsers((await res.json()) as UserRow[])
  }

  async function reloadScopes(uid: number) {
    const res = await apiFetch(`/api/admin/users/${uid}/scopes`)
    if (res.ok) setScopes((await res.json()) as string[])
  }

  useEffect(() => { void reloadUsers() }, [])
  useEffect(() => { if (selected) void reloadScopes(selected); else setScopes([]) }, [selected])

  const selectedUser = useMemo(() => users.find((u) => u.id === selected) ?? null, [users, selected])

  if (!loading && !me) return <Navigate to="/login" replace />
  if (!loading && me && !me.is_superuser) return <Navigate to="/" replace />

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Users className="h-6 w-6 text-indigo-500" />
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">User management</h1>
          <p className="mt-0.5 text-sm text-slate-500">Assign router scopes to restrict user access</p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Users list + create */}
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <div className="font-semibold text-slate-900 dark:text-white">Users</div>
          </div>
          <div className="p-4 space-y-1">
            {users.map((u) => (
              <button
                key={u.id}
                type="button"
                className={[
                  'flex w-full items-center justify-between rounded-xl px-4 py-3 text-left text-sm transition',
                  selected === u.id
                    ? 'bg-violet-500/10 text-violet-700 dark:text-violet-300'
                    : 'hover:bg-slate-50 dark:hover:bg-white/5 text-slate-700 dark:text-slate-300',
                ].join(' ')}
                onClick={() => setSelected(u.id === selected ? null : u.id)}
              >
                <div className="flex items-center gap-2.5">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-violet-500 to-indigo-600 text-xs font-bold text-white">
                    {u.username[0].toUpperCase()}
                  </div>
                  <span className="font-medium">{u.username}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${u.is_superuser ? 'bg-violet-500/10 text-violet-600 dark:text-violet-400' : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400'}`}>
                    {u.is_superuser ? 'admin' : 'user'}
                  </span>
                  {u.id !== me?.id && (
                    <button
                      type="button"
                      className="text-slate-300 hover:text-red-500 transition dark:text-slate-600"
                      onClick={async (e) => {
                        e.stopPropagation()
                        if (!confirm(`Delete ${u.username}?`)) return
                        await apiFetch(`/api/admin/users/${u.id}`, { method: 'DELETE' })
                        if (selected === u.id) setSelected(null)
                        await reloadUsers()
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </button>
            ))}
          </div>

          {/* Create user form */}
          <div className="border-t border-slate-100 p-4 dark:border-slate-700/50">
            <div className="mb-3 text-xs font-medium uppercase tracking-wide text-slate-400">New user</div>
            <form
              className="space-y-2"
              onSubmit={async (e) => {
                e.preventDefault()
                const res = await apiFetch('/api/admin/users', { method: 'POST', body: JSON.stringify(newUser) })
                if (!res.ok) { const err = await res.json().catch(() => ({ detail: 'Error' })); addToast(err.detail ?? 'Failed to create user', 'error'); return }
                setNewUser({ username: '', password: '', is_superuser: false })
                await reloadUsers()
              }}
            >
              <input className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900/50 dark:text-slate-200" placeholder="Username" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
              <input className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900/50 dark:text-slate-200" type="password" placeholder="Password (min. 8 chars)" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
              <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                <input type="checkbox" className="rounded" checked={newUser.is_superuser} onChange={(e) => setNewUser({ ...newUser, is_superuser: e.target.checked })} />
                Superuser (full access)
              </label>
              <button className="inline-flex w-full items-center justify-center gap-1.5 rounded-xl bg-violet-600 py-2 text-xs font-semibold text-white hover:bg-violet-500" type="submit">
                <Plus className="h-3.5 w-3.5" /> Create user
              </button>
            </form>
          </div>
        </div>

        {/* Scopes */}
        <div className="rounded-2xl border border-slate-200 bg-white dark:border-slate-700/50 dark:bg-slate-800/60">
          <div className="border-b border-slate-100 px-5 py-4 dark:border-slate-700/50">
            <div className="font-semibold text-slate-900 dark:text-white">
              Router scopes {selectedUser && <span className="ml-1 text-violet-500">— {selectedUser.username}</span>}
            </div>
          </div>
          <div className="p-4">
            {!selected ? (
              <div className="py-8 text-center text-sm text-slate-400">Select a user to manage their scopes</div>
            ) : selectedUser?.is_superuser ? (
              <div className="py-8 text-center text-sm text-slate-400">Superusers have access to all routers</div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-1.5">
                  {scopes.map((s) => (
                    <div key={s} className="flex items-center justify-between rounded-xl bg-slate-50 px-3 py-2.5 dark:bg-slate-700/40">
                      <span className="font-mono text-xs text-slate-700 dark:text-slate-300">{s}</span>
                      <button
                        type="button"
                        className="text-slate-400 hover:text-red-500 transition"
                        onClick={async () => {
                          await apiFetch(`/api/admin/users/${selected}/scopes/${encodeURIComponent(s)}`, { method: 'DELETE' })
                          await reloadScopes(selected)
                        }}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                  {!scopes.length && <div className="text-sm text-slate-400 py-2">No scopes — this user sees nothing</div>}
                </div>
                <div className="flex gap-2 pt-1">
                  <input
                    className="flex-1 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900/50 dark:text-slate-200"
                    placeholder="routername@docker"
                    value={scopeName}
                    onChange={(e) => setScopeName(e.target.value)}
                  />
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 rounded-xl bg-violet-600 px-3 py-2 text-xs font-semibold text-white hover:bg-violet-500"
                    onClick={async () => {
                      if (!selected || !scopeName.trim()) return
                      const res = await apiFetch(`/api/admin/users/${selected}/scopes`, { method: 'POST', body: JSON.stringify({ router_name: scopeName.trim() }) })
                      if (!res.ok) { const err = await res.json().catch(() => ({ detail: 'Error' })); addToast(err.detail ?? 'Failed to add scope', 'error'); return }
                      setScopeName('')
                      await reloadScopes(selected)
                    }}
                  >
                    <Plus className="h-3.5 w-3.5" /> Add
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
