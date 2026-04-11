import { useEffect, useMemo, useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { apiFetch } from '../api'

type UserRow = { id: number; username: string; is_superuser: boolean }

export function AdminPage() {
  const { me, loading } = useAuth()
  const [users, setUsers] = useState<UserRow[]>([])
  const [selected, setSelected] = useState<number | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const [newUser, setNewUser] = useState({ username: '', password: '', is_superuser: false })
  const [scopeName, setScopeName] = useState('')

  async function reloadUsers() {
    const res = await apiFetch('/api/admin/users')
    if (res.ok) setUsers((await res.json()) as UserRow[])
  }

  async function reloadScopes(userId: number) {
    const res = await apiFetch(`/api/admin/users/${userId}/scopes`)
    if (res.ok) setScopes((await res.json()) as string[])
  }

  useEffect(() => {
    void reloadUsers()
  }, [])

  useEffect(() => {
    if (selected) void reloadScopes(selected)
    else setScopes([])
  }, [selected])

  const selectedUser = useMemo(() => users.find((u) => u.id === selected) ?? null, [users, selected])

  if (!loading && !me) return <Navigate to="/login" replace />
  if (!loading && me && !me.is_superuser) return <Navigate to="/" replace />

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Administration</h1>
        <p className="mt-2 max-w-3xl text-sm text-neutral-600 dark:text-neutral-300">
          Create users and assign router scopes (exact Traefik router name, e.g. <span className="font-mono">myrouter@docker</span>).
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5">
          <div className="text-sm font-medium">Users</div>
          <div className="mt-4 space-y-2">
            {users.map((u) => (
              <button
                key={u.id}
                type="button"
                className={[
                  'flex w-full items-center justify-between rounded-2xl border px-3 py-3 text-left text-sm',
                  selected === u.id ? 'border-neutral-900/20 bg-neutral-50 dark:border-white/20 dark:bg-white/10' : 'border-neutral-100 hover:bg-neutral-50 dark:border-white/10 dark:hover:bg-white/5',
                ].join(' ')}
                onClick={() => setSelected(u.id)}
              >
                <span className="font-medium">{u.username}</span>
                <span className="text-xs text-neutral-500">{u.is_superuser ? 'admin' : 'scoped'}</span>
              </button>
            ))}
          </div>

          <div className="mt-6 border-t border-neutral-100 pt-6 dark:border-white/10">
            <div className="text-sm font-medium">Create user</div>
            <form
              className="mt-3 flex flex-col gap-3"
              onSubmit={async (e) => {
                e.preventDefault()
                const res = await apiFetch('/api/admin/users', {
                  method: 'POST',
                  body: JSON.stringify(newUser),
                })
                if (!res.ok) {
                  alert(await res.text())
                  return
                }
                setNewUser({ username: '', password: '', is_superuser: false })
                await reloadUsers()
              }}
            >
              <input
                className="rounded-2xl border border-neutral-200 bg-neutral-50 px-3 py-2 text-sm dark:border-white/10 dark:bg-black/20"
                placeholder="username"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              />
              <input
                className="rounded-2xl border border-neutral-200 bg-neutral-50 px-3 py-2 text-sm dark:border-white/10 dark:bg-black/20"
                placeholder="password"
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              />
              <label className="flex items-center gap-2 text-sm text-neutral-600 dark:text-neutral-300">
                <input type="checkbox" checked={newUser.is_superuser} onChange={(e) => setNewUser({ ...newUser, is_superuser: e.target.checked })} />
                Superuser
              </label>
              <button className="rounded-2xl bg-neutral-900 px-3 py-2 text-sm text-white dark:bg-white dark:text-neutral-950" type="submit">
                Create
              </button>
            </form>
          </div>
        </div>

        <div className="rounded-3xl border border-neutral-200 bg-white p-6 dark:border-white/10 dark:bg-white/5">
          <div className="text-sm font-medium">Router scopes</div>
          {!selected ? (
            <div className="mt-4 text-sm text-neutral-500">Select a user</div>
          ) : selectedUser?.is_superuser ? (
            <div className="mt-4 text-sm text-neutral-500">Superusers have access to everything.</div>
          ) : (
            <div className="mt-4 flex flex-col gap-3">
              <div className="space-y-2">
                {scopes.map((s) => (
                  <div key={s} className="flex items-center justify-between rounded-2xl border border-neutral-100 px-3 py-2 text-sm dark:border-white/10">
                    <span className="font-mono text-xs">{s}</span>
                    <button
                      type="button"
                      className="text-xs text-red-600"
                      onClick={async () => {
                        const res = await apiFetch(`/api/admin/users/${selected}/scopes/${encodeURIComponent(s)}`, { method: 'DELETE' })
                        if (res.ok) await reloadScopes(selected)
                      }}
                    >
                      Remove
                    </button>
                  </div>
                ))}
                {!scopes.length ? <div className="text-sm text-neutral-500">No scopes</div> : null}
              </div>
              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-2xl border border-neutral-200 bg-neutral-50 px-3 py-2 text-sm dark:border-white/10 dark:bg-black/20"
                  placeholder="router@docker"
                  value={scopeName}
                  onChange={(e) => setScopeName(e.target.value)}
                />
                <button
                  type="button"
                  className="rounded-2xl bg-neutral-900 px-4 py-2 text-sm text-white dark:bg-white dark:text-neutral-950"
                  onClick={async () => {
                    if (!selected) return
                    const res = await apiFetch(`/api/admin/users/${selected}/scopes`, {
                      method: 'POST',
                      body: JSON.stringify({ router_name: scopeName }),
                    })
                    if (!res.ok) {
                      alert(await res.text())
                      return
                    }
                    setScopeName('')
                    await reloadScopes(selected)
                  }}
                >
                  Add
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
