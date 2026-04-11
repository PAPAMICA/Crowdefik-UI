import { useState } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'

export function LoginPage() {
  const { me, login, loading } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  if (!loading && me) return <Navigate to="/" replace />

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      await login(username, password)
    } catch {
      setError('Invalid credentials')
    }
  }

  return (
    <div className="mx-auto flex min-h-dvh max-w-md flex-col justify-center px-5">
      <div className="rounded-3xl border border-neutral-200 bg-white p-8 shadow-sm dark:border-white/10 dark:bg-white/5">
        <div className="mb-6 text-center">
          <div className="text-xl font-semibold tracking-tight">Crowdefik</div>
          <div className="mt-1 text-sm text-neutral-500">Sign in</div>
        </div>
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <label className="flex flex-col gap-2 text-sm">
            <span className="text-neutral-600 dark:text-neutral-300">Username</span>
            <input
              className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 outline-none focus:ring-2 focus:ring-neutral-900/10 dark:border-white/10 dark:bg-black/20 dark:focus:ring-white/10"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </label>
          <label className="flex flex-col gap-2 text-sm">
            <span className="text-neutral-600 dark:text-neutral-300">Password</span>
            <input
              className="rounded-2xl border border-neutral-200 bg-neutral-50 px-4 py-3 outline-none focus:ring-2 focus:ring-neutral-900/10 dark:border-white/10 dark:bg-black/20 dark:focus:ring-white/10"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          {error ? <div className="text-sm text-red-600">{error}</div> : null}
          <button
            className="mt-2 rounded-2xl bg-neutral-900 px-4 py-3 text-sm font-medium text-white hover:bg-neutral-800 dark:bg-white dark:text-neutral-950 dark:hover:bg-neutral-200"
            type="submit"
          >
            Continue
          </button>
        </form>
      </div>
    </div>
  )
}
