import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth'
import { useTheme } from '../theme'
import { apiFetch } from '../api'

const linkClass = ({ isActive }: { isActive: boolean }) =>
  [
    'rounded-full px-4 py-2 text-sm transition',
    isActive
      ? 'bg-black/10 text-neutral-900 dark:bg-white/10 dark:text-white'
      : 'text-neutral-600 hover:text-neutral-900 dark:text-neutral-300 dark:hover:text-white',
  ].join(' ')

export function Layout() {
  const { me, logout } = useAuth()
  const { mode, setMode, effective } = useTheme()

  return (
    <div className="min-h-dvh bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-50">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-5 py-8">
        <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-baseline gap-3">
            <div className="text-lg font-semibold tracking-tight">Crowdefik</div>
            <div className="text-xs text-neutral-500 dark:text-neutral-400">Traefik + CrowdSec</div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <nav className="flex flex-wrap gap-1 rounded-full border border-neutral-200/70 bg-white/60 p-1 backdrop-blur dark:border-white/10 dark:bg-white/5">
              <NavLink className={linkClass} to="/">
                Dashboard
              </NavLink>
              <NavLink className={linkClass} to="/routers">
                Services
              </NavLink>
              <NavLink className={linkClass} to="/alerts">
                Alerts
              </NavLink>
              <NavLink className={linkClass} to="/decisions">
                Decisions
              </NavLink>
              {me?.is_superuser ? (
                <>
                  <NavLink className={linkClass} to="/settings">
                    Settings
                  </NavLink>
                  <NavLink className={linkClass} to="/admin">
                    Admin
                  </NavLink>
                </>
              ) : null}
            </nav>
            <div className="flex items-center gap-2">
              <select
                className="rounded-full border border-neutral-200 bg-white px-3 py-2 text-xs dark:border-white/10 dark:bg-white/5"
                value={mode}
                onChange={(e) => setMode(e.target.value as typeof mode)}
                aria-label="Theme"
              >
                <option value="system">System ({effective})</option>
                <option value="light">Light</option>
                <option value="dark">Dark</option>
              </select>
              <button
                className="rounded-full border border-neutral-200 bg-white px-3 py-2 text-xs hover:bg-neutral-100 dark:border-white/10 dark:bg-white/5 dark:hover:bg-white/10"
                type="button"
                onClick={async () => {
                  await apiFetch('/api/cache/refresh', { method: 'POST' })
                  window.location.reload()
                }}
              >
                Refresh cache
              </button>
              <button
                className="rounded-full border border-neutral-200 bg-white px-3 py-2 text-xs hover:bg-neutral-100 dark:border-white/10 dark:bg-white/5 dark:hover:bg-white/10"
                type="button"
                onClick={() => logout()}
              >
                Logout
              </button>
            </div>
          </div>
        </header>
        <main>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
