import {
  Activity,
  ChevronLeft,
  ChevronRight,
  GanttChartSquare,
  LayoutDashboard,
  LogOut,
  Settings,
  Shield,
  ShieldAlert,
  Users,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { useAuth } from '../auth'
import { useTheme } from '../theme'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', color: 'text-violet-500' },
  { to: '/routers', icon: GanttChartSquare, label: 'Services', color: 'text-blue-500' },
  { to: '/alerts', icon: ShieldAlert, label: 'Alerts', color: 'text-amber-500' },
  { to: '/decisions', icon: Shield, label: 'Decisions', color: 'text-red-500' },
]

const ADMIN_NAV = [
  { to: '/settings', icon: Settings, label: 'Settings', color: 'text-slate-400' },
  { to: '/admin', icon: Users, label: 'Admin', color: 'text-indigo-500' },
]

type Props = { collapsed: boolean; onToggle: () => void }

export function Sidebar({ collapsed, onToggle }: Props) {
  const { me, logout } = useAuth()
  const { mode, setMode } = useTheme()

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    [
      'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-150',
      collapsed ? 'justify-center' : '',
      isActive
        ? 'bg-white/10 text-white shadow-sm'
        : 'text-slate-300 hover:bg-white/5 hover:text-white',
    ].join(' ')

  return (
    <aside
      className={[
        'flex h-dvh flex-col bg-slate-900 transition-all duration-200',
        collapsed ? 'w-16' : 'w-60',
      ].join(' ')}
    >
      {/* Logo */}
      <div className={['flex items-center border-b border-white/10 px-4 py-5', collapsed ? 'justify-center' : 'gap-3'].join(' ')}>
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-violet-500 to-indigo-600 shadow-lg">
          <Activity className="h-4 w-4 text-white" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="text-sm font-semibold text-white">Crowdefik</div>
            <div className="text-[10px] text-slate-400">Traefik · CrowdSec</div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-3 py-4">
        <div className="space-y-1">
          {NAV.map(({ to, icon: Icon, label, color }) => (
            <NavLink key={to} to={to} end={to === '/'} className={linkClass} title={collapsed ? label : undefined}>
              <Icon className={`h-4 w-4 shrink-0 ${color}`} />
              {!collapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </div>

        {me?.is_superuser && (
          <>
            <div className={['mt-4 mb-2 px-3 text-[10px] uppercase tracking-widest text-slate-500', collapsed ? 'text-center' : ''].join(' ')}>
              {collapsed ? '···' : 'Admin'}
            </div>
            <div className="space-y-1">
              {ADMIN_NAV.map(({ to, icon: Icon, label, color }) => (
                <NavLink key={to} to={to} className={linkClass} title={collapsed ? label : undefined}>
                  <Icon className={`h-4 w-4 shrink-0 ${color}`} />
                  {!collapsed && <span>{label}</span>}
                </NavLink>
              ))}
            </div>
          </>
        )}
      </nav>

      {/* Bottom section */}
      <div className="border-t border-white/10 px-3 py-4 space-y-2">
        {/* Theme selector */}
        {!collapsed && (
          <div className="flex gap-1 rounded-xl bg-white/5 p-1">
            {(['light', 'system', 'dark'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                className={[
                  'flex-1 rounded-lg py-1 text-[10px] font-medium capitalize transition',
                  mode === m ? 'bg-white/15 text-white' : 'text-slate-400 hover:text-white',
                ].join(' ')}
              >
                {m}
              </button>
            ))}
          </div>
        )}

        {/* User */}
        <div className={['flex items-center gap-2', collapsed ? 'justify-center' : ''].join(' ')}>
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-violet-500 to-indigo-600 text-[11px] font-bold text-white">
            {me?.username?.[0]?.toUpperCase()}
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-medium text-white">{me?.username}</div>
              <div className="text-[10px] text-slate-400">{me?.is_superuser ? 'Admin' : 'User'}</div>
            </div>
          )}
          {!collapsed && (
            <button type="button" onClick={logout} className="text-slate-400 hover:text-white transition" title="Logout">
              <LogOut className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Collapse toggle */}
        <button
          type="button"
          onClick={onToggle}
          className="flex w-full items-center justify-center rounded-xl py-2 text-slate-500 hover:bg-white/5 hover:text-slate-300 transition"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>
    </aside>
  )
}
