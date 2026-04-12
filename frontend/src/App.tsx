import { Suspense, lazy, type ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import { ThemeProvider } from './theme'
import { ToastProvider } from './components/Toast'
import { Layout } from './components/Layout'
import { Skeleton } from './components/Skeleton'

// Lazy-load all pages to reduce initial bundle size
const LoginPage       = lazy(() => import('./pages/LoginPage').then((m) => ({ default: m.LoginPage })))
const DashboardPage   = lazy(() => import('./pages/DashboardPage').then((m) => ({ default: m.DashboardPage })))
const RoutersPage     = lazy(() => import('./pages/RoutersPage').then((m) => ({ default: m.RoutersPage })))
const AlertsPage      = lazy(() => import('./pages/AlertsPage').then((m) => ({ default: m.AlertsPage })))
const DecisionsPage   = lazy(() => import('./pages/DecisionsPage').then((m) => ({ default: m.DecisionsPage })))
const SettingsPage    = lazy(() => import('./pages/SettingsPage').then((m) => ({ default: m.SettingsPage })))
const AdminPage       = lazy(() => import('./pages/AdminPage').then((m) => ({ default: m.AdminPage })))
const TraefikPage     = lazy(() => import('./pages/TraefikPage').then((m) => ({ default: m.TraefikPage })))
const CrowdSecPage    = lazy(() => import('./pages/CrowdSecPage').then((m) => ({ default: m.CrowdSecPage })))
const ProfilePage     = lazy(() => import('./pages/ProfilePage').then((m) => ({ default: m.ProfilePage })))
const AuditPage       = lazy(() => import('./pages/AuditPage').then((m) => ({ default: m.AuditPage })))
const ServicePage     = lazy(() => import('./pages/ServicePage').then((m) => ({ default: m.ServicePage })))
const IpPage          = lazy(() => import('./pages/IpPage').then((m) => ({ default: m.IpPage })))
const LogsAccessPage  = lazy(() => import('./pages/LogsAccessPage').then((m) => ({ default: m.LogsAccessPage })))
const LogsTraefikPage = lazy(() => import('./pages/LogsTraefikPage').then((m) => ({ default: m.LogsTraefikPage })))
const LogsCrowdSecPage = lazy(() => import('./pages/LogsCrowdSecPage').then((m) => ({ default: m.LogsCrowdSecPage })))
const AllowlistPage    = lazy(() => import('./pages/AllowlistPage').then((m) => ({ default: m.AllowlistPage })))
const RulesPage        = lazy(() => import('./pages/RulesPage').then((m) => ({ default: m.RulesPage })))

function PageLoader() {
  return (
    <div className="space-y-4 p-6">
      <Skeleton className="h-8 w-48" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-2xl" />)}
      </div>
      <Skeleton className="h-64 rounded-2xl" />
    </div>
  )
}

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth()
  if (loading) return <PageLoader />
  if (!me) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ToastProvider>
          <BrowserRouter>
            <Suspense fallback={<PageLoader />}>
              <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route
                  element={
                    <RequireAuth>
                      <Layout />
                    </RequireAuth>
                  }
                >
                  <Route path="/" element={<DashboardPage />} />
                  <Route path="/routers" element={<RoutersPage />} />
                  <Route path="/alerts" element={<AlertsPage />} />
                  <Route path="/decisions" element={<DecisionsPage />} />
                  <Route path="/traefik" element={<TraefikPage />} />
                  <Route path="/crowdsec" element={<CrowdSecPage />} />
                  <Route path="/profile" element={<ProfilePage />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/admin" element={<AdminPage />} />
                  <Route path="/audit" element={<AuditPage />} />
                  <Route path="/services/:host" element={<ServicePage />} />
                  <Route path="/ip/:ip" element={<IpPage />} />
                  <Route path="/logs/access" element={<LogsAccessPage />} />
                  <Route path="/logs/traefik" element={<LogsTraefikPage />} />
                  <Route path="/logs/crowdsec" element={<LogsCrowdSecPage />} />
                  <Route path="/crowdsec/allowlist" element={<AllowlistPage />} />
                  <Route path="/crowdsec/rules" element={<RulesPage />} />
                </Route>
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </ToastProvider>
      </AuthProvider>
    </ThemeProvider>
  )
}
