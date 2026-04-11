import type { ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import { ThemeProvider } from './theme'
import { Layout } from './components/Layout'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { RoutersPage } from './pages/RoutersPage'
import { AlertsPage } from './pages/AlertsPage'
import { DecisionsPage } from './pages/DecisionsPage'
import { SettingsPage } from './pages/SettingsPage'
import { AdminPage } from './pages/AdminPage'
import { TraefikPage } from './pages/TraefikPage'
import { CrowdSecPage } from './pages/CrowdSecPage'
import { ProfilePage } from './pages/ProfilePage'
import { AuditPage } from './pages/AuditPage'
import { ServicePage } from './pages/ServicePage'

function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth()
  if (loading) return <div className="p-10 text-center text-sm text-neutral-500">Loading…</div>
  if (!me) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
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
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}
