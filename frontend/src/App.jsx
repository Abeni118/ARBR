import { useState } from 'react'
import { Navigate, Outlet, Route, Routes, useLocation, useOutletContext } from 'react-router-dom'
import { useAuth } from './auth/AuthContext.jsx'
import { HeaderBar, Sidebar } from './components/DashboardParts.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import SecurityEventsPage from './pages/SecurityEventsPage.jsx'
import ThreatDetectionPage from './pages/ThreatDetectionPage.jsx'
import RiskAnalysisPage from './pages/RiskAnalysisPage.jsx'
import BackupsPage from './pages/BackupsPage.jsx'
import SystemIsolationPage from './pages/SystemIsolationPage.jsx'
import RecoveryPage from './pages/RecoveryPage.jsx'
import AuditLogsPage from './pages/AuditLogsPage.jsx'
import SettingsPage from './pages/SettingsPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import ChangePasswordPage from './pages/ChangePasswordPage.jsx'
import './App.css'

function RequireAuth() {
  const { sessionNotice, status, user } = useAuth()
  if (status === 'loading') return <main className="auth-loading" role="status"><span className="loading-spinner" />Verifying secure session…</main>
  if (!user) return <Navigate to="/login" replace state={{ sessionNotice }} />
  return <Outlet />
}

function LoginGate() {
  const { status, user } = useAuth()
  if (status === 'loading') return <main className="auth-loading" role="status"><span className="loading-spinner" />Verifying secure session…</main>
  if (user) return <Navigate to="/" replace />
  return <LoginPage />
}

function DashboardLayout() {
  const location = useLocation()
  const { logout, user } = useAuth()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [globalSearch, setGlobalSearch] = useState('')
  const pageTitle = {
    '/': 'Dashboard',
    '/security-events': 'Security Events',
    '/threat-detection': 'Threat Detection',
    '/risk-analysis': 'Risk Analysis',
    '/backups': 'Backups',
    '/system-isolation': 'System Isolation',
    '/recovery': 'Recovery',
    '/audit-logs': 'Audit Logs',
    '/settings': 'System Settings',
    '/change-password': 'Change Password',
  }[location.pathname] || 'Dashboard'

  return (
    <div className="app-shell">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((current) => !current)} user={user} onLogout={logout} />
      <div className="main-shell">
        <HeaderBar pageTitle={pageTitle} searchValue={globalSearch} onSearch={setGlobalSearch} notificationOpen={notificationsOpen} onToggleNotifications={() => setNotificationsOpen((current) => !current)} />
        <Outlet context={{ globalSearch, setGlobalSearch }} />
      </div>
    </div>
  )
}

function PageContent({ component: PageComponent }) {
  const { globalSearch, setGlobalSearch } = useOutletContext()
  return <PageComponent globalSearch={globalSearch} onGlobalSearchChange={setGlobalSearch} />
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginGate />} />
      <Route element={<RequireAuth />}>
        <Route element={<DashboardLayout />}>
          <Route index element={<PageContent component={DashboardPage} />} />
          <Route path="security-events" element={<PageContent component={SecurityEventsPage} />} />
          <Route path="threat-detection" element={<PageContent component={ThreatDetectionPage} />} />
          <Route path="risk-analysis" element={<PageContent component={RiskAnalysisPage} />} />
          <Route path="backups" element={<PageContent component={BackupsPage} />} />
          <Route path="system-isolation" element={<PageContent component={SystemIsolationPage} />} />
          <Route path="recovery" element={<PageContent component={RecoveryPage} />} />
          <Route path="audit-logs" element={<PageContent component={AuditLogsPage} />} />
          <Route path="settings" element={<PageContent component={SettingsPage} />} />
          <Route path="change-password" element={<ChangePasswordPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
