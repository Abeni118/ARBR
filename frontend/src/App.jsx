import { useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
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
import './App.css'

function App() {
  const location = useLocation()
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
  }[location.pathname] || 'Dashboard'

  return (
    <div className="app-shell">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((current) => !current)} />
      <div className="main-shell">
        <HeaderBar pageTitle={pageTitle} searchValue={globalSearch} onSearch={setGlobalSearch} notificationOpen={notificationsOpen} onToggleNotifications={() => setNotificationsOpen((current) => !current)} />
        <Routes>
          <Route path="/" element={<DashboardPage globalSearch={globalSearch} onGlobalSearchChange={setGlobalSearch} />} />
          <Route path="/security-events" element={<SecurityEventsPage globalSearch={globalSearch} onGlobalSearchChange={setGlobalSearch} />} />
          <Route path="/threat-detection" element={<ThreatDetectionPage globalSearch={globalSearch} onGlobalSearchChange={setGlobalSearch} />} />
          <Route path="/risk-analysis" element={<RiskAnalysisPage globalSearch={globalSearch} />} />
          <Route path="/backups" element={<BackupsPage globalSearch={globalSearch} />} />
          <Route path="/system-isolation" element={<SystemIsolationPage globalSearch={globalSearch} />} />
          <Route path="/recovery" element={<RecoveryPage globalSearch={globalSearch} />} />
          <Route path="/audit-logs" element={<AuditLogsPage globalSearch={globalSearch} onGlobalSearchChange={setGlobalSearch} />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  )
}

export default App
