import { useMemo, useState } from 'react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Check } from 'lucide-react'
import { metrics, riskTrend, securityEvents } from './data/dashboardData.js'
import {
  ActionPanel,
  DashboardToolbar,
  EventsTable,
  HeaderBar,
  MetricCard,
  Sidebar,
} from './components/DashboardParts.jsx'
import './App.css'

function RiskTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tooltip">
      <strong>{label}</strong>
      <span><i className="legend-dot legend-dot--risk" /> Risk level: {payload[0]?.value}</span>
      <span><i className="legend-dot legend-dot--threat" /> Threat count: {payload[1]?.value}</span>
    </div>
  )
}

function RiskTrendChart() {
  return (
    <section className="panel chart-panel" aria-labelledby="risk-heading">
      <div className="chart-heading">
        <div><h2 id="risk-heading">Risk Overview &amp; Threat Trend</h2><p>Aggregate system risk score against active detected anomalies</p></div>
        <div className="chart-legend"><span><i className="legend-dot legend-dot--risk" />Risk Level</span><span><i className="legend-dot legend-dot--threat" />Threat Count</span></div>
      </div>
      <div className="chart-area">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={riskTrend} margin={{ top: 9, right: 2, bottom: 0, left: -12 }}>
            <CartesianGrid vertical={false} stroke="#30343d" strokeDasharray="2 5" />
            <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} dy={8} />
            <YAxis domain={[0, 80]} ticks={[0, 20, 40, 60, 80]} axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} />
            <Tooltip content={<RiskTooltip />} cursor={{ stroke: '#59606d', strokeDasharray: '3 4' }} />
            <Line type="monotone" dataKey="risk" stroke="#09c7d8" strokeWidth={1.6} dot={false} activeDot={{ r: 3, fill: '#09c7d8', stroke: '#101a34', strokeWidth: 2 }} />
            <Line type="monotone" dataKey="threats" stroke="#f03c4b" strokeWidth={1.5} dot={false} activeDot={{ r: 3, fill: '#f03c4b', stroke: '#101a34', strokeWidth: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}

function StatusFooter() {
  return (
    <footer className="status-footer">
      <div className="system-indicators">
        <span><i className="status-dot status-dot--green" />API Connectivity: Stable</span>
        <span><i className="status-dot status-dot--green" />Threat Database: v4.2.6 (Synced)</span>
        <span><i className="status-dot status-dot--cyan" />Latency: 14ms</span>
      </div>
      <span className="uptime">System Uptime: 120d 14h 28m 11s</span>
    </footer>
  )
}

function App() {
  const [period, setPeriod] = useState('24H')
  const [query, setQuery] = useState('')
  const [filterOpen, setFilterOpen] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [actionState, setActionState] = useState('')

  const filteredEvents = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return securityEvents
    return securityEvents.filter((event) => Object.values(event).some((value) => String(value).toLowerCase().includes(normalizedQuery)))
  }, [query])

  const exportEvents = () => {
    const headers = ['Event ID', 'Timestamp', 'Source IP/Host', 'Event Category', 'Severity', 'Status']
    const rows = filteredEvents.map((event) => [event.id, event.time, event.source, event.category, event.severity, event.status])
    const csv = [headers, ...rows].map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'security-events.csv'
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="app-shell">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((current) => !current)} />
      <div className="main-shell">
        <HeaderBar onSearch={setQuery} notificationOpen={notificationsOpen} onToggleNotifications={() => setNotificationsOpen((current) => !current)} />
        <main className="dashboard-main">
          <section className="overview-heading">
            <div className="overview-title"><h1>Operational Overview</h1><p>SOC Command Center | Security Node: Alpha-01</p></div>
            <DashboardToolbar period={period} onPeriodChange={setPeriod} filterOpen={filterOpen} onFilter={() => setFilterOpen((current) => !current)} onExport={exportEvents} />
          </section>

          <section className="metric-grid" aria-label="System security metrics">
            {metrics.map((metric) => <MetricCard key={metric.label} metric={metric} />)}
          </section>

          <div className="dashboard-grid">
            <RiskTrendChart />
            <ActionPanel actionState={actionState} onAction={setActionState} />
          </div>

          <EventsTable events={filteredEvents} onViewAll={() => setQuery('')} />
          <StatusFooter />
          {actionState && <div className="action-toast" role="status"><Check size={14} /> {actionState === 'isolate' ? 'System isolation protocol initiated' : actionState === 'snapshot' ? 'Immutable snapshot deployment started' : 'Point-in-time recovery verified'}</div>}
        </main>
      </div>
    </div>
  )
}

export default App