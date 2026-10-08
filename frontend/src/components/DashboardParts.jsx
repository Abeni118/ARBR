import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  ChartNoAxesCombined,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Database,
  FileText,
  Fingerprint,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  RotateCcw,
  Search,
  Settings,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'
import { navigationItems } from '../data/dashboardData.js'

const iconMap = {
  dashboard: LayoutDashboard,
  activity: Activity,
  shield: Shield,
  chart: ChartNoAxesCombined,
  database: Database,
  rotate: RotateCcw,
  lock: LockKeyhole,
  file: FileText,
  settings: Settings,
  'shield-check': ShieldCheck,
  alert: AlertTriangle,
  fingerprint: Fingerprint,
}

export function Sidebar({ collapsed, onToggle }) {
  const location = useLocation()
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="brand">
        <div className="brand-mark"><Shield size={16} strokeWidth={2.3} /></div>
        <div className="brand-name">Attack-Resistant<br />Backup &amp; Recovery</div>
        <button className="icon-button sidebar-toggle" aria-label="Toggle sidebar" onClick={onToggle}>
          <Menu size={15} />
        </button>
      </div>
      <nav className="side-nav" aria-label="Main navigation">
        {navigationItems.map(({ label, icon }) => {
          const Icon = iconMap[icon]
          const path = label === 'Dashboard' ? '/' : label === 'Security Events' ? '/security-events' : label === 'Threat Detection' ? '/threat-detection' : label === 'Risk Analysis' ? '/risk-analysis' : label === 'Backups' ? '/backups' : label === 'Recovery' ? '/recovery' : label === 'System Isolation' ? '/system-isolation' : label === 'Audit Logs' ? '/audit-logs' : label === 'Settings' ? '/settings' : null
          const active = path === '/' ? location.pathname === '/' : path === location.pathname
          const contents = <><Icon size={14} strokeWidth={1.8} /><span>{label}</span>{active && <ChevronRight className="nav-chevron" size={12} />}</>
          return path
            ? <Link className={`nav-link ${active ? 'nav-link--active' : ''}`} key={label} to={path} aria-label={label} title={label} aria-current={active ? 'page' : undefined}>{contents}</Link>
            : <button className="nav-link" key={label} type="button" aria-label={label} title={label}>{contents}</button>
        })}
      </nav>
      <div className="sidebar-user">
        <div className="user-avatar">AR</div>
        <div className="user-copy"><strong>API Client</strong><span>MVP Bearer authentication</span></div>
        <ChevronDown className="user-chevron" size={13} />
      </div>
    </aside>
  )
}

export function HeaderBar({ pageTitle = 'Threat Detection', searchValue = '', onSearch, notificationOpen, onToggleNotifications }) {
  return (
    <header className="topbar">
      <div className="breadcrumbs">
        <LayoutDashboard size={13} />
        <span>Dashboard</span>
        <ChevronRight size={12} />
        <Shield size={13} />
        <strong>{pageTitle}</strong>
      </div>
      <div className="topbar-tools">
        <label className="search-box">
          <Search size={13} />
          <input type="search" placeholder="Search threats, systems..." value={searchValue} onChange={(event) => onSearch?.(event.target.value)} />
          <kbd>/</kbd>
        </label>
        <button className={`icon-button notification-button ${notificationOpen ? 'is-active' : ''}`} aria-label="Notifications" onClick={onToggleNotifications}>
          <Bell size={15} />
          <span className="notification-dot" />
        </button>
        {notificationOpen && (
          <div className="notification-popover">
            <strong>Notifications</strong>
            <span>Notification data is not provided by the connected API.</span>
          </div>
        )}
      </div>
    </header>
  )
}

export function MetricCard({ metric }) {
  const Icon = iconMap[metric.icon]
  return (
    <article className="metric-card">
      <div className="metric-copy">
        <span className="eyebrow">{metric.label}</span>
        <strong className="metric-value">{metric.value}</strong>
        {metric.trend && (
          <span className={`metric-trend metric-trend--${metric.trendTone}`}>
            {metric.trendTone === 'good' ? <ArrowDownRight size={12} /> : <ArrowUpRight size={12} />}
            <b>{metric.trend}</b><span>vs last 24h</span>
          </span>
        )}
      </div>
      <div className={`metric-icon metric-icon--${metric.icon}`}><Icon size={18} strokeWidth={1.8} /></div>
    </article>
  )
}

export function EventsTable({ events, onViewAll }) {
  return (
    <section className="panel events-panel" aria-labelledby="events-heading">
      <div className="events-heading">
        <div><h2 id="events-heading">Recent Security Events</h2><p>Latest records returned by the backend</p></div>
        <button className="text-button" onClick={onViewAll}>View All Events <ChevronRight size={13} /></button>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Event ID</th><th>Occurred At</th><th>Source</th><th>Event Type</th><th>Severity</th><th>Processing Status</th></tr></thead>
          <tbody>{events.map((event) => (
            <tr key={event.id}>
              <td className="event-id">{event.id}</td><td className="event-time">{event.time}</td><td>{event.source}</td><td>{event.category}</td>
              <td><span className={`severity severity--${event.severity.toLowerCase()}`}>{event.severity}</span></td>
              <td className={`event-status event-status--${event.status.toLowerCase()}`}>{event.status}</td>
            </tr>
          ))}</tbody>
        </table>
        {events.length === 0 && <div className="empty-table"><CircleHelp size={16} /> No matching security events</div>}
      </div>
    </section>
  )
}
