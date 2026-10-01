import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  ChartNoAxesCombined,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Database,
  Download,
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
  SlidersHorizontal,
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
          const path = label === 'Dashboard' ? '/' : label === 'Security Events' ? '/security-events' : label === 'Threat Detection' ? '/threat-detection' : label === 'Risk Analysis' ? '/risk-analysis' : label === 'Backups' ? '/backups' : null
          const active = path === '/' ? location.pathname === '/' : path === location.pathname
          const contents = <><Icon size={14} strokeWidth={1.8} /><span>{label}</span>{active && <ChevronRight className="nav-chevron" size={12} />}</>
          return path
            ? <Link className={`nav-link ${active ? 'nav-link--active' : ''}`} key={label} to={path} aria-label={label} title={label} aria-current={active ? 'page' : undefined}>{contents}</Link>
            : <button className="nav-link" key={label} type="button" aria-label={label} title={label}>{contents}</button>
        })}
      </nav>
      <div className="sidebar-user">
        <div className="user-avatar">AR</div>
        <div className="user-copy"><strong>Alex Rivers</strong><span>Senior Security Analyst</span></div>
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
            <strong>Security alerts</strong>
            <span><i className="alert-dot" /> 2 high-priority alerts require review</span>
            <span><i className="success-dot" /> Immutable snapshot verified</span>
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

export function ActionPanel({ actionState, onAction }) {
  return (
    <section className="panel action-panel" aria-labelledby="actions-heading">
      <div className="panel-heading">
        <div><h2 id="actions-heading">Tactical Actions</h2><p>Rapid response to system isolation protocols</p></div>
      </div>
      <div className="action-buttons">
        <button className="action-button action-button--danger" onClick={() => onAction('isolate')}>
          <Shield size={14} /><span>{actionState === 'isolate' ? 'ISOLATION INITIATED' : 'INITIATE SYSTEM ISOLATION'}</span><ArrowUpRight size={13} />
        </button>
        <button className="action-button action-button--cyan" onClick={() => onAction('snapshot')}>
          <Database size={13} /><span>{actionState === 'snapshot' ? 'SNAPSHOT DEPLOYED' : 'DEPLOY IMMUTABLE SNAPSHOT'}</span><ArrowRight size={13} />
        </button>
        <button className="action-button action-button--neutral" onClick={() => onAction('restore')}>
          <RotateCcw size={14} /><span>{actionState === 'restore' ? 'RECOVERY VERIFIED' : 'RESTORE TO POINT-IN-TIME'}</span><ArrowUpRight size={13} />
        </button>
      </div>
      <div className="resource-section">
        <span className="eyebrow">Resource Allocation</span>
        <div className="resource-row"><div className="resource-label"><span>Compute Nodes</span><b>82%</b></div><div className="resource-track"><i className="resource-fill resource-fill--cyan" style={{ width: '82%' }} /></div></div>
        <div className="resource-row"><div className="resource-label"><span>Immutable Storage</span><b>45%</b></div><div className="resource-track"><i className="resource-fill resource-fill--green" style={{ width: '45%' }} /></div></div>
      </div>
    </section>
  )
}

export function EventsTable({ events, onViewAll }) {
  return (
    <section className="panel events-panel" aria-labelledby="events-heading">
      <div className="events-heading">
        <div><h2 id="events-heading">Recent Security Events</h2><p>Latest telemetry from global defense nodes</p></div>
        <button className="text-button" onClick={onViewAll}>View All Events <ChevronRight size={13} /></button>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Event ID</th><th>Timestamp</th><th>Source IP/Host</th><th>Event Category</th><th>Severity</th><th>Status</th></tr></thead>
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

export function DashboardToolbar({ period, onPeriodChange, onFilter, filterOpen, onExport }) {
  return (
    <div className="dashboard-toolbar">
      <div className="period-selector" aria-label="Chart time range">
        {['1H', '6H', '24H', '7D'].map((range) => <button key={range} className={period === range ? 'selected' : ''} onClick={() => onPeriodChange(range)}>{range}</button>)}
      </div>
      <div className="toolbar-actions">
        <div className="filter-wrap">
          <button className={`toolbar-button ${filterOpen ? 'selected' : ''}`} onClick={onFilter}><SlidersHorizontal size={13} />Filter</button>
          {filterOpen && <div className="filter-popover"><strong>Event filters</strong><label><input type="checkbox" defaultChecked /> Threats &amp; alerts</label><label><input type="checkbox" defaultChecked /> Backup integrity</label><label><input type="checkbox" /> Resolved events</label></div>}
        </div>
        <button className="toolbar-button" onClick={onExport}><Download size={13} />Export</button>
      </div>
    </div>
  )
}
