import { useMemo, useState } from 'react'
import { Activity, AlertTriangle, ArrowLeft, ArrowRight, Check, Download, Eye, FileText, Filter, RefreshCw, ShieldAlert, UserCog, Workflow, X } from 'lucide-react'
import { auditActors, auditEventTypes, auditLogRecords, auditSeverities, auditStatuses, auditSummary, recentAuditActivity } from '../data/auditLogData.js'
import './AuditLogsPage.css'

const summaryIcons = { total: FileText, critical: ShieldAlert, admin: UserCog, automated: Workflow, failed: AlertTriangle }
const pageSize = 10

function AuditSummaryCards() {
  return <section className="audit-summary-grid" aria-label="Audit event summary">{auditSummary.map((item) => {
    const Icon = summaryIcons[item.icon]
    return <article className={`audit-summary-card audit-summary-card--${item.tone}`} key={item.label}><div className="audit-summary-copy"><span className="eyebrow">{item.label}</span><strong>{item.value}</strong><span>{item.support}</span></div><div className="audit-summary-icon"><Icon size={17} strokeWidth={1.8} /></div></article>
  })}</section>
}

function AuditSeverity({ severity }) {
  return <span className={`severity severity--${severity.toLowerCase()}`}>{severity}</span>
}

function AuditStatus({ status }) {
  return <span className={`audit-status-badge audit-status-badge--${status.toLowerCase()}`}><i />{status}</span>
}

function AuditFilters({ filters, onChange, searchTerm, onSearchChange, onClear, count }) {
  const options = [
    ['dateRange', 'Any Date', ['Today', 'Last 24 hours', 'Last 7 days']],
    ['severity', 'All Severities', auditSeverities],
    ['eventType', 'All Event Types', auditEventTypes],
    ['actor', 'All Actors', auditActors],
    ['status', 'All Statuses', auditStatuses],
  ]
  return <div className="audit-filter-bar">
    <label className="event-search"><Filter size={14} /><input type="search" aria-label="Search audit logs" placeholder="Search event ID, actor, action, resource..." value={searchTerm} onChange={(event) => onSearchChange(event.target.value)} /></label>
    <div className="event-select-filters">{options.map(([name, placeholder, values]) => <label className="event-select" key={name}><span className="sr-only">{placeholder}</span><select value={filters[name]} onChange={(event) => onChange(name, event.target.value)}><option value="">{placeholder}</option>{values.map((value) => <option value={value} key={value}>{value}</option>)}</select><span className="audit-select-chevron">⌄</span></label>)}</div>
    <div className="audit-filter-actions"><span><Filter size={11} />{count.toLocaleString()} matching events</span><button className="event-clear-button" onClick={onClear}><X size={12} />Clear Filters</button></div>
  </div>
}

function AuditLogTable({ events, onSelect }) {
  return <div className="audit-table-scroll"><table className="audit-table"><thead><tr><th>Timestamp</th><th>Event ID</th><th>Actor</th><th>Action</th><th>Resource</th><th>Event Type</th><th>Severity</th><th>Status</th><th>Details</th></tr></thead><tbody>
    {events.map((event) => <tr key={event.id} tabIndex={0} onClick={() => onSelect(event)} onKeyDown={(keyEvent) => { if (keyEvent.key === 'Enter' || keyEvent.key === ' ') { keyEvent.preventDefault(); onSelect(event) } }}>
      <td className="audit-timestamp">{event.timestamp}</td><td className="audit-id">{event.id}</td><td className="audit-actor">{event.actor}<small>{event.actorType}</small></td><td>{event.action}</td><td>{event.resource}</td><td>{event.eventType}</td><td><AuditSeverity severity={event.severity} /></td><td><AuditStatus status={event.status} /></td><td><button className="row-action" aria-label={`View audit event ${event.id}`} onClick={(clickEvent) => { clickEvent.stopPropagation(); onSelect(event) }}><Eye size={14} /></button></td>
    </tr>)}
    {events.length === 0 && <tr><td className="audit-empty" colSpan="9">No audit events match the selected filters.</td></tr>}
  </tbody></table></div>
}

function AuditPagination({ page, total, onPageChange }) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1
  const end = Math.min(page * pageSize, total)
  const pages = Array.from({ length: Math.min(5, pageCount) }, (_, index) => Math.min(Math.max(page - 2, 1), Math.max(pageCount - 4, 1)) + index)
  return <div className="event-pagination audit-pagination"><div className="pagination-summary">Showing <strong>{start}–{end}</strong> of <strong>{total.toLocaleString()}</strong> events</div><div className="pagination-controls" aria-label="Audit log pagination"><button aria-label="Previous page" disabled={page <= 1} onClick={() => onPageChange(page - 1)}><ArrowLeft size={13} /></button>{pages.map((pageNumber) => <button key={pageNumber} className={page === pageNumber ? 'current' : ''} onClick={() => onPageChange(pageNumber)}>{pageNumber}</button>)}{pageCount > 5 && <span>… {pageCount}</span>}<button aria-label="Next page" disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}><ArrowRight size={13} /></button></div></div>
}

function RecentAuditActivity() {
  return <section className="panel audit-activity-panel" aria-labelledby="audit-activity-heading"><header className="audit-section-heading"><div><h2 id="audit-activity-heading">Recent Activity</h2><p>Latest notable security operations</p></div><Activity size={14} /></header><ol className="audit-activity-list">{recentAuditActivity.map((event) => <li className={`audit-activity-item audit-activity-item--${event.type}`} key={`${event.time}-${event.title}`}><span>{event.time}</span><i /><div><strong>{event.resource.split(' · ')[0]} {event.title.toLowerCase()}</strong><small>Actor: {event.resource.split(' · Actor: ')[1]}</small></div></li>)}</ol></section>
}

function AuditEventDetails({ event, onClose }) {
  return <div className="event-drawer-backdrop" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget) onClose() }}><aside className="event-details-drawer audit-details-drawer" role="dialog" aria-modal="true" aria-labelledby="audit-details-title">
    <header className="event-drawer-header"><div><span className="eyebrow">Immutable activity record</span><h2 id="audit-details-title">Audit Event Details</h2></div><button className="icon-button" aria-label="Close audit event details" onClick={onClose}><X size={17} /></button></header>
    <div className="event-drawer-event-heading"><div><span className="event-id">{event.id}</span><span className="event-drawer-date">{event.timestamp}</span></div><AuditSeverity severity={event.severity} /></div>
    <section className="detail-section"><h3>Event information</h3><dl className="event-detail-grid">
      <div><dt>Event ID</dt><dd className="event-id">{event.id}</dd></div><div><dt>Timestamp</dt><dd>{event.timestamp}</dd></div><div><dt>Actor</dt><dd>{event.actor}</dd></div><div><dt>Actor type</dt><dd>{event.actorType}</dd></div><div><dt>Action</dt><dd>{event.action}</dd></div><div><dt>Resource</dt><dd>{event.resource}</dd></div><div><dt>Source IP</dt><dd>{event.sourceIp}</dd></div><div><dt>Event type</dt><dd>{event.eventType}</dd></div><div><dt>Severity</dt><dd><AuditSeverity severity={event.severity} /></dd></div><div><dt>Status</dt><dd><AuditStatus status={event.status} /></dd></div>
    </dl></section>
    <section className="detail-section"><h3>Description</h3><p className="detail-body">{event.description}</p></section>
    <section className="audit-integrity-note"><ShieldAlert size={14} /><span>Audit record is retained in the protected event log. Record ID and timestamp are immutable.</span></section>
    <div className="event-drawer-actions"><button className="resolve-event-button" onClick={onClose}><Check size={13} />Done</button></div>
  </aside></div>
}

export default function AuditLogsPage({ globalSearch = '', onToast, onGlobalSearchChange }) {
  const [filters, setFilters] = useState({ dateRange: '', severity: '', eventType: '', actor: '', status: '' })
  const [page, setPage] = useState(1)
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [refreshed, setRefreshed] = useState(false)
  const filteredEvents = useMemo(() => auditLogRecords.filter((event) => {
    const query = globalSearch.trim().toLowerCase()
    const matchesSearch = !query || [event.id, event.timestamp, event.actor, event.actorType, event.action, event.resource, event.eventType, event.severity, event.status].some((value) => value.toLowerCase().includes(query))
    const matchesSeverity = !filters.severity || event.severity === filters.severity
    const matchesType = !filters.eventType || event.eventType === filters.eventType
    const matchesActor = !filters.actor || event.actor === filters.actor
    const matchesStatus = !filters.status || event.status === filters.status
    const matchesDate = !filters.dateRange || (filters.dateRange === 'Today' ? event.timestamp.startsWith('2026-10-01') : filters.dateRange === 'Last 24 hours' ? event.minutesAgo <= 1440 : event.minutesAgo <= 10080)
    return matchesSearch && matchesSeverity && matchesType && matchesActor && matchesStatus && matchesDate
  }), [filters, globalSearch])
  const pageCount = Math.max(1, Math.ceil(filteredEvents.length / pageSize))
  const visibleEvents = filteredEvents.slice((page - 1) * pageSize, page * pageSize)
  const updateFilter = (name, value) => { setFilters((current) => ({ ...current, [name]: value })); setPage(1) }
  const clearFilters = () => { setFilters({ dateRange: '', severity: '', eventType: '', actor: '', status: '' }); onGlobalSearchChange?.(''); setPage(1) }
  const exportLogs = () => {
    const columns = ['Timestamp', 'Event ID', 'Actor', 'Actor Type', 'Action', 'Resource', 'Source IP', 'Event Type', 'Severity', 'Status', 'Description']
    const rows = filteredEvents.map((event) => [event.timestamp, event.id, event.actor, event.actorType, event.action, event.resource, event.sourceIp, event.eventType, event.severity, event.status, event.description])
    const csv = [columns, ...rows].map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const link = document.createElement('a'); link.href = url; link.download = 'audit-log.csv'; link.click(); URL.revokeObjectURL(url)
    onToast?.('Audit log export prepared')
  }
  return <main className="audit-logs-main">
    <section className="audit-page-heading"><div><h1>Audit Logs</h1><p>Track security operations, administrative actions, and system activity.</p></div><div className="audit-page-actions"><span>{refreshed ? 'Updated just now' : 'Last event received just now'}</span><button className="toolbar-button" onClick={() => { setRefreshed(true); onToast?.('Audit log refreshed') }}><RefreshCw size={13} />Refresh</button><button className="toolbar-button audit-export-button" onClick={exportLogs}><Download size={13} />Export</button></div></section>
    <AuditSummaryCards />
    <div className="audit-content-grid"><section className="panel audit-log-panel" aria-labelledby="audit-log-heading">
      <header className="audit-section-heading"><div><h2 id="audit-log-heading">Audit Log</h2><p>Auditable record of human, service, and security-engine activity</p></div><span className="live-indicator"><i className="status-dot status-dot--green" />AUDIT COLLECTION ACTIVE</span></header>
      <AuditFilters filters={filters} onChange={updateFilter} searchTerm={globalSearch} onSearchChange={(value) => { onGlobalSearchChange?.(value); setPage(1) }} onClear={clearFilters} count={filteredEvents.length} />
      <AuditLogTable events={visibleEvents} onSelect={setSelectedEvent} />
      <AuditPagination page={page} total={filteredEvents.length} onPageChange={(nextPage) => setPage(Math.max(1, Math.min(nextPage, pageCount)))} />
    </section><RecentAuditActivity /></div>
    <footer className="audit-page-footer"><span><i className="status-dot status-dot--green" />Audit collector operational</span><span>Retention policy: 365 days <span className="footer-divider">|</span> Mock data source</span></footer>
    {selectedEvent && <AuditEventDetails event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
  </main>
}
