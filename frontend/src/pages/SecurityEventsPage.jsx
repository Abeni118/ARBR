import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  CalendarDays,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Database,
  Download,
  Eye,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import './SecurityEventsPage.css'
import {
  eventActivityByPeriod,
  eventFilterOptions,
  eventSummary,
  securityEventRecords,
} from '../data/securityEventData.js'

const summaryIcons = { activity: Activity, alert: AlertTriangle, clock: Clock3, calendar: CalendarDays, nodes: Database }
const pageSizes = [10, 25, 50]

function EventActivityTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tooltip">
      <strong>{label}</strong>
      <span><i className="legend-dot legend-dot--risk" /> Events detected: {payload[0]?.value}</span>
      <span><i className="legend-dot legend-dot--threat" /> Critical events: {payload[1]?.value}</span>
    </div>
  )
}

function EventSummaryCards() {
  return (
    <section className="event-summary-grid" aria-label="Security event summary">
      {eventSummary.map((item) => {
        const Icon = summaryIcons[item.icon]
        return (
          <article className={`event-summary-card event-summary-card--${item.tone}`} key={item.label}>
            <div className="event-summary-copy">
              <span className="eyebrow">{item.label}</span>
              <strong>{item.value}</strong>
              <span className="event-summary-support">{item.support}</span>
            </div>
            <div className="event-summary-icon"><Icon size={17} strokeWidth={1.8} /></div>
          </article>
        )
      })}
    </section>
  )
}

function EventActivityChart({ period }) {
  const chartRows = eventActivityByPeriod[period]
  return (
    <section className="panel event-activity-panel" aria-labelledby="event-activity-heading">
      <div className="event-activity-heading">
        <div><h2 id="event-activity-heading">Event Activity</h2><p>Security events detected over time</p></div>
        <div className="chart-legend">
          <span><i className="legend-dot legend-dot--risk" />All Events</span>
          <span><i className="legend-dot legend-dot--threat" />Critical</span>
        </div>
      </div>
      <div className="event-activity-chart">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartRows} margin={{ top: 12, right: 8, bottom: 0, left: -12 }}>
            <CartesianGrid vertical={false} stroke="#30343d" strokeDasharray="2 5" />
            <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} dy={8} />
            <YAxis domain={[0, 60]} ticks={[0, 15, 30, 45, 60]} axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} />
            <Tooltip content={<EventActivityTooltip />} cursor={{ stroke: '#59606d', strokeDasharray: '3 4' }} />
            <Line type="monotone" dataKey="events" stroke="#09c7d8" strokeWidth={1.7} dot={false} activeDot={{ r: 3, fill: '#09c7d8', stroke: '#101a34', strokeWidth: 2 }} />
            <Line type="monotone" dataKey="critical" stroke="#f03c4b" strokeWidth={1.5} dot={false} activeDot={{ r: 3, fill: '#f03c4b', stroke: '#101a34', strokeWidth: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}

function EventFilters({ filters, searchTerm, onSearchChange, onFilterChange, onClear, onExport, filteredCount }) {
  const selectOptions = [
    ['severity', 'All Severities', eventFilterOptions.severities],
    ['category', 'All Categories', eventFilterOptions.categories],
    ['status', 'All Statuses', eventFilterOptions.statuses],
    ['source', 'All Sources', eventFilterOptions.sources],
    ['timeRange', 'Any Time', ['Last hour', 'Last 6 hours', 'Last 24 hours', 'Last 7 days']],
  ]
  return (
    <div className="event-filter-bar">
      <label className="event-search">
        <Search size={14} />
        <input className="event-filter-search" type="search" aria-label="Search security events" placeholder="Search event ID, source, IP address..." value={searchTerm} onChange={(event) => onSearchChange(event.target.value)} />
      </label>
      <div className="event-select-filters">
        {selectOptions.map(([name, placeholder, values]) => (
          <label className="event-select" key={name}>
            <span className="sr-only">{placeholder}</span>
            <select value={filters[name]} onChange={(event) => onFilterChange(name, event.target.value)}>
              <option value="">{placeholder}</option>
              {values.map((value) => <option key={value} value={value}>{value}</option>)}
            </select>
            <ChevronDown size={12} />
          </label>
        ))}
      </div>
      <div className="event-filter-actions">
        <button className="event-clear-button" onClick={onClear}><X size={12} />Clear Filters</button>
        <button className="toolbar-button" onClick={onExport}><Download size={13} />Export</button>
      </div>
      <div className="filter-result-count"><Filter size={11} /> {filteredCount.toLocaleString()} matching events</div>
    </div>
  )
}

function SeverityBadge({ severity }) {
  return <span className={`severity severity--${severity.toLowerCase()}`}>{severity}</span>
}

function StatusBadge({ status }) {
  return <span className={`event-status-badge event-status-badge--${status.toLowerCase()}`}>{status}</span>
}

function Pagination({ page, pageSize, total, onPageChange, onPageSizeChange }) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize))
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1
  const end = Math.min(page * pageSize, total)
  const pages = Array.from({ length: Math.min(5, pageCount) }, (_, index) => {
    const firstPage = Math.min(Math.max(page - 2, 1), Math.max(pageCount - 4, 1))
    return firstPage + index
  })
  return (
    <div className="event-pagination">
      <div className="pagination-summary">Showing <strong>{start}–{end}</strong> of <strong>{total.toLocaleString()}</strong> events</div>
      <label className="rows-per-page">Rows per page
        <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
          {pageSizes.map((size) => <option value={size} key={size}>{size}</option>)}
        </select>
      </label>
      <div className="pagination-controls" aria-label="Pagination">
        <button aria-label="Previous page" disabled={page <= 1} onClick={() => onPageChange(page - 1)}><ArrowLeft size={13} /></button>
        {pages.map((pageNumber) => <button key={pageNumber} className={page === pageNumber ? 'current' : ''} onClick={() => onPageChange(pageNumber)}>{pageNumber}</button>)}
        {pageCount > 5 && <span>… {pageCount}</span>}
        <button aria-label="Next page" disabled={page >= pageCount} onClick={() => onPageChange(page + 1)}><ArrowRight size={13} /></button>
      </div>
    </div>
  )
}

function SecurityEventTable({ events, onSelect }) {
  return (
    <div className="security-event-table-scroll">
      <table className="security-event-table">
        <thead><tr><th>Event ID</th><th>Timestamp</th><th>Source</th><th>Source IP</th><th>Event Category</th><th>Description</th><th>Severity</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} tabIndex={0} onClick={() => onSelect(event)} onKeyDown={(keyEvent) => { if (keyEvent.key === 'Enter' || keyEvent.key === ' ') { keyEvent.preventDefault(); onSelect(event) } }}>
              <td className="event-id">{event.id}</td>
              <td className="event-time">{event.timestamp}</td>
              <td>{event.source}</td>
              <td className="event-ip">{event.sourceIp}</td>
              <td>{event.category}</td>
              <td className="event-description-cell">{event.description}</td>
              <td><SeverityBadge severity={event.severity} /></td>
              <td><StatusBadge status={event.status} /></td>
              <td><button className="row-action" aria-label={`View details for ${event.id}`} onClick={(clickEvent) => { clickEvent.stopPropagation(); onSelect(event) }}><Eye size={14} /></button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EventDetailsDrawer({ event, onClose, onResolve, onIsolate }) {
  const [confirmIsolation, setConfirmIsolation] = useState(false)
  const [investigating, setInvestigating] = useState(false)
  useEffect(() => {
    const onEscape = (keyboardEvent) => { if (keyboardEvent.key === 'Escape') onClose() }
    window.addEventListener('keydown', onEscape)
    return () => window.removeEventListener('keydown', onEscape)
  }, [onClose])

  return (
    <div className="event-drawer-backdrop" onMouseDown={(mouseEvent) => { if (mouseEvent.target === mouseEvent.currentTarget) onClose() }}>
      <aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="event-details-title">
        <header className="event-drawer-header">
          <div><span className="eyebrow">Investigation workspace</span><h2 id="event-details-title">Event Details</h2></div>
          <button className="icon-button" aria-label="Close event details" onClick={onClose}><X size={17} /></button>
        </header>
        <div className="event-drawer-event-heading">
          <div><span className="event-id">{event.id}</span><span className="event-drawer-date">{event.date} · {event.timestamp}</span></div>
          <SeverityBadge severity={event.severity} />
        </div>
        <section className="detail-section">
          <h3>Event information</h3>
          <dl className="event-detail-grid">
            <div><dt>Source system</dt><dd>{event.source}</dd></div>
            <div><dt>Source IP</dt><dd>{event.sourceIp}</dd></div>
            <div><dt>Event category</dt><dd>{event.category}</dd></div>
            <div><dt>Status</dt><dd><StatusBadge status={event.status} /></dd></div>
            <div><dt>Risk score</dt><dd><span className={`risk-score risk-score--${event.riskScore >= 75 ? 'high' : event.riskScore >= 40 ? 'medium' : 'low'}`}>{event.riskScore}<small> / 100</small></span></dd></div>
            <div><dt>Description</dt><dd>{event.description}</dd></div>
          </dl>
        </section>
        <section className="detail-section"><h3>Detection reason</h3><p className="detail-body">{event.detectionReason}</p></section>
        <section className="detail-section">
          <h3>Response timeline</h3>
          <ol className="event-timeline">
            {['Event Detected', 'Event Analyzed', 'Risk Score Updated', 'Decision Made', 'Response Applied'].map((step, index) => (
              <li className={index < 4 || event.status !== 'Investigating' ? 'timeline-complete' : 'timeline-pending'} key={step}>
                <i>{index < 4 || event.status !== 'Investigating' ? <Check size={10} /> : index + 1}</i>
                <div><strong>{step}</strong><span>{index === 0 ? `${event.date} ${event.timestamp}` : ['Correlation engine completed analysis', `Risk score set to ${event.riskScore}/100`, 'Automated response policy evaluated', event.status === 'Investigating' ? 'Awaiting analyst action' : `${event.status} by response policy`][index - 1]}</span></div>
              </li>
            ))}
          </ol>
        </section>
        <section className="detail-section detail-response">
          <h3>Recommended response</h3>
          <p className="detail-body">{event.response}</p>
          <div className="related-events"><span>Related events</span>{event.relatedEvents.map((id) => <span className="event-id" key={id}>{id}</span>)}</div>
        </section>
        <div className="event-drawer-actions">
          <button className="toolbar-button" onClick={() => setInvestigating(true)}><Search size={13} />{investigating ? 'Investigation Active' : 'Investigate'}</button>
          <button className="resolve-event-button" onClick={() => onResolve(event.id)}><ShieldCheck size={13} />Mark as Resolved</button>
          <button className="isolate-event-button" onClick={() => setConfirmIsolation(true)}><ShieldAlert size={13} />Isolate System</button>
        </div>
        {confirmIsolation && (
          <div className="confirmation-backdrop" role="presentation">
            <section className="confirmation-dialog" role="alertdialog" aria-modal="true" aria-labelledby="isolate-confirm-title">
              <div className="confirmation-icon"><ShieldAlert size={19} /></div>
              <h3 id="isolate-confirm-title">Confirm system isolation</h3>
              <p>Isolate <strong>{event.source}</strong>? This may interrupt services while the node is contained.</p>
              <div><button className="toolbar-button" onClick={() => setConfirmIsolation(false)}>Cancel</button><button className="isolate-event-button" onClick={() => onIsolate(event)}>Confirm Isolation</button></div>
            </section>
          </div>
        )}
      </aside>
    </div>
  )
}

function EventFiltersToolbar({ period, setPeriod, onExport }) {
  return (
    <div className="event-page-toolbar">
      <div className="period-selector" aria-label="Event activity time range">
        {['1H', '6H', '24H', '7D'].map((range) => <button type="button" key={range} className={period === range ? 'selected' : ''} onClick={() => setPeriod(range)}>{range}</button>)}
      </div>
      <div className="toolbar-actions">
        <button className="toolbar-button" onClick={() => document.querySelector('.event-filter-search input')?.focus()}><Filter size={13} />Filter</button>
        <button className="toolbar-button" onClick={onExport}><ArrowDownToLine size={13} />Export</button>
      </div>
    </div>
  )
}

export default function SecurityEventsPage({ globalSearch, onGlobalSearchChange, onToast }) {
  const [period, setPeriod] = useState('24H')
  const [filters, setFilters] = useState({ severity: '', category: '', status: '', source: '', timeRange: '' })
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [events, setEvents] = useState(securityEventRecords)
  const [loadState, setLoadState] = useState('loading')

  useEffect(() => {
    const timer = window.setTimeout(() => setLoadState('success'), 250)
    return () => window.clearTimeout(timer)
  }, [])

  const filteredEvents = useMemo(() => events.filter((event) => {
    const query = globalSearch.trim().toLowerCase()
    const matchesQuery = !query || [event.id, event.source, event.sourceIp, event.category, event.description].some((value) => value.toLowerCase().includes(query))
    const matchesSeverity = !filters.severity || event.severity === filters.severity
    const matchesCategory = !filters.category || event.category === filters.category
    const matchesStatus = !filters.status || event.status === filters.status
    const matchesSource = !filters.source || event.source === filters.source
    const matchesTime = !filters.timeRange || (
      filters.timeRange === 'Last hour' ? event.minutesAgo <= 60
        : filters.timeRange === 'Last 6 hours' ? event.minutesAgo <= 360
          : filters.timeRange === 'Last 24 hours' ? event.minutesAgo <= 1440
            : event.minutesAgo <= 10080
    )
    return matchesQuery && matchesSeverity && matchesCategory && matchesStatus && matchesSource && matchesTime
  }), [events, filters, globalSearch])

  const pageCount = Math.max(1, Math.ceil(filteredEvents.length / pageSize))
  const visibleEvents = filteredEvents.slice((page - 1) * pageSize, page * pageSize)

  const updateFilter = (name, value) => {
    setFilters((current) => ({ ...current, [name]: value }))
    setPage(1)
  }
  const clearFilters = () => {
    setFilters({ severity: '', category: '', status: '', source: '', timeRange: '' })
    onGlobalSearchChange('')
    setPage(1)
  }

  const exportEvents = () => {
    const header = ['Event ID', 'Timestamp', 'Source', 'Source IP', 'Event Category', 'Description', 'Severity', 'Status']
    const rows = filteredEvents.map((event) => [event.id, event.timestamp, event.source, event.sourceIp, event.category, event.description, event.severity, event.status])
    const csv = [header, ...rows].map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\n')
    const downloadUrl = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const link = document.createElement('a')
    link.href = downloadUrl
    link.download = 'security-event-log.csv'
    link.click()
    URL.revokeObjectURL(downloadUrl)
  }

  const markResolved = (eventId) => {
    setEvents((current) => current.map((event) => event.id === eventId ? { ...event, status: 'Resolved' } : event))
    setSelectedEvent(null)
    onToast('Event marked as resolved')
  }

  const isolateSystem = (event) => {
    setSelectedEvent(null)
    onToast(`${event.source} isolation request submitted`)
  }

  return (
    <main className="security-events-main">
      <section className="security-events-heading">
        <div><h1>Security Events</h1><p>Centralized security telemetry and event monitoring</p></div>
        <EventFiltersToolbar period={period} setPeriod={setPeriod} onExport={exportEvents} />
      </section>
      <EventSummaryCards />
      <EventActivityChart period={period} />
      <section className="panel security-log-panel" aria-labelledby="security-log-heading">
        <header className="security-log-heading">
          <div><h2 id="security-log-heading">Security Event Log</h2><p>Latest telemetry collected from monitored systems</p></div>
          <span className="live-indicator"><i className="status-dot status-dot--green" />LIVE TELEMETRY</span>
        </header>
        <EventFilters filters={filters} searchTerm={globalSearch} onSearchChange={onGlobalSearchChange} onFilterChange={updateFilter} onClear={clearFilters} onExport={exportEvents} filteredCount={filteredEvents.length} />
        {loadState === 'loading' && <div className="event-state"><span className="loading-spinner" />Loading security events...</div>}
        {loadState === 'error' && <div className="event-state event-state--error"><CircleHelp size={17} />Unable to load security events<button onClick={() => { setLoadState('loading'); window.setTimeout(() => setLoadState('success'), 250) }}>Retry</button></div>}
        {loadState === 'success' && filteredEvents.length === 0 && <div className="event-state"><CircleHelp size={17} />No security events found</div>}
        {loadState === 'success' && filteredEvents.length > 0 && <>
          <SecurityEventTable events={visibleEvents} onSelect={setSelectedEvent} />
          <Pagination page={page} pageSize={pageSize} total={filteredEvents.length} onPageChange={(nextPage) => setPage(Math.max(1, Math.min(nextPage, pageCount)))} onPageSizeChange={(nextSize) => { setPageSize(nextSize); setPage(1) }} />
        </>}
      </section>
      <div className="security-events-footer">
        <span><i className="status-dot status-dot--green" />Event collector operational</span>
        <span>Last ingestion: just now <span className="footer-divider">|</span> Retention policy: 365 days</span>
      </div>
      {selectedEvent && <EventDetailsDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} onResolve={markResolved} onIsolate={isolateSystem} />}
    </main>
  )
}
