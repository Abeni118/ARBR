import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  Clock3,
  CircleHelp,
  Download,
  Eye,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
  ChevronDown,
  X,
} from 'lucide-react'
import './ThreatDetectionPage.css'
import { threatFilterOptions, threats as initialThreats } from '../data/threatData.js'

const summaryCards = [
  { label: 'Total Threats', icon: AlertTriangle, tone: 'cyan', getValue: (items) => items.length },
  { label: 'Critical Threats', icon: ShieldAlert, tone: 'red', getValue: (items) => items.filter((threat) => threat.severity === 'CRITICAL').length },
  { label: 'Active Threats', icon: Clock3, tone: 'amber', getValue: (items) => items.filter((threat) => threat.status !== 'Resolved').length },
  { label: 'Resolved Threats', icon: ShieldCheck, tone: 'green', getValue: (items) => items.filter((threat) => threat.status === 'Resolved').length },
]

function SeverityBadge({ severity }) {
  return <span className={`severity severity--${severity.toLowerCase()}`}>{severity}</span>
}

function StatusBadge({ status }) {
  return <span className={`threat-status-badge threat-status-badge--${status.toLowerCase()}`}>{status}</span>
}

function ThreatSummary({ items }) {
  return (
    <section className="threat-summary-grid" aria-label="Threat summary">
      {summaryCards.map(({ label, icon: Icon, tone, getValue }) => (
        <article className={`threat-summary-card threat-summary-card--${tone}`} key={label}>
          <div className="threat-summary-copy"><span className="eyebrow">{label}</span><strong>{getValue(items)}</strong></div>
          <div className="threat-summary-icon"><Icon size={17} strokeWidth={1.8} /></div>
        </article>
      ))}
    </section>
  )
}

function ThreatFilters({ filters, onFilterChange, onClear, onExport, searchTerm, onSearchChange, filteredCount }) {
  const options = [
    ['severity', 'All Severities', threatFilterOptions.severities],
    ['type', 'All Threat Types', threatFilterOptions.types],
    ['status', 'All Statuses', threatFilterOptions.statuses],
    ['dateRange', 'Any Date', threatFilterOptions.dateRanges],
  ]
  return (
    <div className="threat-filter-bar">
      <label className="event-search">
        <Search size={14} />
        <input type="search" aria-label="Search threats" placeholder="Search threat, source, resource..." value={searchTerm} onChange={(event) => onSearchChange(event.target.value)} />
      </label>
      <div className="event-select-filters">
        {options.map(([name, placeholder, values]) => (
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
      <div className="threat-filter-actions">
        <button className="event-clear-button" onClick={onClear}><X size={12} />Clear Filters</button>
        <button className="toolbar-button" onClick={onExport}><Download size={13} />Export</button>
      </div>
      <div className="threat-filter-count"><Filter size={11} /> {filteredCount} matching threats</div>
    </div>
  )
}

function ThreatTable({ items, onSelect }) {
  return (
    <div className="threat-table-scroll">
      <table className="threat-table">
        <thead><tr><th>Threat</th><th>Type</th><th>Severity</th><th>Source</th><th>Detected At</th><th>Status</th><th>Action</th></tr></thead>
        <tbody>
          {items.map((threat) => (
            <tr key={threat.id} tabIndex={0} onClick={() => onSelect(threat)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(threat) } }}>
              <td><span className="threat-name">{threat.name}</span><span className="threat-id">{threat.id}</span></td>
              <td>{threat.type}</td>
              <td><SeverityBadge severity={threat.severity} /></td>
              <td>{threat.source}</td>
              <td className="event-time">{threat.detectedAt}</td>
              <td><StatusBadge status={threat.status} /></td>
              <td><button className="row-action" aria-label={`View details for ${threat.name}`} onClick={(event) => { event.stopPropagation(); onSelect(threat) }}><Eye size={14} /></button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ThreatDetailsDrawer({ threat, onClose, onResolve, onContain, onInvestigate }) {
  useEffect(() => {
    const onEscape = (event) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onEscape)
    return () => window.removeEventListener('keydown', onEscape)
  }, [onClose])

  return (
    <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
      <aside className="event-details-drawer threat-details-drawer" role="dialog" aria-modal="true" aria-labelledby="threat-details-title">
        <header className="event-drawer-header">
          <div><span className="eyebrow">Threat investigation</span><h2 id="threat-details-title">Threat Details</h2></div>
          <button className="icon-button" aria-label="Close threat details" onClick={onClose}><X size={17} /></button>
        </header>
        <div className="event-drawer-event-heading">
          <div><strong className="threat-detail-name">{threat.name}</strong><span className="event-drawer-date">{threat.id} · {threat.detectedAt}</span></div>
          <SeverityBadge severity={threat.severity} />
        </div>
        <section className="detail-section">
          <h3>Threat information</h3>
          <dl className="event-detail-grid">
            <div><dt>Threat type</dt><dd>{threat.type}</dd></div>
            <div><dt>Current status</dt><dd><StatusBadge status={threat.status} /></dd></div>
            <div><dt>Source</dt><dd>{threat.source}</dd></div>
            <div><dt>Detected at</dt><dd>{threat.detectedAt}</dd></div>
            <div><dt>Affected resource</dt><dd>{threat.affectedResource}</dd></div>
            <div><dt>Description</dt><dd>{threat.description}</dd></div>
          </dl>
        </section>
        <section className="detail-section"><h3>Indicators &amp; events</h3><ul className="threat-indicator-list">{threat.indicators.map((indicator) => <li key={indicator}>{indicator}</li>)}</ul></section>
        <section className="detail-section threat-response-section"><h3>Response taken / recommended</h3><p className="detail-body">{threat.response}</p></section>
        <div className="event-drawer-actions">
          <button className="toolbar-button" onClick={() => onInvestigate(threat)}><Search size={13} />Investigate</button>
          {threat.status !== 'Contained' && threat.status !== 'Resolved' && <button className="isolate-event-button" onClick={() => onContain(threat)}><ShieldAlert size={13} />Contain Threat</button>}
          {threat.status !== 'Resolved' && <button className="resolve-event-button" onClick={() => onResolve(threat.id)}><ShieldCheck size={13} />Mark Resolved</button>}
        </div>
      </aside>
    </div>
  )
}

export default function ThreatDetectionPage({ globalSearch, onGlobalSearchChange, onToast }) {
  const [filters, setFilters] = useState({ severity: '', type: '', status: '', dateRange: '' })
  const [items, setItems] = useState(initialThreats)
  const [selectedThreat, setSelectedThreat] = useState(null)

  const filteredThreats = useMemo(() => items.filter((threat) => {
    const query = globalSearch.trim().toLowerCase()
    const matchesQuery = !query || [threat.id, threat.name, threat.type, threat.source, threat.affectedResource, threat.description].some((value) => value.toLowerCase().includes(query))
    const matchesSeverity = !filters.severity || threat.severity === filters.severity
    const matchesType = !filters.type || threat.type === filters.type
    const matchesStatus = !filters.status || threat.status === filters.status
    const matchesDate = !filters.dateRange || (filters.dateRange === 'Last hour' ? threat.minutesAgo <= 60 : filters.dateRange === 'Last 24 hours' ? threat.minutesAgo <= 1440 : threat.minutesAgo <= 10080)
    return matchesQuery && matchesSeverity && matchesType && matchesStatus && matchesDate
  }), [filters, globalSearch, items])

  const updateStatus = (id, status) => {
    setItems((current) => current.map((threat) => threat.id === id ? { ...threat, status } : threat))
    setSelectedThreat((current) => current?.id === id ? { ...current, status } : current)
  }
  const clearFilters = () => {
    setFilters({ severity: '', type: '', status: '', dateRange: '' })
    onGlobalSearchChange('')
  }
  const exportThreats = () => {
    const headers = ['ID', 'Threat', 'Type', 'Severity', 'Source', 'Detected At', 'Status', 'Affected Resource', 'Response']
    const rows = filteredThreats.map((threat) => [threat.id, threat.name, threat.type, threat.severity, threat.source, threat.detectedAt, threat.status, threat.affectedResource, threat.response])
    const csv = [headers, ...rows].map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\n')
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'threat-detection-report.csv'
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <main className="threat-detection-main">
      <section className="threat-page-heading"><div><h1>Threat Detection</h1><p>Monitor detected threats, suspicious activity, and security events across the backup environment.</p></div></section>
      <ThreatSummary items={items} />
      <section className="panel threat-log-panel" aria-labelledby="threat-log-heading">
        <header className="threat-log-heading">
          <div><h2 id="threat-log-heading">Detected Threats</h2><p>Prioritized threats and automated response status</p></div>
          <span className="live-indicator"><i className="status-dot status-dot--green" />MONITORING ACTIVE</span>
        </header>
        <ThreatFilters filters={filters} onFilterChange={(name, value) => setFilters((current) => ({ ...current, [name]: value }))} onClear={clearFilters} onExport={exportThreats} searchTerm={globalSearch} onSearchChange={onGlobalSearchChange} filteredCount={filteredThreats.length} />
        {filteredThreats.length > 0 ? <ThreatTable items={filteredThreats} onSelect={setSelectedThreat} /> : <div className="threat-empty-state"><CircleHelp size={17} />No threats match the selected filters</div>}
        <footer className="threat-log-footer"><span><i className="status-dot status-dot--green" />Threat monitoring operational</span><span>{filteredThreats.length} threats displayed <span className="footer-divider">|</span> Mock data source</span></footer>
      </section>
      {selectedThreat && <ThreatDetailsDrawer
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
        onResolve={(id) => { updateStatus(id, 'Resolved'); onToast('Threat marked as resolved') }}
        onContain={(threat) => { updateStatus(threat.id, 'Contained'); onToast(`${threat.name} contained`) }}
        onInvestigate={(threat) => { updateStatus(threat.id, 'Investigating'); onToast(`Investigation started for ${threat.name}`) }}
      />}
    </main>
  )
}