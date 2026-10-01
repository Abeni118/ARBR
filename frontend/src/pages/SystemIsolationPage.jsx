import { useMemo, useState } from 'react'
import { Activity, AlertTriangle, Check, Clock3, Eye, LockKeyhole, RefreshCw, RotateCcw, Server, Shield, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import { isolationActivity, isolationSummary, isolatedSystems as initialSystems } from '../data/systemIsolationData.js'
import './SystemIsolationPage.css'

const summaryIcons = { systems: Server, isolated: LockKeyhole, pending: Clock3, critical: ShieldAlert, recent: Activity }

function IsolationSummary() {
  return <section className="isolation-summary-grid" aria-label="System isolation summary">
    {isolationSummary.map((item) => {
      const Icon = summaryIcons[item.icon]
      return <article className={`isolation-summary-card isolation-summary-card--${item.tone}`} key={item.label}>
        <div className="isolation-summary-copy"><span className="eyebrow">{item.label}</span><strong>{item.value}</strong><span className="isolation-summary-support">{item.support}</span></div>
        <div className="isolation-summary-icon"><Icon size={17} strokeWidth={1.8} /></div>
      </article>
    })}
  </section>
}

function IsolationBadge({ status }) {
  return <span className={`isolation-status-badge isolation-status-badge--${status.toLowerCase().replaceAll(' ', '-')}`}><i />{status}</span>
}

function IsolationStatusPanel({ systems }) {
  const counts = [
    { label: 'Active Isolation', count: systems.filter((item) => item.status === 'Isolated').length, tone: 'red', Icon: LockKeyhole },
    { label: 'Pending Isolation', count: systems.filter((item) => item.status === 'Isolation Pending').length, tone: 'amber', Icon: Clock3 },
    { label: 'Isolation Failed', count: systems.filter((item) => item.status === 'Isolation Failed').length, tone: 'red', Icon: AlertTriangle },
    { label: 'Cleared / Released', count: systems.filter((item) => item.status === 'Released').length, tone: 'green', Icon: ShieldCheck },
  ]
  return <section className="panel isolation-status-panel" aria-labelledby="isolation-status-heading">
    <header className="isolation-section-heading"><div><h2 id="isolation-status-heading">Isolation Status</h2><p>Containment controls across monitored network segments</p></div><IsolationBadge status="Active" /></header>
    <div className="isolation-status-summary"><div className="isolation-status-mark"><Shield size={18} /></div><div><strong>{counts[0].count} systems currently isolated</strong><span>Network containment is active for high-risk resources</span></div><span className="live-indicator"><i className="status-dot status-dot--green" />POLICY ENFORCED</span></div>
    <div className="isolation-count-grid">{counts.map(({ label, count, tone, Icon }) => <div className={`isolation-count isolation-count--${tone}`} key={label}><Icon size={14} /><strong>{count}</strong><span>{label}</span></div>)}</div>
  </section>
}

function AffectedSystemsTable({ systems, search, onSelect, onAction }) {
  const filtered = useMemo(() => systems.filter((item) => Object.values(item).some((value) => String(value).toLowerCase().includes(search.trim().toLowerCase()))), [systems, search])
  return <section className="panel isolation-table-panel" aria-labelledby="affected-systems-heading">
    <header className="isolation-section-heading"><div><h2 id="affected-systems-heading">Affected Systems</h2><p>Threat-affected assets and current containment actions</p></div><span className="live-indicator"><i className="status-dot status-dot--cyan" />{filtered.length} SYSTEMS DISPLAYED</span></header>
    <div className="isolation-table-scroll"><table className="isolation-table"><thead><tr><th>System</th><th>IP Address</th><th>Risk Level</th><th>Threat</th><th>Isolation Status</th><th>Isolation Time</th><th>Current Action</th><th>Action</th></tr></thead><tbody>
      {filtered.map((system) => <tr key={system.id} tabIndex={0} onClick={() => onSelect(system)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(system) } }}>
        <td><span className="isolation-system-name">{system.system}</span><span className="isolation-system-id">{system.id}</span></td><td className="event-time">{system.ip}</td><td><span className={`severity severity--${system.risk.toLowerCase()}`}>{system.risk}</span></td><td>{system.threat}</td><td><IsolationBadge status={system.status} /></td><td className="event-time">{system.isolationTime}</td><td>{system.action}</td>
        <td><div className="isolation-row-actions"><button className="row-action" aria-label={`View ${system.system} isolation details`} onClick={(event) => { event.stopPropagation(); onSelect(system) }}><Eye size={14} /></button>{system.status !== 'Released' && <button className={`isolation-row-action ${system.status === 'Isolated' ? 'isolation-row-action--release' : ''}`} onClick={(event) => { event.stopPropagation(); onAction(system) }}>{system.status === 'Isolated' ? 'Release' : system.status === 'Isolation Failed' ? 'Retry' : 'Isolate'}</button>}</div></td>
      </tr>)}
      {filtered.length === 0 && <tr><td className="isolation-no-results" colSpan="8">No systems match the current search.</td></tr>}
    </tbody></table></div>
    <footer className="isolation-table-footer"><span>Mock isolation telemetry</span><span>Select a row to inspect containment details</span></footer>
  </section>
}

function IsolationActivity() {
  return <section className="panel isolation-activity-panel" aria-labelledby="isolation-activity-heading">
    <header className="isolation-section-heading"><div><h2 id="isolation-activity-heading">Recent Isolation Activity</h2><p>Containment decisions and network policy events</p></div></header>
    <ol className="isolation-activity-list">{isolationActivity.map((entry) => <li className={`isolation-activity-item isolation-activity-item--${entry.type}`} key={`${entry.time}-${entry.title}`}><span>{entry.time}</span><i /><div><strong>{entry.title}</strong><small>{entry.system}</small></div></li>)}</ol>
  </section>
}

function IsolationDetails({ system, onClose, onAction }) {
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer isolation-details-drawer" role="dialog" aria-modal="true" aria-labelledby="isolation-details-title">
    <header className="event-drawer-header"><div><span className="eyebrow">Containment workspace</span><h2 id="isolation-details-title">System Isolation</h2></div><button className="icon-button" aria-label="Close isolation details" onClick={onClose}><X size={17} /></button></header>
    <div className="event-drawer-event-heading"><div><strong className="isolation-drawer-name">{system.system}</strong><span className="event-drawer-date">{system.id} · {system.ip}</span></div><IsolationBadge status={system.status} /></div>
    <section className="detail-section"><h3>System information</h3><dl className="event-detail-grid"><div><dt>System</dt><dd>{system.system}</dd></div><div><dt>IP address</dt><dd>{system.ip}</dd></div><div><dt>System type</dt><dd>{system.type}</dd></div><div><dt>Network segment</dt><dd>{system.segment}</dd></div><div><dt>Risk level</dt><dd><span className={`severity severity--${system.risk.toLowerCase()}`}>{system.risk}</span></dd></div><div><dt>Threat</dt><dd>{system.threat}</dd></div><div><dt>Isolation time</dt><dd>{system.isolationTime}</dd></div><div><dt>Current action</dt><dd>{system.action}</dd></div></dl></section>
    <section className="detail-section"><h3>Containment status</h3><p className="detail-body">{system.status === 'Isolated' ? 'Network access is restricted by the isolation policy. Forensic access remains available to authorized responders.' : system.status === 'Isolation Pending' ? 'The isolation request is queued and awaiting endpoint acknowledgement.' : system.status === 'Isolation Failed' ? 'The endpoint did not acknowledge the isolation request. Review agent connectivity before retrying.' : 'This system has been released from isolation and returned to normal network policy.'}</p></section>
    <div className="event-drawer-actions"><button className="toolbar-button" onClick={() => onAction(system)}><RotateCcw size={13} />{system.status === 'Isolated' ? 'Release System' : 'Apply Isolation'}</button><button className="resolve-event-button" onClick={onClose}><Check size={13} />Done</button></div>
  </aside></div>
}

export default function SystemIsolationPage({ globalSearch = '', onToast }) {
  const [systems, setSystems] = useState(initialSystems)
  const [selectedSystem, setSelectedSystem] = useState(null)
  const [refreshed, setRefreshed] = useState(false)
  const toast = onToast ?? (() => {})
  const updateIsolation = (system) => {
    const nextStatus = system.status === 'Isolated' ? 'Released' : 'Isolated'
    const nextAction = nextStatus === 'Isolated' ? 'Under Investigation' : 'Released by analyst'
    setSystems((current) => current.map((item) => item.id === system.id ? { ...item, status: nextStatus, action: nextAction, isolationTime: nextStatus === 'Isolated' ? 'Just now' : item.isolationTime } : item))
    setSelectedSystem((current) => current?.id === system.id ? { ...current, status: nextStatus, action: nextAction } : current)
    toast(nextStatus === 'Isolated' ? `${system.system} isolation request applied` : `${system.system} released from isolation`)
  }
  return <main className="system-isolation-main">
    <section className="isolation-page-heading"><div><h1>System Isolation</h1><p>Monitor and manage isolated systems to contain active security threats.</p></div><div className="isolation-page-actions"><IsolationBadge status="Active" /><span>{refreshed ? 'Updated just now' : 'Policy sync 4 min ago'}</span><button className="toolbar-button" onClick={() => { setRefreshed(true); toast('Isolation status refreshed') }}><RefreshCw size={13} />Refresh</button></div></section>
    <IsolationSummary />
    <IsolationStatusPanel systems={systems} />
    <div className="isolation-content-grid"><AffectedSystemsTable systems={systems} search={globalSearch} onSelect={setSelectedSystem} onAction={updateIsolation} /><IsolationActivity /></div>
    <footer className="isolation-page-footer"><span><i className="status-dot status-dot--green" />Isolation policy operational</span><span>Network controls: Enforced <span className="footer-divider">|</span> Mock data source</span></footer>
    {selectedSystem && <IsolationDetails system={selectedSystem} onClose={() => setSelectedSystem(null)} onAction={updateIsolation} />}
  </main>
}
