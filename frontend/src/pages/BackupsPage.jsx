import { useMemo, useState } from 'react'
import { Check, Clock3, Database, Eye, FileCheck2, LockKeyhole, Plus, RefreshCw, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import { backupActivity, backupRecords, backupSummary } from '../data/backupData.js'
import './BackupsPage.css'

const summaryIcons = { total: Database, healthy: ShieldCheck, warning: FileCheck2, failed: ShieldAlert, recent: Clock3 }

function BackupSummaryCards() {
  return <section className="backup-summary-grid" aria-label="Backup summary">
    {backupSummary.map((item) => {
      const Icon = summaryIcons[item.icon]
      return <article className={`backup-summary-card backup-summary-card--${item.tone}`} key={item.label}>
        <div className="backup-summary-copy"><span className="eyebrow">{item.label}</span><strong>{item.value}</strong><span className="backup-summary-support">{item.support}</span></div>
        <div className="backup-summary-icon"><Icon size={17} strokeWidth={1.8} /></div>
      </article>
    })}
  </section>
}

function BackupHealth({ items }) {
  const verifying = items.filter((item) => item.integrity === 'Verifying').length
  return <section className="panel backup-health-panel" aria-labelledby="backup-health-heading">
    <header className="backup-section-heading"><div><h2 id="backup-health-heading">Backup Health</h2><p>Repository health and verification status</p></div><strong className="backup-health-value">82%</strong></header>
    <div className="backup-health-track" role="img" aria-label="Backup health 82 percent"><i className="backup-health-good" /><i className="backup-health-warning" /><i className="backup-health-failed" /></div>
    <div className="backup-health-legend"><span><i className="backup-legend-dot backup-legend-dot--healthy" />Healthy <b>19</b></span><span><i className="backup-legend-dot backup-legend-dot--warning" />Warning <b>{3 + verifying}</b></span><span><i className="backup-legend-dot backup-legend-dot--failed" />Failed <b>2</b></span></div>
    <p className="backup-health-note"><ShieldCheck size={13} /> Immutable storage integrity is operational</p>
  </section>
}

function IntegrityPanel({ items, onVerifyAll }) {
  const pending = items.filter((item) => item.integrity === 'Warning' || item.integrity === 'Verifying').length
  return <section className="panel backup-integrity-panel" aria-labelledby="backup-integrity-heading">
    <header className="backup-section-heading"><div><h2 id="backup-integrity-heading">Backup Integrity</h2><p>Integrity Verification</p></div><span className="backup-integrity-mark"><LockKeyhole size={15} /> SHA-256</span></header>
    <div className="integrity-verified-time"><span>Last verified</span><strong>5 minutes ago</strong></div>
    <div className="integrity-count-grid"><div><strong>19</strong><span>Verified</span></div><div><strong>{pending || 3}</strong><span>Pending</span></div><div><strong>2</strong><span>Failed</span></div></div>
    <button className="toolbar-button verify-all-button" onClick={onVerifyAll}><FileCheck2 size={13} />Verify All Backups</button>
  </section>
}

function BackupStatus({ status }) {
  const className = status.toLowerCase().replaceAll(' ', '-')
  return <span className={`backup-status-badge backup-status-badge--${className}`}><i />{status}</span>
}

function BackupTable({ items, search, onSelect, onVerify }) {
  const filtered = useMemo(() => items.filter((item) => Object.values(item).some((value) => String(value).toLowerCase().includes(search.trim().toLowerCase()))), [items, search])
  return <section className="panel backup-repository-panel" aria-labelledby="backup-repository-heading">
    <header className="backup-section-heading"><div><h2 id="backup-repository-heading">Backup Repository</h2><p>Protected recovery points and latest integrity checks</p></div><span className="live-indicator"><i className="status-dot status-dot--green" />REPOSITORY ONLINE</span></header>
    <div className="backup-table-scroll"><table className="backup-table"><thead><tr><th>Backup ID</th><th>System / Resource</th><th>Backup Type</th><th>Size</th><th>Created</th><th>Integrity</th><th>Status</th><th>Actions</th></tr></thead><tbody>
      {filtered.map((item) => <tr key={item.id} tabIndex={0} onClick={() => onSelect(item)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(item) } }}>
        <td className="backup-id">{item.id}</td><td>{item.resource}</td><td>{item.type}</td><td>{item.size}</td><td className="event-time">{item.created}</td><td><BackupStatus status={item.integrity} /></td><td><BackupStatus status={item.status} /></td>
        <td><div className="backup-row-actions"><button className="row-action" aria-label={`View ${item.id} details`} onClick={(event) => { event.stopPropagation(); onSelect(item) }}><Eye size={14} /></button>{item.integrity === 'Warning' && <button className="backup-verify-row" onClick={(event) => { event.stopPropagation(); onVerify(item.id) }}>Verify</button>}</div></td>
      </tr>)}
      {filtered.length === 0 && <tr><td className="backup-no-results" colSpan="8">No backups match the current search.</td></tr>}
    </tbody></table></div>
    <footer className="backup-table-footer"><span>Showing {filtered.length} of {items.length} recent backups</span><span>Select a row to inspect recovery details</span></footer>
  </section>
}

function RecoveryReadiness({ items }) {
  return <section className="panel recovery-readiness-panel" aria-labelledby="recovery-readiness-heading">
    <header className="backup-section-heading"><div><h2 id="recovery-readiness-heading">Recovery Readiness</h2><p>Latest verified restore points by system</p></div></header>
    <div className="readiness-list">{items.map((item) => {
      const readiness = item.integrity === 'Verified' && item.status === 'Healthy' ? 'Recovery Ready' : item.integrity === 'Warning' || item.integrity === 'Verifying' ? 'Verification Required' : 'Not Ready'
      return <div className="readiness-row" key={item.resource}><div className="readiness-resource"><span className={`readiness-state-dot readiness-state-dot--${readiness === 'Recovery Ready' ? 'ready' : readiness === 'Not Ready' ? 'failed' : 'warning'}`} /><div><strong>{item.resource}</strong><span>Last verified: {item.verifiedAt}</span></div></div><BackupStatus status={readiness} /></div>
    })}</div>
  </section>
}

function BackupActivity() {
  return <section className="panel backup-activity-panel" aria-labelledby="backup-activity-heading">
    <header className="backup-section-heading"><div><h2 id="backup-activity-heading">Recent Backup Activity</h2><p>Latest repository and integrity events</p></div></header>
    <ol className="backup-activity-list">{backupActivity.map((activity) => <li key={`${activity.time}-${activity.title}`} className={`backup-activity-item backup-activity-item--${activity.type}`}>
      <span className="backup-activity-time">{activity.time}</span><i className="backup-activity-marker" /><div><strong>{activity.title}</strong><span>{activity.resource}</span></div>
    </li>)}</ol>
  </section>
}

function BackupDetailsDrawer({ backup, onClose, onVerify }) {
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
    <aside className="event-details-drawer backup-details-drawer" role="dialog" aria-modal="true" aria-labelledby="backup-details-title">
      <header className="event-drawer-header"><div><span className="eyebrow">Recovery point</span><h2 id="backup-details-title">Backup Details</h2></div><button className="icon-button" aria-label="Close backup details" onClick={onClose}><X size={17} /></button></header>
      <div className="backup-drawer-record"><div><strong>{backup.id}</strong><span>{backup.resource} · {backup.created}</span></div><BackupStatus status={backup.status} /></div>
      <section className="detail-section"><h3>Backup information</h3><dl className="event-detail-grid">
        <div><dt>Backup ID</dt><dd className="backup-id">{backup.id}</dd></div><div><dt>Source system</dt><dd>{backup.resource}</dd></div>
        <div><dt>Backup type</dt><dd>{backup.type}</dd></div><div><dt>File size</dt><dd>{backup.size}</dd></div>
        <div><dt>Creation time</dt><dd>{backup.created}</dd></div><div><dt>Encryption</dt><dd><span className="backup-encryption"><LockKeyhole size={12} />{backup.encryption}</span></dd></div>
        <div><dt>Integrity status</dt><dd><BackupStatus status={backup.integrity} /></dd></div><div><dt>Verification time</dt><dd>{backup.verifiedAt}</dd></div>
        <div><dt>Checksum</dt><dd className="backup-checksum">{backup.checksum}</dd></div><div><dt>Recovery ready</dt><dd><BackupStatus status={backup.recoveryReady} /></dd></div>
      </dl></section>
      <div className="backup-drawer-actions"><button className="toolbar-button" onClick={() => onVerify(backup.id)}><FileCheck2 size={13} />Verify Integrity</button><button className="resolve-event-button" onClick={onClose}><Check size={13} />Done</button></div>
    </aside>
  </div>
}

export default function BackupsPage({ globalSearch = '', onToast }) {
  const [items, setItems] = useState(backupRecords)
  const [selectedBackup, setSelectedBackup] = useState(null)
  const [refreshed, setRefreshed] = useState(false)
  const toast = onToast ?? (() => {})

  const verifyBackups = (ids) => {
    setItems((current) => current.map((item) => ids.includes(item.id) && item.integrity !== 'Failed' ? { ...item, integrity: 'Verifying', status: 'Verifying' } : item))
    toast(ids.length > 1 ? 'Backup integrity verification started' : 'Backup integrity verification started')
    window.setTimeout(() => {
      setItems((current) => current.map((item) => ids.includes(item.id) && item.integrity === 'Verifying' ? { ...item, integrity: 'Verified', status: 'Healthy', recoveryReady: 'Yes', verifiedAt: 'Just now' } : item))
      setSelectedBackup((current) => current && ids.includes(current.id) ? { ...current, integrity: 'Verified', status: 'Healthy', recoveryReady: 'Yes', verifiedAt: 'Just now' } : current)
      toast('Backup integrity verification completed')
    }, 900)
  }

  return <main className="backups-main">
    <section className="backups-page-heading"><div><h1>Backups</h1><p>Monitor backup health, integrity, and recovery readiness.</p></div>
      <div className="backups-page-actions"><span className="backup-updated-label">{refreshed ? 'Updated just now' : 'Repository synced 5 min ago'}</span><button className="toolbar-button" onClick={() => { setRefreshed(true); toast('Backup repository refreshed') }}><RefreshCw size={13} />Refresh</button><button className="toolbar-button backup-create-button" onClick={() => toast('Backup job queued for the next scheduled run')}><Plus size={13} />Create Backup</button></div>
    </section>
    <BackupSummaryCards />
    <div className="backup-overview-grid"><BackupHealth items={items} /><IntegrityPanel items={items} onVerifyAll={() => verifyBackups(items.filter((item) => item.integrity === 'Warning').map((item) => item.id))} /></div>
    <BackupTable items={items} search={globalSearch} onSelect={setSelectedBackup} onVerify={(id) => verifyBackups([id])} />
    <div className="backup-support-grid"><RecoveryReadiness items={items} /><BackupActivity /></div>
    <footer className="backups-page-footer"><span><i className="status-dot status-dot--green" />Backup repository operational</span><span>Retention policy: 365 days <span className="footer-divider">|</span> Mock data source</span></footer>
    {selectedBackup && <BackupDetailsDrawer backup={selectedBackup} onClose={() => setSelectedBackup(null)} onVerify={(id) => verifyBackups([id])} />}
  </main>
}