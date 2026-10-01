import { useMemo, useState } from 'react'
import { Activity, Check, Clock3, Database, Eye, FileCheck2, LockKeyhole, Play, RefreshCw, RotateCcw, ShieldCheck, X } from 'lucide-react'
import { recoveryActivity, recoveryReadiness, recoverySummary, restorePoints as initialRestorePoints } from '../data/recoveryData.js'
import './RecoveryPage.css'

const summaryIcons = { ready: ShieldCheck, points: Database, warning: FileCheck2, jobs: RotateCcw, recent: Clock3 }

function RecoverySummary() {
  return <section className="recovery-summary-grid" aria-label="Recovery summary">{recoverySummary.map((item) => {
    const Icon = summaryIcons[item.icon]
    return <article className={`recovery-summary-card recovery-summary-card--${item.tone}`} key={item.label}><div className="recovery-summary-copy"><span className="eyebrow">{item.label}</span><strong>{item.value}</strong><span>{item.support}</span></div><div className="recovery-summary-icon"><Icon size={17} strokeWidth={1.8} /></div></article>
  })}</section>
}

function RecoveryBadge({ status }) {
  return <span className={`recovery-status-badge recovery-status-badge--${status.toLowerCase().replaceAll(' ', '-')}`}><i />{status}</span>
}

function RecoveryReadinessPanel({ points }) {
  const readyCount = points.filter((point) => point.readiness === 'Recovery Ready').length
  const pendingCount = points.filter((point) => point.readiness === 'Verification Required').length
  const failedCount = points.filter((point) => point.readiness === 'Not Ready').length
  return <section className="panel recovery-health-panel" aria-labelledby="recovery-health-heading">
    <header className="recovery-section-heading"><div><h2 id="recovery-health-heading">Recovery Readiness</h2><p>Verified restore points available for safe recovery</p></div><span className="recovery-readiness-percent">{Math.round((readyCount / Math.max(points.length, 1)) * 100)}%</span></header>
    <div className="recovery-readiness-track" role="img" aria-label={`${readyCount} of ${points.length} restore points recovery ready`}><i className="recovery-track-ready" style={{ width: `${(readyCount / Math.max(points.length, 1)) * 100}%` }} /><i className="recovery-track-warning" style={{ width: `${(pendingCount / Math.max(points.length, 1)) * 100}%` }} /><i className="recovery-track-failed" style={{ width: `${(failedCount / Math.max(points.length, 1)) * 100}%` }} /></div>
    <div className="recovery-readiness-legend"><span><i className="recovery-legend-dot recovery-legend-dot--ready" />Ready <b>{readyCount}</b></span><span><i className="recovery-legend-dot recovery-legend-dot--warning" />Verification Required <b>{pendingCount}</b></span><span><i className="recovery-legend-dot recovery-legend-dot--failed" />Not Ready <b>{failedCount}</b></span></div>
    <div className="recovery-readiness-note"><ShieldCheck size={13} /><span>Recovery jobs run in an isolated network before production restoration.</span></div>
  </section>
}

function RecoveryPlan({ active }) {
  const steps = [
    { title: 'Select verified restore point', detail: 'Choose a clean, integrity-verified backup', done: true },
    { title: 'Prepare isolated environment', detail: 'Restore without production network access', done: true },
    { title: 'Validate services and data', detail: 'Run malware scan and checksum validation', done: active },
    { title: 'Approve production cutover', detail: 'Analyst approval required before release', done: false },
  ]
  return <section className="panel recovery-plan-panel" aria-labelledby="recovery-plan-heading"><header className="recovery-section-heading"><div><h2 id="recovery-plan-heading">Recovery Workflow</h2><p>Controlled restore sequence and approval gates</p></div><span className="live-indicator"><i className={`status-dot ${active ? 'status-dot--cyan' : 'status-dot--green'}`} />{active ? 'JOB IN PROGRESS' : 'READY'}</span></header>
    <ol className="recovery-plan-list">{steps.map((step, index) => <li className={step.done ? 'recovery-plan-step recovery-plan-step--done' : 'recovery-plan-step'} key={step.title}><i>{step.done ? <Check size={10} /> : index + 1}</i><div><strong>{step.title}</strong><span>{step.detail}</span></div></li>)}</ol>
  </section>
}

function RestorePointTable({ points, search, onSelect, onRecover }) {
  const filtered = useMemo(() => points.filter((point) => Object.values(point).some((value) => String(value).toLowerCase().includes(search.trim().toLowerCase()))), [points, search])
  return <section className="panel restore-points-panel" aria-labelledby="restore-points-heading"><header className="recovery-section-heading"><div><h2 id="restore-points-heading">Available Restore Points</h2><p>Clean recovery points and integrity verification status</p></div><span className="live-indicator"><i className="status-dot status-dot--green" />VAULT ONLINE</span></header>
    <div className="restore-points-table-scroll"><table className="restore-points-table"><thead><tr><th>Restore Point</th><th>System</th><th>Type</th><th>Size</th><th>Created</th><th>Integrity</th><th>Readiness</th><th>Action</th></tr></thead><tbody>{filtered.map((point) => <tr key={point.id} tabIndex={0} onClick={() => onSelect(point)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(point) } }}>
      <td className="recovery-point-id">{point.id}</td><td>{point.system}</td><td>{point.type}</td><td>{point.size}</td><td className="event-time">{point.created}</td><td><RecoveryBadge status={point.integrity} /></td><td><RecoveryBadge status={point.readiness} /></td><td><div className="recovery-row-actions"><button className="row-action" aria-label={`View ${point.id} details`} onClick={(event) => { event.stopPropagation(); onSelect(point) }}><Eye size={14} /></button>{point.readiness === 'Recovery Ready' && <button className="recovery-start-row" onClick={(event) => { event.stopPropagation(); onRecover(point) }}>Restore</button>}</div></td>
    </tr>)}{filtered.length === 0 && <tr><td className="recovery-no-results" colSpan="8">No restore points match the current search.</td></tr>}</tbody></table></div>
    <footer className="recovery-table-footer"><span>Showing {filtered.length} of {points.length} restore points</span><span>Failed or unverified points cannot be restored</span></footer>
  </section>
}

function RecoveryReadinessList() {
  return <section className="panel recovery-system-list-panel" aria-labelledby="recovery-systems-heading"><header className="recovery-section-heading"><div><h2 id="recovery-systems-heading">Protected Systems</h2><p>Latest clean restore point by resource</p></div></header><div className="recovery-system-list">{recoveryReadiness.map((item) => <div className="recovery-system-row" key={item.system}><div className="recovery-system-copy"><span className={`recovery-system-dot recovery-system-dot--${item.readiness === 'Recovery Ready' ? 'ready' : item.readiness === 'Not Ready' ? 'failed' : 'warning'}`} /><div><strong>{item.system}</strong><span>{item.point} · verified {item.verified}</span></div></div><RecoveryBadge status={item.readiness} /></div>)}</div></section>
}

function RecoveryActivity() {
  return <section className="panel recovery-activity-panel" aria-labelledby="recovery-activity-heading"><header className="recovery-section-heading"><div><h2 id="recovery-activity-heading">Recent Recovery Activity</h2><p>Restore validation and recovery job events</p></div></header><ol className="recovery-activity-list">{recoveryActivity.map((item) => <li className={`recovery-activity-item recovery-activity-item--${item.type}`} key={`${item.time}-${item.title}`}><span>{item.time}</span><i /><div><strong>{item.title}</strong><small>{item.system}</small></div></li>)}</ol></section>
}

function RestoreDetails({ point, onClose, onVerify, onRecover }) {
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer recovery-details-drawer" role="dialog" aria-modal="true" aria-labelledby="restore-details-title">
    <header className="event-drawer-header"><div><span className="eyebrow">Verified recovery point</span><h2 id="restore-details-title">Restore Details</h2></div><button className="icon-button" aria-label="Close restore point details" onClick={onClose}><X size={17} /></button></header>
    <div className="event-drawer-event-heading"><div><strong className="restore-drawer-id">{point.id}</strong><span className="event-drawer-date">{point.system} · {point.created}</span></div><RecoveryBadge status={point.readiness} /></div>
    <section className="detail-section"><h3>Restore point information</h3><dl className="event-detail-grid"><div><dt>Source system</dt><dd>{point.system}</dd></div><div><dt>Backup type</dt><dd>{point.type}</dd></div><div><dt>File size</dt><dd>{point.size}</dd></div><div><dt>Creation time</dt><dd>{point.created}</dd></div><div><dt>Encryption</dt><dd><span className="recovery-encryption"><LockKeyhole size={12} />{point.encrypted}</span></dd></div><div><dt>Integrity</dt><dd><RecoveryBadge status={point.integrity} /></dd></div><div><dt>Verification time</dt><dd>{point.verifiedAt}</dd></div><div><dt>Recovery environment</dt><dd>{point.environment}</dd></div><div><dt>Checksum</dt><dd className="recovery-checksum">{point.checksum}</dd></div></dl></section>
    <section className="detail-section"><h3>Safety gate</h3><p className="detail-body">{point.readiness === 'Recovery Ready' ? 'This restore point passed integrity verification and is eligible for recovery in an isolated environment. Production cutover requires analyst approval.' : point.readiness === 'Verification Required' ? 'Integrity verification is required before this restore point can be used for recovery.' : 'This point is quarantined and must not be restored. Select an earlier verified recovery point.'}</p></section>
    <div className="event-drawer-actions"><button className="toolbar-button" onClick={() => onVerify(point)}><FileCheck2 size={13} />Verify Integrity</button><button className="recovery-drawer-start" disabled={point.readiness !== 'Recovery Ready'} onClick={() => onRecover(point)}><Play size={12} />Start Recovery</button></div>
  </aside></div>
}

export default function RecoveryPage({ globalSearch = '', onToast }) {
  const [points, setPoints] = useState(initialRestorePoints)
  const [selectedPoint, setSelectedPoint] = useState(null)
  const [jobActive, setJobActive] = useState(true)
  const [refreshed, setRefreshed] = useState(false)
  const toast = onToast ?? (() => {})
  const verifyPoint = (point) => {
    if (point.integrity === 'Failed') { toast(`${point.id} failed integrity and remains quarantined`); return }
    setPoints((current) => current.map((item) => item.id === point.id ? { ...item, integrity: 'Verified', readiness: 'Recovery Ready', verifiedAt: 'Just now' } : item))
    setSelectedPoint((current) => current?.id === point.id ? { ...current, integrity: 'Verified', readiness: 'Recovery Ready', verifiedAt: 'Just now' } : current)
    toast(`Integrity verification completed for ${point.id}`)
  }
  const startRecovery = (point) => {
    setJobActive(true)
    toast(`Recovery job queued for ${point.system} in an isolated environment`)
    setSelectedPoint(null)
  }
  return <main className="recovery-main">
    <section className="recovery-page-heading"><div><h1>Recovery</h1><p>Validate recovery readiness and restore protected systems safely.</p></div><div className="recovery-page-actions"><span>{refreshed ? 'Updated just now' : 'Recovery status synced 2 min ago'}</span><button className="toolbar-button" onClick={() => { setRefreshed(true); toast('Recovery status refreshed') }}><RefreshCw size={13} />Refresh</button><button className="action-button action-button--neutral recovery-test-button" onClick={() => { setJobActive(true); toast('Recovery test started in isolated environment') }}><Activity size={13} />Run Recovery Test</button></div></section>
    <RecoverySummary />
    <div className="recovery-overview-grid"><RecoveryReadinessPanel points={points} /><RecoveryPlan active={jobActive} /></div>
    <RestorePointTable points={points} search={globalSearch} onSelect={setSelectedPoint} onRecover={startRecovery} />
    <div className="recovery-support-grid"><RecoveryReadinessList /><RecoveryActivity /></div>
    <footer className="recovery-page-footer"><span><i className="status-dot status-dot--green" />Recovery orchestration operational</span><span>Restore policy: Isolated validation <span className="footer-divider">|</span> Mock data source</span></footer>
    {selectedPoint && <RestoreDetails point={selectedPoint} onClose={() => setSelectedPoint(null)} onVerify={verifyPoint} onRecover={startRecovery} />}
  </main>
}
