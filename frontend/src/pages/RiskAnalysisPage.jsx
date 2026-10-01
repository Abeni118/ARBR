import { useMemo, useState } from 'react'
import { Activity, AlertTriangle, Clock3, Database, Fingerprint, RefreshCw, Shield, ShieldAlert, ShieldCheck } from 'lucide-react'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { affectedResources, riskContributors, riskFactors, riskHistory, riskSummary } from '../data/riskAnalysisData.js'
import './RiskAnalysisPage.css'

const summaryIcons = { risk: Fingerprint, critical: ShieldAlert, resources: Database, threats: AlertTriangle, assessment: Clock3 }

function RiskSummaryCards() {
  return <section className="risk-summary-grid" aria-label="Risk summary">
    {riskSummary.map((item) => {
      const Icon = summaryIcons[item.icon]
      return <article className={`risk-summary-card risk-summary-card--${item.tone}`} key={item.label}>
        <div className="risk-summary-copy"><span className="eyebrow">{item.label}</span><strong>{item.value}</strong><span className="risk-summary-support">{item.support}</span></div>
        <div className="risk-summary-icon"><Icon size={17} strokeWidth={1.8} /></div>
      </article>
    })}
  </section>
}

function RiskScorePanel() {
  return <section className="panel risk-score-panel" aria-labelledby="risk-score-heading">
    <header className="risk-section-heading"><div><h2 id="risk-score-heading">Current Risk Score</h2><p>Composite assessment across active security signals</p></div><span className="severity severity--high">HIGH</span></header>
    <div className="risk-score-content">
      <div className="risk-score-meter" role="img" aria-label="Risk score 78 out of 100, high">
        <div className="risk-score-meter-inner"><strong>78</strong><span>/ 100</span><b>HIGH</b></div>
      </div>
      <div className="risk-contributors"><span className="eyebrow">Contributing factors</span>{riskContributors.map((factor) => <div className="risk-contributor" key={factor.label}>
        <div><span>{factor.label}</span><strong>+{factor.value}</strong></div><div className="risk-factor-track"><i style={{ width: `${factor.value * 2.4}%` }} /></div>
      </div>)}</div>
    </div>
    <div className="risk-score-scale"><span>LOW 0–24</span><span>MEDIUM 25–49</span><span>HIGH 50–74</span><span>CRITICAL 75–100</span></div>
  </section>
}

function RiskHistoryChart() {
  return <section className="panel risk-history-panel" aria-labelledby="risk-history-heading">
    <header className="risk-section-heading"><div><h2 id="risk-history-heading">Risk History</h2><p>Risk score progression over the last 90 minutes</p></div><span className="chart-legend"><i className="legend-dot legend-dot--risk" />Risk score</span></header>
    <div className="risk-history-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={riskHistory} margin={{ top: 10, right: 8, bottom: 0, left: -14 }}>
      <CartesianGrid vertical={false} stroke="#30343d" strokeDasharray="2 5" />
      <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} dy={8} />
      <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} />
      <Tooltip contentStyle={{ border: '1px solid #384253', borderRadius: 2, color: '#dce3ec', background: '#131e33', fontSize: 9 }} />
      <Line type="monotone" dataKey="score" name="Risk score" stroke="#09c7d8" strokeWidth={1.8} dot={{ r: 2, fill: '#09c7d8', strokeWidth: 0 }} activeDot={{ r: 4, fill: '#09c7d8', stroke: '#101a34', strokeWidth: 2 }} />
    </LineChart></ResponsiveContainer></div>
  </section>
}

function RiskFactorsTable({ search }) {
  const filtered = useMemo(() => riskFactors.filter((row) => Object.values(row).some((value) => String(value).toLowerCase().includes(search.trim().toLowerCase()))), [search])
  return <section className="panel risk-table-panel" aria-labelledby="risk-factors-heading">
    <header className="risk-section-heading"><div><h2 id="risk-factors-heading">Risk Factors</h2><p>Signals currently influencing the aggregate risk score</p></div><span className="live-indicator"><i className="status-dot status-dot--green" />4 ACTIVE FACTORS</span></header>
    <div className="risk-table-scroll"><table className="risk-table"><thead><tr><th>Risk Factor</th><th>Category</th><th>Severity</th><th>Score Contribution</th><th>Detected</th><th>Status</th></tr></thead><tbody>
      {filtered.map((row) => <tr key={row.id}><td><span className="risk-row-name">{row.factor}</span><span className="risk-row-id">{row.id}</span></td><td>{row.category}</td><td><span className={`severity severity--${row.severity.toLowerCase()}`}>{row.severity}</span></td><td className="risk-contribution-value">{row.contribution}</td><td className="event-time">{row.detected}</td><td><span className={`risk-state risk-state--${row.status.toLowerCase().replaceAll(' ', '-')}`}>{row.status}</span></td></tr>)}
      {filtered.length === 0 && <tr><td className="risk-no-results" colSpan="6">No risk factors match the current search.</td></tr>}
    </tbody></table></div>
  </section>
}

function AffectedResourcesTable({ search }) {
  const filtered = useMemo(() => affectedResources.filter((row) => Object.values(row).some((value) => String(value).toLowerCase().includes(search.trim().toLowerCase()))), [search])
  return <section className="panel risk-table-panel" aria-labelledby="affected-resources-heading">
    <header className="risk-section-heading"><div><h2 id="affected-resources-heading">Affected Resources</h2><p>Systems requiring additional monitoring or containment</p></div><span className="live-indicator"><i className="status-dot status-dot--cyan" />7 RESOURCES IMPACTED</span></header>
    <div className="risk-table-scroll"><table className="risk-table resources-table"><thead><tr><th>Resource</th><th>Type</th><th>Risk Level</th><th>Current Status</th><th>Last Activity</th></tr></thead><tbody>
      {filtered.map((row) => <tr key={row.resource}><td className="event-id">{row.resource}</td><td>{row.type}</td><td><span className={`severity severity--${row.risk.toLowerCase()}`}>{row.risk}</span></td><td><span className={`risk-state risk-state--${row.status.toLowerCase().replaceAll(' ', '-')}`}>{row.status}</span></td><td className="event-time">{row.activity}</td></tr>)}
      {filtered.length === 0 && <tr><td className="risk-no-results" colSpan="5">No resources match the current search.</td></tr>}
    </tbody></table></div>
  </section>
}

function RecommendedResponse({ onAction }) {
  return <section className="panel recommended-response" aria-labelledby="recommended-response-heading">
    <div className="response-copy"><div className="response-icon"><ShieldAlert size={17} /></div><div><span className="eyebrow">Recommended Response</span><h2 id="recommended-response-heading">High risk detected</h2><p>Isolate affected resources and verify backup integrity before initiating recovery.</p></div></div>
    <div className="response-actions">
      <button className="toolbar-button" onClick={() => onAction('Investigation started')}><Activity size={13} />Investigate</button>
      <button className="isolate-event-button" onClick={() => onAction('Resource isolation request submitted')}><Shield size={13} />Isolate Resource</button>
      <button className="toolbar-button" onClick={() => onAction('Backup integrity verification requested')}><ShieldCheck size={13} />Verify Backup</button>
      <button className="action-button action-button--neutral" onClick={() => onAction('Recovery readiness check started')}><Database size={13} />Start Recovery</button>
    </div>
  </section>
}

export default function RiskAnalysisPage({ globalSearch = '', onToast }) {
  const [refreshed, setRefreshed] = useState(false)
  return <main className="risk-analysis-main">
    <section className="risk-page-heading"><div><h1>Risk Analysis</h1><p>Analyze security risks, affected resources, and recommended response actions.</p></div>
      <div className="risk-page-actions"><span className="risk-updated-label">{refreshed ? 'Updated just now' : 'Assessment updated 2 min ago'}</span><button className="toolbar-button" onClick={() => setRefreshed(true)}><RefreshCw size={13} />Refresh</button></div>
    </section>
    <RiskSummaryCards />
    <div className="risk-overview-grid"><RiskScorePanel /><RiskHistoryChart /></div>
    <RecommendedResponse onAction={onToast ?? (() => {})} />
    <div className="risk-tables-grid"><RiskFactorsTable search={globalSearch} /><AffectedResourcesTable search={globalSearch} /></div>
    <footer className="risk-page-footer"><span><i className="status-dot status-dot--green" />Risk engine operational</span><span>Assessment model: v2.8 <span className="footer-divider">|</span> Mock data source</span></footer>
  </main>
}