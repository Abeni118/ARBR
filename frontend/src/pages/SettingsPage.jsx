import { useEffect, useState } from 'react'
import { Activity, Bell, ClipboardList, KeyRound, RefreshCw, Settings, ShieldCheck } from 'lucide-react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { api } from '../api/client.js'
import { displayValue, formatTimestamp } from '../api/formatters.js'
import { ApiState } from '../components/ApiState.jsx'
import { useAuth } from '../auth/AuthContext.jsx'
import './SettingsPage.css'

const settingsPages = [
	{ path: '/settings/general', label: 'General', description: 'Application identity, display behavior, and system configuration.' },
	{ path: '/settings/security-access', label: 'Security & Access', description: 'Current account, role permissions, and cookie-session security.' },
	{ path: '/settings/notifications', label: 'Notifications', description: 'Server-provided notification policy; delivery preferences are not exposed.' },
	{ path: '/settings/system-integrations', label: 'System & Integrations', description: 'Live backend health and available operational policy status.' },
	{ path: '/settings/audit-monitoring', label: 'Audit & Monitoring', description: 'Audit API availability and configured risk thresholds.' },
]

const roleDescriptions = {
	viewer: 'Read access to authenticated operational data.',
	analyst: 'Read access plus analyst workflow operations, including asset registration.',
	approver: 'Read access plus action-request approval and rejection.',
	admin: 'All human-user operations; system settings remain read-only.',
}

function useApiResource(path, refreshKey = 0) {
	const requestKey = `${refreshKey}:${path}`
	const [state, setState] = useState({ requestKey: '', data: null, loading: false, error: null })
	useEffect(() => {
		const controller = new AbortController()
		api.get(path, { signal: controller.signal })
			.then((data) => setState({ requestKey, data, loading: false, error: null }))
			.catch((error) => {
				if (error.name !== 'AbortError') setState({ requestKey, data: null, loading: false, error })
			})
		return () => controller.abort()
	}, [path, refreshKey, requestKey])
	return state.requestKey === requestKey ? state : { data: null, loading: true, error: null }
}

function SettingsCard({ title, description, icon: Icon, children }) {
	return (
		<section className="panel settings-card settings-section-card" aria-label={title}>
			<header className="settings-card-heading">
				<span className="settings-card-icon"><Icon size={19} aria-hidden="true" /></span>
				<div><h2>{title}</h2><p className="settings-card-description">{description}</p></div>
			</header>
			<div className="settings-card-content">{children}</div>
		</section>
	)
}

function SettingsValues({ values, emptyMessage = 'No values were returned by the settings API.' }) {
	const entries = Object.entries(values || {})
	if (!entries.length) return <p className="settings-section-empty">{emptyMessage}</p>
	return (
		<dl className="settings-values">
			{entries.map(([key, value]) => <div className="settings-value-row" key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{displayValue(value)}</dd></div>)}
		</dl>
	)
}

function SettingsData({ path = '/settings', refreshKey = 0, children }) {
	const { data, loading, error } = useApiResource(path, refreshKey)
	return <ApiState loading={loading} error={error} empty={!data ? 'No response was returned.' : null}>{data && children(data)}</ApiState>
}

export function SettingsLayout() {
	const location = useLocation()
	const page = settingsPages.find((item) => item.path === location.pathname) || settingsPages[0]
	return (
		<main className="settings-main">
			<section className="api-page-heading"><div><h1>{page.label}</h1><p>{page.description}</p></div></section>
			<nav className="panel settings-section-nav" aria-label="Settings navigation">
				{settingsPages.map((item) => <NavLink key={item.path} to={item.path} end aria-label={`${item.label} settings`}>{item.label}</NavLink>)}
			</nav>
			<Outlet />
		</main>
	)
}

export function SettingsGeneralPage() {
	return (
		<div className="settings-sections-grid">
			<SettingsCard title="Application" description="Application identity and server-managed configuration metadata." icon={Settings}>
				<dl className="settings-values"><div className="settings-value-row"><dt>Application</dt><dd>Attack-Resistant Backup &amp; Recovery</dd></div></dl>
				<SettingsData>{(data) => <dl className="settings-values">
					<div className="settings-value-row"><dt>Configuration version</dt><dd>{displayValue(data.version)}</dd></div>
					<div className="settings-value-row"><dt>Last updated</dt><dd>{formatTimestamp(data.updated_at)}</dd></div>
				</dl>}</SettingsData>
			</SettingsCard>
			<SettingsCard title="Appearance & display" description="Display behavior currently available in this frontend." icon={Activity}>
				<dl className="settings-values">
					<div className="settings-value-row"><dt>Appearance</dt><dd>Built-in dark navy interface</dd></div>
					<div className="settings-value-row"><dt>Appearance preference storage</dt><dd>Not stored locally or by the server</dd></div>
					<div className="settings-value-row"><dt>Date and time format</dt><dd>Browser locale and time zone</dd></div>
				</dl>
				<p className="settings-readonly-note">There are no supported theme, time-zone, or date-format controls. No changes are saved from this page.</p>
			</SettingsCard>
		</div>
	)
}

export function SettingsSecurityAccessPage() {
	const { user } = useAuth()
	return (
		<div className="settings-sections-grid">
			<SettingsCard title="Authenticated account" description="Identity fields supplied by the current authenticated session." icon={ShieldCheck}>
				<dl className="settings-values">
					<div className="settings-value-row"><dt>Account ID</dt><dd>{user?.user_id || 'Not provided'}</dd></div>
					<div className="settings-value-row"><dt>Display name</dt><dd>{user?.display_name || 'Not provided'}</dd></div>
					<div className="settings-value-row"><dt>Assigned role</dt><dd>{user?.role || 'Not provided'}</dd></div>
					<div className="settings-value-row"><dt>Role permissions</dt><dd>{roleDescriptions[user?.role] || 'Permission details are not available for this role.'}</dd></div>
				</dl>
				<p className="settings-readonly-note">The authenticated-user API does not expose a separate username. No credentials, hashes, or tokens are displayed.</p>
			</SettingsCard>
			<SettingsCard title="Session & authentication" description="Current browser-session protections and account actions." icon={KeyRound}>
				<dl className="settings-values">
					<div className="settings-value-row"><dt>Session status</dt><dd>{user ? 'Authenticated' : 'Unavailable'}</dd></div>
					<div className="settings-value-row"><dt>Authentication</dt><dd>HttpOnly cookie session</dd></div>
					<div className="settings-value-row"><dt>Session expiry</dt><dd>Not exposed by the API</dd></div>
					<div className="settings-value-row"><dt>State-changing request protection</dt><dd>CSRF validation enabled</dd></div>
				</dl>
				<Link className="toolbar-button settings-password-link" to="/change-password"><KeyRound size={14} /> Change password</Link>
			</SettingsCard>
		</div>
	)
}

export function SettingsNotificationsPage() {
	return (
		<div className="settings-sections-grid">
			<SettingsCard title="Notification policy" description="Values returned by the backend notification policy." icon={Bell}>
				<SettingsData>{(data) => <SettingsValues values={data.notification_policy} emptyMessage="No notification preferences are configured in the backend response." />}</SettingsData>
			</SettingsCard>
			<SettingsCard title="Delivery & personal preferences" description="Notifications that can currently be managed through the application." icon={Activity}>
				<div className="settings-unavailable-state"><Bell size={20} /><p>Notification delivery status, channels, category subscriptions, and user-level severity controls are not exposed by the available API.</p></div>
				<p className="settings-readonly-note">These preferences are unavailable; this page does not show editable switches or claim to save changes.</p>
			</SettingsCard>
		</div>
	)
}

export function SettingsSystemIntegrationsPage() {
	const [refresh, setRefresh] = useState(0)
	const health = useApiResource('/health', refresh)
	return (
		<div className="settings-sections-grid">
			<SettingsCard title="Backend API" description="Connection status from a live health endpoint request." icon={Activity}>
				<div className="settings-health-row">
					<ApiState loading={health.loading} error={health.error} onRetry={() => setRefresh((value) => value + 1)} empty={!health.loading && !health.error && !health.data ? 'No health response was returned.' : null}>
						{health.data && <span className={`settings-inline-status ${health.data.status === 'ok' ? 'settings-inline-status--ok' : 'settings-inline-status--error'}`}>{health.data.status === 'ok' ? 'Connected' : 'Health check reported'} · {displayValue(health.data.status)}</span>}
					</ApiState>
					<button className="toolbar-button" type="button" onClick={() => setRefresh((value) => value + 1)} disabled={health.loading}><RefreshCw size={14} /> Check again</button>
				</div>
			</SettingsCard>
			<SettingsCard title="Integrations" description="Only integration status verifiable by an available endpoint is reported." icon={ShieldCheck}>
				<dl className="settings-values">
					<div className="settings-value-row"><dt>Wazuh</dt><dd>Unverified — no integration health endpoint is available</dd></div>
					<div className="settings-value-row"><dt>Backup / recovery components</dt><dd>Status is not exposed by the system health endpoint</dd></div>
				</dl>
			</SettingsCard>
			<SettingsCard title="Operational policies" description="Read-only policy values supplied by the system settings API." icon={Settings}>
				<SettingsData>{(data) => <div className="settings-policy-subsections">
					{['isolation_policy', 'backup_policy', 'recovery_policy'].map((section) => <section className="settings-policy-block" key={section}><h3>{section.replaceAll('_', ' ')}</h3><SettingsValues values={data[section]} emptyMessage="No values returned." /></section>)}
				</div>}</SettingsData>
			</SettingsCard>
		</div>
	)
}

export function SettingsAuditMonitoringPage() {
	const [refresh, setRefresh] = useState(0)
	const audit = useApiResource('/audit-logs?page=1&page_size=1', refresh)
	return (
		<div className="settings-sections-grid">
			<SettingsCard title="Audit records" description="Existing authenticated audit-log endpoint and returned record count." icon={ClipboardList}>
				<ApiState loading={audit.loading} error={audit.error} onRetry={() => setRefresh((value) => value + 1)} empty={!audit.loading && !audit.error && !audit.data ? 'No audit response was returned.' : null}>
					{audit.data && <dl className="settings-values">
						<div className="settings-value-row"><dt>Matching audit records</dt><dd>{displayValue(audit.data.total)}</dd></div>
						<div className="settings-value-row"><dt>Severity summary</dt><dd>Not provided by the audit API</dd></div>
					</dl>}
				</ApiState>
				<Link className="toolbar-button settings-password-link" to="/audit-logs">View audit logs <ClipboardList size={14} /></Link>
			</SettingsCard>
			<SettingsCard title="Risk thresholds" description="Threshold values returned by the read-only settings API." icon={ShieldCheck}>
				<SettingsData>{(data) => <SettingsValues values={data.risk_thresholds} emptyMessage="No threshold values were returned." />}</SettingsData>
				<p className="settings-readonly-note">Threshold settings are read-only; the API does not support editing from this frontend.</p>
			</SettingsCard>
		</div>
	)
}
