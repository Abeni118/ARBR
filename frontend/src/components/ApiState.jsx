import { CircleHelp } from 'lucide-react'
import { displayValue } from '../api/formatters.js'

export function ApiState({ loading, error, empty, onRetry, children }) {
  if (loading) return <div className="api-state" role="status"><span className="loading-spinner" />Loading data from the API…</div>
  if (error) return <div className="api-state api-state--error" role="alert"><CircleHelp size={16} /><span><strong>{error.status === 401 ? 'Authentication required' : error.status === 403 ? 'Permission denied' : 'API request failed'}</strong><br />{error.message || 'The API request failed.'}</span>{onRetry && <button className="toolbar-button" onClick={onRetry}>Retry</button>}</div>
  if (empty) return <div className="api-state"><CircleHelp size={16} />{empty}</div>
  return children
}

export function ApiDetail({ label, value }) {
  if (value === null || value === undefined || value === '') return null
  return <div><dt>{label}</dt><dd>{displayValue(value)}</dd></div>
}
