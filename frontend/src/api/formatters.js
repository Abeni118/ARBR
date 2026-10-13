export function formatTimestamp(value) {
  if (value === null || value === undefined || value === '') return 'Not recorded'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

export function formatBytes(value) {
  if (value === null || value === undefined) return 'Not recorded'
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let amount = value
  let unitIndex = -1
  do {
    amount /= 1024
    unitIndex += 1
  } while (amount >= 1024 && unitIndex < units.length - 1)
  return `${amount.toFixed(1)} ${units[unitIndex]}`
}

export function displayValue(value) {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export function statusClass(value) {
  return String(value || 'unknown').toLowerCase().replaceAll('_', '-').replace(/[^a-z0-9-]/g, '')
}
