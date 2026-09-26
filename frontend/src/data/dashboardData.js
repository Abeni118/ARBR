export const navigationItems = [
  { label: 'Dashboard', icon: 'dashboard' },
  { label: 'Security Events', icon: 'activity' },
  { label: 'Threat Detection', icon: 'shield' },
  { label: 'Risk Analysis', icon: 'chart' },
  { label: 'Backups', icon: 'database' },
  { label: 'Recovery', icon: 'rotate' },
  { label: 'System Isolation', icon: 'lock' },
  { label: 'Audit Logs', icon: 'file' },
  { label: 'Settings', icon: 'settings' },
]

export const metrics = [
  { label: 'System Status', value: 'SECURE', kind: 'secure', icon: 'shield-check' },
  { label: 'Active Threats', value: '12', trend: '+4.2%', trendTone: 'danger', icon: 'alert' },
  { label: 'Risk Score', value: '38', trend: '−12.5%', trendTone: 'good', icon: 'fingerprint' },
  { label: 'Protected Backups', value: '1.2 PB', icon: 'database' },
]

export const riskTrend = [
  { time: '00:00', risk: 34, threats: 3 },
  { time: '04:00', risk: 40, threats: 4 },
  { time: '08:00', risk: 31, threats: 2 },
  { time: '12:00', risk: 59, threats: 8 },
  { time: '16:00', risk: 57, threats: 7 },
  { time: '20:00', risk: 45, threats: 4 },
  { time: '23:59', risk: 41, threats: 3 },
]

export const securityEvents = [
  { id: 'EVT-9021', time: '14:22:01', source: '192.168.1.104', category: 'Brute Force Attempt', severity: 'HIGH', status: 'Blocked' },
  { id: 'EVT-9020', time: '14:15:46', source: 'Cloud-Gateway-02', category: 'Data Exfiltration Suspect', severity: 'CRITICAL', status: 'Isolating' },
  { id: 'EVT-8919', time: '13:58:12', source: 'Storage-Node-Alpha', category: 'Immutable Lock Verified', severity: 'INFO', status: 'Success' },
  { id: 'EVT-8918', time: '13:42:58', source: '10.0.4.52', category: 'Unusual Port Scan', severity: 'MEDIUM', status: 'Monitoring' },
  { id: 'EVT-8917', time: '13:30:05', source: 'Auth-Server-01', category: 'Multiple Failed Logins', severity: 'LOW', status: 'Resolved' },
]

export const resourceUsage = [
  { label: 'Compute Nodes', value: 82, color: 'cyan' },
  { label: 'Immutable Storage', value: 45, color: 'green' },
]
