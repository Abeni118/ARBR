export const riskSummary = [
  { label: 'Overall Risk Score', value: '78 / 100', support: 'HIGH RISK', tone: 'red', icon: 'risk' },
  { label: 'Critical Risks', value: '3', support: '2 require review', tone: 'red', icon: 'critical' },
  { label: 'Affected Resources', value: '7', support: 'Across 4 systems', tone: 'amber', icon: 'resources' },
  { label: 'Active Threats', value: '5', support: 'Monitoring active', tone: 'cyan', icon: 'threats' },
  { label: 'Last Assessment', value: '2 min ago', support: 'Updated automatically', tone: 'green', icon: 'assessment' },
]

export const riskContributors = [
  { label: 'Suspicious Authentication Activity', value: 20 },
  { label: 'Malware Detection', value: 25 },
  { label: 'Abnormal Network Traffic', value: 15 },
  { label: 'Backup Integrity Warning', value: 18 },
]

export const riskFactors = [
  { id: 'RSK-1042', factor: 'Suspicious Login Attempts', category: 'Authentication', severity: 'HIGH', contribution: '+18', detected: '10 min ago', status: 'Active' },
  { id: 'RSK-1041', factor: 'Abnormal Network Traffic', category: 'Network', severity: 'HIGH', contribution: '+20', detected: '15 min ago', status: 'Active' },
  { id: 'RSK-1040', factor: 'Possible Malware Activity', category: 'Endpoint', severity: 'CRITICAL', contribution: '+30', detected: '22 min ago', status: 'Investigating' },
  { id: 'RSK-1039', factor: 'Backup Integrity Warning', category: 'Backup', severity: 'MEDIUM', contribution: '+10', detected: '31 min ago', status: 'Monitoring' },
]

export const affectedResources = [
  { resource: 'SERVER-01', type: 'Server', risk: 'HIGH', status: 'Under Investigation', activity: '2 min ago' },
  { resource: 'DB-PROD-01', type: 'Database', risk: 'CRITICAL', status: 'Protected', activity: '5 min ago' },
  { resource: 'BACKUP-NODE-02', type: 'Backup Server', risk: 'MEDIUM', status: 'Monitoring', activity: '12 min ago' },
  { resource: 'AUTH-GATEWAY-01', type: 'Identity Service', risk: 'HIGH', status: 'Under Investigation', activity: '16 min ago' },
]

export const riskHistory = [
  { time: '10:00', score: 32 },
  { time: '10:15', score: 41 },
  { time: '10:30', score: 48 },
  { time: '10:45', score: 62 },
  { time: '11:00', score: 71 },
  { time: '11:15', score: 78 },
]