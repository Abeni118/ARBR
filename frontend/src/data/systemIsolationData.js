export const isolationSummary = [
  { label: 'Total Systems', value: '24', support: 'Across 6 network segments', tone: 'cyan', icon: 'systems' },
  { label: 'Isolated Systems', value: '4', support: 'Containment active', tone: 'red', icon: 'isolated' },
  { label: 'Isolation Pending', value: '2', support: 'Awaiting policy response', tone: 'amber', icon: 'pending' },
  { label: 'Critical Systems', value: '3', support: 'High-priority assets', tone: 'amber', icon: 'critical' },
  { label: 'Last Isolation Event', value: '4 min ago', support: 'SERVER-01', tone: 'green', icon: 'recent' },
]

export const isolatedSystems = [
  { id: 'SYS-1042', system: 'SERVER-01', ip: '10.10.10.21', type: 'Application Server', risk: 'CRITICAL', threat: 'Ransomware Activity', status: 'Isolated', isolationTime: '10:42 AM', action: 'Under Investigation', segment: 'Production / Tier 1', lastActivity: '2 min ago' },
  { id: 'SYS-1041', system: 'SERVER-02', ip: '10.10.10.22', type: 'Application Server', risk: 'HIGH', threat: 'Suspicious Network Activity', status: 'Isolation Pending', isolationTime: '10:37 AM', action: 'Pending', segment: 'Production / Tier 1', lastActivity: '4 min ago' },
  { id: 'SYS-1039', system: 'DB-PROD-01', ip: '10.10.10.30', type: 'Database', risk: 'HIGH', threat: 'Unauthorized Access', status: 'Isolated', isolationTime: '09:51 AM', action: 'Protected', segment: 'Production / Data', lastActivity: '5 min ago' },
  { id: 'SYS-1037', system: 'BACKUP-NODE-02', ip: '10.10.20.12', type: 'Backup Server', risk: 'MEDIUM', threat: 'Integrity Anomaly', status: 'Isolation Failed', isolationTime: '09:32 AM', action: 'Retry Required', segment: 'Backup / Vault', lastActivity: '12 min ago' },
  { id: 'SYS-1034', system: 'AUTH-GATEWAY-01', ip: '10.10.10.5', type: 'Identity Service', risk: 'HIGH', threat: 'Credential Abuse', status: 'Isolated', isolationTime: '09:18 AM', action: 'Under Investigation', segment: 'Production / Edge', lastActivity: '18 min ago' },
  { id: 'SYS-1032', system: 'WORKSTATION-14', ip: '10.10.30.44', type: 'Endpoint', risk: 'MEDIUM', threat: 'Suspicious Process', status: 'Isolation Pending', isolationTime: '09:12 AM', action: 'Pending', segment: 'Office / Endpoints', lastActivity: '21 min ago' },
  { id: 'SYS-1030', system: 'API-GATEWAY-02', ip: '10.10.10.8', type: 'Gateway', risk: 'HIGH', threat: 'Lateral Movement', status: 'Isolated', isolationTime: '08:56 AM', action: 'Forensic Review', segment: 'Production / Edge', lastActivity: '28 min ago' },
  { id: 'SYS-1028', system: 'BUILD-NODE-03', ip: '10.10.30.63', type: 'Build Server', risk: 'LOW', threat: 'Policy Review Complete', status: 'Released', isolationTime: '08:41 AM', action: 'Released by analyst', segment: 'Engineering / CI', lastActivity: '34 min ago' },
]

export const isolationActivity = [
  { time: '10:42', title: 'System isolated', system: 'SERVER-01 · Ransomware containment applied', type: 'danger' },
  { time: '10:37', title: 'Isolation requested', system: 'SERVER-02 · Awaiting endpoint acknowledgement', type: 'warning' },
  { time: '09:51', title: 'Network quarantine confirmed', system: 'DB-PROD-01 · Forensic access retained', type: 'success' },
  { time: '09:32', title: 'Isolation command failed', system: 'BACKUP-NODE-02 · Retry required', type: 'danger' },
]
