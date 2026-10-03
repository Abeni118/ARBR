export const backupSummary = [
  { label: 'Total Backups', value: '24', support: 'Across 8 systems', tone: 'cyan', icon: 'total' },
  { label: 'Healthy Backups', value: '19', support: 'Recovery ready', tone: 'green', icon: 'healthy' },
  { label: 'Verification Required', value: '3', support: 'Action recommended', tone: 'amber', icon: 'warning' },
  { label: 'Failed Backups', value: '2', support: 'Review required', tone: 'red', icon: 'failed' },
  { label: 'Last Successful Backup', value: '8 min ago', support: 'SERVER-01', tone: 'green', icon: 'recent' },
]

export const backupRecords = [
  { id: 'BKP-2026-091', resource: 'SERVER-01', type: 'Full', size: '12.4 GB', created: '10:42 AM', integrity: 'Verified', status: 'Healthy', encryption: 'Enabled', checksum: 'SHA-256 · 9f86d081884c7d65…', verifiedAt: '5 minutes ago', recoveryReady: 'Yes' },
  { id: 'BKP-2026-090', resource: 'DB-PROD-01', type: 'Incremental', size: '4.8 GB', created: '09:30 AM', integrity: 'Verified', status: 'Healthy', encryption: 'Enabled', checksum: 'SHA-256 · 2c26b46b68ffc68f…', verifiedAt: '8 minutes ago', recoveryReady: 'Yes' },
  { id: 'BKP-2026-089', resource: 'SERVER-02', type: 'Full', size: '15.1 GB', created: '08:15 AM', integrity: 'Warning', status: 'Needs Verification', encryption: 'Enabled', checksum: 'SHA-256 · a3f5c9e17b2d8a41…', verifiedAt: '2 hours ago', recoveryReady: 'Verification Required' },
  { id: 'BKP-2026-088', resource: 'DB-PROD-02', type: 'Incremental', size: '3.2 GB', created: '07:45 AM', integrity: 'Failed', status: 'Failed', encryption: 'Enabled', checksum: 'SHA-256 · checksum mismatch', verifiedAt: 'Today, 07:48 AM', recoveryReady: 'No' },
]

export const recoveryReadiness = [
  { resource: 'SERVER-01', status: 'Recovery Ready', verified: '5 min ago' },
  { resource: 'DB-PROD-01', status: 'Recovery Ready', verified: '8 min ago' },
  { resource: 'SERVER-02', status: 'Verification Required', verified: '2 hours ago' },
  { resource: 'DB-PROD-02', status: 'Not Ready', verified: 'Today, 07:48 AM' },
]

export const backupActivity = [
  { time: '10:42', title: 'Backup created', resource: 'SERVER-01', type: 'success' },
  { time: '10:37', title: 'Integrity verified', resource: 'DB-PROD-01', type: 'success' },
  { time: '10:21', title: 'Verification failed', resource: 'SERVER-02', type: 'danger' },
  { time: '09:55', title: 'Backup completed', resource: 'DB-PROD-02', type: 'neutral' },
]