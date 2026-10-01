export const recoverySummary = [
  { label: 'Recovery-Ready Systems', value: '19', support: 'Verified restore points available', tone: 'green', icon: 'ready' },
  { label: 'Available Restore Points', value: '24', support: 'Across 8 protected systems', tone: 'cyan', icon: 'points' },
  { label: 'Verification Required', value: '3', support: 'Review before restoration', tone: 'amber', icon: 'warning' },
  { label: 'Active Recovery Jobs', value: '1', support: 'Isolated environment', tone: 'cyan', icon: 'jobs' },
  { label: 'Last Recovery Test', value: 'Today, 09:15', support: 'Completed successfully', tone: 'green', icon: 'recent' },
]

export const restorePoints = [
  { id: 'BKP-2026-091', system: 'SERVER-01', created: 'Today, 10:42 AM', age: '8 min ago', type: 'Full', size: '12.4 GB', integrity: 'Verified', readiness: 'Recovery Ready', encrypted: 'Enabled', checksum: 'SHA-256 · 9f86d081884c7d65…', verifiedAt: '5 minutes ago', environment: 'Isolated recovery network' },
  { id: 'BKP-2026-090', system: 'DB-PROD-01', created: 'Today, 09:30 AM', age: '1 hr ago', type: 'Incremental', size: '4.8 GB', integrity: 'Verified', readiness: 'Recovery Ready', encrypted: 'Enabled', checksum: 'SHA-256 · 2c26b46b68ffc68f…', verifiedAt: '8 minutes ago', environment: 'Isolated recovery network' },
  { id: 'BKP-2026-089', system: 'SERVER-02', created: 'Today, 08:15 AM', age: '2 hr ago', type: 'Full', size: '15.1 GB', integrity: 'Warning', readiness: 'Verification Required', encrypted: 'Enabled', checksum: 'SHA-256 · a3f5c9e17b2d8a41…', verifiedAt: '2 hours ago', environment: 'Pending verification' },
  { id: 'BKP-2026-088', system: 'DB-PROD-02', created: 'Today, 07:45 AM', age: '3 hr ago', type: 'Incremental', size: '3.2 GB', integrity: 'Failed', readiness: 'Not Ready', encrypted: 'Enabled', checksum: 'SHA-256 · checksum mismatch', verifiedAt: 'Today, 07:48 AM', environment: 'Quarantined' },
  { id: 'BKP-2026-087', system: 'AUTH-GATEWAY-01', created: 'Today, 06:30 AM', age: '4 hr ago', type: 'Full', size: '8.6 GB', integrity: 'Verified', readiness: 'Recovery Ready', encrypted: 'Enabled', checksum: 'SHA-256 · 118a2f0cde736ab1…', verifiedAt: 'Today, 06:35 AM', environment: 'Isolated recovery network' },
]

export const recoveryReadiness = [
  { system: 'SERVER-01', point: 'BKP-2026-091', readiness: 'Recovery Ready', verified: '5 min ago' },
  { system: 'DB-PROD-01', point: 'BKP-2026-090', readiness: 'Recovery Ready', verified: '8 min ago' },
  { system: 'SERVER-02', point: 'BKP-2026-089', readiness: 'Verification Required', verified: '2 hours ago' },
  { system: 'DB-PROD-02', point: 'BKP-2026-088', readiness: 'Not Ready', verified: 'Today, 07:48 AM' },
]

export const recoveryActivity = [
  { time: '10:48', title: 'Recovery point validated', system: 'BKP-2026-091 · SERVER-01', type: 'success' },
  { time: '10:22', title: 'Isolated recovery environment prepared', system: 'RECOVERY-NODE-02 · Job RCV-018', type: 'neutral' },
  { time: '09:15', title: 'Recovery test completed', system: 'DB-PROD-01 · Integrity confirmed', type: 'success' },
  { time: '08:21', title: 'Restore point quarantined', system: 'BKP-2026-088 · Checksum mismatch', type: 'danger' },
]
