const auditEventSeeds = [
  { actor: 'admin', actorType: 'Human', action: 'System isolated', resource: 'SERVER-01', eventType: 'System Isolation', severity: 'CRITICAL', status: 'SUCCESS', sourceIp: '10.10.10.15', description: 'SERVER-01 was isolated after the risk engine classified the system as critical.' },
  { actor: 'risk-engine', actorType: 'Automated Engine', action: 'Risk score updated', resource: 'SERVER-02', eventType: 'Risk Analysis', severity: 'HIGH', status: 'SUCCESS', sourceIp: '127.0.0.1', description: 'Risk score increased from 62 to 81 after correlation of suspicious network activity.' },
  { actor: 'backup-service', actorType: 'System Service', action: 'Backup verified', resource: 'BKP-2026-091', eventType: 'Backup Integrity', severity: 'MEDIUM', status: 'SUCCESS', sourceIp: '10.10.20.8', description: 'SHA-256 checksum matched the signed manifest for the latest recovery point.' },
  { actor: 'admin', actorType: 'Human', action: 'Recovery started', resource: 'SERVER-03', eventType: 'Recovery', severity: 'HIGH', status: 'SUCCESS', sourceIp: '10.10.10.15', description: 'Recovery job RCV-018 started in an isolated validation environment.' },
  { actor: 'recovery-service', actorType: 'System Service', action: 'Recovery failed', resource: 'SERVER-05', eventType: 'Recovery', severity: 'CRITICAL', status: 'FAILED', sourceIp: '10.10.20.14', description: 'Recovery validation failed because the restored volume did not match the expected checksum.' },
  { actor: 'analyst.jlee', actorType: 'Human', action: 'Threat marked contained', resource: 'THR-2045', eventType: 'Threat Detection', severity: 'HIGH', status: 'SUCCESS', sourceIp: '10.10.10.22', description: 'Threat containment was confirmed after the affected endpoint stopped beaconing.' },
  { actor: 'auth-gateway', actorType: 'System Service', action: 'Privileged login rejected', resource: 'AUTH-GATEWAY-01', eventType: 'Authentication', severity: 'HIGH', status: 'FAILED', sourceIp: '198.51.100.42', description: 'Authentication was denied after repeated failed MFA challenges from an untrusted address.' },
  { actor: 'admin', actorType: 'Human', action: 'Retention policy changed', resource: 'immutable-vault-01', eventType: 'Configuration', severity: 'MEDIUM', status: 'SUCCESS', sourceIp: '10.10.10.15', description: 'Backup retention was updated to comply with the approved change request CHG-2281.' },
  { actor: 'audit-agent', actorType: 'Automated Engine', action: 'Policy snapshot recorded', resource: 'security-policy-v4', eventType: 'Administration', severity: 'LOW', status: 'SUCCESS', sourceIp: '127.0.0.1', description: 'A signed configuration snapshot was recorded for audit and rollback.' },
  { actor: 'backup-service', actorType: 'System Service', action: 'Backup job queued', resource: 'DB-PROD-02', eventType: 'Backup', severity: 'MEDIUM', status: 'PENDING', sourceIp: '10.10.20.8', description: 'Scheduled incremental backup entered the protected repository queue.' },
]

const startTimes = ['2026-10-01 17:02:31', '2026-10-01 16:58:12', '2026-10-01 16:51:44', '2026-10-01 16:42:09', '2026-10-01 16:39:22', '2026-10-01 16:31:07', '2026-10-01 16:24:53', '2026-10-01 16:18:40', '2026-10-01 16:11:28', '2026-10-01 16:05:02']

export const auditLogRecords = Array.from({ length: 1284 }, (_, index) => {
  const seed = auditEventSeeds[index % auditEventSeeds.length]
  const minutesAgo = Math.floor(index / auditEventSeeds.length) * 8
  const timestamp = new Date(new Date(startTimes[index % startTimes.length].replace(' ', 'T') + 'Z').getTime() - minutesAgo * 60_000)
    .toISOString().replace('T', ' ').slice(0, 19)
  return {
    ...seed,
    id: `AUD-${String(982 + index).padStart(5, '0')}`,
    timestamp,
    minutesAgo,
  }
})

export const auditSummary = [
  { label: 'Total Events', value: '1,284', support: 'Across all security operations', tone: 'cyan', icon: 'total' },
  { label: 'Critical Events', value: '12', support: 'Immediate review required', tone: 'red', icon: 'critical' },
  { label: 'Administrative Actions', value: '86', support: 'Human-initiated changes', tone: 'amber', icon: 'admin' },
  { label: 'Automated Actions', value: '342', support: 'Engine and service activity', tone: 'green', icon: 'automated' },
  { label: 'Failed Actions', value: '7', support: 'Review failure details', tone: 'red', icon: 'failed' },
]

export const auditEventTypes = ['Authentication', 'Threat Detection', 'Risk Analysis', 'System Isolation', 'Backup', 'Backup Integrity', 'Recovery', 'Configuration', 'Administration']
export const auditActors = [...new Set(auditEventSeeds.map(({ actor }) => actor))]
export const auditStatuses = ['SUCCESS', 'FAILED', 'PENDING']
export const auditSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export const recentAuditActivity = auditLogRecords.slice(0, 4).map((event) => ({
  time: event.timestamp.slice(11, 16),
  title: event.action,
  resource: `${event.resource} · Actor: ${event.actor}`,
  type: event.status === 'FAILED' ? 'danger' : event.severity === 'CRITICAL' ? 'warning' : 'success',
}))
