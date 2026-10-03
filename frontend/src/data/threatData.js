const threatSeeds = [
  {
    name: 'Ransomware Activity', type: 'Ransomware', severity: 'CRITICAL', source: 'Backup-Proxy-03', status: 'Active',
    description: 'Rapid file renaming and encryption-like writes were detected in a protected backup staging area.',
    affectedResource: 'backup-staging-03 / volume B',
    indicators: ['File entropy increased 4.8× above baseline', '1,284 files renamed in 90 seconds', 'Shadow-copy deletion command observed'],
    response: 'The write path was suspended automatically. Isolate the proxy, preserve a forensic snapshot, and verify the last known-good restore point.',
  },
  {
    name: 'Unauthorized File Modification', type: 'Integrity Violation', severity: 'HIGH', source: 'Storage-Node-Alpha', status: 'Investigating',
    description: 'Protected manifest files changed outside the approved maintenance window.',
    affectedResource: 'immutable-vault-01 / manifest.json',
    indicators: ['Manifest hash mismatch', 'Change request not found', 'Change originated from service account svc-backup'],
    response: 'Immutable retention prevented overwrite. Validate the service account activity and compare against the signed manifest.',
  },
  {
    name: 'Suspicious Login', type: 'Identity Anomaly', severity: 'MEDIUM', source: 'Auth-Server-01', status: 'Active',
    description: 'A privileged account authenticated from an unfamiliar network and device fingerprint.',
    affectedResource: 'administrator account / control plane',
    indicators: ['Unrecognized source network 198.51.100.42', 'MFA challenge passed after 7 failures', 'Login time differs from user baseline'],
    response: 'Session was revoked and step-up authentication required. Confirm the account owner and review recent privileged actions.',
  },
  {
    name: 'Backup Deletion Attempt', type: 'Destructive Action', severity: 'CRITICAL', source: 'Cloud-Gateway-02', status: 'Contained',
    description: 'A delete request targeted multiple protected recovery points using a compromised API credential.',
    affectedResource: 'recovery-set-prod-07 / 36 snapshots',
    indicators: ['36 delete requests in 12 seconds', 'Credential used from an untrusted IP', 'Object-lock policy denied all requests'],
    response: 'Requests were denied by object lock and the credential was disabled. Credential rotation and audit review are in progress.',
  },
  {
    name: 'Malware Detected', type: 'Malware', severity: 'HIGH', source: 'Recovery-Node-02', status: 'Investigating',
    description: 'A known malicious payload was identified in a quarantined recovery image during validation.',
    affectedResource: 'restore-point-RP-441 / isolated sandbox',
    indicators: ['Signature match: Trojan.Generic.441', 'File hash matched threat intelligence feed', 'No outbound connections observed'],
    response: 'The restore image remains quarantined. Select an earlier clean recovery point and scan adjacent snapshots before restoration.',
  },
  {
    name: 'Privilege Escalation', type: 'Privilege Abuse', severity: 'HIGH', source: 'Compute-Node-04', status: 'Active',
    description: 'A backup operator process attempted to obtain an administrator token on a protected node.',
    affectedResource: 'compute-node-04 / backup-agent',
    indicators: ['Unexpected token elevation request', 'Unsigned process spawned by backup-agent', 'Attempt blocked by endpoint policy'],
    response: 'The process was terminated automatically. Review agent integrity and rotate credentials associated with this node.',
  },
  {
    name: 'Unusual Backup Access', type: 'Access Anomaly', severity: 'LOW', source: 'Storage-Node-Beta', status: 'Resolved',
    description: 'Read volume for a protected archive exceeded the normal access rate for this service.',
    affectedResource: 'archive-finance-2026 / snapshot set',
    indicators: ['Read rate reached 2.1× the 30-day baseline', 'Access used an authorized service identity', 'No data transfer to untrusted destinations'],
    response: 'Activity was verified as a scheduled restore drill. Monitoring thresholds were updated and the event was closed.',
  },
  {
    name: 'Credential Exposure Signal', type: 'Credential Risk', severity: 'MEDIUM', source: 'CI-Runner-01', status: 'Resolved',
    description: 'A secret-scanning rule found a backup token in a temporary build artifact.',
    affectedResource: 'build-artifacts / job 8f12a',
    indicators: ['Backup token pattern matched', 'Artifact access limited to internal runners', 'Token revoked before external access'],
    response: 'The token was revoked, the artifact purged, and the pipeline updated to use the managed secret store.',
  },
]

const detectionTimes = ['2026-09-28 14:32:18', '2026-09-28 14:18:45', '2026-09-28 13:56:02', '2026-09-28 13:41:29', '2026-09-28 12:58:11', '2026-09-28 12:36:54', '2026-09-28 11:52:07', '2026-09-27 18:24:36']
const minutesAgo = [8, 22, 45, 59, 102, 123, 168, 1196]

export const threats = threatSeeds.map((threat, index) => ({
  ...threat,
  id: `THR-${String(2048 - index).padStart(4, '0')}`,
  detectedAt: detectionTimes[index],
  minutesAgo: minutesAgo[index],
}))

export const threatFilterOptions = {
  severities: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
  types: [...new Set(threats.map(({ type }) => type))],
  statuses: ['Active', 'Investigating', 'Contained', 'Resolved'],
  dateRanges: ['Last hour', 'Last 24 hours', 'Last 7 days'],
}